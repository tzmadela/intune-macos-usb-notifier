#!/bin/zsh

# -------------------------------------------------------------------------
# macOS USB Security Notifier (Production v5.0)
# Architecture:
#   - LaunchDaemon (root): watches IOKit electrical attach events via
#     ioreg -w, touches /var/run/usb_attach_trigger on any USB change
#   - LaunchAgent (user): wakes on trigger file change, scans IORegistry
#     for new devices, checks whitelist, shows popup for blocked drives
#   - check_serial.py: reads live /Library/Managed Preferences/com.microsoft.wdav.plist
#     — zero maintenance, auto-updates when MDM/Intune profile changes
# -------------------------------------------------------------------------

LOG="/var/log/usb_watcher.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [USB-WATCHER-DEPLOY] $1" >> "$LOG"
}

# 1. Pre-create log file as root with world-writable permissions so the
#    standard user running the LaunchAgent worker can also append to it.
touch "$LOG"
chmod 666 "$LOG"
log "Deployment started."
log "Log file created and permissions set (666)."

# Create the secure tools directory
mkdir -p "/Library/Application Support/ITTools"

# Create the trigger file watched by the LaunchAgent.
# Must exist before the LaunchAgent loads or WatchPaths silently fails.
# World-writable so the root LaunchDaemon can touch it.
touch /var/run/usb_attach_trigger
chmod 666 /var/run/usb_attach_trigger

# -------------------------------------------------------------------------
# 2. Create the Serial Whitelist Checker (Python)
#    Reads the live Intune managed plist — same file Defender uses.
# -------------------------------------------------------------------------
cat << 'PYEOF' > "/Library/Application Support/ITTools/check_serial.py"
#!/usr/bin/env python3
import plistlib, json, sys

MANAGED_PLIST = "/Library/Managed Preferences/com.microsoft.wdav.plist"

if len(sys.argv) < 2:
    print("error:missing serial argument")
    sys.exit(0)

serial_check = sys.argv[1].strip().upper()

try:
    with open(MANAGED_PLIST, "rb") as f:
        plist_data = plistlib.load(f)
except FileNotFoundError:
    print("error:managed plist not found")
    sys.exit(0)
except Exception as e:
    print(f"error:plist read failed:{e}")
    sys.exit(0)

try:
    device_control = plist_data.get("deviceControl", {})
    policy_json_str = device_control.get("policy", "")
    if not policy_json_str:
        print("error:no deviceControl.policy key in plist")
        sys.exit(0)
    policy = json.loads(policy_json_str)
except Exception as e:
    print(f"error:policy parse failed:{e}")
    sys.exit(0)

whitelisted = set(
    clause["value"].strip().upper()
    for group in policy.get("groups", [])
    for clause in group.get("query", {}).get("clauses", [])
    if clause.get("$type") == "serialNumber" and clause.get("value")
)

print("whitelisted" if serial_check in whitelisted else "blocked")
PYEOF

chmod +x "/Library/Application Support/ITTools/check_serial.py"
log "Serial checker helper written (reads live Intune managed plist)."

# -------------------------------------------------------------------------
# 3. Create the Main Worker Script
#    Runs as the logged-in user via LaunchAgent.
# -------------------------------------------------------------------------
cat << 'EOF' > "/Library/Application Support/ITTools/usb_serial_popup.sh"
#!/bin/zsh

LOG="/var/log/usb_watcher.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [USB-WATCHER] $1" >> "$LOG"
}

# ---------------------------------------------------------------------------
# is_fake_serial <serial>
# Returns 0 (true/fake) for known hub/chipset fake serials.
# ---------------------------------------------------------------------------
is_fake_serial() {
    local s="$1"
    [[ -z "${s// /}" ]]  && return 0
    [[ ${#s} -lt 4 ]]    && return 0
    [[ "$s" =~ ^0+$ ]]   && return 0
    
    case "$s" in
        "000001"|"0000001"|"00000001"|"000000000"|"0000000000000001"| \
        "0123456789ABCDE"|"000000000000"|"123456789"|"ABCDEF"|"000000"|"000000001539") 
            return 0 
            ;;
        # Wildcard prefix match for ASIX chips that use MAC Addresses as Serials
        "00CEC8"*)
            return 0
            ;;
    esac
    return 1
}

# ---------------------------------------------------------------------------
# get_usb_devices
# Scans the full IOService plane and extracts per-device hardware logic.
# ---------------------------------------------------------------------------
get_usb_devices() {
    /usr/sbin/ioreg -p IOService -l 2>/dev/null | \
    /usr/bin/python3 -c "
import sys, re

raw = sys.stdin.buffer.read().decode('utf-8', errors='ignore')
blocks = raw.split('+-o ')
seen = set()

for block in blocks:
    if 'USB Serial Number' not in block:
        continue

    # --- GATE 1: CLASS WHITELIST ---
    # 0x00 = Composite (Modern flash drives, hubs)
    # 0x08 = Mass Storage (Traditional flash drives)
    # 0xFF = Vendor Specific (NVMe Enclosures)
    class_match = re.search(r'\"bDeviceClass\"\s*=\s*([0-9]+)', block)
    b_class = int(class_match.group(1)) if class_match else None
    is_storage_candidate = b_class in [0, 8, 255] if b_class is not None else True

    if not is_storage_candidate:
        continue

    # --- GATE 2: NAME FILTER ---
    # Safety net to catch hubs and ethernet adapters trying to pass as 0x00.
    device_name = block.split('\n')[0].lower()
    is_ignored_name = ('lan' in device_name or 'ethernet' in device_name or
                       'network' in device_name or 'reader' in device_name)

    if 'hub' in device_name or is_ignored_name:
        continue

    loc_m = re.search(r'\"locationID\"\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)', block)
    vid_m = re.search(r'\"idVendor\"\s*=\s*([0-9]+)', block)
    pid_m = re.search(r'\"idProduct\"\s*=\s*([0-9]+)', block)
    ser_m = re.search(r'\"USB Serial Number\"\s*=\s*\"([^\"]+)\"', block)

    if not ser_m:
        continue

    serial  = ser_m.group(1).strip()
    loc_raw = loc_m.group(1) if loc_m else '0x0'
    if not loc_raw.startswith('0x'):
        try: loc_raw = hex(int(loc_raw))
        except: pass
    loc_hex = loc_raw.lower()
    
    try:
        vid_hex = f'0x{int(vid_m.group(1)):04x}' if vid_m else '0x0000'
    except:
        vid_hex = '0x0000'
        
    try:
        pid_hex = f'0x{int(pid_m.group(1)):04x}' if pid_m else '0x0000'
    except:
        pid_hex = '0x0000'

    key = f'{loc_hex}:{serial}'
    if key not in seen:
        seen.add(key)
        print(f'{loc_hex} {vid_hex} {pid_hex} {serial}')
" 2>/dev/null
}

# ---------------------------------------------------------------------------
# is_whitelisted <serial>
# Delegates to check_serial.py which reads the live Intune managed plist.
# ---------------------------------------------------------------------------
is_whitelisted() {
    local serial="$1"
    local checker="/Library/Application Support/ITTools/check_serial.py"

    if [[ ! -f "$checker" ]]; then
        log "WARNING: check_serial.py not found — treating as blocked."
        return 1
    fi

    local result
    result=$(/usr/bin/python3 "$checker" "$serial" 2>/dev/null)

    case "$result" in
        whitelisted)
            log "Serial '$serial' is whitelisted — skipping."
            return 0
            ;;
        blocked)
            return 1
            ;;
        *)
            log "WARNING: Unexpected checker result '$result' for '$serial' — treating as blocked."
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

# Allow IORegistry to fully populate after electrical attach event
sleep 2

LOGGED_IN_USER=$(stat -f "%Su" /dev/console)
LOGGED_IN_UID=$(id -u "$LOGGED_IN_USER" 2>/dev/null)

if [[ -z "$LOGGED_IN_USER" ]] || [[ -z "$LOGGED_IN_UID" ]]; then
    log "ERROR: Could not determine logged-in user. Exiting."
    exit 1
fi

PREV_DEVICES_FILE="/tmp/it_usb_prev_devices_${LOGGED_IN_UID}.txt"
PREV_DEVICES=$(cat "$PREV_DEVICES_FILE" 2>/dev/null || echo "")

CURR_DEVICES=$(get_usb_devices)
echo "$CURR_DEVICES" | awk '{print $1}' | sort | uniq > "$PREV_DEVICES_FILE"

NEW_LOCS=$(comm -13 \
    <(echo "$PREV_DEVICES" | awk '{print $1}' | sort | uniq) \
    <(echo "$CURR_DEVICES" | awk '{print $1}' | sort | uniq))

if [[ -z "$NEW_LOCS" ]]; then
    exit 0
fi

SEEN_PORTS_FILE="/tmp/it_usb_seen_ports_${LOGGED_IN_UID}.txt"
echo "" > "$SEEN_PORTS_FILE"

echo "$NEW_LOCS" | while read -r loc_hex; do
    [[ -z "$loc_hex" ]] && continue

    DEVICE_LINE=$(echo "$CURR_DEVICES" | awk -v loc="$loc_hex" '$1 == loc' | head -1)
    SERIAL=$(echo "$DEVICE_LINE" | awk '{print $4}')
    VID=$(echo "$DEVICE_LINE"    | awk '{print $2}')

    # --- USB3 DUAL-ENUMERATION DEDUP ---
    PORT_PATH=$(echo "$loc_hex" | sed -E 's/0x..([0-9a-f]{6})/0x\1/')
    if grep -qx "$PORT_PATH" "$SEEN_PORTS_FILE" 2>/dev/null; then
        continue
    fi
    echo "$PORT_PATH" >> "$SEEN_PORTS_FILE"

    # --- SAFE VENDOR FILTER (Defense in Depth) ---
    # Only skip vendors that mathematically do not make generic USB storage drives.
    # Apple (0x05ac), MS Surface Docks (0x045e), Google (0x18d1), Moto (0x22b8), OnePlus (0x2a70)
    case "$VID" in
        "0x05ac"|"0x045e"|"0x18d1"|"0x22b8"|"0x2a70")
            log "Skipping $loc_hex: Safe vendor bypass for $VID."
            continue
            ;;
    esac

    # --- FAKE SERIAL FILTER ---
    if is_fake_serial "$SERIAL"; then
        log "Skipping $loc_hex: fake or empty serial '$SERIAL'."
        continue
    fi

    # --- WHITELIST CHECK ---
    if is_whitelisted "$SERIAL"; then
        continue
    fi

    log "Device $loc_hex confirmed blocked. Showing popup. Serial: $SERIAL"

    # --- UI TRIGGER ---
    DIALOG_RESULT=$(launchctl asuser "$LOGGED_IN_UID" osascript 2>/dev/null << APPLESCRIPT
set serialVal to "$SERIAL"
set dlg to display dialog "A USB Drive was inserted and is currently blocked by company security policy.\n\nIf you require access, please copy the Hardware Serial Number below and send it to the IT Helpdesk:" with title "IT Security: USB Blocked" default answer serialVal buttons {"Copy Serial & Close", "Close"} default button "Copy Serial & Close" with icon stop

set chosenButton to button returned of dlg
set finalSerial to text returned of dlg

if chosenButton is "Copy Serial & Close" then
    set the clipboard to finalSerial
end if

return chosenButton & (ASCII character 31) & finalSerial
APPLESCRIPT
)

    OSASCRIPT_EXIT=$?
    if [[ $OSASCRIPT_EXIT -ne 0 ]]; then
        log "WARNING: osascript exited $OSASCRIPT_EXIT for $loc_hex."
    else
        BUTTON=$(echo "$DIALOG_RESULT" | cut -d$'\x1f' -f1)
        if [[ "$BUTTON" == "Copy Serial & Close" ]]; then
            log "Serial copied to clipboard for $loc_hex."
        fi
    fi
done

rm -f "$SEEN_PORTS_FILE"
EOF

chmod +x "/Library/Application Support/ITTools/usb_serial_popup.sh"
log "Worker script written and made executable."

# -------------------------------------------------------------------------
# 4. Create the Hardware Listener LaunchDaemon (runs as root)
# -------------------------------------------------------------------------
cat << 'EOF' > "/Library/Application Support/ITTools/usb_hardware_listener.sh"
#!/bin/zsh
{ /usr/sbin/ioreg -c IOUSBHostDevice -w 0 2>/dev/null & \
  /usr/sbin/ioreg -c IOUSBDevice -w 0 2>/dev/null; } | \
while read -r line; do
    touch /var/run/usb_attach_trigger
done
EOF

chmod +x "/Library/Application Support/ITTools/usb_hardware_listener.sh"

cat << 'EOF' > /Library/LaunchDaemons/com.company.usbhardwarelistener.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.usbhardwarelistener</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/zsh</string>
        <string>/Library/Application Support/ITTools/usb_hardware_listener.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

chmod 644 /Library/LaunchDaemons/com.company.usbhardwarelistener.plist
chown root:wheel /Library/LaunchDaemons/com.company.usbhardwarelistener.plist

launchctl bootout system /Library/LaunchDaemons/com.company.usbhardwarelistener.plist 2>/dev/null
launchctl bootstrap system /Library/LaunchDaemons/com.company.usbhardwarelistener.plist
log "Hardware listener LaunchDaemon deployed and loaded."

# -------------------------------------------------------------------------
# 5. Create the LaunchAgent (runs as logged-in user)
# -------------------------------------------------------------------------
cat << 'EOF' > /Library/LaunchAgents/com.company.usbwatcher.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.usbwatcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/zsh</string>
        <string>/Library/Application Support/ITTools/usb_serial_popup.sh</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>/var/run/usb_attach_trigger</string>
    </array>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/usb_watcher.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/usb_watcher.log</string>
</dict>
</plist>
EOF

chmod 644 /Library/LaunchAgents/com.company.usbwatcher.plist
chown root:wheel /Library/LaunchAgents/com.company.usbwatcher.plist

LOGGED_IN_USER=$(stat -f "%Su" /dev/console)
LOGGED_IN_USER_ID=$(id -u "$LOGGED_IN_USER" 2>/dev/null)

if [[ -n "$LOGGED_IN_USER_ID" ]]; then
    launchctl bootout gui/$LOGGED_IN_USER_ID /Library/LaunchAgents/com.company.usbwatcher.plist 2>/dev/null
    launchctl bootstrap gui/$LOGGED_IN_USER_ID /Library/LaunchAgents/com.company.usbwatcher.plist
    log "LaunchAgent loaded for user '$LOGGED_IN_USER' (UID $LOGGED_IN_USER_ID)."
else
    log "ERROR: Could not determine logged-in user UID. LaunchAgent not loaded."
fi

log "Deployment complete."
echo "USB Watcher successfully deployed. Log: $LOG"
