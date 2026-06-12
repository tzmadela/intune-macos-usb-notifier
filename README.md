
# macOS USB Security Enforcer for Microsoft Defender

A custom, zero-maintenance middleware architecture that bridges the gap between the raw macOS hardware layer (`IOKit`) and Microsoft Defender for Endpoint Device Control. Designed for deployment via Microsoft Intune.

## The Problem
Microsoft Defender's Device Control for macOS effectively blocks unauthorized USB storage, but its native user notifications are often silent or lack the hardware serial numbers users need to request IT access. Furthermore, standard USB bus scanning frequently triggers false-positive storage blocks on generic multi-port hubs and network adapters.

## The Solution
This project implements a vendor-agnostic USB filtering pipeline that extracts and evaluates raw macOS electrical bus data, completely eliminating the maintenance overhead of manually blocking/allowing specific Vendor IDs.

### Architecture
1. **The Watcher (Root LaunchDaemon):** Polls the IOKit electrical bus (`IOUSBHostDevice`) for live attach/detach events without draining battery.
2. **The Smart Filter (Python):** Parses raw `ioreg` buffer data using regex. It evaluates the physical USB `bDeviceClass` (allowing only `0x08` Mass Storage, `0xFF` Vendor Specific, and `0x00` Composite) while actively filtering out networking and hub endpoints.
3. **The Validator (Bash & Python):** Reads the live Microsoft Defender `wdav.plist` pushed by MDM (Intune/Jamf) to check if the drive's serial number is already whitelisted.
4. **The UI (AppleScript):** If blocked, it alerts the user in their active GUI session and automatically copies the exact hardware serial number to their clipboard for streamlined IT ticketing.

## Deployment
Deploy the master `usb_watcher_deploy.sh` script via Microsoft Intune as a macOS shell script. Set **Run script as signed-in user** to **No** (requires root to configure Daemons).
