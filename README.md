# MAC Address Tracker

**Coded by Cyber Security Engineer Mr Sabaz Ali Khan**

A Bash project for **authorized/local-network inventory and monitoring**. It reads the Linux neighbor table (`ip neigh`) to show MAC addresses that your machine has already learned from normal local network traffic.

## Features

- Show local IP-to-MAC neighbor mappings
- Filter by network interface
- Search a specific MAC address in the local neighbor cache
- Watch for neighbor-table changes
- Try local OUI/vendor lookup when an OUI database is installed
- Export current results to CSV
- Custom ASCII banner

## Requirements

- Linux
- Bash 4+
- `iproute2` (`ip` command)

Optional vendor databases:

- `/usr/share/ieee-data/oui.txt`
- `/usr/share/misc/oui.txt`
- `/usr/share/nmap/nmap-mac-prefixes`

On Debian/Kali/Ubuntu, `ieee-data` can provide a local OUI database.

## Run

```bash
chmod +x mac_tracker.sh
./mac_tracker.sh
```

If the neighbor table is empty, use your network normally (for example, open your router/local services) and then check again. This project intentionally does not perform stealth, remote, or unauthorized tracking.

## Notes

MAC addresses are Layer-2 identifiers and generally do not travel across routers. This tool is designed for your own LAN or other networks where you have permission.
