#!/usr/bin/env bash

# ================================================================
# MAC Address Tracker
# Coded by Cyber Security Engineer Mr Sabaz Ali Khan
# Purpose: Authorized/local network inventory and monitoring only.
# ================================================================

set -u

VERSION="1.0"
APP_NAME="MAC Address Tracker"
CREDIT="Coded by Cyber Security Engineer Mr Sabaz Ali Khan"

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    clear 2>/dev/null || true
    printf "%b\n" "$CYAN"
    cat <<'BANNER'
 /$$      /$$ /$$                        /$$$$$$                      /$$
| $$  /$ | $$| $$                       /$$__  $$                    |__/
| $$ /$$$| $$| $$$$$$$   /$$$$$$       | $$  \ $$ /$$$$$$/$$$$        /$$
| $$/$$ $$ $$| $$__  $$ /$$__  $$      | $$$$$$$$| $$_  $$_  $$      | $$
| $$$$_  $$$$| $$  \ $$| $$  \ $$      | $$__  $$| $$ \ $$ \ $$      | $$
| $$$/ \  $$$| $$  | $$| $$  | $$      | $$  | $$| $$ | $$ | $$      | $$
| $$/   \  $$| $$  | $$|  $$$$$$/      | $$  | $$| $$ | $$ | $$      | $$
|__/     \__/|__/  |__/ \______/       |__/  |__/|__/ |__/ |__/      |__/
BANNER
    printf "%b\n" "$NC"
    printf "%b%s v%s%b\n" "$BOLD$GREEN" "$APP_NAME" "$VERSION" "$NC"
    printf "%b%s%b\n" "$YELLOW" "$CREDIT" "$NC"
    printf "%bAuthorized/local network monitoring only.%b\n\n" "$BLUE" "$NC"
}

pause() {
    read -r -p "Press Enter to continue..." _
}

need_ip() {
    if ! command -v ip >/dev/null 2>&1; then
        printf "%b[!] The 'ip' command is required. Install package: iproute2%b\n" "$RED" "$NC"
        exit 1
    fi
}

normalize_mac() {
    # Converts AA-BB-CC-DD-EE-FF to aa:bb:cc:dd:ee:ff
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr '-' ':'
}

valid_mac() {
    [[ "$1" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]
}

lookup_vendor() {
    local mac="$1"
    local prefix compact vendor_file line
    prefix=$(printf '%s' "$mac" | tr '[:lower:]' '[:upper:]' | cut -d: -f1-3 | tr ':' '-')
    compact=$(printf '%s' "$prefix" | tr -d '-')

    for vendor_file in \
        /usr/share/ieee-data/oui.txt \
        /usr/share/misc/oui.txt \
        /usr/share/nmap/nmap-mac-prefixes; do
        [[ -r "$vendor_file" ]] || continue

        if [[ "$vendor_file" == *nmap-mac-prefixes ]]; then
            line=$(grep -i -m1 "^${compact}[[:space:]]" "$vendor_file" 2>/dev/null || true)
            [[ -n "$line" ]] && { printf '%s' "${line#* }"; return; }
        else
            line=$(grep -i -m1 -E "^(${prefix}|${compact})[[:space:]]+\(hex\)" "$vendor_file" 2>/dev/null || true)
            [[ -n "$line" ]] && { printf '%s' "$line" | sed -E 's/^[^[:space:]]+[[:space:]]+\(hex\)[[:space:]]+//'; return; }
        fi
    done

    printf 'Unknown/Local DB unavailable'
}

show_interfaces() {
    printf "%bAvailable interfaces:%b\n" "$BOLD" "$NC"
    ip -o link show | awk -F': ' '{gsub(/@.*/,"",$2); print "  - "$2}'
}

show_neighbors() {
    local iface="${1:-}"
    local rows

    printf "%b\n%-16s %-20s %-12s %-18s %s%b\n" "$BOLD" "IP ADDRESS" "MAC ADDRESS" "STATE" "INTERFACE" "VENDOR" "$NC"
    printf '%s\n' "---------------------------------------------------------------------------------------------------"

    if [[ -n "$iface" ]]; then
        rows=$(ip neigh show dev "$iface" 2>/dev/null || true)
    else
        rows=$(ip neigh show 2>/dev/null || true)
    fi

    if [[ -z "$rows" ]]; then
        printf "%bNo neighbor entries found. Generate normal local network traffic, then try again.%b\n" "$YELLOW" "$NC"
        return
    fi

    while read -r line; do
        [[ -n "$line" ]] || continue
        local ipaddr mac dev state vendor
        ipaddr=$(awk '{print $1}' <<<"$line")
        dev=$(awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' <<<"$line")
        mac=$(awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}' <<<"$line")
        state=$(awk '{print $NF}' <<<"$line")

        [[ -n "$mac" ]] || mac="N/A"
        if [[ "$mac" != "N/A" ]]; then
            vendor=$(lookup_vendor "$mac")
        else
            vendor="N/A"
        fi

        printf "%-16s %-20s %-12s %-18s %s\n" "$ipaddr" "$mac" "$state" "$dev" "$vendor"
    done <<< "$rows"
}

search_mac() {
    local input mac matches
    read -r -p "Enter MAC address (example aa:bb:cc:dd:ee:ff): " input
    mac=$(normalize_mac "$input")

    if ! valid_mac "$mac"; then
        printf "%bInvalid MAC address format.%b\n" "$RED" "$NC"
        return
    fi

    matches=$(ip neigh show | grep -i -F "$mac" || true)
    if [[ -z "$matches" ]]; then
        printf "%bMAC %s is not currently present in the local neighbor cache.%b\n" "$YELLOW" "$mac" "$NC"
        return
    fi

    printf "%bMatch found:%b\n" "$GREEN" "$NC"
    printf '%s\n' "$matches"
    printf "Vendor: %s\n" "$(lookup_vendor "$mac")"
}

watch_neighbors() {
    local interval iface previous current added removed
    read -r -p "Interface (leave blank for all): " iface
    read -r -p "Refresh interval in seconds [5]: " interval
    interval="${interval:-5}"

    if ! [[ "$interval" =~ ^[1-9][0-9]*$ ]]; then
        printf "%bInvalid interval.%b\n" "$RED" "$NC"
        return
    fi

    if [[ -n "$iface" ]] && ! ip link show "$iface" >/dev/null 2>&1; then
        printf "%bInterface '%s' not found.%b\n" "$RED" "$iface" "$NC"
        return
    fi

    printf "%bMonitoring local neighbor cache. Press Ctrl+C to stop.%b\n" "$GREEN" "$NC"

    if [[ -n "$iface" ]]; then
        previous=$(ip neigh show dev "$iface" 2>/dev/null | sort || true)
    else
        previous=$(ip neigh show 2>/dev/null | sort || true)
    fi

    trap 'printf "\nStopped monitoring.\n"; trap - INT; return 0' INT

    while true; do
        sleep "$interval"
        if [[ -n "$iface" ]]; then
            current=$(ip neigh show dev "$iface" 2>/dev/null | sort || true)
        else
            current=$(ip neigh show 2>/dev/null | sort || true)
        fi

        added=$(comm -13 <(printf '%s\n' "$previous") <(printf '%s\n' "$current") || true)
        removed=$(comm -23 <(printf '%s\n' "$previous") <(printf '%s\n' "$current") || true)

        if [[ -n "$added" ]]; then
            printf "%b[+] New/changed neighbor entry:%b\n%s\n" "$GREEN" "$NC" "$added"
        fi
        if [[ -n "$removed" ]]; then
            printf "%b[-] Removed/changed neighbor entry:%b\n%s\n" "$YELLOW" "$NC" "$removed"
        fi

        previous="$current"
    done
}

export_csv() {
    local file="mac_neighbors_$(date '+%Y%m%d_%H%M%S').csv"
    printf 'timestamp,ip,mac,state,interface,vendor\n' > "$file"

    while read -r line; do
        [[ -n "$line" ]] || continue
        local ipaddr mac dev state vendor ts
        ts=$(date '+%Y-%m-%d %H:%M:%S')
        ipaddr=$(awk '{print $1}' <<<"$line")
        dev=$(awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' <<<"$line")
        mac=$(awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}' <<<"$line")
        state=$(awk '{print $NF}' <<<"$line")
        [[ -n "$mac" ]] || mac="N/A"
        if [[ "$mac" != "N/A" ]]; then
            vendor=$(lookup_vendor "$mac")
        else
            vendor="N/A"
        fi
        # Basic CSV escaping for vendor.
        vendor=${vendor//\"/\"\"}
        printf '"%s","%s","%s","%s","%s","%s"\n' "$ts" "$ipaddr" "$mac" "$state" "$dev" "$vendor" >> "$file"
    done < <(ip neigh show 2>/dev/null)

    printf "%bSaved: %s%b\n" "$GREEN" "$file" "$NC"
}

main_menu() {
    need_ip

    while true; do
        banner
        cat <<'MENU'
[1] Show local MAC/IP neighbors
[2] Show neighbors on one interface
[3] Search a MAC address in local cache
[4] Watch neighbor-table changes
[5] Export current neighbors to CSV
[6] Show network interfaces
[0] Exit
MENU
        printf '\n'
        read -r -p "Choose an option: " choice

        case "$choice" in
            1)
                show_neighbors
                pause
                ;;
            2)
                show_interfaces
                printf '\n'
                read -r -p "Interface name: " iface
                if ip link show "$iface" >/dev/null 2>&1; then
                    show_neighbors "$iface"
                else
                    printf "%bInterface not found.%b\n" "$RED" "$NC"
                fi
                pause
                ;;
            3)
                search_mac
                pause
                ;;
            4)
                watch_neighbors
                pause
                ;;
            5)
                export_csv
                pause
                ;;
            6)
                show_interfaces
                pause
                ;;
            0)
                printf "%bGoodbye.%b\n" "$GREEN" "$NC"
                exit 0
                ;;
            *)
                printf "%bInvalid option.%b\n" "$RED" "$NC"
                sleep 1
                ;;
        esac
    done
}

main_menu
