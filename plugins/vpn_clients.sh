#!/bin/zsh
# Plugin: VPN inventory and session status
plugin_main() {
    local configured=0 connected=0
    local clients=()

    if command -v scutil >/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ "$line" =~ '^\*' ]] || continue
            (( configured++ ))
            [[ "$line" == *"Connected"* ]] && (( connected++ ))
        done < <(scutil --nc list 2>/dev/null || true)
    fi

    if command -v networksetup >/dev/null 2>&1; then
        local ns_services=$(networksetup -listallnetworkservices 2>/dev/null || true)
        while IFS= read -r svc; do
            [[ "$svc" == "An asterisk*"* ]] && continue
            [[ "$svc" =~ (?i)vpn|(?i)cisco|(?i)globalprotect|(?i)anyconnect|(?i)zscaler ]] || continue
            clients+=("$svc")
        done <<< "$ns_services"
    fi

    if pgrep -lf "(cisco|anyconnect|globalprotect|zscaler|nordvpn|openvpn)" >/dev/null 2>&1; then
        while IFS= read -r proc; do
            clients+=($(echo "$proc" | awk '{print $2}' ))
        done < <(pgrep -lf "(cisco|anyconnect|globalprotect|zscaler|nordvpn|openvpn)" 2>/dev/null || true)
    fi

    local uniq_clients="none"
    if (( ${#clients[@]} > 0 )); then
        uniq_clients=$(printf "%s\n" "${clients[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')
    fi

    echo "vpn:configured=$configured;connected=$connected;clients=$uniq_clients"
}
