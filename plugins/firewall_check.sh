#!/bin/zsh
# Plugin: Firewall status check
plugin_main() {
    local fw_status="unknown"
    if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null; then
        fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print tolower($0)}')
    fi
    echo "firewall:$fw_status"
}
