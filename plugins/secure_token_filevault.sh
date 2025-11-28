#!/bin/zsh
# Plugin: SecureToken and FileVault membership per account
plugin_main() {
    local user="$PLUGIN_USER"
    local token_status="unknown"
    local fv_status="unknown"

    if command -v sysadminctl >/dev/null 2>&1; then
        local raw_status=$(sysadminctl -secureTokenStatus "$user" 2>/dev/null | tr -d '.' | tail -n1)
        if [[ "$raw_status" =~ [Ee]nabled ]]; then
            token_status="enabled"
        elif [[ "$raw_status" =~ [Dd]isabled ]]; then
            token_status="disabled"
        elif [[ -n "$raw_status" ]]; then
            token_status=$(echo "$raw_status" | awk '{print tolower($NF)}')
        fi
    fi

    if command -v fdesetup >/dev/null 2>&1; then
        local fv_list=$(fdesetup list 2>/dev/null | awk -F',' '{print $1}' | xargs)
        if echo "$fv_list" | grep -qw "$user"; then
            fv_status="enabled"
        elif [[ -n "$fv_list" ]]; then
            fv_status="not_listed"
        fi
    fi

    echo "securetoken:filevault=$fv_status,token=$token_status"
}
