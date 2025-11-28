#!/bin/zsh
# Plugin: Authentication authority and password hint visibility
plugin_main() {
    local user="$PLUGIN_USER"
    local hint="absent"
    local flags=()

    if dscl . -read "/Users/$user" hint >/dev/null 2>&1; then
        hint="present"
    fi

    local auth=$(dscl . -read "/Users/$user" AuthenticationAuthority 2>/dev/null | tr '\n' ' ')
    if [[ -n "$auth" ]]; then
        [[ "$auth" == *";LocalCachedUser;"* ]] && flags+=(LocalCachedUser)
        [[ "$auth" == *";ShadowHash;"* ]] && flags+=(ShadowHash)
        [[ "$auth" == *";SecureToken;"* ]] && flags+=(SecureToken)
        [[ "$auth" == *";Kerberos;"* ]] && flags+=(Kerberos)
        [[ "$auth" == *";NoPasswd;"* ]] && flags+=(NoPassword)
    fi

    local flag_str="${flags[*]:-none}"
    echo "auth_policy:hint=$hint,auth_flags=$flag_str"
}
