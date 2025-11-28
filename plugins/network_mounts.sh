#!/bin/zsh
# Plugin: Network mounts and share usage
plugin_main() {
    local user="$PLUGIN_USER"
    local mount_count=0
    local mounts=()

    while IFS= read -r line; do
        mounts+=("$(echo "$line" | awk '{print $1}' )")
        (( mount_count++ ))
    done < <(mount 2>/dev/null | grep -Ei '\\s(smbfs|afpfs)\\s' | grep -i "/Users/$user" || true)

    if [[ -d /Volumes ]]; then
        while IFS= read -r vol; do
            mounts+=("/Volumes/$vol")
        done < <(ls /Volumes 2>/dev/null | grep -Ev "^(Macintosh HD|Preboot|Recovery|VM)$" || true)
    fi

    local uniq_mounts="none"
    if (( ${#mounts[@]} > 0 )); then
        uniq_mounts=$(printf "%s\n" "${mounts[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')
        [[ $mount_count -eq 0 ]] && mount_count=${#mounts[@]}
    fi

    echo "network_mounts:active=$mount_count;paths=$uniq_mounts"
}
