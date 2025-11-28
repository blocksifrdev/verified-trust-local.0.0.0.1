#!/bin/zsh
# Plugin: SSH Key Hygiene
plugin_main() {
    local user="$PLUGIN_USER"
    local ssh_dir="/Users/$user/.ssh"
    [[ -d "$ssh_dir" ]] || { echo "ssh_keys:none"; return 0; }
    local old_keys=$(find "$ssh_dir" -maxdepth 1 -name 'id_*' -type f -mtime +180 2>/dev/null | wc -l | xargs)
    echo "ssh_keys:total=$(ls "$ssh_dir"/id_* 2>/dev/null | wc -l | xargs),old=$old_keys"
}
