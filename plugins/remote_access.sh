#!/bin/zsh
# Plugin: Remote access surface (SSH, Apple Events, Screen Sharing/ARD)
plugin_main() {
    local ssh_state="unknown" apple_events="unknown" screenshare="unknown" ard="unknown"

    if command -v systemsetup >/dev/null 2>&1; then
        local ssh_out=$(systemsetup -getremotelogin 2>/dev/null || true)
        [[ "$ssh_out" == *"On"* ]] && ssh_state="on" || ssh_state="off"

        local ae_out=$(systemsetup -getremoteappleevents 2>/dev/null || true)
        [[ "$ae_out" == *"On"* ]] && apple_events="on" || apple_events="off"
    fi

    if command -v launchctl >/dev/null 2>&1; then
        if launchctl list 2>/dev/null | grep -q "com.apple.screensharing"; then
            screenshare="enabled"
        else
            screenshare="disabled"
        fi
        if launchctl list 2>/dev/null | grep -q "com.apple.ard.agent"; then
            ard="enabled"
        else
            ard="disabled"
        fi
    fi

    echo "remote_access:ssh=$ssh_state;apple_events=$apple_events;screensharing=$screenshare;ard=$ard"
}
