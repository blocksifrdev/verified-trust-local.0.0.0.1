#!/bin/zsh
# Plugin: TCC privacy overrides for camera/microphone/screen recording/automation
plugin_main() {
    local user="$PLUGIN_USER"
    local tcc_db="/Users/$user/Library/Application Support/com.apple.TCC/TCC.db"

    [[ -f "$tcc_db" ]] || { echo "tcc_privacy:db_absent"; return 0; }
    command -v sqlite3 >/dev/null 2>&1 || { echo "tcc_privacy:db_present_sqlite_missing"; return 0; }

    local camera=$(sqlite3 "$tcc_db" "select count(*) from access where service='kTCCServiceCamera' and allowed=1;" 2>/dev/null | xargs || echo "0")
    local mic=$(sqlite3 "$tcc_db" "select count(*) from access where service='kTCCServiceMicrophone' and allowed=1;" 2>/dev/null | xargs || echo "0")
    local screen=$(sqlite3 "$tcc_db" "select count(*) from access where service='kTCCServiceScreenCapture' and allowed=1;" 2>/dev/null | xargs || echo "0")
    local automation=$(sqlite3 "$tcc_db" "select count(*) from access where service='kTCCServiceAppleEvents' and allowed=1;" 2>/dev/null | xargs || echo "0")

    echo "tcc_privacy:camera=$camera,mic=$mic,screen=$screen,automation=$automation"
}
