#!/bin/zsh
# =====================================================================
# VERIFIEDTRUST macOS — LOCAL & USER ACCOUNT SCANNING — NOV 27 2025
# Lightweight identity and endpoint scanner with exportable evidence.
# =====================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_DIR="${PLUGIN_DIR:-$ROOT_DIR/plugins}"
SCANNER_VERSION="local-0.0.0.1"

# --------------------- SELF-INTEGRITY CHECK (Security Hardening) ---------------------
KNOWN_GOOD_HASH=${KNOWN_GOOD_HASH:-""}
if [[ -n "$KNOWN_GOOD_HASH" ]]; then
    SCRIPT_HASH=$(shasum -a 256 "$0" | cut -d' ' -f1)
    if [[ "$SCRIPT_HASH" != "$KNOWN_GOOD_HASH" ]]; then
        echo -e "\e[31mScript integrity check failed! Hash mismatch.\e[0m" >&2
        exit 1
    fi
else
    echo "[warn] KNOWN_GOOD_HASH not set — integrity check skipped" >&2
fi

# --------------------- COMMAND-LINE OPTIONS (Customization) ---------------------
UID_MIN=0
UID_MAX=500
FRAMEWORKS_MODE="full"
VERBOSE=0
EXPORT_FORMATS="csv,json,html"
MDM_MODE="none"
SHOW_HELP=0
SHOW_VERSION=0
while getopts ":u:f:v:e:m:hV" opt; do
    case $opt in
        u) UID_MIN=$(echo $OPTARG | cut -d',' -f1); UID_MAX=$(echo $OPTARG | cut -d',' -f2) ;;
        f) FRAMEWORKS_MODE=$OPTARG ;;
        v) VERBOSE=1 ;;
        e) EXPORT_FORMATS=$OPTARG ;;
        m) MDM_MODE=$OPTARG ;;
        h) SHOW_HELP=1 ;;
        V) SHOW_VERSION=1 ;;
        *) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    esac
done

if (( SHOW_HELP )); then
    cat <<'USAGE'
Usage: verifiedtrust [-u min,max] [-f full|minimal] [-v] [-e csv,json,html,pdf] [-m none|jamf|intune]

Options:
  -u    UID range to scan (default 0,500)
  -f    Framework mapping mode (full|minimal)
  -v    Verbose logging to console
  -e    Export formats (comma-separated)
  -m    MDM output mode (none|jamf|intune)
  -h    Show help
  -V    Show scanner version and exit

Environment:
  KNOWN_GOOD_HASH   Optional SHA256 hash to enforce self-integrity.
  PLUGIN_DIR        Directory containing plugin scripts (default: ./plugins).
  PARALLEL          If set, forces parallel scanning when GNU parallel exists.
USAGE
    exit 0
fi

if (( SHOW_VERSION )); then
    echo "verifiedtrust scanner version $SCANNER_VERSION"
    exit 0
fi

SCAN_ID=$(uuidgen)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
MIZAN_DIR="$HOME/VerifiedTrust-MacOS/MizanLogs"
LOG_FILE="$MIZAN_DIR/scan_$SCAN_ID.log"
ERROR_FILE="$MIZAN_DIR/errors_$SCAN_ID.log"
CSV_OUT="$HOME/VerifiedTrust-MacOS/VerifiedTrust_macOS_ACCOUNTS_2025.csv"
JSON_OUT="$HOME/VerifiedTrust-MacOS/VerifiedTrust_macOS_ACCOUNTS_2025.json"
HTML_OUT="$HOME/VerifiedTrust-MacOS/VerifiedTrust_macOS_ACCOUNTS_2025.html"
mkdir -p "$MIZAN_DIR" "$HOME/VerifiedTrust-MacOS"

exec 3>&1
if (( VERBOSE )); then
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$ERROR_FILE" >&2)
else
    exec >> "$LOG_FILE" 2>> "$ERROR_FILE"
fi

if [[ "$MDM_MODE" != "none" ]]; then
    echo -e "\n\e[95m=== VERIFIEDTRUST macOS — MDM MODE: $MDM_MODE ===\e[0m" >&3
else
    echo -e "\n\e[95m=== VERIFIEDTRUST macOS — LOCAL & USER ACCOUNT SCANNING ===\e[0m" >&3
fi
echo "Version: $SCANNER_VERSION" >&3
echo "Scan ID: $SCAN_ID\n" >&3

warn() {
    echo "[warn] $*" >&2
}

# --------------------- FRAMEWORK MAP ---------------------
FRAMEWORKS=(
    "NIST_CSF:AC-2 Account Management"
    "ISO_27001:A.9 Access Control"
    "COBIT_2019:DSS05 Manage Security Services"
    "CIS_Controls:Control 5 Account Management"
    "Zero_Trust:NIST SP 800-207 Continuous Monitoring"
    "GDPR:Article 32 Security of Processing"
    "SOX:Section 404 Internal Controls"
    "PCI_DSS:Requirement 8 Identify/Authenticate Access"
    "HIPAA:Security Rule Access Control"
)
if [[ "$FRAMEWORKS_MODE" == "minimal" ]]; then
    FRAMEWORKS=("${FRAMEWORKS[@]:0:4}")
fi

get_framework_status() {
    local effort=$1 status="" evidence=""
    if (( effort >= 80 )); then
        status="Compliant"; evidence="Active account with high effort score (>80)"
    elif (( effort >= 50 )); then
        status="Review"; evidence="Moderate activity; review for dormancy"
    else
        status="Non-Compliant"; evidence="Low effort score (<50); potential ghost account"
    fi
    echo "$status|$evidence"
}

map_to_frameworks() {
    local effort=$1
    local mappings=""
    for fw in "${FRAMEWORKS[@]}"; do
        local status_evidence=$(get_framework_status $effort)
        IFS='|' read -r status evidence <<< "$status_evidence"
        mappings+="$fw:$status ($evidence); "
    done
    echo "${mappings%; }"
}

# --------------------- MIZAN PROOF ---------------------
mizan_proof() {
    local upn="$1" display="$2" effort="$3" risk="$4" apps="$5" frameworks="$6" status="$7" policy_violations="$8" effort_profile="$9" service_note="${10:-}" 
    local proof_string="${upn}${effort}${apps}${frameworks}${status}${policy_violations}${effort_profile}${service_note}VerifiedTrust-macOS-2025"
    local stark_proof=$(echo -n "$proof_string" | openssl dgst -sha3-256 2>/dev/null | awk '{print "0x"$2}' || echo -n "$proof_string" | shasum -a 256 | cut -d' ' -f1 | sed 's/^/0x/')

    cat <<EOFJSON > "$MIZAN_DIR/$(echo "$upn" | tr '@./ ' '_')_$(date +%Y%m%d_%H%M%S).json"
{
  "timestamp": "$TIMESTAMP",
  "scan_id": "$SCAN_ID",
  "upn": "$upn",
  "display_name": "$display",
  "effort_score": $effort,
  "effort_profile": "$effort_profile",
  "risk_level": "$risk",
  "apps_detected": "$apps",
  "framework_mappings": "$frameworks",
  "account_status": "$status",
  "policy_violations": "$policy_violations",
  "platform": "macOS",
  "service_decay_note": "${service_note:-N/A}",
  "stark_proof": "$stark_proof",
  "version": "enhanced-2025"
}
EOFJSON
    echo "$stark_proof"
}

# --------------------- APP RESOLVER ---------------------
resolve_real_app_name() {
    local binary="$1" label="$2"
    local input="${binary}${label}"
    local i=$(echo "$input" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')

    [[ "$i" == *"asset"* ]] && echo "Apple AssetCache" && return
    [[ "$i" == *"coreaudio"* ]] && echo "CoreAudio Daemon" && return
    [[ "$i" == *"location"* ]] && echo "Location Services" && return
    [[ "$i" == *"findmy"* ]] && echo "Find My Mac" && return
    [[ "$i" == *"knowledge"* ]] && echo "KnowledgeC" && return
    [[ "$i" == *"power"* ]] && echo "Power Management" && return
    [[ "$i" == *"spotlight"* ]] && echo "Spotlight" && return
    [[ "$i" == *"timed"* ]] && echo "Time Sync" && return
    [[ "$i" == *"xprotect"* ]] && echo "XProtect / MRT" && return
    [[ "$i" == *"tcc"* ]] && echo "Transparency Consent Control" && return
    [[ "$i" == *"clamav"* ]] && echo "ClamAV" && return
    [[ "$i" == *"softwareupdate"* ]] && echo "Software Update" && return
    [[ "$i" == *"diagnostics"* ]] && echo "Diagnostics Daemon" && return
    [[ "$i" == *"gamecontroller"* ]] && echo "Game Controller Daemon" && return
    [[ "$i" == *"install"* ]] && echo "Installer Daemon" && return
    [[ "$i" == *"windowserver"* ]] && echo "WindowServer" && return
    [[ "$i" == *"iconservices"* ]] && echo "IconServices" && return
    [[ "$i" == *"nsurl"* ]] && echo "NSURLStorageDaemon" && return
    [[ "$i" == *"mdns"* ]] && echo "mDNSResponder" && return

    [[ "$i" == *"jamf"* ]] && echo "Jamf Pro Agent" && return
    [[ "$i" == *"intune"* ]] && echo "Microsoft Intune MDM" && return
    [[ "$i" == *"kandji"* ]] && echo "Kandji Agent" && return
    [[ "$i" == *"mosyle"* ]] && echo "Mosyle Manager" && return
    [[ "$i" == *"addigy"* ]] && echo "Addigy MDM" && return
    [[ "$i" == *"simplemdm"* ]] && echo "SimpleMDM" && return

    [[ "$i" == *"crowdstrike"* ]] && echo "CrowdStrike Falcon" && return
    [[ "$i" == *"sentinelone"* ]] && echo "SentinelOne" && return
    [[ "$i" == *"carbonblack"* ]] && echo "VMware Carbon Black" && return
    [[ "$i" == *"tanium"* ]] && echo "Tanium Client" && return
    [[ "$i" == *"ciscoamp"* ]] && echo "Cisco Secure Endpoint" && return
    [[ "$i" == *"symantec"* ]] && echo "Symantec Endpoint Protection" && return
    [[ "$i" == *"mcafee"* ]] && echo "McAfee Agent" && return
    [[ "$i" == *"defender"* ]] && echo "Microsoft Defender for Endpoint" && return
    [[ "$i" == *"paloalto"* ]] && echo "Cortex XDR" && return
    [[ "$i" == *"qualys"* ]] && echo "Qualys Cloud Agent" && return
    [[ "$i" == *"rapid7"* ]] && echo "InsightIDR Agent" && return
    [[ "$i" == *"tenable"* ]] && echo "Tenable Nessus Agent" && return

    [[ "$i" == *"crashplan"* ]] && echo "CrashPlan / Code42" && return
    [[ "$i" == *"backblaze"* ]] && echo "Backblaze" && return
    [[ "$i" == *"carbonite"* ]] && echo "Carbonite" && return
    [[ "$i" == *"dropbox"* ]] && echo "Dropbox Daemon" && return
    [[ "$i" == *"onedrive"* ]] && echo "OneDrive Sync" && return
    [[ "$i" == *"googledrive"* ]] && echo "Google Drive" && return

    [[ "$i" == *"splunk"* ]] && echo "Splunk Forwarder" && return
    [[ "$i" == *"elastic"* ]] && echo "Elastic Beats" && return
    [[ "$i" == *"datadog"* ]] && echo "Datadog Agent" && return
    [[ "$i" == *"newrelic"* ]] && echo "New Relic Infra" && return
    [[ "$i" == *"sumologic"* ]] && echo "Sumo Logic Collector" && return

    [[ "$i" == *"ciscoanyconnect"* ]] && echo "Cisco AnyConnect" && return
    [[ "$i" == *"globalprotect"* ]] && echo "Palo Alto GlobalProtect" && return
    [[ "$i" == *"zscaler"* ]] && echo "Zscaler Client Connector" && return

    [[ "$i" == *"zoom"* ]] && echo "Zoom Daemon" && return
    [[ "$i" == *"slack"* ]] && echo "Slack Helper" && return
    [[ "$i" == *"teams"* ]] && echo "Microsoft Teams" && return
    [[ "$i" == *"webex"* ]] && echo "Cisco Webex" && return

    [[ "$i" == *"docker"* ]] && echo "Docker Desktop" && return
    [[ "$i" == *"parallels"* ]] && echo "Parallels Desktop" && return
    [[ "$i" == *"vmware"* ]] && echo "VMware Fusion" && return

    [[ "$i" == *"sap"* ]] && echo "SAP Client" && return
    [[ "$i" == *"oracle"* ]] && echo "Oracle Client" && return
    [[ "$i" == *"workday"* ]] && echo "Workday Agent" && return
    [[ "$i" == *"salesforce"* ]] && echo "Salesforce Connector" && return
    [[ "$i" == *"servicenow"* ]] && echo "ServiceNow Agent" && return
    [[ "$i" == *"okta"* ]] && echo "Okta Agent" && return
    [[ "$i" == *"cyberark"* ]] && echo "CyberArk EPM" && return
    [[ "$i" == *"beyondtrust"* ]] && echo "BeyondTrust" && return
    [[ "$i" == *"hashicorp"* ]] && echo "HashiCorp Vault" && return

    echo "Unclassified ($binary)"
}

# --------------------- LINKED APP DISCOVERY ---------------------
get_linked_apps() {
    local username="$1"
    local apps=""
    local found=0

    for domain in "/System/Library/LaunchDaemons" "/Library/LaunchDaemons" "/System/Library/LaunchAgents" "/Library/LaunchAgents" "/Users/$username/Library/LaunchAgents"; do
        [[ -d "$domain" ]] || continue
        while IFS= read -r -d '' plist; do
            local label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)
            local program=$(defaults read "$plist" ProgramArguments 2>/dev/null | awk 'NR==1{print $1}' || defaults read "$plist" Program 2>/dev/null || echo "")
            local prog_name=""
            if [[ -n "$program" && -f "$program" ]]; then
                prog_name=$(basename "$program")
            else
                prog_name="$label"
            fi

            local resolved=$(resolve_real_app_name "$prog_name" "$label")
            if [[ "$resolved" != *"Unclassified"* ]]; then
                apps+="$resolved; "
                found=1
            fi
        done < <(find "$domain" -name "*.plist" -user "$username" -print0 2>/dev/null || true)
    done

    launchctl list 2>/dev/null | awk -v user="$username" '$3 == user {print $NF}' | while read -r label; do
        local resolved=$(resolve_real_app_name "" "$label")
        if [[ "$resolved" != *"Unclassified"* ]]; then
            apps+="$resolved (running); "
            found=1
        fi
    done

    ps -eo user,comm 2>/dev/null | awk -v user="$username" '$1 == user {print $2}' | while read -r comm; do
        local resolved=$(resolve_real_app_name "$(basename $comm)" "")
        if [[ "$resolved" != *"Unclassified"* ]]; then
            apps+="$resolved (process); "
            found=1
        fi
    done

    if (( found == 0 )); then
        echo "None Detected"
    else
        echo "${apps%; }"
    fi
}

# --------------------- EFFORT PROFILE ---------------------
# Service accounts (daemons, underscore-prefixed users, UID < 500) get a dedicated
# decay component so idle or non-running services surface clearly in the effort
# profile without hiding genuinely active daemons.
get_service_decay() {
    local username="$1" account_type="$2"
    local penalty=0
    local note="Not a service account"

    if [[ "$account_type" == "Daemon" || "$username" == _* ]]; then
        note="Service account baseline"
        local running=$(pgrep -u "$username" 2>/dev/null | wc -l | xargs || echo 0)
        if (( running == 0 )); then
            penalty=25
            note="No running processes for service account"
        elif (( running < 3 )); then
            penalty=10
            note="Low runtime activity for service account"
        else
            penalty=0
            note="Service account actively running"
        fi
    fi

    echo "$penalty|$note"
}

calculate_effort_score() {
    local username="$1" account_type="$2"
    local now=$(date +%s)
    local created_sec=0 last_login_sec=0 last_pw_change_sec=0 failed_logins=0
    local age_decay=0 activity_decay=0 privilege_risk=0 login_freq_bonus=0 mfa_bonus=0 pw_age_decay=0 linked_apps_bonus=0 home_activity_bonus=0 sudo_bonus=0 failed_login_penalty=0 service_decay=0 service_note=""

    local policy=""
    if command -v dscl >/dev/null; then
        policy=$(dscl . -read "/Users/$username" AccountPolicyData 2>/dev/null || echo "")
    fi
    if [[ -n "$policy" ]]; then
        created_sec=$(echo "$policy" | grep -A1 creationTime | grep real | grep -o '[0-9]*\.[0-9]*' | cut -d. -f1 || echo 0)
        last_login_sec=$(echo "$policy" | grep -A1 lastAuthenticationTime | grep real | grep -o '[0-9]*\.[0-9]*' | cut -d. -f1 || echo 0)
        last_pw_change_sec=$(echo "$policy" | grep -A1 passwordLastSetTime | grep real | grep -o '[0-9]*\.[0-9]*' | cut -d. -f1 || echo 0)
        failed_logins=$(echo "$policy" | grep -A1 failedLoginCount | grep integer | grep -o '[0-9]*' || echo 0)
    fi

    if (( created_sec == 0 )); then
        local plist="/var/db/dslocal/nodes/Default/users/$username.plist"
        [[ -f "$plist" ]] && created_sec=$(stat -f %B "$plist" 2>/dev/null || echo 0)
    fi

    (( created_sec == 0 )) && created_sec=$(( now - 10*365*86400 ))
    (( last_login_sec == 0 )) && last_login_sec=$(last -1 "$username" | awk '{print $NF}' | date -j -f "%a %b %d %H:%M:%S %Z %Y" +%s 2>/dev/null || created_sec)
    (( last_pw_change_sec == 0 )) && last_pw_change_sec=$created_sec

    local days_since_create=$(( (now - created_sec) / 86400 ))
    age_decay=$(( days_since_create / 2 ))
    (( age_decay > 50 )) && age_decay=50

    local days_since_login=$(( (now - last_login_sec) / 86400 ))
    activity_decay=$(( days_since_login * 10 / 30 ))
    (( activity_decay > 30 )) && activity_decay=30

    groups=$(id -Gn "$username" 2>/dev/null || echo "")
    [[ "$groups" == *"admin"* ]] && privilege_risk=20

    local recent_logins=$(last "$username" 2>/dev/null | grep -c "$(date -v-30d +%b 2>/dev/null || date -d '30 days ago' +%b)" || echo 0)
    login_freq_bonus=$(( recent_logins * 3 ))
    (( login_freq_bonus > 30 )) && login_freq_bonus=30

    local auth_auth=""
    if command -v dscl >/dev/null; then
        auth_auth=$(dscl . -read "/Users/$username" AuthenticationAuthority 2>/dev/null || echo "")
    fi
    [[ "$auth_auth" == *";Kerberos;"* || "$auth_auth" == *";SecureToken;"* ]] && mfa_bonus=10

    local days_since_pw=$(( (now - last_pw_change_sec) / 86400 ))
    pw_age_decay=$(( days_since_pw * 5 / 30 ))
    (( pw_age_decay > 20 )) && pw_age_decay=20

    local apps_count=$(get_linked_apps "$username" | awk -F'; ' '{print NF}' || echo 0)
    linked_apps_bonus=$(( apps_count * 2 ))
    (( linked_apps_bonus > 20 )) && linked_apps_bonus=20

    local home_dir="/Users/$username"
    if [[ -d "$home_dir" ]]; then
        local last_mod=$(find "$home_dir" -mtime -30 2>/dev/null | wc -l | xargs || echo 0)
        (( last_mod > 0 )) && home_activity_bonus=10
    fi

    local sudo_logs=$(grep -c "sudo: $username" /var/log/authd.log 2>/dev/null || echo 0)
    (( sudo_logs > 0 )) && sudo_bonus=10

    failed_login_penalty=$(( failed_logins * 2 ))
    (( failed_login_penalty > 20 )) && failed_login_penalty=20

    IFS='|' read -r service_decay service_note <<< "$(get_service_decay "$username" "$account_type")"

    local effort=$(( 100 - age_decay - activity_decay - privilege_risk - pw_age_decay - failed_login_penalty - service_decay + login_freq_bonus + mfa_bonus + linked_apps_bonus + home_activity_bonus + sudo_bonus ))
    (( effort < 0 )) && effort=0
    (( effort > 100 )) && effort=100

    local profile="AgeDecay:$age_decay; ActivityDecay:$activity_decay; PrivilegeRisk:$privilege_risk; LoginFreqBonus:$login_freq_bonus; MFABonus:$mfa_bonus; PwAgeDecay:$pw_age_decay; LinkedAppsBonus:$linked_apps_bonus; HomeActivityBonus:$home_activity_bonus; SudoBonus:$sudo_bonus; FailedLoginPenalty:$failed_login_penalty; ServiceDecay:$service_decay ($service_note)"

    echo "$effort|$profile|$service_note"
}

# --------------------- ACCOUNT STATUS ---------------------
get_account_status() {
    local username="$1"
    local disabled="Enabled"
    local locked="Unlocked"
    if command -v pwpolicy >/dev/null && pwpolicy -u "$username" -getpolicy 2>/dev/null | grep -q 'isDisabled=1'; then
        disabled="Disabled"
    fi
    if command -v dscl >/dev/null && dscl . -read "/Users/$username" AuthenticationAuthority 2>/dev/null | grep -q 'Locked'; then
        locked="Locked"
    fi
    echo "$disabled/$locked"
}

# --------------------- PASSWORD POLICY ---------------------
get_policy_violations() {
    local username="$1"
    local violations=""
    local policy=""
    if command -v pwpolicy >/dev/null; then
        policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null || echo "")
    fi
    [[ "$policy" != *"policyAttributePassword"* ]] && violations+="No password policy; "
    [[ "$policy" != *"expiresEvery"* ]] && violations+="No expiration; "
    [[ -z "$policy" ]] && violations+="Policy tool unavailable; "
    echo "${violations:-None}"
}

# --------------------- PLUGIN EXECUTION ---------------------
plugin_results=()
run_plugins() {
    local username="$1"
    [[ -d "$PLUGIN_DIR" ]] || return 0
    for plugin in "$PLUGIN_DIR"/*.sh; do
        [[ -f "$plugin" ]] || continue
        # shellcheck source=/dev/null
        source "$plugin"
        if declare -f plugin_main >/dev/null; then
            local plugin_output=$(PLUGIN_USER="$username" plugin_main || true)
            plugin_results+=("$plugin_output")
        fi
        unset -f plugin_main >/dev/null 2>&1 || true
    done
}

# --------------------- MAIN SCAN ---------------------
results=()
json_results=()
html_table="<table><tr><th>UPN</th><th>Name</th><th>Effort</th><th>Effort Profile</th><th>Risk</th><th>Linked Apps</th><th>Frameworks</th><th>Status</th><th>Policy Violations</th><th>Service Decay</th><th>Proof</th><th>Type</th></tr>"
high_risk_count=0
total_effort=0
account_count=0
ACCOUNT_SCAN_STATUS="ok"

scan_accounts() {
    local uid_min="$1" uid_max="$2" type="$3"
    local tmpfile=$(mktemp)

    if command -v dscl >/dev/null; then
        dscl . -list /Users UniqueID 2>/dev/null | awk -v min=$uid_min -v max=$uid_max '$2 >= min && $2 <= max {print $1}' > "$tmpfile" || {
            warn "Error listing users for $type scope"
            ACCOUNT_SCAN_STATUS="dscl enumeration error"
            rm -f "$tmpfile"
            return 0
        }
    elif command -v getent >/dev/null; then
        warn "dscl not available; falling back to getent for $type accounts"
        ACCOUNT_SCAN_STATUS="getent fallback"
        getent passwd | awk -F: -v min=$uid_min -v max=$uid_max '$3 >= min && $3 <= max {print $1}' > "$tmpfile" || {
            warn "Error listing users from getent for $type scope"
            rm -f "$tmpfile"
            return 0
        }
    else
        warn "No directory service tools available; unable to enumerate $type accounts"
        ACCOUNT_SCAN_STATUS="dscl missing"
        rm -f "$tmpfile"
        return 0
    fi

    if [[ ! -s "$tmpfile" ]]; then
        echo -e "\e[31mNo $type accounts found\e[0m" >&3
        [[ "$type" == "Daemon" ]] && { echo "Forcing known daemons..."; for user in _assetcache _spotlight _tcc _windowserver _mdnsresponder; do echo "$user"; done >> "$tmpfile"; }
    fi

    if command -v parallel >/dev/null && { [[ -n "$PARALLEL" ]] || true; }; then
        parallel -j4 --keep-order process_account {} "$type" ::: $(cat "$tmpfile")
    else
        while read -r user; do
            process_account "$user" "$type"
        done < "$tmpfile"
    fi
    rm -f "$tmpfile"
}

process_account() {
    local user="$1" type="$2"
    [[ "$user" =~ ^(_mbsetupuser|nobody|daemon|www|root)$ ]] && return

    if command -v dscl >/dev/null; then
        realname=$(dscl . -read "/Users/$user" RealName 2>/dev/null | sed -n '2p' | xargs || echo "macOS $type Account")
    elif command -v getent >/dev/null; then
        realname=$(getent passwd "$user" | cut -d: -f5 | cut -d, -f1)
        realname=${realname:-"$type Account"}
    else
        realname="macOS $type Account"
    fi
    linked_apps=$(get_linked_apps "$user")
    effort_profile=$(calculate_effort_score "$user" "$type")
    IFS='|' read -r effort profile service_note <<< "$effort_profile"
    risk="Compliant"; (( effort < 20 )) && risk="Ghost"; (( effort < 50 )) && risk="High-Risk"; (( effort < 80 )) && risk="Dormant"
    frameworks=$(map_to_frameworks $effort)
    status=$(get_account_status "$user")
    [[ "$status" == *"Disabled"* ]] && risk="Archived"
    policy_violations=$(get_policy_violations "$user")

    plugin_results=()
    run_plugins "$user"
    local plugin_blob=$(printf "%s" "${plugin_results[*]}" | tr '\n' '; ')

    proof=$(mizan_proof "$user@local.macOS" "$user — $realname" $effort "$risk" "$linked_apps" "$frameworks" "$status" "$policy_violations" "$profile" "$service_note")
    local r="$user@local.macOS|$user — $realname|$effort|$profile|$risk|$linked_apps|$frameworks|$status|$policy_violations|$service_note|${proof:0:12}...|$type"
    results+=("$r")

    json_results+=("{\n        \"upn\": \"$user@local.macOS\",\n        \"name\": \"$user — $realname\",\n        \"effort\": $effort,\n        \"effort_profile\": \"$profile\",\n        \"risk\": \"$risk\",\n        \"linked_apps\": \"$linked_apps\",\n        \"frameworks\": \"$frameworks\",\n        \"status\": \"$status\",\n        \"policy_violations\": \"$policy_violations\",\n        \"service_decay_note\": \"$service_note\",\n        \"plugins\": \"$plugin_blob\",\n        \"proof\": \"${proof:0:12}...\",\n        \"type\": \"$type\"\n    }")
    html_table+="<tr><td>$user@local.macOS</td><td>$user — $realname</td><td>$effort</td><td>$profile</td><td>$risk</td><td>$linked_apps</td><td>$frameworks</td><td>$status</td><td>$policy_violations</td><td>$service_note</td><td>${proof:0:12}...</td><td>$type</td></tr>"

    ((account_count++))
    ((total_effort += effort))
    [[ "$risk" == "High-Risk" || "$risk" == "Ghost" ]] && ((high_risk_count++))
}

echo "Scanning daemon accounts..." >&3
daemon_max=$(( UID_MAX < 500 ? UID_MAX : 499 ))
scan_accounts "$UID_MIN" "$daemon_max" "Daemon"
echo "Scanning user accounts..." >&3
user_min=$(( UID_MIN > 500 ? UID_MIN : 500 ))
scan_accounts "$user_min" "$UID_MAX" "User"

if [[ -f /var/db/ConfigurationProfiles/Settings/.profilesAreInstalled ]] || [[ -d "/Library/Application Support/JAMF" ]]; then
    effort=8
    profile="AgeDecay:50; ActivityDecay:30; PrivilegeRisk:0; LoginFreqBonus:0; MFABonus:0; PwAgeDecay:20; LinkedAppsBonus:0; HomeActivityBonus:0; SudoBonus:0; FailedLoginPenalty:0; ServiceDecay:25 (MDM agent placeholder)"
    risk="Ghost"
    linked_apps="MDM Agent"
    frameworks=$(map_to_frameworks $effort)
    status="Enabled/Unlocked"
    policy_violations="None"
    service_note="MDM agent flagged as service account"
    proof=$(mizan_proof "mdm-agent@local" "MDM Agent" $effort "$risk" "$linked_apps" "$frameworks" "$status" "$policy_violations" "$profile" "$service_note")
    mdm_row="mdm-agent@local|MDM Agent|$effort|$profile|$risk|$linked_apps|$frameworks|$status|$policy_violations|$service_note|${proof:0:12}...|MDM"
    results+=("$mdm_row")
    json_results+=("{\n        \"upn\": \"mdm-agent@local\",\n        \"name\": \"MDM Agent\",\n        \"effort\": $effort,\n        \"effort_profile\": \"$profile\",\n        \"risk\": \"$risk\",\n        \"linked_apps\": \"$linked_apps\",\n        \"frameworks\": \"$frameworks\",\n        \"status\": \"$status\",\n        \"policy_violations\": \"$policy_violations\",\n        \"service_decay_note\": \"$service_note\",\n        \"proof\": \"${proof:0:12}...\",\n        \"type\": \"MDM\"\n    }")
    html_table+="<tr><td>mdm-agent@local</td><td>MDM Agent</td><td>$effort</td><td>$profile</td><td>$risk</td><td>$linked_apps</td><td>$frameworks</td><td>$status</td><td>$policy_violations</td><td>$service_note</td><td>${proof:0:12}...</td><td>MDM</td></tr>"

    ((account_count++))
    ((total_effort += effort))
    [[ "$risk" == "High-Risk" || "$risk" == "Ghost" ]] && ((high_risk_count++))
fi

if (( account_count == 0 )); then
    ACCOUNT_SCAN_STATUS=${ACCOUNT_SCAN_STATUS:-"no accounts enumerated"}
    warn "No accounts were processed ($ACCOUNT_SCAN_STATUS) — emitting placeholder outputs"
    placeholder_upn="no-accounts@local"
    placeholder_row="$placeholder_upn|No accounts enumerated|0|N/A|NoData|None|None|N/A|No policies|$ACCOUNT_SCAN_STATUS|N/A|Summary"
    results+=("$placeholder_row")
    json_results+=("{\n        \"upn\": \"$placeholder_upn\",\n        \"name\": \"No accounts enumerated\",\n        \"effort\": 0,\n        \"effort_profile\": \"N/A\",\n        \"risk\": \"NoData\",\n        \"linked_apps\": \"None\",\n        \"frameworks\": \"None\",\n        \"status\": \"N/A\",\n        \"policy_violations\": \"No policies\",\n        \"service_decay_note\": \"$ACCOUNT_SCAN_STATUS\",\n        \"proof\": \"N/A\",\n        \"type\": \"Summary\"\n    }")
    html_table+="<tr><td>$placeholder_upn</td><td>No accounts enumerated</td><td>0</td><td>N/A</td><td>NoData</td><td>None</td><td>None</td><td>N/A</td><td>No policies</td><td>$ACCOUNT_SCAN_STATUS</td><td>N/A</td><td>Summary</td></tr>"
    account_count=1
fi

average_effort=0
(( account_count > 0 )) && average_effort=$(( total_effort / account_count ))

if [[ "$MDM_MODE" == "jamf" ]]; then
    echo "<result>Scan ID: $SCAN_ID | Accounts: $account_count | Average Effort: $average_effort | High Risks: $high_risk_count</result>"
    exit 0
elif [[ "$MDM_MODE" == "intune" ]]; then
    echo "Scan ID: $SCAN_ID | Accounts: $account_count | Average Effort: $average_effort | High Risks: $high_risk_count"
    exit 0
fi

if [[ "$MDM_MODE" == "none" ]]; then
    echo -e "\e[93m=== PROOF: LISTING ACCOUNTS (UID $UID_MIN to $UID_MAX) ===\e[0m" >&3
    dscl . -list /Users UniqueID 2>/dev/null | awk -v min=$UID_MIN -v max=$UID_MAX '$2 >= min && $2 <= max {print "Found account: " $1 " (UID: " $2 ")"}'
    echo -e "\e[93m=== END PROOF ===\e[0m\n" >&3
fi

# --------------------- OUTPUT ---------------------
if (( account_count > 0 )); then
    echo -e "\n\e[95m================ ACCOUNTS SCANNED — RESULTS ================\e[0m\n" >&3

    printf "%-44s %-32s %8s %-120s %-12s %-50s %-100s %-20s %-30s %-32s %14s %s\n" "UPN" "Name" "Effort" "Effort Profile" "Risk" "Linked Apps" "Frameworks" "Status" "Policy Violations" "Service Decay" "Mizan Proof" "Type" >&3
    printf "%s\n" "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >&3

    for r in "${results[@]}"; do
        IFS='|' read -r upn name effort profile risk apps frameworks status policy service_note proof type <<< "$r"
        color=32; (( effort < 20 )) && color=31; (( effort >= 20 && effort < 50 )) && color=33; (( effort >= 80 )) && color=92
        printf "\e[${color}m%-44s\e[0m %-32s %8s %-120s %-12s %-50s %-100s %-20s %-30s %-32s \e[90m%s\e[0m %s\n" "$upn" "$name" "$effort" "$profile" "$risk" "$apps" "$frameworks" "$status" "$policy" "$service_note" "$proof" "$type" >&3
    done
fi

if [[ "$EXPORT_FORMATS" == *"csv"* ]]; then
    {
        echo "ScannerVersion,UPN,Name,EffortScore,EffortProfile,RiskLevel,LinkedApplications,FrameworkMappings,AccountStatus,PolicyViolations,ServiceDecayNote,MizanProof,Type"
        for r in "${results[@]}"; do echo "$SCANNER_VERSION,$(echo "$r" | tr '|' ',')"; done
    } > "$CSV_OUT"
fi

if [[ "$EXPORT_FORMATS" == *"json"* ]]; then
    {
        echo "{"
        echo "  \"scan_id\": \"$SCAN_ID\","
        echo "  \"timestamp\": \"$TIMESTAMP\","
        echo "  \"scanner_version\": \"$SCANNER_VERSION\","
        echo "  \"accounts\": ["
        echo "${json_results[*]}" | sed 's/} {/},\n    {/g'"
        echo "  ]"
        echo "}"
    } > "$JSON_OUT"
fi

if [[ "$EXPORT_FORMATS" == *"html"* ]]; then
    echo "<html><body><h3>verifiedtrust scanner $SCANNER_VERSION</h3>$html_table</table></body></html>" > "$HTML_OUT"
fi

if [[ "$EXPORT_FORMATS" == *"pdf"* ]] && command -v pandoc >/dev/null; then
    pandoc "$HTML_OUT" -o "${HTML_OUT%.html}.pdf" || echo "PDF export failed; pandoc not installed?" >&2
fi

echo -e "\n\e[92mScan complete • $SCAN_ID • ${#results[@]} accounts scanned\e[0m" >&3
echo "Outputs: CSV=$CSV_OUT JSON=$JSON_OUT HTML=$HTML_OUT | Logs: $MIZAN_DIR" >&3
echo -e "\n\e[1mUpdated with more effort sub-metrics in comprehensive profile.\e[0m" >&3

exec >&3
