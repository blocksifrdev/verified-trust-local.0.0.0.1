#!/bin/zsh
# =====================================================================
# VERIFIEDTRUST MULTI-OS — LOCAL, USER & CLOUD IDENTITY SCANNING — NOV 27 2025
# Lightweight identity and endpoint/cloud identity scanner with exportable evidence.
# =====================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_DIR="${PLUGIN_DIR:-$ROOT_DIR/plugins}"

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
TARGET_OS="auto"
CLOUD_MODE="none"
PLUGIN_TRUST_MODE="${PLUGIN_TRUST_MODE:-strict}"
PLUGIN_ALLOWLIST="${PLUGIN_ALLOWLIST:-}"
SHOW_HELP=0
while getopts ":u:f:v:e:m:o:c:h" opt; do
    case $opt in
        u) UID_MIN=$(echo $OPTARG | cut -d',' -f1); UID_MAX=$(echo $OPTARG | cut -d',' -f2) ;;
        f) FRAMEWORKS_MODE=$OPTARG ;;
        v) VERBOSE=1 ;;
        e) EXPORT_FORMATS=$OPTARG ;;
        m) MDM_MODE=$OPTARG ;;
        o) TARGET_OS=$OPTARG ;;
        c) CLOUD_MODE=$OPTARG ;;
        h) SHOW_HELP=1 ;;
        *) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    esac
done

if ! [[ "$UID_MIN" =~ ^[0-9]+$ && "$UID_MAX" =~ ^[0-9]+$ ]] || (( UID_MIN > UID_MAX )); then
    echo "Invalid UID range: $UID_MIN,$UID_MAX (expected min,max with min <= max)" >&2
    exit 1
fi

if [[ ! "$TARGET_OS" =~ ^(auto|macos|linux|windows)$ ]]; then
    echo "Invalid OS target: $TARGET_OS (expected auto|macos|linux|windows)" >&2
    exit 1
fi

if [[ ! "$CLOUD_MODE" =~ ^(none|aws|azure|gcp|all)$ ]]; then
    echo "Invalid cloud mode: $CLOUD_MODE (expected none|aws|azure|gcp|all)" >&2
    exit 1
fi

if [[ ! "$PLUGIN_TRUST_MODE" =~ ^(strict|permissive)$ ]]; then
    echo "Invalid PLUGIN_TRUST_MODE: $PLUGIN_TRUST_MODE (expected strict|permissive)" >&2
    exit 1
fi

if (( SHOW_HELP )); then
    cat <<'USAGE'
Usage: verifiedtrust [-u min,max] [-f full|minimal] [-v] [-e csv,json,html,pdf] [-m none|jamf|intune] [-o auto|macos|linux|windows] [-c none|aws|azure|gcp|all]

Options:
  -u    UID range to scan (default 0,500)
  -f    Framework mapping mode (full|minimal)
  -v    Verbose logging to console
  -e    Export formats (comma-separated)
  -m    MDM output mode (none|jamf|intune)
  -o    Target OS scanner (auto|macos|linux|windows)
  -c    Cloud identity mode (none|aws|azure|gcp|all)
  -h    Show help

Environment:
  KNOWN_GOOD_HASH   Optional SHA256 hash to enforce self-integrity.
  PLUGIN_DIR        Directory containing plugin scripts (default: ./plugins).
  PLUGIN_TRUST_MODE Plugin validation mode: strict|permissive (default: strict).
  PLUGIN_ALLOWLIST  Comma-separated plugin basenames allowed to run (default: all discovered plugins).
  PARALLEL          Requests parallel scanning when GNU parallel exists (local build currently uses sequential mode).
USAGE
    exit 0
fi

SCAN_ID=$(uuidgen 2>/dev/null || echo "scan-$(date +%s)-$RANDOM")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
detect_platform() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Darwin) echo "macos" ;;
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null; then
                echo "windows"
            else
                echo "linux"
            fi
            ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *) echo "linux" ;;
    esac
}

PLATFORM="${TARGET_OS}"
[[ "$PLATFORM" == "auto" ]] && PLATFORM="$(detect_platform)"
PLATFORM_LABEL="$(echo "$PLATFORM" | tr '[:lower:]' '[:upper:]')"

MIZAN_DIR="$HOME/VerifiedTrust-${PLATFORM_LABEL}/MizanLogs"
LOG_FILE="$MIZAN_DIR/scan_$SCAN_ID.log"
ERROR_FILE="$MIZAN_DIR/errors_$SCAN_ID.log"
CSV_OUT="$HOME/VerifiedTrust-${PLATFORM_LABEL}/VerifiedTrust_${PLATFORM_LABEL}_ACCOUNTS_2025.csv"
JSON_OUT="$HOME/VerifiedTrust-${PLATFORM_LABEL}/VerifiedTrust_${PLATFORM_LABEL}_ACCOUNTS_2025.json"
HTML_OUT="$HOME/VerifiedTrust-${PLATFORM_LABEL}/VerifiedTrust_${PLATFORM_LABEL}_ACCOUNTS_2025.html"
mkdir -p "$MIZAN_DIR" "$HOME/VerifiedTrust-${PLATFORM_LABEL}"

exec 3>&1
if (( VERBOSE )); then
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$ERROR_FILE" >&2)
else
    exec >> "$LOG_FILE" 2>> "$ERROR_FILE"
fi

if [[ "$MDM_MODE" != "none" && "$PLATFORM" == "macos" ]]; then
    echo -e "\n\e[95m=== VERIFIEDTRUST ${PLATFORM_LABEL} — MDM MODE: $MDM_MODE ===\e[0m" >&3
else
    echo -e "\n\e[95m=== VERIFIEDTRUST ${PLATFORM_LABEL} — LOCAL, USER & CLOUD IDENTITY SCANNING ===\e[0m" >&3
fi
echo "Scan ID: $SCAN_ID\n" >&3

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

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    echo "$s"
}

csv_escape() {
    local s="$1"
    s="${s//\"/\"\"}"
    echo "\"$s\""
}

# --------------------- MIZAN PROOF ---------------------
mizan_proof() {
    local upn="$1" display="$2" effort="$3" risk="$4" apps="$5" frameworks="$6" status="$7" policy_violations="$8" effort_profile="$9" service_note="${10:-}" 
    local proof_string="${upn}${effort}${apps}${frameworks}${status}${policy_violations}${effort_profile}${service_note}VerifiedTrust-${PLATFORM_LABEL}-2025"
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
  "platform": "$PLATFORM_LABEL",
  "service_decay_note": "${service_note:-N/A}",
  "stark_proof": "$stark_proof",
  "version": "enhanced-2025-multios-cloud"
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
    if [[ "$PLATFORM" == "linux" ]]; then
        local apps
        apps=$(ps -u "$username" -o comm= 2>/dev/null | head -n 8 | paste -sd'; ' -)
        echo "${apps:-None Detected}"
        return 0
    elif [[ "$PLATFORM" == "windows" ]]; then
        echo "Windows linked apps require PowerShell endpoint telemetry"
        return 0
    fi
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
    if [[ "$PLATFORM" == "linux" ]]; then
        local effort=75
        local profile="AgeDecay:10; ActivityDecay:10; PrivilegeRisk:0; LoginFreqBonus:5; MFABonus:0; PwAgeDecay:5; LinkedAppsBonus:5; HomeActivityBonus:0; SudoBonus:0; FailedLoginPenalty:0; ServiceDecay:0 (Linux baseline)"
        local groups=$(id -Gn "$username" 2>/dev/null || true)
        [[ "$groups" == *"sudo"* || "$groups" == *"wheel"* ]] && effort=$(( effort - 15 )) && profile="${profile}; PrivilegedGroup:yes"
        echo "$effort|$profile|Linux baseline"
        return 0
    elif [[ "$PLATFORM" == "windows" ]]; then
        local effort=70
        local profile="AgeDecay:10; ActivityDecay:15; PrivilegeRisk:10; LoginFreqBonus:0; MFABonus:0; PwAgeDecay:10; LinkedAppsBonus:0; HomeActivityBonus:0; SudoBonus:0; FailedLoginPenalty:0; ServiceDecay:0 (Windows baseline)"
        echo "$effort|$profile|Windows baseline"
        return 0
    fi
    local now=$(date +%s)
    local created_sec=0 last_login_sec=0 last_pw_change_sec=0 failed_logins=0
    local age_decay=0 activity_decay=0 privilege_risk=0 login_freq_bonus=0 mfa_bonus=0 pw_age_decay=0 linked_apps_bonus=0 home_activity_bonus=0 sudo_bonus=0 failed_login_penalty=0 service_decay=0 service_note=""

    local policy=$(dscl . -read "/Users/$username" AccountPolicyData 2>/dev/null || echo "")
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

    local auth_auth=$(dscl . -read "/Users/$username" AuthenticationAuthority 2>/dev/null || echo "")
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
    if [[ "$PLATFORM" == "linux" ]]; then
        passwd -S "$username" 2>/dev/null | awk '{print ($2=="L" ? "Disabled/Locked" : "Enabled/Unlocked")}' || echo "Unknown"
        return 0
    elif [[ "$PLATFORM" == "windows" ]]; then
        echo "Unknown"
        return 0
    fi
    local disabled="Enabled"
    local locked="Unlocked"
    if pwpolicy -u "$username" -getpolicy 2>/dev/null | grep -q 'isDisabled=1'; then
        disabled="Disabled"
    fi
    if dscl . -read "/Users/$username" AuthenticationAuthority 2>/dev/null | grep -q 'Locked'; then
        locked="Locked"
    fi
    echo "$disabled/$locked"
}

# --------------------- PASSWORD POLICY ---------------------
get_policy_violations() {
    local username="$1"
    if [[ "$PLATFORM" == "linux" ]]; then
        local violations=""
        chage -l "$username" 2>/dev/null | grep -qi "never" && violations+="No expiration; "
        echo "${violations:-None}"
        return 0
    elif [[ "$PLATFORM" == "windows" ]]; then
        echo "None"
        return 0
    fi
    local violations=""
    local policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null || echo "")
    [[ "$policy" != *"policyAttributePassword"* ]] && violations+="No password policy; "
    [[ "$policy" != *"expiresEvery"* ]] && violations+="No expiration; "
    echo "${violations:-None}"
}

# --------------------- PLUGIN EXECUTION ---------------------
plugin_results=()
plugin_allowed() {
    local plugin_base="$1"
    [[ -z "$PLUGIN_ALLOWLIST" ]] && return 0
    local candidate oldifs="$IFS" found=1
    IFS=','
    for candidate in $PLUGIN_ALLOWLIST; do
        if [[ "$candidate" == "$plugin_base" ]]; then
            found=0
            break
        fi
    done
    IFS="$oldifs"
    return $found
}

plugin_is_trusted() {
    local plugin="$1"
    [[ "$PLUGIN_TRUST_MODE" == "permissive" ]] && return 0

    local owner mode
    if [[ "$PLATFORM" == "linux" ]]; then
        owner=$(stat -c '%U' "$plugin" 2>/dev/null || echo "unknown")
        mode=$(stat -c '%a' "$plugin" 2>/dev/null || echo "666")
    else
        owner=$(stat -f '%Su' "$plugin" 2>/dev/null || echo "unknown")
        mode=$(stat -f '%OLp' "$plugin" 2>/dev/null | tail -c 4 | tr -d ' ' || echo "666")
    fi

    [[ "$owner" != "root" && "$owner" != "${USER:-unknown}" ]] && return 1
    local group_perm=${mode:1:1}
    local other_perm=${mode:2:1}
    (( group_perm >= 2 || other_perm >= 2 )) && return 1
    return 0
}

run_plugins() {
    local username="$1"
    [[ -d "$PLUGIN_DIR" ]] || return 0
    for plugin in "$PLUGIN_DIR"/*.sh; do
        [[ -f "$plugin" ]] || continue
        local plugin_base
        plugin_base="$(basename "$plugin")"
        if ! plugin_allowed "$plugin_base"; then
            echo "[warn] skipping plugin not in allowlist: $plugin_base" >&2
            continue
        fi
        if ! plugin_is_trusted "$plugin"; then
            echo "[warn] skipping untrusted plugin (owner/perms): $plugin_base" >&2
            continue
        fi
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

scan_accounts() {
    local uid_filter="$1" type="$2"
    local tmpfile=$(mktemp)
    if [[ "$PLATFORM" == "macos" ]]; then
        dscl . -list /Users UniqueID 2>/dev/null | awk -v min="$UID_MIN" -v max="$UID_MAX" "$uid_filter" > "$tmpfile" || { echo "Error listing users" >&2; return 1; }
    elif [[ "$PLATFORM" == "linux" ]]; then
        getent passwd | awk -F: -v min="$UID_MIN" -v max="$UID_MAX" '{print $1" "$3}' | awk -v min="$UID_MIN" -v max="$UID_MAX" "$uid_filter" > "$tmpfile" || { echo "Error listing linux users" >&2; return 1; }
    else
        if command -v powershell >/dev/null 2>&1; then
            powershell -NoProfile -Command 'Get-LocalUser | ForEach-Object { "{0} {1}" -f $_.Name, ($_.SID.Value.Split("-")[-1]) }' 2>/dev/null | awk -v min="$UID_MIN" -v max="$UID_MAX" "$uid_filter" > "$tmpfile" || true
        else
            echo "[warn] windows target requested but powershell is not available; skipping local account enumeration" >&2
        fi
    fi

    if [[ ! -s "$tmpfile" ]]; then
        echo -e "\e[31mNo $type accounts found\e[0m" >&3
        [[ "$type" == "Daemon" && "$PLATFORM" == "macos" ]] && { echo "Forcing known daemons..."; for user in _assetcache _spotlight _tcc _windowserver _mdnsresponder; do echo "$user"; done >> "$tmpfile"; }
    fi

    if command -v parallel >/dev/null 2>&1 && [[ -n "${PARALLEL:-}" ]]; then
        echo "[warn] PARALLEL requested, but sequential mode is used for reliable function scope in zsh." >&2
    fi
    while read -r user; do
        process_account "$user" "$type"
    done < "$tmpfile"
    rm -f "$tmpfile"
}

process_account() {
    local user="$1" type="$2"
    [[ "$user" =~ ^(_mbsetupuser|nobody|daemon|www|root)$ ]] && return

    realname=$(dscl . -read "/Users/$user" RealName 2>/dev/null | sed -n '2p' | xargs || echo "macOS $type Account")
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

    proof=$(mizan_proof "$user@local.$PLATFORM" "$user — $realname" $effort "$risk" "$linked_apps" "$frameworks" "$status" "$policy_violations" "$profile" "$service_note")
    local r="$user@local.$PLATFORM|$user — $realname|$effort|$profile|$risk|$linked_apps|$frameworks|$status|$policy_violations|$service_note|${proof:0:12}...|$type"
    results+=("$r")

    json_results+=("{\"upn\":\"$(json_escape "$user@local.$PLATFORM")\",\"name\":\"$(json_escape "$user — $realname")\",\"effort\":$effort,\"effort_profile\":\"$(json_escape "$profile")\",\"risk\":\"$(json_escape "$risk")\",\"linked_apps\":\"$(json_escape "$linked_apps")\",\"frameworks\":\"$(json_escape "$frameworks")\",\"status\":\"$(json_escape "$status")\",\"policy_violations\":\"$(json_escape "$policy_violations")\",\"service_decay_note\":\"$(json_escape "$service_note")\",\"plugins\":\"$(json_escape "$plugin_blob")\",\"proof\":\"$(json_escape "${proof:0:12}...")\",\"type\":\"$(json_escape "$type")\"}")
    html_table+="<tr><td>$user@local.$PLATFORM</td><td>$user — $realname</td><td>$effort</td><td>$profile</td><td>$risk</td><td>$linked_apps</td><td>$frameworks</td><td>$status</td><td>$policy_violations</td><td>$service_note</td><td>${proof:0:12}...</td><td>$type</td></tr>"

    ((account_count+=1))
    ((total_effort += effort))
    [[ "$risk" == "High-Risk" || "$risk" == "Ghost" ]] && ((high_risk_count+=1))
    return 0
}

append_cloud_identity() {
    local upn="$1" provider="$2" identity_type="$3" effort="$4" risk="$5" policy_violations="$6" service_note="$7"
    local profile="AgeDecay:0; ActivityDecay:15; PrivilegeRisk:$((100-effort)); LoginFreqBonus:0; MFABonus:0; PwAgeDecay:10; LinkedAppsBonus:0; HomeActivityBonus:0; SudoBonus:0; FailedLoginPenalty:0; ServiceDecay:10 (${provider} cloud posture)"
    local linked_apps="${provider} control plane"
    local frameworks
    frameworks=$(map_to_frameworks "$effort")
    local status="Enabled/Unknown"
    local proof
    proof=$(mizan_proof "$upn" "$upn" "$effort" "$risk" "$linked_apps" "$frameworks" "$status" "$policy_violations" "$profile" "$service_note")
    local r="$upn|$upn|$effort|$profile|$risk|$linked_apps|$frameworks|$status|$policy_violations|$service_note|${proof:0:12}...|$identity_type"
    results+=("$r")
    json_results+=("{\"upn\":\"$(json_escape "$upn")\",\"name\":\"$(json_escape "$upn")\",\"effort\":$effort,\"effort_profile\":\"$(json_escape "$profile")\",\"risk\":\"$(json_escape "$risk")\",\"linked_apps\":\"$(json_escape "$linked_apps")\",\"frameworks\":\"$(json_escape "$frameworks")\",\"status\":\"$(json_escape "$status")\",\"policy_violations\":\"$(json_escape "$policy_violations")\",\"service_decay_note\":\"$(json_escape "$service_note")\",\"proof\":\"$(json_escape "${proof:0:12}...")\",\"type\":\"$(json_escape "$identity_type")\"}")
    html_table+="<tr><td>$upn</td><td>$upn</td><td>$effort</td><td>$profile</td><td>$risk</td><td>$linked_apps</td><td>$frameworks</td><td>$status</td><td>$policy_violations</td><td>$service_note</td><td>${proof:0:12}...</td><td>$identity_type</td></tr>"
    ((account_count+=1))
    ((total_effort += effort))
    [[ "$risk" == "High-Risk" || "$risk" == "Ghost" ]] && ((high_risk_count+=1))
    return 0
}

assess_aws_identity() {
    local user="$1"
    local effort=70
    local risk="Dormant"
    local violations=""

    aws iam get-login-profile --user-name "$user" >/dev/null 2>&1 || { effort=$((effort-15)); violations+="No console profile; "; }
    local mfa_count
    mfa_count=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices | length(@)' --output text 2>/dev/null || echo "0")
    [[ "$mfa_count" == "0" || "$mfa_count" == "None" ]] && { effort=$((effort-20)); violations+="MFA missing; "; }
    local key_count
    key_count=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`] | length(@)' --output text 2>/dev/null || echo "0")
    (( key_count > 1 )) && { effort=$((effort-15)); violations+="Multiple active access keys; "; }

    (( effort < 0 )) && effort=0
    (( effort > 100 )) && effort=100
    (( effort < 50 )) && risk="High-Risk"
    (( effort < 20 )) && risk="Ghost"
    echo "$effort|$risk|${violations:-None}|AWS IAM depth checks"
}

assess_azure_identity() {
    local upn="$1"
    local effort=68
    local risk="Dormant"
    local violations=""

    local role_count
    role_count=$(az role assignment list --assignee "$upn" --query 'length(@)' -o tsv 2>/dev/null || echo "0")
    (( role_count > 5 )) && { effort=$((effort-18)); violations+="High role assignment count; "; }

    local mfa_methods
    mfa_methods=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/users/$upn/authentication/methods" --query 'value | length(@)' -o tsv 2>/dev/null || echo "0")
    [[ "$mfa_methods" == "0" || "$mfa_methods" == "None" ]] && { effort=$((effort-20)); violations+="No auth methods on record; "; }

    (( effort < 0 )) && effort=0
    (( effort > 100 )) && effort=100
    (( effort < 50 )) && risk="High-Risk"
    (( effort < 20 )) && risk="Ghost"
    echo "$effort|$risk|${violations:-None}|Azure identity depth checks"
}

assess_gcp_identity() {
    local sa="$1"
    local effort=72
    local risk="Dormant"
    local violations=""

    local key_count
    key_count=$(gcloud iam service-accounts keys list --iam-account="$sa" --managed-by=user --format='value(name)' 2>/dev/null | wc -l | xargs || echo "0")
    (( key_count > 0 )) && { effort=$((effort-22)); violations+="User-managed keys present; "; }

    local role_bindings
    role_bindings=$(gcloud projects get-iam-policy "$(gcloud config get-value project 2>/dev/null)" --flatten='bindings[].members' --filter="bindings.members:serviceAccount:$sa" --format='value(bindings.role)' 2>/dev/null | wc -l | xargs || echo "0")
    (( role_bindings > 8 )) && { effort=$((effort-12)); violations+="High IAM binding count; "; }

    (( effort < 0 )) && effort=0
    (( effort > 100 )) && effort=100
    (( effort < 50 )) && risk="High-Risk"
    (( effort < 20 )) && risk="Ghost"
    echo "$effort|$risk|${violations:-None}|GCP service account depth checks"
}

scan_cloud_identities() {
    local provider="$1"
    local found=0
    local effort risk violations note
    case "$provider" in
        aws)
            if command -v aws >/dev/null 2>&1; then
                while read -r user; do
                    [[ -z "$user" ]] && continue
                    IFS='|' read -r effort risk violations note <<< "$(assess_aws_identity "$user")"
                    append_cloud_identity "${user}@aws" "AWS" "CloudUser" "$effort" "$risk" "$violations" "$note"
                    found=1
                done < <(aws iam list-users --query 'Users[].UserName' --output text 2>/dev/null | tr '\t' '\n')
            fi
            ;;
        azure)
            if command -v az >/dev/null 2>&1; then
                while read -r user; do
                    [[ -z "$user" ]] && continue
                    IFS='|' read -r effort risk violations note <<< "$(assess_azure_identity "$user")"
                    append_cloud_identity "$user" "Azure" "CloudUser" "$effort" "$risk" "$violations" "$note"
                    found=1
                done < <(az ad user list --query '[].userPrincipalName' -o tsv 2>/dev/null)
            fi
            ;;
        gcp)
            if command -v gcloud >/dev/null 2>&1; then
                while read -r sa; do
                    [[ -z "$sa" ]] && continue
                    IFS='|' read -r effort risk violations note <<< "$(assess_gcp_identity "$sa")"
                    append_cloud_identity "$sa" "GCP" "CloudServiceAccount" "$effort" "$risk" "$violations" "$note"
                    found=1
                done < <(gcloud iam service-accounts list --format='value(email)' 2>/dev/null)
            fi
            ;;
    esac

    if (( found == 0 )); then
        echo "[warn] $provider scan requested but no identities found (CLI missing, unauthenticated, or no permissions)." >&2
    fi
}

echo "Scanning daemon accounts..." >&3
scan_accounts '$2 >= min && $2 <= max && $2 < 500 && $2 > 0 {print $1}' "Daemon"
echo "Scanning user accounts..." >&3
scan_accounts '$2 >= min && $2 <= max && $2 >= 500 {print $1}' "User"

if [[ "$CLOUD_MODE" == "aws" || "$CLOUD_MODE" == "all" ]]; then
    echo "Scanning AWS identities..." >&3
    scan_cloud_identities "aws"
fi
if [[ "$CLOUD_MODE" == "azure" || "$CLOUD_MODE" == "all" ]]; then
    echo "Scanning Azure identities..." >&3
    scan_cloud_identities "azure"
fi
if [[ "$CLOUD_MODE" == "gcp" || "$CLOUD_MODE" == "all" ]]; then
    echo "Scanning GCP identities..." >&3
    scan_cloud_identities "gcp"
fi

if [[ "$PLATFORM" == "macos" ]] && { [[ -f /var/db/ConfigurationProfiles/Settings/.profilesAreInstalled ]] || [[ -d "/Library/Application Support/JAMF" ]]; }; then
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
    json_results+=("{\"upn\":\"mdm-agent@local\",\"name\":\"MDM Agent\",\"effort\":$effort,\"effort_profile\":\"$(json_escape "$profile")\",\"risk\":\"$(json_escape "$risk")\",\"linked_apps\":\"$(json_escape "$linked_apps")\",\"frameworks\":\"$(json_escape "$frameworks")\",\"status\":\"$(json_escape "$status")\",\"policy_violations\":\"$(json_escape "$policy_violations")\",\"service_decay_note\":\"$(json_escape "$service_note")\",\"proof\":\"$(json_escape "${proof:0:12}...")\",\"type\":\"MDM\"}")
    html_table+="<tr><td>mdm-agent@local</td><td>MDM Agent</td><td>$effort</td><td>$profile</td><td>$risk</td><td>$linked_apps</td><td>$frameworks</td><td>$status</td><td>$policy_violations</td><td>$service_note</td><td>${proof:0:12}...</td><td>MDM</td></tr>"

    ((account_count+=1))
    ((total_effort += effort))
    [[ "$risk" == "High-Risk" || "$risk" == "Ghost" ]] && ((high_risk_count+=1))
fi

average_effort=0
(( account_count > 0 )) && average_effort=$(( total_effort / account_count ))

if [[ "$PLATFORM" == "macos" && "$MDM_MODE" == "jamf" ]]; then
    echo "<result>Scan ID: $SCAN_ID | Accounts: $account_count | Average Effort: $average_effort | High Risks: $high_risk_count</result>"
    exit 0
elif [[ "$PLATFORM" == "macos" && "$MDM_MODE" == "intune" ]]; then
    echo "Scan ID: $SCAN_ID | Accounts: $account_count | Average Effort: $average_effort | High Risks: $high_risk_count"
    exit 0
fi

if [[ "$MDM_MODE" == "none" ]]; then
    echo -e "\e[93m=== PROOF: LISTING ACCOUNTS (UID $UID_MIN to $UID_MAX) ===\e[0m" >&3
    if [[ "$PLATFORM" == "macos" ]]; then
        dscl . -list /Users UniqueID 2>/dev/null | awk -v min=$UID_MIN -v max=$UID_MAX '$2 >= min && $2 <= max {print "Found account: " $1 " (UID: " $2 ")"}'
    elif [[ "$PLATFORM" == "linux" ]]; then
        getent passwd | awk -F: -v min=$UID_MIN -v max=$UID_MAX '$3 >= min && $3 <= max {print "Found account: " $1 " (UID: " $3 ")"}'
    else
        echo "Windows proof listing requires PowerShell local user access."
    fi
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
        echo "UPN,Name,EffortScore,EffortProfile,RiskLevel,LinkedApplications,FrameworkMappings,AccountStatus,PolicyViolations,ServiceDecayNote,MizanProof,Type"
        for r in "${results[@]}"; do
            IFS='|' read -r upn name effort profile risk apps frameworks status policy service_note proof type <<< "$r"
            echo "$(csv_escape "$upn"),$(csv_escape "$name"),$(csv_escape "$effort"),$(csv_escape "$profile"),$(csv_escape "$risk"),$(csv_escape "$apps"),$(csv_escape "$frameworks"),$(csv_escape "$status"),$(csv_escape "$policy"),$(csv_escape "$service_note"),$(csv_escape "$proof"),$(csv_escape "$type")"
        done
    } > "$CSV_OUT"
fi

if [[ "$EXPORT_FORMATS" == *"json"* ]]; then
    {
        echo "{"
        echo "  \"scan_id\": \"$(json_escape "$SCAN_ID")\"," 
        echo "  \"timestamp\": \"$(json_escape "$TIMESTAMP")\"," 
        echo "  \"accounts\": ["
        idx=1
        total=${#json_results[@]}
        for obj in "${json_results[@]}"; do
            if (( idx < total )); then
                echo "    $obj,"
            else
                echo "    $obj"
            fi
            ((idx+=1))
        done
        echo "  ]"
        echo "}"
    } > "$JSON_OUT"
fi

if [[ "$EXPORT_FORMATS" == *"html"* ]]; then
    echo "<html><body>$html_table</table></body></html>" > "$HTML_OUT"
fi

if [[ "$EXPORT_FORMATS" == *"pdf"* ]] && command -v pandoc >/dev/null; then
    pandoc "$HTML_OUT" -o "${HTML_OUT%.html}.pdf" || echo "PDF export failed; pandoc not installed?" >&2
fi

echo -e "\n\e[92mScan complete • $SCAN_ID • ${#results[@]} accounts scanned\e[0m" >&3
echo "Outputs: CSV=$CSV_OUT JSON=$JSON_OUT HTML=$HTML_OUT | Logs: $MIZAN_DIR" >&3
echo -e "\n\e[1mUpdated with more effort sub-metrics in comprehensive profile.\e[0m" >&3

exec >&3
