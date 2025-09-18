#!/usr/bin/env zsh

# npm-worm-scanner.sh - Enhanced scanner for npm Shai-Hulud worm indicators
#
# This script has been upgraded for improved security, robustness, and more
# specific indicators of compromise.
#
# Usage: ./npm-worm-scanner.sh [directory] [--json]
# If no directory specified, scans from the current directory.

# --- Script Configuration & Robustness ---
# Removed set -euo pipefail to prevent silent exits in pipe operations
set -u

# --- Argument Parsing ---
SCAN_DIR="${1:-.}"
OUTPUT_JSON=false
for arg in "$@"; do
    if [[ "$arg" == "--json" ]]; then
        OUTPUT_JSON=true
    fi
done

# --- Colors for human-readable output (disabled in JSON mode) ---
if [[ "$OUTPUT_JSON" == "false" ]]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    NC='\033[0m' # No Color
else
    RED='' YELLOW='' GREEN='' BLUE='' CYAN='' MAGENTA='' NC=''
fi

# --- Known Indicators of Compromise (IoCs) ---
MALICIOUS_HASH="46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
MALICIOUS_WORKFLOW_NAME="shai-hulud-workflow.yml"
MALICIOUS_WEBHOOK_URL="webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
MALICIOUS_TEMP_FILES=("/tmp/processor.sh" "/tmp/migrate-repos.sh")
SCRIPT_NAME=$(basename "$0")

# --- Dependency & Tool Checks ---
MISSING_DEPS=()
command -v jq >/dev/null 2>&1 || MISSING_DEPS+=("jq (for package.json analysis)")
command -v git >/dev/null 2>&1 || MISSING_DEPS+=("git (for repository analysis)")

GREP_CMD="grep"
GREP_ARGS="-r"
if command -v rg >/dev/null 2>&1; then
    GREP_CMD="rg"
    # --no-heading: cleaner output, --with-filename: useful for parsing
    GREP_ARGS="--no-heading --with-filename --line-number"
fi

HASH_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
    HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    HASH_CMD="shasum -a 256"
fi

# --- State Initialization ---
typeset -i found_issues=0
typeset -i scanned_dirs=0
typeset -i scanned_pkgs=0
typeset -a suspicious_files=()

# --- Functions ---

# JSON output structure
json_output() {
    local issues_json="["
    local first=true
    # Create a unique, sorted list of suspicious files
    if [[ ${#suspicious_files[@]} -gt 0 ]]; then
        local unique_files=$(printf '%s\n' "${suspicious_files[@]}" | sort -u)
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            [[ "$first" == "true" ]] && first=false || issues_json+=","
            issues_json+="\"$file\""
        done <<< "$unique_files"
    fi
    issues_json+="]"

    cat <<EOF
{
  "scan_completed": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "scan_directory": "$SCAN_DIR",
  "issues_found": $found_issues,
  "scanned_git_directories": $scanned_dirs,
  "scanned_package_json": $scanned_pkgs,
  "suspicious_files": $issues_json,
  "missing_dependencies": [$(printf '"%s",' "${MISSING_DEPS[@]}" | sed 's/,$//')],
  "tools_used": {
    "grep": "$GREP_CMD",
    "hash": "$HASH_CMD"
  }
}
EOF
}

# Logging function for consistent output
log() {
    [[ "$OUTPUT_JSON" == "false" ]] && echo -e "$@"
}

# Function to check if a path is within a git repository
in_git_repo() {
    git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1
}

# Function to compute file hash safely
get_file_hash() {
    local file="$1"
    if [[ -n "$HASH_CMD" ]] && [[ -f "$file" ]]; then
        $HASH_CMD "$file" 2>/dev/null | awk '{print $1}'
    else
        echo "unknown"
    fi
}

# Add a file to the suspicious list, ensuring no duplicates
add_suspicious_file() {
    local file="$1"
    # Using =~ for array containment check
    if [[ ! " ${suspicious_files[*]} " =~ " ${file} " ]]; then
        suspicious_files+=("$file")
    fi
}

# --- Scan Execution ---

# Header for human-readable output
if [[ "$OUTPUT_JSON" == "false" ]]; then
    log "${BLUE}🔍 Enhanced NPM Worm Scanner - Checking for Shai-Hulud indicators${NC}"
    log "${BLUE}================================================================${NC}"
    log "Scanning directory: $SCAN_DIR"
    log "Started at:         $(date)"

    if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
        log "\n${YELLOW}⚠️  Missing optional dependencies (some checks will be skipped):${NC}"
        printf '   - %s\n' "${MISSING_DEPS[@]}"
    fi

    log "Using search tool:  $GREP_CMD"
    log ""
fi

# --- STAGE 1: System-Level Checks ---
log "${YELLOW}🔬 Checking for system-level indicators...${NC}"
for temp_file in "${MALICIOUS_TEMP_FILES[@]}"; do
    if [[ -f "$temp_file" ]]; then
        log "${RED}🚨 CRITICAL: Found malicious temporary file: $temp_file${NC}"
        add_suspicious_file "$temp_file"
        ((found_issues++))
    fi
done

# --- STAGE 2: File & Directory Structure Checks ---
log "\n${YELLOW}📁 Building file index and checking for suspicious files/directories...${NC}"

# Find all relevant files once to improve performance
ALL_FILES=$(find "$SCAN_DIR" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || echo "")
PKG_FILES=$(echo "$ALL_FILES" | grep 'package\.json$' || echo "")

# 2.1: Check for the malicious workflow file
if [[ -n "$ALL_FILES" ]]; then
    echo "$ALL_FILES" | grep -F "$MALICIOUS_WORKFLOW_NAME" 2>/dev/null | while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        log "${RED}⚠️  FOUND: Malicious workflow file name${NC}"
        log "   Location: ${file}"
        add_suspicious_file "$file"
        ((found_issues++))
    done || true
fi

# 2.2: Search for bundle.js in package roots (where package.json exists)
if [[ -n "$PKG_FILES" ]]; then
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        ((scanned_pkgs++))
        pkg_dir=$(dirname "$pkg")
        bundle_path="$pkg_dir/bundle.js"
        if [[ -f "$bundle_path" ]]; then
            log "${RED}⚠️  FOUND: bundle.js in a package root${NC}"
            log "   Location: ${bundle_path}"
            
            hash=$(get_file_hash "$bundle_path")
            if [[ "$hash" == "$MALICIOUS_HASH" ]]; then
                log "${RED}   🚨 CRITICAL: Hash matches known malicious bundle.js!${NC}"
            else
                log "   Hash: $hash (does not match known hash)"
            fi
            
            add_suspicious_file "$bundle_path"
            ((found_issues++))
        fi
    done <<< "$PKG_FILES"
fi

# 2.3: Check git repos for structural indicators
find "$SCAN_DIR" -type d -name ".git" 2>/dev/null | while IFS= read -r gitdir; do
    [[ -z "$gitdir" ]] && continue
    ((scanned_dirs++))
    repo_dir=$(dirname "$gitdir")
    repo_name=$(basename "$repo_dir")

    # Check for shai-hulud branch
    if git -C "$repo_dir" branch -a 2>/dev/null | grep -q "shai-hulud"; then
        log "${RED}⚠️  FOUND: 'shai-hulud' branch in repository${NC}"
        log "   Location: ${repo_dir}"
        ((found_issues++))
    fi

    # Check for '-migration' repo name suffix
    if [[ "$repo_name" =~ -migration$ ]]; then
        log "${RED}⚠️  FOUND: Repository name ends in '-migration'${NC}"
        log "   Location: ${repo_dir}"
        ((found_issues++))
    fi
done || true

# --- STAGE 3: Content-Based Checks ---

# 3.1: Check for exposed npm tokens in .npmrc files
log "\n${YELLOW}🔑 Checking for exposed npm tokens in .npmrc files...${NC}"
if [[ -n "$ALL_FILES" ]]; then
    echo "$ALL_FILES" | grep '\.npmrc$' 2>/dev/null | while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        if grep -Eq "//registry\.npmjs\.org/:_authToken=|//npm\.pkg\.github\.com/:_authToken=" "$file" 2>/dev/null; then
            log "${RED}⚠️  FOUND: .npmrc file with authentication token${NC}"
            log "   Location: ${file}"
            add_suspicious_file "$file"
            ((found_issues++))
        fi
    done || true
fi

# 3.2: Check package.json files for malicious install scripts
if command -v jq >/dev/null 2>&1 && [[ -n "$PKG_FILES" ]]; then
    log "\n${YELLOW}📦 Checking package.json files for suspicious scripts...${NC}"
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        # Specific check for the known worm behavior
        malicious_postinstall=$(jq -r '.scripts.postinstall // ""' "$pkg" 2>/dev/null | grep -E "node.*bundle\.js" || echo "")
        
        if [[ -n "$malicious_postinstall" ]]; then
            log "${RED}🚨 CRITICAL: Found malicious 'postinstall' script in ${pkg}${NC}"
            log "   Script:   postinstall: \"$malicious_postinstall\""
            add_suspicious_file "$pkg"
            ((found_issues++))
        fi
        
        # Broader check for other suspicious lifecycle scripts
        suspicious_scripts=$(jq -r '.scripts // {} | to_entries[] | select(
            (.key | test("^(pre|post)?install$|^prepare$")) and 
            (.value | test("curl|wget|eval\\(|--force"))
        ) | "\(.key): \(.value)"' "$pkg" 2>/dev/null || echo "")

        if [[ -n "$suspicious_scripts" ]]; then
            log "${YELLOW}⚠️  FOUND: Potentially suspicious lifecycle script(s) in ${pkg}${NC}"
            echo "$suspicious_scripts" | while IFS= read -r script; do
                log "   Script: $script"
            done
            add_suspicious_file "$pkg"
            ((found_issues++))
        fi
    done <<< "$PKG_FILES"
fi

# 3.3: Use grep/rg to scan all code for string indicators
log "\n${YELLOW}🌐 Scanning all non-binary files for string indicators...${NC}"
if [[ "$GREP_CMD" == "rg" ]]; then
    # First search for the exact webhook URL
    rg --type-not binary -F "$MALICIOUS_WEBHOOK_URL" \
        --glob "!$SCRIPT_NAME" \
        --glob "!node_modules/**" \
        --glob "!.git/**" \
        "$SCAN_DIR" 2>/dev/null | while IFS= read -r line; do
        
        file=$(echo "$line" | cut -d: -f1)
        match=$(echo "$line" | cut -d: -f3-)

        log "${RED}🚨 CRITICAL: Found known malicious webhook URL!${NC}"
        log "   File:    $file"
        log "   Context: ${match}"
        add_suspicious_file "$file"
        ((found_issues++))
    done || true

    # Then search for other patterns
    rg -e "npm publish.*--force" \
       -e "trufflehog.*filesystem.*/" \
        --glob "!$SCRIPT_NAME" \
        --glob "!node_modules/**" \
        --glob "!.git/**" \
        "$SCAN_DIR" 2>/dev/null | while IFS= read -r line; do
        
        file=$(echo "$line" | cut -d: -f1)
        match=$(echo "$line" | cut -d: -f3-)

        log "${RED}⚠️  FOUND: Suspicious string indicator${NC}"
        log "   File:    $file"
        log "   Context: ${match}"
        add_suspicious_file "$file"
        ((found_issues++))
    done || true
else
    # Fallback to standard grep
    $GREP_CMD $GREP_ARGS -F "$MALICIOUS_WEBHOOK_URL" "$SCAN_DIR" \
        --include="*.js" --include="*.json" --include="*.yml" --include="*.yaml" --include="*.sh" \
        --exclude="$SCRIPT_NAME" --exclude-dir=node_modules --exclude-dir=.git 2>/dev/null | while IFS= read -r line; do
        
        file=$(echo "$line" | cut -d: -f1)
        log "${RED}🚨 CRITICAL: Found known malicious webhook URL!${NC}"
        log "   File:    ${file}"
        log "   Match:   $line"
        add_suspicious_file "$file"
        ((found_issues++))
    done || true

    # Search for other patterns
    for pattern in "npm publish.*--force" "trufflehog.*filesystem.*/"; do
        $GREP_CMD $GREP_ARGS "$pattern" "$SCAN_DIR" \
            --include="*.js" --include="*.json" --include="*.yml" --include="*.yaml" --include="*.sh" \
            --exclude="$SCRIPT_NAME" --exclude-dir=node_modules --exclude-dir=.git 2>/dev/null | while IFS= read -r line; do
            
            file=$(echo "$line" | cut -d: -f1)
            log "${RED}⚠️  FOUND: Suspicious pattern${NC}"
            log "   File:    ${file}"
            log "   Match:   $line"
            add_suspicious_file "$file"
            ((found_issues++))
        done || true
    done
fi

# --- Summary ---
if [[ "$OUTPUT_JSON" == "true" ]]; then
    json_output
else
    log "\n${BLUE}================================================================${NC}"
    log "Scan completed at: $(date)"
    log "Scanned directories with .git: $scanned_dirs"
    log "Scanned package.json files:    $scanned_pkgs"
    log ""
    
    if [[ $found_issues -eq 0 ]]; then
        log "${GREEN}✅ No specific indicators of the Shai-Hulud worm were found.${NC}"
    else
        log "${RED}🚨 Found $found_issues potential indicator(s). Manual review is required.${NC}"
        
        # Print unique, sorted list of files
        if [[ ${#suspicious_files[@]} -gt 0 ]]; then
            log "\n${YELLOW}📄 Suspicious files requiring immediate manual review:${NC}"
            printf '%s\n' "${suspicious_files[@]}" | sort -u | sed 's/^/   - /'
        fi
        
        log "\n${YELLOW}Recommended Next Steps:${NC}"
        log "1. ${RED}Immediately rotate any credentials or tokens found in .npmrc or source code.${NC}"
        log "2. Analyze the git history of suspicious files for unauthorized changes."
        log "3. If a malicious 'bundle.js' was found, delete it and remove the 'postinstall' script from package.json."
        log "4. Review GitHub audit logs for unexpected repository creations or token usage."
        log "5. Run 'npm audit' in affected packages to check for other vulnerabilities."
        log "6. Review your npm and GitHub account security settings and enable 2FA."
    fi
fi

# Exit with status 1 if issues were found, 0 otherwise.
exit $((found_issues > 0 ? 1 : 0))
