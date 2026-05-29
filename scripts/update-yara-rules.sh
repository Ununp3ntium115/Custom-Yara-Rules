#!/bin/bash
#
# YARA Rules Auto-Update Script
# Updates YARA rules daily from multiple sources:
#   1. YARA Forge (yarahq.github.io) - 11,000+ rules
#   2. Citizen Lab malware signatures
#   3. macOS-specific rules (pedramamini)
#   4. Awesome-YARA curated rules (InQuest)
#   5. YARAify/abuse.ch (YARAhub community rules)
#   6. DetectRaptor (mgreen27) - Velociraptor YARA & VQL artifacts
#   7. GlasswormYARA custom rules
#
# Creates comprehensive offline zip package for Velociraptor Claw Edition
# and 3rd party tools. GitHub Actions publishes the package to the
# Custom-Yara-Rules repository every day.
#
# Install cron job (runs daily at 3 AM):
#   crontab -e
#   0 3 * * * /Users/brodynielsen/GitRepos/Velociraptor_ClawEdition/scripts/update-yara-rules.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
YARA_DIR="$REPO_ROOT/yara-rules"
LOG_FILE="$YARA_DIR/update.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
DATE_SHORT=$(date '+%Y-%m-%d')
TMP_DIR="/tmp/yara-update-$$"

# Canonical public repository used by Velociraptor Claw Edition clients.
CUSTOM_YARA_RULES_REPO="${CUSTOM_YARA_RULES_REPO:-Ununp3ntium115/Custom-Yara-Rules}"
CUSTOM_YARA_RULES_RELEASE_TAG="${CUSTOM_YARA_RULES_RELEASE_TAG:-latest}"
CUSTOM_YARA_RULES_REPO_PATH="${CUSTOM_YARA_RULES_REPO_PATH:-$YARA_DIR/custom-repo}"
YARA_OFFLINE_ASSET="${YARA_OFFLINE_ASSET:-velociraptor-claw-yara-offline.zip}"
STATIC_YARA_PACKAGE_URL="${STATIC_YARA_PACKAGE_URL:-https://github.com/Ununp3ntium115/Custom-Yara-Rules/releases/download/latest/velociraptor-claw-yara-offline.zip}"
CUSTOM_YARA_RULES_DOWNLOAD_URL="$STATIC_YARA_PACKAGE_URL"

# YARA Forge download URLs
CORE_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
EXTENDED_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"
FULL_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"

# macOS-specific rules
MACOS_RULES_URL="https://gist.githubusercontent.com/pedramamini/c586a151a978f971b70412ca4485c491/raw/macos_malware.yar"

mkdir -p "$YARA_DIR"
echo "[$TIMESTAMP] Starting YARA rules update (multi-source)..." >> "$LOG_FILE"

# §P193 — Deduplicate case-pair YARA filenames. On case-insensitive
# filesystems (APFS, NTFS) git can't track both APT_APT10.yar and
# apt_apt10.yar — one always overwrites the other on checkout. First-
# write-wins policy: alphabetically first variant kept; later case-
# variants logged and removed before they reach git.
dedupe_case_pairs() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0
    local removed=0
    while IFS= read -r dup_name; do
        # Find both variants of this case-pair
        local files
        files=$(ls "$dir" 2>/dev/null | awk -v target="$dup_name" 'tolower($0) == tolower(target)')
        # Keep alphabetically first, remove the rest
        local keep=$(echo "$files" | sort | head -1)
        while IFS= read -r f; do
            if [[ -n "$f" && "$f" != "$keep" ]]; then
                rm -f "$dir/$f"
                removed=$((removed+1))
                echo "[$TIMESTAMP] §P193 dedupe: removed case-variant $f (kept $keep)" >> "$LOG_FILE"
            fi
        done <<< "$files"
    done < <(ls "$dir" 2>/dev/null | sort -f | uniq -id)
    echo "[$TIMESTAMP] §P193 dedupe in $dir: $removed case-variants removed" >> "$LOG_FILE"
}

# Create directories
mkdir -p "$YARA_DIR/packages/full"
mkdir -p "$YARA_DIR/packages/core"
mkdir -p "$YARA_DIR/packages/extended"
mkdir -p "$YARA_DIR/sources/awesome-yara"
mkdir -p "$YARA_DIR/sources/macos-specific"
mkdir -p "$YARA_DIR/sources/citizenlab"
mkdir -p "$YARA_DIR/sources/yaraify-abusech"
mkdir -p "$YARA_DIR/sources/detectraptor"
mkdir -p "$YARA_DIR/sources/glassworm"
mkdir -p "$YARA_DIR/vql-artifacts"
mkdir -p "$YARA_DIR/offline-package"
mkdir -p "$CUSTOM_YARA_RULES_REPO_PATH"
mkdir -p "$TMP_DIR"

cd "$YARA_DIR"

# Backup existing rules
if [ -d "packages" ] && [ "$(ls -A packages 2>/dev/null)" ]; then
    echo "[$TIMESTAMP] Backing up existing rules..." >> "$LOG_FILE"
    cp -r packages "packages.backup.$(date +%Y%m%d)" 2>/dev/null || true
fi

# ========================================
# 1. YARA Forge (Primary Source - 11,000+ rules)
# ========================================
echo "[$TIMESTAMP] Downloading YARA Forge rules..." >> "$LOG_FILE"

curl -L -s -o yara-forge-rules-full.zip "$FULL_URL" 2>> "$LOG_FILE"
echo "[$TIMESTAMP] Downloaded full rules ($(ls -lh yara-forge-rules-full.zip | awk '{print $5}'))" >> "$LOG_FILE"

curl -L -s -o yara-forge-rules-core.zip "$CORE_URL" 2>> "$LOG_FILE"
echo "[$TIMESTAMP] Downloaded core rules ($(ls -lh yara-forge-rules-core.zip | awk '{print $5}'))" >> "$LOG_FILE"

curl -L -s -o yara-forge-rules-extended.zip "$EXTENDED_URL" 2>> "$LOG_FILE"
echo "[$TIMESTAMP] Downloaded extended rules ($(ls -lh yara-forge-rules-extended.zip | awk '{print $5}'))" >> "$LOG_FILE"

# Extract YARA Forge rules
echo "[$TIMESTAMP] Extracting YARA Forge rules..." >> "$LOG_FILE"
unzip -o -q yara-forge-rules-full.zip >> "$LOG_FILE" 2>&1
unzip -o -q yara-forge-rules-core.zip >> "$LOG_FILE" 2>&1
unzip -o -q yara-forge-rules-extended.zip >> "$LOG_FILE" 2>&1

# ========================================
# 2. Citizen Lab Malware Signatures
# ========================================
echo "[$TIMESTAMP] Downloading Citizen Lab malware signatures..." >> "$LOG_FILE"

git clone --depth 1 https://github.com/citizenlab/malware-signatures.git "$TMP_DIR/citizenlab" 2>> "$LOG_FILE" || true
if [ -d "$TMP_DIR/citizenlab/yara" ]; then
    cp -r "$TMP_DIR/citizenlab/yara/"* sources/citizenlab/ 2>/dev/null || true
fi
find "$TMP_DIR/citizenlab" -maxdepth 1 -name "*.yar" -exec cp {} sources/citizenlab/ \; 2>/dev/null || true
find "$TMP_DIR/citizenlab" -maxdepth 1 -name "*.yara" -exec cp {} sources/citizenlab/ \; 2>/dev/null || true
echo "[$TIMESTAMP] Citizen Lab rules downloaded" >> "$LOG_FILE"

# ========================================
# 3. macOS-Specific YARA Rules (pedramamini)
# ========================================
echo "[$TIMESTAMP] Downloading macOS-specific YARA rules..." >> "$LOG_FILE"

curl -L -s -o sources/macos-specific/macos_malware.yar "$MACOS_RULES_URL" 2>> "$LOG_FILE" || true
echo "[$TIMESTAMP] macOS-specific rules downloaded" >> "$LOG_FILE"

# ========================================
# 4. Awesome-YARA Repository (InQuest)
# ========================================
echo "[$TIMESTAMP] Downloading Awesome-YARA curated rules..." >> "$LOG_FILE"

git clone --depth 1 https://github.com/InQuest/awesome-yara.git "$TMP_DIR/awesome-yara" 2>> "$LOG_FILE" || true
cp "$TMP_DIR/awesome-yara/README.md" sources/awesome-yara/SOURCES.md 2>/dev/null || true

# Florian Roth's signature-base
git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$TMP_DIR/signature-base" 2>> "$LOG_FILE" || true
if [ -d "$TMP_DIR/signature-base/yara" ]; then
    find "$TMP_DIR/signature-base/yara" -name "*.yar" -exec cp {} sources/awesome-yara/ \; 2>/dev/null || true
fi

# Yara-Rules project
git clone --depth 1 https://github.com/Yara-Rules/rules.git "$TMP_DIR/yara-rules-repo" 2>> "$LOG_FILE" || true
if [ -d "$TMP_DIR/yara-rules-repo" ]; then
    find "$TMP_DIR/yara-rules-repo" -name "*.yar" -exec cp {} sources/awesome-yara/ \; 2>/dev/null || true
    find "$TMP_DIR/yara-rules-repo" -name "*.yara" -exec cp {} sources/awesome-yara/ \; 2>/dev/null || true
fi
echo "[$TIMESTAMP] Awesome-YARA rules downloaded" >> "$LOG_FILE"

# §P193 — Dedupe case-pair filenames AFTER all three upstreams (InQuest
# README, signature-base, Yara-Rules/rules) have written to awesome-yara/.
# Without this the daily cron regresses 7acfc66c's tree cleanup every run.
dedupe_case_pairs "$YARA_DIR/sources/awesome-yara"

# ========================================
# 5. YARAify / abuse.ch (YARAhub - Community Rules)
# ========================================
echo "[$TIMESTAMP] Downloading YARAify/abuse.ch rules..." >> "$LOG_FILE"

# YARAify bulk download - TLP:WHITE community rules
# Download from: https://yaraify.abuse.ch/yarahub/
curl -L -s -o sources/yaraify-abusech/yaraify-rules.zip \
    "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip" 2>> "$LOG_FILE" || true

# Extract the rules
if [ -f "sources/yaraify-abusech/yaraify-rules.zip" ]; then
    cd sources/yaraify-abusech
    unzip -o -q yaraify-rules.zip 2>/dev/null || true
    cd "$YARA_DIR"
fi
echo "[$TIMESTAMP] YARAify/abuse.ch rules downloaded" >> "$LOG_FILE"

# ========================================
# 6. DetectRaptor (mgreen27) - Velociraptor YARA & VQL
# ========================================
echo "[$TIMESTAMP] Updating DetectRaptor (mgreen27)..." >> "$LOG_FILE"

# Check if DetectRaptor is a git submodule in the repo root
DETECTRAPTOR_DIR="$REPO_ROOT/DetectRaptor"
if [ -d "$DETECTRAPTOR_DIR/.git" ] || [ -f "$DETECTRAPTOR_DIR/.git" ]; then
    echo "[$TIMESTAMP] Updating DetectRaptor submodule..." >> "$LOG_FILE"
    cd "$REPO_ROOT"
    git submodule update --remote --merge DetectRaptor 2>> "$LOG_FILE" || true
    cd "$YARA_DIR"
else
    # Clone fresh if not a submodule
    echo "[$TIMESTAMP] Cloning DetectRaptor..." >> "$LOG_FILE"
    rm -rf "$TMP_DIR/detectraptor"
    git clone --depth 1 https://github.com/mgreen27/DetectRaptor.git "$TMP_DIR/detectraptor" 2>> "$LOG_FILE" || true
    DETECTRAPTOR_DIR="$TMP_DIR/detectraptor"
fi

# Copy DetectRaptor YARA rules
if [ -d "$DETECTRAPTOR_DIR/yara" ]; then
    echo "[$TIMESTAMP] Copying DetectRaptor YARA rules..." >> "$LOG_FILE"
    cp -r "$DETECTRAPTOR_DIR/yara/"* sources/detectraptor/ 2>/dev/null || true
    find "$DETECTRAPTOR_DIR/yara" -name "*.yar" -exec cp {} sources/detectraptor/ \; 2>/dev/null || true
    find "$DETECTRAPTOR_DIR/yara" -name "*.yara" -exec cp {} sources/detectraptor/ \; 2>/dev/null || true
fi

# Copy DetectRaptor VQL artifacts
if [ -d "$DETECTRAPTOR_DIR/vql" ]; then
    echo "[$TIMESTAMP] Copying DetectRaptor VQL artifacts..." >> "$LOG_FILE"
    cp -r "$DETECTRAPTOR_DIR/vql/"* "$YARA_DIR/vql-artifacts/" 2>/dev/null || true
fi

# Copy DetectRaptor CSV data files
if [ -d "$DETECTRAPTOR_DIR/csv" ]; then
    echo "[$TIMESTAMP] Copying DetectRaptor CSV data..." >> "$LOG_FILE"
    mkdir -p "$YARA_DIR/detection-data"
    cp -r "$DETECTRAPTOR_DIR/csv/"* "$YARA_DIR/detection-data/" 2>/dev/null || true
fi

echo "[$TIMESTAMP] DetectRaptor rules downloaded" >> "$LOG_FILE"

# ========================================
# 7. Combine All Rules into Master File
# ========================================
echo "[$TIMESTAMP] Combining all rules into master file..." >> "$LOG_FILE"

MASTER_FILE="packages/full/combined-rules-master.yar"
echo "// Velociraptor Claw Edition - Combined YARA Rules" > "$MASTER_FILE"
echo "// Generated: $TIMESTAMP" >> "$MASTER_FILE"
echo "// Sources: YARA Forge, Citizen Lab, macOS-Specific, Awesome-YARA, YARAify/abuse.ch, DetectRaptor, GlasswormYARA" >> "$MASTER_FILE"
echo "" >> "$MASTER_FILE"

# Add YARA Forge full rules
if [ -f "packages/full/yara-rules-full.yar" ]; then
    echo "// ========== YARA Forge Rules ==========" >> "$MASTER_FILE"
    cat packages/full/yara-rules-full.yar >> "$MASTER_FILE"
    echo "" >> "$MASTER_FILE"
fi

# Add Citizen Lab rules
if [ -d "sources/citizenlab" ] && ls sources/citizenlab/*.yar 1>/dev/null 2>&1; then
    echo "// ========== Citizen Lab Rules ==========" >> "$MASTER_FILE"
    for file in sources/citizenlab/*.yar; do
        cat "$file" >> "$MASTER_FILE" 2>/dev/null || true
        echo "" >> "$MASTER_FILE"
    done
fi

# Add macOS-specific rules
if [ -f "sources/macos-specific/macos_malware.yar" ]; then
    echo "// ========== macOS-Specific Rules ==========" >> "$MASTER_FILE"
    cat sources/macos-specific/macos_malware.yar >> "$MASTER_FILE" 2>/dev/null || true
    echo "" >> "$MASTER_FILE"
fi

# Add Awesome-YARA collected rules
if [ -d "sources/awesome-yara" ] && ls sources/awesome-yara/*.yar 1>/dev/null 2>&1; then
    echo "// ========== Awesome-YARA Collected Rules ==========" >> "$MASTER_FILE"
    for file in sources/awesome-yara/*.yar; do
        cat "$file" >> "$MASTER_FILE" 2>/dev/null || true
        echo "" >> "$MASTER_FILE"
    done
fi

# Add YARAify/abuse.ch rules
if [ -d "sources/yaraify-abusech" ]; then
    echo "// ========== YARAify/abuse.ch Rules ==========" >> "$MASTER_FILE"
    find sources/yaraify-abusech -name "*.yar" -exec cat {} \; >> "$MASTER_FILE" 2>/dev/null || true
    find sources/yaraify-abusech -name "*.yara" -exec cat {} \; >> "$MASTER_FILE" 2>/dev/null || true
    echo "" >> "$MASTER_FILE"
fi

# Add DetectRaptor rules
if [ -d "sources/detectraptor" ] && ls sources/detectraptor/*.yar 1>/dev/null 2>&1; then
    echo "// ========== DetectRaptor (mgreen27) Rules ==========" >> "$MASTER_FILE"
    for file in sources/detectraptor/*.yar; do
        cat "$file" >> "$MASTER_FILE" 2>/dev/null || true
        echo "" >> "$MASTER_FILE"
    done
fi

# Add GlasswormYARA custom rules (from Ununp3ntium115/GlasswormYARA)
echo "[$TIMESTAMP] Fetching GlasswormYARA custom rules..." >> "$LOG_FILE"
GLASSWORM_URL="https://raw.githubusercontent.com/Ununp3ntium115/GlasswormYARA/main/Glasswormrules"
curl -L -s -o sources/glassworm/glassworm-rules.yar "$GLASSWORM_URL" 2>> "$LOG_FILE"
GLASSWORM_IOCS_URL="https://raw.githubusercontent.com/Ununp3ntium115/GlasswormYARA/main/IOCs-GlassWorm.csv"
curl -L -s -o sources/glassworm/IOCs-GlassWorm.csv "$GLASSWORM_IOCS_URL" 2>> "$LOG_FILE"
GLASSWORM_HASHES_URL="https://raw.githubusercontent.com/Ununp3ntium115/GlasswormYARA/main/Glassworm-Files.csv"
curl -L -s -o sources/glassworm/Glassworm-Files.csv "$GLASSWORM_HASHES_URL" 2>> "$LOG_FILE"
if [ -f "sources/glassworm/glassworm-rules.yar" ]; then
    GLASSWORM_RULE_COUNT=$(grep -c "^rule " sources/glassworm/glassworm-rules.yar 2>/dev/null || echo "0")
    echo "[$TIMESTAMP] GlasswormYARA: $GLASSWORM_RULE_COUNT rules downloaded" >> "$LOG_FILE"
    echo "// ========== GlasswormYARA Custom Rules ==========" >> "$MASTER_FILE"
    cat sources/glassworm/glassworm-rules.yar >> "$MASTER_FILE" 2>/dev/null || true
    echo "" >> "$MASTER_FILE"
fi

# ========================================
# 8. Count rules and create version info
# ========================================
FORGE_COUNT=$(grep -c "^rule " packages/full/yara-rules-full.yar 2>/dev/null || echo "0")
CITIZENLAB_COUNT=$(cat sources/citizenlab/*.yar 2>/dev/null | grep -c "^rule " || echo "0")
MACOS_COUNT=$(cat sources/macos-specific/*.yar 2>/dev/null | grep -c "^rule " || echo "0")
AWESOME_COUNT=$(cat sources/awesome-yara/*.yar 2>/dev/null | grep -c "^rule " || echo "0")
YARAIFY_COUNT=$(find sources/yaraify-abusech -name "*.yar" -exec cat {} + 2>/dev/null | grep -c "^rule " || echo "0")
DETECTRAPTOR_COUNT=$(cat sources/detectraptor/*.yar 2>/dev/null | grep -c "^rule " || echo "0")
GLASSWORM_COUNT=$(cat sources/glassworm/*.yar 2>/dev/null | grep -c "^rule " || echo "0")
VQL_ARTIFACT_COUNT=$(find "$YARA_DIR/vql-artifacts" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
TOTAL_COUNT=$(grep -c "^rule " "$MASTER_FILE" 2>/dev/null || echo "unknown")

echo "[$TIMESTAMP] Rule counts - Forge: $FORGE_COUNT, Citizen Lab: $CITIZENLAB_COUNT, macOS: $MACOS_COUNT, Awesome: $AWESOME_COUNT, YARAify: $YARAIFY_COUNT, DetectRaptor: $DETECTRAPTOR_COUNT, Glassworm: $GLASSWORM_COUNT, Total: $TOTAL_COUNT" >> "$LOG_FILE"
echo "[$TIMESTAMP] VQL Artifacts: $VQL_ARTIFACT_COUNT" >> "$LOG_FILE"

cat > "$YARA_DIR/version.json" << EOF
{
  "updated": "$TIMESTAMP",
  "total_rules": "$TOTAL_COUNT",
  "vql_artifacts": "$VQL_ARTIFACT_COUNT",
  "sources": {
    "yara_forge": {
      "url": "https://yarahq.github.io/",
      "rule_count": "$FORGE_COUNT",
      "packages": ["full", "extended", "core"]
    },
    "citizenlab": {
      "url": "https://github.com/citizenlab/malware-signatures",
      "rule_count": "$CITIZENLAB_COUNT"
    },
    "macos_specific": {
      "url": "https://gist.github.com/pedramamini/c586a151a978f971b70412ca4485c491",
      "rule_count": "$MACOS_COUNT"
    },
    "awesome_yara": {
      "url": "https://github.com/InQuest/awesome-yara",
      "rule_count": "$AWESOME_COUNT",
      "includes": ["Neo23x0/signature-base", "Yara-Rules/rules"]
    },
    "yaraify_abusech": {
      "url": "https://yaraify.abuse.ch/yarahub/",
      "rule_count": "$YARAIFY_COUNT",
      "description": "YARAhub community rules (TLP:WHITE)"
    },
    "detectraptor": {
      "url": "https://github.com/mgreen27/DetectRaptor",
      "rule_count": "$DETECTRAPTOR_COUNT",
      "description": "Velociraptor YARA & VQL detection artifacts"
    },
    "glassworm_yara": {
      "url": "https://github.com/Ununp3ntium115/GlasswormYARA",
      "rule_count": "$GLASSWORM_COUNT",
      "description": "Custom GlasswormYARA rules and IOC data"
    }
  },
  "published_repository": {
    "repository": "$CUSTOM_YARA_RULES_REPO",
    "release_tag": "$CUSTOM_YARA_RULES_RELEASE_TAG",
    "defined_repo_path": "yara-rules/custom-repo",
    "static_package_url": "$STATIC_YARA_PACKAGE_URL",
    "offline_package_url": "$CUSTOM_YARA_RULES_DOWNLOAD_URL"
  },
  "packages": {
    "full": "yara-forge-rules-full.zip",
    "extended": "yara-forge-rules-extended.zip",
    "core": "yara-forge-rules-core.zip",
    "combined": "combined-rules-master.yar",
    "offline": "$YARA_OFFLINE_ASSET"
  }
}
EOF

# ========================================
# 9. Create Comprehensive Offline Zip Package
# ========================================
echo "[$TIMESTAMP] Creating offline zip package..." >> "$LOG_FILE"

OFFLINE_ZIP="$YARA_DIR/offline-package/$YARA_OFFLINE_ASSET"
OFFLINE_DIR="$YARA_DIR/offline-package/build"

# Clean and create build directory
rm -rf "$OFFLINE_DIR"
mkdir -p "$OFFLINE_DIR"

# Copy all YARA rules
mkdir -p "$OFFLINE_DIR/yara-rules"
cp "$MASTER_FILE" "$OFFLINE_DIR/yara-rules/" 2>/dev/null || true
cp -r "$YARA_DIR/sources/"* "$OFFLINE_DIR/yara-rules/" 2>/dev/null || true

# Copy VQL artifacts
if [ -d "$YARA_DIR/vql-artifacts" ]; then
    mkdir -p "$OFFLINE_DIR/vql-artifacts"
    cp -r "$YARA_DIR/vql-artifacts/"* "$OFFLINE_DIR/vql-artifacts/" 2>/dev/null || true
fi

# Copy detection data (CSVs)
if [ -d "$YARA_DIR/detection-data" ]; then
    mkdir -p "$OFFLINE_DIR/detection-data"
    cp -r "$YARA_DIR/detection-data/"* "$OFFLINE_DIR/detection-data/" 2>/dev/null || true
fi

# Copy version info
cp "$YARA_DIR/version.json" "$OFFLINE_DIR/" 2>/dev/null || true

# Create README for the offline package
cat > "$OFFLINE_DIR/README.md" << OFFLINEREADME
# Velociraptor Claw Edition - Offline YARA Rules Package

**Generated:** $TIMESTAMP
**Total YARA Rules:** $TOTAL_COUNT
**VQL Artifacts:** $VQL_ARTIFACT_COUNT

## Contents

- \`yara-rules/\` - All YARA rules from 7 sources
  - \`combined-rules-master.yar\` - Single consolidated file
  - Source directories with individual rule files
- \`vql-artifacts/\` - Velociraptor VQL detection artifacts
- \`detection-data/\` - CSV detection data files
- \`version.json\` - Version and source information

## Sources

1. **YARA Forge** (yarahq.github.io) - $FORGE_COUNT rules
2. **Citizen Lab** (malware-signatures) - $CITIZENLAB_COUNT rules
3. **macOS-Specific** (pedramamini) - $MACOS_COUNT rules
4. **Awesome-YARA** (InQuest) - $AWESOME_COUNT rules
5. **YARAify/abuse.ch** (YARAhub) - $YARAIFY_COUNT rules
6. **DetectRaptor** (mgreen27) - $DETECTRAPTOR_COUNT rules
7. **GlasswormYARA** (custom rules) - $GLASSWORM_COUNT rules

## Published Repository

- Repository: https://github.com/$CUSTOM_YARA_RULES_REPO
- Static package URL: $STATIC_YARA_PACKAGE_URL

## Usage

### With YARA CLI
\`\`\`bash
yara -r yara-rules/combined-rules-master.yar /path/to/scan
\`\`\`

### With Velociraptor
Import VQL artifacts into Velociraptor:
\`\`\`
velociraptor artifacts install vql-artifacts/*.yaml
\`\`\`

### With 3rd Party Tools
Point your DFIR tool to \`yara-rules/combined-rules-master.yar\`
OFFLINEREADME

# Create the zip file
cd "$OFFLINE_DIR"
rm -f "$OFFLINE_ZIP"
zip -r -q "$OFFLINE_ZIP" .
cd "$YARA_DIR"

# Calculate zip size
ZIP_SIZE=$(ls -lh "$OFFLINE_ZIP" 2>/dev/null | awk '{print $5}')
echo "[$TIMESTAMP] Offline package created: $OFFLINE_ZIP ($ZIP_SIZE)" >> "$LOG_FILE"

# Clean up build directory
rm -rf "$OFFLINE_DIR"

# Clean up temp directory
rm -rf "$TMP_DIR"

# Clean up old backups older than 7 days
find "$YARA_DIR" -name "packages.backup.*" -mtime +7 -exec rm -rf {} \; 2>/dev/null || true

echo "[$TIMESTAMP] YARA rules update complete!" >> "$LOG_FILE"

# ========================================
# 10. Commit changes to git (skip in CI — workflow publishes via release)
# ========================================
if [ -n "$CI" ]; then
    echo "[$TIMESTAMP] Running in CI — skipping git commit (workflow handles publish)" >> "$LOG_FILE"
elif [ -d "$REPO_ROOT/.git" ]; then
    cd "$REPO_ROOT"

    if git diff --quiet yara-rules/ 2>/dev/null && git diff --cached --quiet yara-rules/ 2>/dev/null; then
        echo "[$TIMESTAMP] No changes to commit" >> "$LOG_FILE"
    else
        echo "[$TIMESTAMP] Committing YARA rules to git..." >> "$LOG_FILE"

        git add yara-rules/

        git commit -m "chore(yara): Daily YARA rules update - $TOTAL_COUNT rules ($DATE_SHORT)

Updated from 7 sources:
- YARA Forge (yarahq.github.io): $FORGE_COUNT rules
- Citizen Lab malware signatures: $CITIZENLAB_COUNT rules
- macOS-specific rules (pedramamini): $MACOS_COUNT rules
- Awesome-YARA curated rules (InQuest): $AWESOME_COUNT rules
- YARAify/abuse.ch (YARAhub): $YARAIFY_COUNT rules
- DetectRaptor (mgreen27): $DETECTRAPTOR_COUNT rules
- GlasswormYARA custom rules: $GLASSWORM_COUNT rules

VQL Artifacts: $VQL_ARTIFACT_COUNT

Offline package: yara-rules/offline-package/$YARA_OFFLINE_ASSET
Combined master file: yara-rules/packages/full/combined-rules-master.yar

Auto-generated by update-yara-rules.sh cron job" >> "$LOG_FILE" 2>&1

        echo "[$TIMESTAMP] Git commit created. Push manually or let GitHub Actions handle it." >> "$LOG_FILE"
    fi
fi

echo ""
echo "=== YARA Rules Summary ==="
echo "YARA Forge: $FORGE_COUNT rules"
echo "Citizen Lab: $CITIZENLAB_COUNT rules"
echo "macOS Specific: $MACOS_COUNT rules"
echo "Awesome-YARA: $AWESOME_COUNT rules"
echo "YARAify/abuse.ch: $YARAIFY_COUNT rules"
echo "DetectRaptor: $DETECTRAPTOR_COUNT rules"
echo "GlasswormYARA: $GLASSWORM_COUNT rules"
echo "----------------------------"
echo "Total Combined: $TOTAL_COUNT rules"
echo "VQL Artifacts: $VQL_ARTIFACT_COUNT"
echo ""
echo "Offline Package: $ZIP_SIZE"
echo "Published Repo: $CUSTOM_YARA_RULES_REPO"
echo "Static Package URL: $STATIC_YARA_PACKAGE_URL"
echo ""
echo "[$TIMESTAMP] Script completed successfully" >> "$LOG_FILE"
