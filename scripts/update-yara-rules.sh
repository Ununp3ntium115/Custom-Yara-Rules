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
# and 3rd party tools.
#
# TWO CONSUMERS — do not confuse them:
#
# 1. THE SHIPPED APP (Mac App Store) — UNAFFECTED by the publish state.
#    The "Embed Bundled Rule Packs" phase in apps/macos-app/project.yml reads
#    the LOCAL file yara-rules/packages/full/combined-rules-master.yar and zips
#    it into Contents/Resources/default-yara-pack.zip. No network call at build
#    time, and none at runtime — the app may never fetch rules from a web
#    store, per Apple guidelines 2.4.5/2.5.2. That "full distillation" is why
#    this script's local output is the source of truth for the bundle, and why
#    the MAS audit enforces runtimeDownloadAllowed:false.
#    => The bundled pack's freshness depends ONLY on this script's daily local
#       run, never on the public repo.
#
# 2. THE PUBLIC Custom-Yara-Rules REPO (external/3rd-party consumers) —
#    published by scripts/run-yara-update-local.sh via
#    ~/Library/LaunchAgents/com.velociraptor.yara-update.plist.
#    This header previously claimed "GitHub Actions publishes the package ...
#    every day", which has been FALSE since Actions went billing-dead
#    (2026-03-05, every run startup_failure at 0s). Verified 2026-08-02: the
#    public repo's last commit AND last release are both 2026-06-24 — 39 days
#    stale — because that launch agent is not loaded:
#      launchctl list | grep -i yara        # empty output == not publishing
#      launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.velociraptor.yara-update.plist
#    (bounded bootout/bootstrap only — never an unbounded `launchctl kickstart`.)
#    Impact is on downstream/3rd-party users of that repo, NOT on the Store build.
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


# Prevent overlapping launchd/manual runs from mixing partially refreshed trees.
LOCK_DIR="$REPO_ROOT/.git/yara-update.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "[$TIMESTAMP] Another YARA update is already running; refusing to overlap." >> "$LOG_FILE"
    exit 2
fi
release_lock() { rmdir "$LOCK_DIR" 2>/dev/null || true; }
trap release_lock EXIT

download() {
    local url="$1"
    local destination="$2"
    curl --fail --show-error --location --retry 3 --retry-delay 2 \
        --connect-timeout 20 --max-time 600 --output "$destination" "$url"
}

download_optional() {
    local url="$1"
    local destination="$2"
    rm -f "$destination"
    if ! download "$url" "$destination"; then
        echo "[$TIMESTAMP] Optional source unavailable; quarantined without stale fallback: $url" >> "$LOG_FILE"
        return 0
    fi
}

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
        local keep
        keep=$(echo "$files" | sort | head -1)
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

download "$FULL_URL" yara-forge-rules-full.zip 2>> "$LOG_FILE"
echo "[$TIMESTAMP] Downloaded full rules ($(ls -lh yara-forge-rules-full.zip | awk '{print $5}'))" >> "$LOG_FILE"

download "$CORE_URL" yara-forge-rules-core.zip 2>> "$LOG_FILE"
echo "[$TIMESTAMP] Downloaded core rules ($(ls -lh yara-forge-rules-core.zip | awk '{print $5}'))" >> "$LOG_FILE"

download "$EXTENDED_URL" yara-forge-rules-extended.zip 2>> "$LOG_FILE"
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

download_optional "$MACOS_RULES_URL" sources/macos-specific/macos_malware.yar 2>> "$LOG_FILE"
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
download_optional "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip" \
    sources/yaraify-abusech/yaraify-rules.zip 2>> "$LOG_FILE"

# Extract the rules
if [ -f "sources/yaraify-abusech/yaraify-rules.zip" ]; then
    cd sources/yaraify-abusech
    unzip -tqq yaraify-rules.zip
    unzip -o -q yaraify-rules.zip
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
#
# DELIBERATELY still *.yar only, though Citizen Lab ships .yara exclusively, so
# this block emits NOTHING today (kanban t_f7c0794b). Widening the glob is a
# one-word change and is NOT made here on purpose: citizenlab carries an
# unresolved prose licence ("upstream per-file; preserve notices") with no legal
# review on record (kanban t_4a5c367f), and it is pinned in
# scripts/validate-yara-package.sh UNRESOLVED_BASELINE. Widening the glob would
# begin REDISTRIBUTING that content, turning an accounting bug into a licensing
# one. The provenance lie it caused is fixed at the counter instead.
#
# TO ENABLE, once the licence is answered: change the two globs below to
#   sources/citizenlab/*.yar sources/citizenlab/*.yara
# and the counter above follows automatically.
if [ -d "sources/citizenlab" ] && ls sources/citizenlab/*.yar 1>/dev/null 2>&1; then
    echo "// ========== Citizen Lab Rules ==========" >> "$MASTER_FILE"
    for file in sources/citizenlab/*.yar; do
        cat "$file" >> "$MASTER_FILE" 2>/dev/null || true
        echo "" >> "$MASTER_FILE"
    done
fi

# Keep non-compatible feeds in sources/ and the offline package for review,
# but quarantine them from the production master until a yarac compatibility
# pass proves the complete source can compile without optional modules.
echo "// Quarantined sources: macOS-specific, Awesome-YARA, YARAify/abuse.ch" >> "$MASTER_FILE"
echo "// See yara-rules/source-manifest.json for provenance and reasons." >> "$MASTER_FILE"
echo "" >> "$MASTER_FILE"

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
download "$GLASSWORM_URL" sources/glassworm/glassworm-rules.yar 2>> "$LOG_FILE"
GLASSWORM_IOCS_URL="https://raw.githubusercontent.com/Ununp3ntium115/GlasswormYARA/main/IOCs-GlassWorm.csv"
download "$GLASSWORM_IOCS_URL" sources/glassworm/IOCs-GlassWorm.csv 2>> "$LOG_FILE"
GLASSWORM_HASHES_URL="https://raw.githubusercontent.com/Ununp3ntium115/GlasswormYARA/main/Glassworm-Files.csv"
download "$GLASSWORM_HASHES_URL" sources/glassworm/Glassworm-Files.csv 2>> "$LOG_FILE"
if [ -f "sources/glassworm/glassworm-rules.yar" ]; then
    GLASSWORM_RULE_COUNT=$(grep -c "^rule " sources/glassworm/glassworm-rules.yar 2>/dev/null || echo "0")
    echo "[$TIMESTAMP] GlasswormYARA: $GLASSWORM_RULE_COUNT rules downloaded" >> "$LOG_FILE"
    echo "// ========== GlasswormYARA Custom Rules ==========" >> "$MASTER_FILE"
    cat sources/glassworm/glassworm-rules.yar >> "$MASTER_FILE" 2>/dev/null || true
    echo "" >> "$MASTER_FILE"
fi

# ========================================
# 7b. De-duplicate rule names across sources
# ========================================
# Multiple upstream sources overlap heavily (YARA Forge already bundles
# signature-base + VOLEXITY, and this script also pulls signature-base /
# Yara-Rules directly), so the SAME rule ships under the SAME name many times.
# libyara ABORTS the entire compile on any "duplicated identifier", so a pack
# with duplicate rule names fails to compile and NOTHING can scan (~14k dups
# observed → 18k compile errors). Name-dedup (keep first occurrence) here so the
# published master pack always compiles.
if [ -f "$SCRIPT_DIR/dedup-yara-rules.py" ]; then
    _dedup_tmp="$(/usr/bin/mktemp)"
    if python3 "$SCRIPT_DIR/dedup-yara-rules.py" "$MASTER_FILE" "$_dedup_tmp" >> "$LOG_FILE" 2>&1; then
        mv -f "$_dedup_tmp" "$MASTER_FILE"
        echo "[$TIMESTAMP] Rule-name dedup applied to $MASTER_FILE" >> "$LOG_FILE"
    else
        rm -f "$_dedup_tmp"
        # Was a soft warning. Now fatal: 7c below resolves a "duplicated identifier"
        # by DROPPING rule blocks, so letting ~14k duplicates through would have it
        # delete them wholesale and still report success.
        echo "[$TIMESTAMP] ERROR: rule-name dedup failed; refusing to publish (7c would drop duplicates as compile errors)" >> "$LOG_FILE"
        exit 1
    fi
fi

# ========================================
# 7c. Drop rules the SHIPPED engine cannot compile
# ========================================
# The app links a static libyara built `--without-crypto --disable-dotnet`, so
# `pe.number_of_signatures`, `pe.signatures[]`, `pe.is_signed` and the whole
# `dotnet` module do not exist for it. Upstream packs use them freely. libyara
# aborts the ENTIRE compile on any error, so 1,626 unusable rules cost all
# 12,401 and the scanner loaded ZERO rules -- every scan reported "no matches".
#
# Validation alone could not catch this: it gated with PATH `yarac` (Homebrew,
# with OpenSSL + dotnet), an engine strictly MORE capable than the one we ship.
# Filter against the real engine here so the published pack always loads.
# Every failure below is FATAL. A missing script, an unbuildable gate, or a
# failed filter must never degrade to "publish unfiltered" -- that silent-skip
# is the exact failure class this whole change exists to remove.
if [ ! -f "$SCRIPT_DIR/filter-yara-rules-vendored.py" ]; then
    echo "[$TIMESTAMP] ERROR: filter-yara-rules-vendored.py is missing; refusing to publish" >> "$LOG_FILE"
    exit 1
fi

_gate_bin="$(bash "$SCRIPT_DIR/build/build-yara-gate.sh" 2>>"$LOG_FILE")" || _gate_bin=""
if [ -z "$_gate_bin" ]; then
    echo "[$TIMESTAMP] ERROR: vendored-engine gate unavailable; refusing to publish an unverified pack" >> "$LOG_FILE"
    exit 1
fi

# TWO ARTIFACTS, not one. The filter used to overwrite $MASTER_FILE in place, but that
# file is what the PUBLIC publish lane ships (Ununp3ntium115/Custom-Yara-Rules). Third
# parties consuming it run their own, usually FULL-FEATURED, yara — for them the 1,608
# authenticode and 18 dotnet rules work fine, and imposing our engine's restriction on
# them silently deleted 1,626 working detections (t_df722d31). So:
#   combined-rules-master.yar         -> FULL pack, published, unchanged for consumers
#   combined-rules-vendored-compat.yar -> filtered pack the APP bundles, because the
#                                         shipped static libyara cannot compile the rest
COMPAT_FILE="$(dirname "$MASTER_FILE")/combined-rules-vendored-compat.yar"
if ! _filt_summary=$(python3 "$SCRIPT_DIR/filter-yara-rules-vendored.py" \
        "$MASTER_FILE" "$COMPAT_FILE" "$_gate_bin" 2>>"$LOG_FILE"); then
    rm -f "$COMPAT_FILE"
    echo "[$TIMESTAMP] ERROR: vendored-engine filter failed; refusing to publish" >> "$LOG_FILE"
    exit 1
fi
VENDORED_FILTER_SUMMARY="$_filt_summary"
echo "[$TIMESTAMP] Vendored-engine compat pack written to $COMPAT_FILE: $_filt_summary" >> "$LOG_FILE"

# ========================================
# 8. Count rules and create version info
# ========================================
count_rules_in_dir() {
    local dir="$1"
    local count=0 file file_count
    [[ -d "$dir" ]] || { printf '0'; return; }
    while IFS= read -r -d '' file; do
        file_count=$(grep -c "^rule " "$file" 2>/dev/null || true)
        [[ "$file_count" =~ ^[0-9]+$ ]] || file_count=0
        count=$((count + file_count))
    done < <(find "$dir" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 2>/dev/null)
    printf '%s' "$count"
}

# Count rules under $1 matching ONLY the glob $2 — used where a count must mirror
# the assembler's predicate rather than everything present on disk.
count_rules_matching() {
    local dir="$1" pattern="$2" count=0 file file_count
    [[ -d "$dir" ]] || { printf '0'; return; }
    while IFS= read -r -d '' file; do
        file_count=$(grep -c "^rule " "$file" 2>/dev/null || true)
        [[ "$file_count" =~ ^[0-9]+$ ]] || file_count=0
        count=$((count + file_count))
    done < <(find "$dir" -type f -name "$pattern" -print0 2>/dev/null)
    printf '%s' "$count"
}

FORGE_COUNT=$(count_rules_in_dir packages/full)
# PROVENANCE HONESTY (2026-09-03, kanban t_f7c0794b).
#
# count_rules_in_dir globs BOTH *.yar and *.yara. The ASSEMBLER above globs only
# *.yar, and Citizen Lab ships .yara exclusively — so the assembler emits nothing
# while this counter reported 4. That number is not cosmetic: it flows into
# version.json ("rule_count"), both READMEs, the offline-package manifest, the
# daily log line and the commit message. Every one of them claimed rules that are
# not in the pack. Verified: grep -c for OLEAuthor/OLETitle/OLELastSavedBy in
# combined-rules-master.yar returns 0.
#
# The count must describe what SHIPS, so it now uses the assembler's own
# predicate. When the glob below is widened (see the comment at the Citizen Lab
# assembly block) this count follows automatically — the two can no longer drift.
CITIZENLAB_COUNT=$(count_rules_matching sources/citizenlab "*.yar")
CITIZENLAB_ON_DISK=$(count_rules_in_dir sources/citizenlab)
if [ "$CITIZENLAB_COUNT" != "$CITIZENLAB_ON_DISK" ]; then
  echo "[$TIMESTAMP] WARNING: citizenlab has ${CITIZENLAB_ON_DISK} rules on disk but ${CITIZENLAB_COUNT} reach the pack (extension-glob mismatch, kanban t_f7c0794b)" >> "$LOG_FILE"
  echo "WARNING: citizenlab contributes ${CITIZENLAB_COUNT} of ${CITIZENLAB_ON_DISK} rules on disk (see kanban t_f7c0794b)" >&2
fi
MACOS_COUNT=$(count_rules_in_dir sources/macos-specific)
AWESOME_COUNT=$(count_rules_in_dir sources/awesome-yara)
YARAIFY_COUNT=$(count_rules_in_dir sources/yaraify-abusech)
DETECTRAPTOR_COUNT=$(count_rules_in_dir sources/detectraptor)
GLASSWORM_COUNT=$(count_rules_in_dir sources/glassworm)
VQL_ARTIFACT_COUNT=$(find "$YARA_DIR/vql-artifacts" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | wc -l | tr -d ' ')
# NOT `grep -c "^rule "` -- that misses private and indented declarations and
# under-reported this pack by 24, disagreeing with what validate and the engine report.
TOTAL_COUNT=$(grep -cE '^[[:space:]]*(global[[:space:]]+)?(private[[:space:]]+)?rule[[:space:]]' "$MASTER_FILE" 2>/dev/null || true)
[[ "$TOTAL_COUNT" =~ ^[0-9]+$ ]] || TOTAL_COUNT=0

echo "[$TIMESTAMP] Rule counts - Forge: $FORGE_COUNT, Citizen Lab: $CITIZENLAB_COUNT, macOS: $MACOS_COUNT, Awesome: $AWESOME_COUNT, YARAify: $YARAIFY_COUNT, DetectRaptor: $DETECTRAPTOR_COUNT, Glassworm: $GLASSWORM_COUNT, Total: $TOTAL_COUNT" >> "$LOG_FILE"
echo "[$TIMESTAMP] VQL Artifacts: $VQL_ARTIFACT_COUNT" >> "$LOG_FILE"

cat > "$YARA_DIR/version.json" << EOF
{
  "updated": "$TIMESTAMP",
  "total_rules": "$TOTAL_COUNT",
  "vql_artifacts": "$VQL_ARTIFACT_COUNT",
  "vendored_engine_filter": ${VENDORED_FILTER_SUMMARY:-null},
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
# BOTH packs ship. The app downloads this zip and installs from it at RUNTIME
# (YARARulesUpdaterService), so shipping only the full master would reinstall a
# pack the app's --without-crypto libyara cannot compile and bring back the
# zero-rules failure through the update path. External consumers still get the
# full master; the app prefers the compat member when present.
cp "$COMPAT_FILE" "$OFFLINE_DIR/yara-rules/" 2>/dev/null || true
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
cp "$YARA_DIR/source-manifest.json" "$OFFLINE_DIR/" 2>/dev/null || true

# Create README for the offline package
cat > "$OFFLINE_DIR/README.md" << OFFLINEREADME
# Velociraptor Claw Edition - Offline YARA Rules Package

**Generated:** $TIMESTAMP
**Total YARA Rules:** $TOTAL_COUNT
**VQL Artifacts:** $VQL_ARTIFACT_COUNT

## Contents

- \`yara-rules/\` - All YARA rules from 7 sources
  - \`combined-rules-master.yar\` - Single consolidated file. **This is the only
    file verified to compile against the engine Claw Edition ships** (a static
    libyara built \`--without-crypto --disable-dotnet\`).
  - Source directories with individual rule files. **NOT filtered.** They retain
    rules using \`pe.number_of_signatures\`/\`pe.signatures\`/\`pe.is_signed\` and the
    \`dotnet\` module, which that engine does not provide. libyara aborts the whole
    compile on any error, so loading these directories recursively with Claw
    Edition's engine will load ZERO rules. Use them with a full-featured
    \`yara\`/\`yarac\` build, or use the master file.
- \`vql-artifacts/\` - Velociraptor VQL detection artifacts
- \`detection-data/\` - CSV detection data files
- \`version.json\` - Version and source information
- \`source-manifest.json\` - Source licenses, provenance, and production/quarantine status

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

# Do not commit or publish a package that fails manifest, ZIP, or yarac checks.
bash "$SCRIPT_DIR/validate-yara-package.sh" >> "$LOG_FILE" 2>&1

# Clean up old backups older than 7 days
find "$YARA_DIR" -name "packages.backup.*" -mtime +7 -exec rm -rf {} \; 2>/dev/null || true

echo "[$TIMESTAMP] YARA rules update complete!" >> "$LOG_FILE"

# ========================================
# 10. Commit changes to git
#
# The $CI branch below is retained for a CI runner that publishes via release.
# NOTE: no such runner is currently alive — GitHub Actions is billing-dead on
# this repo — so in practice this branch is unreachable and the local path
# below is what runs. Do not read "skipping — workflow handles publish" as
# evidence that anything published.
# ========================================
if [ -n "$CI" ]; then
    echo "[$TIMESTAMP] Running in CI — skipping git commit (workflow would handle publish; note Actions is billing-dead as of 2026-08-02)" >> "$LOG_FILE"
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

        echo "[$TIMESTAMP] Git commit created." >> "$LOG_FILE"

        # ----------------------------------------------------------------
        # Push the commit.
        #
        # This block used to say "Push manually or let GitHub Actions handle
        # it." Actions on this repo has been billing-dead since 2026-03-05 —
        # every run returns startup_failure at 0s — so the delegated push
        # never happened and daily commits accumulated LOCAL-ONLY. Observed
        # 2026-08-02: four unpushed commits (YARA daily, VQL indentation, B7
        # pointer, ops board) had to be pushed by hand.
        #
        # Safety rules, because a cron that pushes is a mutation:
        #   * fast-forward ONLY — never force, never push over divergence
        #   * only from the expected branch
        #   * resolve the real remote (claw is primary, origin is legacy)
        #   * a push failure (offline, credential prompt under launchd) logs
        #     loudly but never fails the update run — the commit is already
        #     safe locally
        # Opt out with YARA_UPDATE_AUTO_PUSH=0.
        # ----------------------------------------------------------------
        if [ "${YARA_UPDATE_AUTO_PUSH:-1}" != "1" ]; then
            echo "[$TIMESTAMP] Auto-push disabled (YARA_UPDATE_AUTO_PUSH=${YARA_UPDATE_AUTO_PUSH}); commit left local." >> "$LOG_FILE"
        else
            PUSH_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
            EXPECTED_BRANCH="${YARA_UPDATE_PUSH_BRANCH:-main}"

            # Prefer the primary remote; fall back rather than guessing.
            PUSH_REMOTE=""
            for candidate in claw origin; do
                if git remote get-url "$candidate" >/dev/null 2>&1; then
                    PUSH_REMOTE="$candidate"
                    break
                fi
            done

            if [ "$PUSH_BRANCH" != "$EXPECTED_BRANCH" ]; then
                echo "[$TIMESTAMP] Push skipped — on branch '$PUSH_BRANCH', expected '$EXPECTED_BRANCH'. Commit left local." >> "$LOG_FILE"
            elif [ -z "$PUSH_REMOTE" ]; then
                echo "[$TIMESTAMP] Push skipped — no 'claw' or 'origin' remote configured. Commit left local." >> "$LOG_FILE"
            else
                git fetch "$PUSH_REMOTE" "$EXPECTED_BRANCH" >> "$LOG_FILE" 2>&1 || true
                REMOTE_REF="$PUSH_REMOTE/$EXPECTED_BRANCH"

                if ! git rev-parse --verify "$REMOTE_REF" >/dev/null 2>&1; then
                    echo "[$TIMESTAMP] Push skipped — $REMOTE_REF not resolvable after fetch. Commit left local." >> "$LOG_FILE"
                elif ! git merge-base --is-ancestor "$REMOTE_REF" HEAD 2>/dev/null; then
                    # Remote has commits we do not: pushing would either be
                    # rejected or (with force) destroy them. Never force here.
                    echo "[$TIMESTAMP] Push skipped — $REMOTE_REF has diverged from HEAD (not a fast-forward). Reconcile manually; commit left local." >> "$LOG_FILE"
                else
                    AHEAD_COUNT="$(git rev-list --count "$REMOTE_REF..HEAD" 2>/dev/null || echo "?")"
                    echo "[$TIMESTAMP] Pushing $AHEAD_COUNT commit(s) to $REMOTE_REF (fast-forward)..." >> "$LOG_FILE"
                    if git push "$PUSH_REMOTE" "$EXPECTED_BRANCH" >> "$LOG_FILE" 2>&1; then
                        echo "[$TIMESTAMP] Push OK — $REMOTE_REF now at $(git rev-parse --short HEAD)" >> "$LOG_FILE"
                    else
                        echo "[$TIMESTAMP] WARNING: push FAILED (offline, or credentials unavailable to this cron context). Commit is safe locally; push manually with: git push $PUSH_REMOTE $EXPECTED_BRANCH" >> "$LOG_FILE"
                    fi
                fi
            fi
        fi
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
