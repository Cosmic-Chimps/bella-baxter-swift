#!/usr/bin/env bash
# test-samples.sh — run all Swift SDK samples and verify outputs
# Usage: ./test-samples.sh <api-key>
set -euo pipefail

API_KEY="${1:-}"
if [[ -z "$API_KEY" ]]; then
    echo "Usage: $0 <api-key>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="$SCRIPT_DIR/samples"
DEMO_ENV="$SCRIPT_DIR/../../../demo.env"

SAMPLE_01="$SAMPLES_DIR/01-dotenv-file"
SAMPLE_02="$SAMPLES_DIR/02-process-inject"
SAMPLE_03="$SAMPLES_DIR/03-swift-cli"
SAMPLE_04="$SAMPLES_DIR/04-ios-app"   # skipped — SwiftUI, cannot run as CLI
SAMPLE_05="$SAMPLES_DIR/05-typed-secrets"

BELLA_URL="http://localhost:5522"

# ── Expected values (read from demo.env) ─────────────────────────────────────
PORT_EXPECTED="$(grep '^PORT=' "$DEMO_ENV" | cut -d= -f2-)"
DATABASE_URL_EXPECTED="$(grep '^DATABASE_URL=' "$DEMO_ENV" | cut -d= -f2-)"
EXTERNAL_API_KEY_EXPECTED="$(grep '^EXTERNAL_API_KEY=' "$DEMO_ENV" | cut -d= -f2-)"
GLEAP_API_KEY_EXPECTED="$(grep '^GLEAP_API_KEY=' "$DEMO_ENV" | cut -d= -f2-)"
ENABLE_FEATURES_EXPECTED="$(grep '^ENABLE_FEATURES=' "$DEMO_ENV" | cut -d= -f2-)"
APP_ID_EXPECTED="$(grep '^APP_ID=' "$DEMO_ENV" | cut -d= -f2-)"
CONNSTRING_EXPECTED="$(grep '^ConnectionStrings__Postgres=' "$DEMO_ENV" | cut -d= -f2-)"
APP_CONFIG_EXPECTED="$(grep '^APP_CONFIG=' "$DEMO_ENV" | cut -d= -f2- | sed 's/^"//;s/"$//' | sed 's/\\"/"/g')"

# ── Result tracking ───────────────────────────────────────────────────────────
PASS=0
FAIL=0
RESULTS=()

pass() {
    local name="$1"
    echo "  ✅ $name"
    PASS=$((PASS + 1))
    RESULTS+=("PASS: $name")
}

fail() {
    local name="$1"
    echo "  ❌ $name"
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL: $name")
}

check_val() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        pass "$label"
    else
        fail "$label -- expected '$expected' got '$actual'"
    fi
}

# Check all 8 secrets in the output text of a CLI sample.
# Values are extracted via: sed 's/^[^:]*:[[:space:]]*//' on each matching line.
check_all_secrets() {
    local prefix="$1" output="$2"
    local _extract
    _extract() { echo "$output" | grep "^$1" | sed 's/^[^:]*:[[:space:]]*//' | head -1; }
    check_val "$prefix PORT"                        "$PORT_EXPECTED"             "$(_extract PORT)"
    check_val "$prefix DATABASE_URL"                "$DATABASE_URL_EXPECTED"     "$(_extract DATABASE_URL)"
    check_val "$prefix EXTERNAL_API_KEY"            "$EXTERNAL_API_KEY_EXPECTED" "$(_extract EXTERNAL_API_KEY)"
    check_val "$prefix GLEAP_API_KEY"               "$GLEAP_API_KEY_EXPECTED"    "$(_extract GLEAP_API_KEY)"
    check_val "$prefix ENABLE_FEATURES"             "$ENABLE_FEATURES_EXPECTED"  "$(_extract ENABLE_FEATURES)"
    check_val "$prefix APP_ID"                      "$APP_ID_EXPECTED"           "$(_extract APP_ID)"
    check_val "$prefix ConnectionStrings__Postgres"  "$CONNSTRING_EXPECTED"       "$(_extract ConnectionStrings__Postgres)"
    check_val "$prefix APP_CONFIG"                  "$APP_CONFIG_EXPECTED"       "$(_extract APP_CONFIG)"
}

# ── Pre-build all samples (except 04) ────────────────────────────────────────
echo ""
echo "─── Build ───────────────────────────────────────────────────────────"
for sample_name in 01-dotenv-file 02-process-inject 03-swift-cli 05-typed-secrets; do
    echo -n "  Building $sample_name ... "
    if (cd "$SAMPLES_DIR/$sample_name" && swift build 2>/dev/null); then
        echo "✅"
        PASS=$((PASS + 1))
        RESULTS+=("PASS: build $sample_name")
    else
        echo "❌"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL: build $sample_name")
    fi
done

echo -n "  Building 04-ios-app (build-only, no run) ... "
if (cd "$SAMPLE_04" && swift build 2>/dev/null); then
    echo "✅"
    PASS=$((PASS + 1))
    RESULTS+=("PASS: build 04-ios-app")
else
    echo "❌ (skipped — needs iOS/macOS Xcode target)"
    # Not a hard failure — ios-app is a documentation sample
fi

# ── Authentication ────────────────────────────────────────────────────────────
echo ""
echo "─── Authentication ──────────────────────────────────────────────────"
if bella login --api-key "$API_KEY" --url "$BELLA_URL" --force 2>/dev/null; then
    pass "bella login --api-key"
else
    fail "bella login --api-key"
    echo "FATAL: could not log in — aborting"
    exit 1
fi

# ── 01-dotenv-file ────────────────────────────────────────────────────────────
echo ""
echo "─── 01-dotenv-file ──────────────────────────────────────────────────"
cd "$SAMPLE_01"
DOT_ENV_FILE="$SAMPLE_01/.env"
rm -f "$DOT_ENV_FILE"

if bella secrets get -o "$DOT_ENV_FILE" 2>/dev/null; then
    pass "bella secrets get -o .env"
else
    fail "bella secrets get -o .env"
fi

if [[ -f "$DOT_ENV_FILE" ]]; then
    # Validate .env file values
    _port="$(grep '^PORT='                        "$DOT_ENV_FILE" | cut -d= -f2-)"
    _db_url="$(grep '^DATABASE_URL='              "$DOT_ENV_FILE" | cut -d= -f2-)"
    _api_key="$(grep '^EXTERNAL_API_KEY='         "$DOT_ENV_FILE" | cut -d= -f2-)"
    _gleap="$(grep '^GLEAP_API_KEY='              "$DOT_ENV_FILE" | cut -d= -f2-)"
    _enable="$(grep '^ENABLE_FEATURES='           "$DOT_ENV_FILE" | cut -d= -f2-)"
    _app_id="$(grep '^APP_ID='                    "$DOT_ENV_FILE" | cut -d= -f2-)"
    _connstr="$(grep '^ConnectionStrings__Postgres=' "$DOT_ENV_FILE" | cut -d= -f2-)"
    _app_cfg="$(grep '^APP_CONFIG='               "$DOT_ENV_FILE" | cut -d= -f2- | sed 's/^"//;s/"$//' | sed 's/\\"/"/g')"
    check_val "01: PORT"                       "$PORT_EXPECTED"             "$_port"
    check_val "01: DATABASE_URL"               "$DATABASE_URL_EXPECTED"     "$_db_url"
    check_val "01: EXTERNAL_API_KEY"           "$EXTERNAL_API_KEY_EXPECTED" "$_api_key"
    check_val "01: GLEAP_API_KEY"              "$GLEAP_API_KEY_EXPECTED"    "$_gleap"
    check_val "01: ENABLE_FEATURES"            "$ENABLE_FEATURES_EXPECTED"  "$_enable"
    check_val "01: APP_ID"                     "$APP_ID_EXPECTED"           "$_app_id"
    check_val "01: ConnectionStrings__Postgres" "$CONNSTRING_EXPECTED"      "$_connstr"
    check_val "01: APP_CONFIG"                 "$APP_CONFIG_EXPECTED"       "$_app_cfg"
fi

# Run the Swift binary (reads from .env file)
OUTPUT_01="$(cd "$SAMPLE_01" && .build/debug/DotenvFileSample 2>/dev/null)"
if echo "$OUTPUT_01" | grep -q "PORT"; then
    pass "01: DotenvFileSample runs ok"
else
    fail "01: DotenvFileSample runs ok"
fi
rm -f "$DOT_ENV_FILE"

# ── 02-process-inject ─────────────────────────────────────────────────────────
echo ""
echo "─── 02-process-inject ───────────────────────────────────────────────"
cd "$SAMPLE_02"
OUTPUT_02="$(bella run --app swift-02-process-inject -- .build/debug/ProcessInjectSample 2>/dev/null)"

# Sample 02 masks secret values in stdout (mask(str) = first 8 chars + ***,
# maskKey(str) = first 4 chars + ***). Compare expected masked forms.
_ev() { echo "$OUTPUT_02" | grep "^$1" | sed 's/^[^:]*:[[:space:]]*//' | head -1; }
check_val "02: PORT"                        "$PORT_EXPECTED"                                     "$(_ev PORT)"
check_val "02: DATABASE_URL"                "${DATABASE_URL_EXPECTED:0:8}***"                    "$(_ev DATABASE_URL)"
check_val "02: EXTERNAL_API_KEY"            "${EXTERNAL_API_KEY_EXPECTED:0:4}***"                "$(_ev EXTERNAL_API_KEY)"
check_val "02: GLEAP_API_KEY"               "${GLEAP_API_KEY_EXPECTED:0:4}***"                   "$(_ev GLEAP_API_KEY)"
check_val "02: ENABLE_FEATURES"             "$ENABLE_FEATURES_EXPECTED"                          "$(_ev ENABLE_FEATURES)"
check_val "02: APP_ID"                      "$APP_ID_EXPECTED"                                   "$(_ev APP_ID)"
check_val "02: ConnectionStrings__Postgres"  "${CONNSTRING_EXPECTED:0:8}***"                     "$(_ev ConnectionStrings__Postgres)"
check_val "02: APP_CONFIG"                  "$APP_CONFIG_EXPECTED"                               "$(_ev APP_CONFIG)"

# ── 03-swift-cli ──────────────────────────────────────────────────────────────
echo ""
echo "─── 03-swift-cli ────────────────────────────────────────────────────"
cd "$SAMPLE_03"
OUTPUT_03="$(BELLA_BAXTER_URL="$BELLA_URL" \
    BELLA_API_KEY="$API_KEY" \
    .build/debug/PullSecretsSample 2>/dev/null)"

# Output is KEY=VALUE lines
check_val "03: PORT"                       "$PORT_EXPECTED"             "$(echo "$OUTPUT_03" | grep '^PORT='                        | cut -d= -f2-)"
check_val "03: DATABASE_URL"               "$DATABASE_URL_EXPECTED"     "$(echo "$OUTPUT_03" | grep '^DATABASE_URL='                 | cut -d= -f2-)"
check_val "03: EXTERNAL_API_KEY"           "$EXTERNAL_API_KEY_EXPECTED" "$(echo "$OUTPUT_03" | grep '^EXTERNAL_API_KEY='             | cut -d= -f2-)"
check_val "03: GLEAP_API_KEY"              "$GLEAP_API_KEY_EXPECTED"    "$(echo "$OUTPUT_03" | grep '^GLEAP_API_KEY='                | cut -d= -f2-)"
check_val "03: ENABLE_FEATURES"            "$ENABLE_FEATURES_EXPECTED"  "$(echo "$OUTPUT_03" | grep '^ENABLE_FEATURES='              | cut -d= -f2-)"
check_val "03: APP_ID"                     "$APP_ID_EXPECTED"           "$(echo "$OUTPUT_03" | grep '^APP_ID='                       | cut -d= -f2-)"
check_val "03: ConnectionStrings__Postgres" "$CONNSTRING_EXPECTED"      "$(echo "$OUTPUT_03" | grep '^ConnectionStrings__Postgres='  | cut -d= -f2-)"
check_val "03: APP_CONFIG"                 "$APP_CONFIG_EXPECTED"       "$(echo "$OUTPUT_03" | grep '^APP_CONFIG='                   | cut -d= -f2-)"

# ── 04-ios-app (skipped) ──────────────────────────────────────────────────────
echo ""
echo "─── 04-ios-app (skipped — documentation/iOS sample, cannot run as CLI) ───"

# ── 05-typed-secrets ─────────────────────────────────────────────────────────
echo ""
echo "─── 05-typed-secrets ────────────────────────────────────────────────"
cd "$SAMPLE_05"
OUTPUT_05="$(bella run --app swift-05-typed-secrets -- .build/debug/TypedSecretsSample 2>/dev/null)"

# Check raw string values (unmasked fields); strip " ← TypeName" annotations
_t() { echo "$OUTPUT_05" | grep "$1" | sed 's/^[^:]*:[[:space:]]*//' | sed 's/[[:space:]]*←.*$//' | sed 's/[[:space:]]*$//' | head -1; }
check_val "05: PORT (Int)"             "$PORT_EXPECTED"                                                          "$(_t 'Int.*PORT')"
check_val "05: ENABLE_FEATURES (Bool)" "$ENABLE_FEATURES_EXPECTED"                                               "$(_t 'Bool.*ENABLE_FEATURES')"
check_val "05: APP_ID (UUID)"          "$(echo "$APP_ID_EXPECTED" | tr '[:lower:]' '[:upper:]')"                 "$(_t 'GUID.*APP_ID')"
check_val "05: APP_CONFIG.setting1"    "value1"                                                                  "$(_t 'setting1')"
check_val "05: APP_CONFIG.setting2"    "42"                                                                      "$(_t 'setting2')"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "─── Summary ──────────────────────────────────────────────────────────"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
TOTAL=$((PASS + FAIL))
echo "PASS: $PASS  FAIL: $FAIL  TOTAL: $TOTAL"
echo ""

[[ $FAIL -eq 0 ]]
