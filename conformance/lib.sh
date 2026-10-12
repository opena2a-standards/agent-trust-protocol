# Helpers shared by level1.sh and level2.sh; sourced, not run.

CONFORMANCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMAS_DIR="$CONFORMANCE_DIR/../schemas"

for tool in curl jq; do
  command -v "$tool" > /dev/null || { echo "error: $tool is required" >&2; exit 1; }
done
for schema in discovery-v1 trust-proof-v1 revocation-list-v1; do
  [ -r "$SCHEMAS_DIR/$schema.schema.json" ] || {
    echo "error: $SCHEMAS_DIR/$schema.schema.json not found; run the script from a checkout of the repository" >&2
    exit 1
  }
done
DISCOVERY_SCHEMA=$(cat "$SCHEMAS_DIR/discovery-v1.schema.json")
PROOF_SCHEMA=$(cat "$SCHEMAS_DIR/trust-proof-v1.schema.json")
REVOCATION_SCHEMA=$(cat "$SCHEMAS_DIR/revocation-list-v1.schema.json")

PASS=0
FAIL=0
DETAIL=""

test_case() {
  local name="$1" result="$2"
  if [ "$result" = "0" ]; then
    echo "PASS: $name"; PASS=$((PASS + 1))
  else
    echo "FAIL: $name${DETAIL:+ ($DETAIL)}"; FAIL=$((FAIL + 1))
  fi
  DETAIL=""
}

# unmet REASON: fail with REASON as the next test_case's detail.
unmet() {
  DETAIL="$1"
  return 1
}

# check BODY FILTER [jq options]: pass when BODY is one JSON value and every
# condition in the object FILTER maps it to is true; otherwise DETAIL says what
# is not met. FILTER may use the definitions in checks.jq and the schemas as
# $discovery_schema, $proof_schema and $revocation_schema.
check() {
  local body="$1" filter="$2" outcome
  shift 2
  outcome=$(printf '%s' "$body" | jq -rs -L "$CONFORMANCE_DIR" \
    --argjson discovery_schema "$DISCOVERY_SCHEMA" \
    --argjson proof_schema "$PROOF_SCHEMA" \
    --argjson revocation_schema "$REVOCATION_SCHEMA" \
    "$@" "include \"checks\"; report($filter)" 2> /dev/null) || outcome="body is not JSON"
  DETAIL="$outcome"
  [ -z "$outcome" ]
}

# field BODY FILTER: print the string FILTER selects from a one-value JSON BODY,
# or nothing.
field() {
  printf '%s' "$1" | jq -rs "if length == 1 then .[0] | try ($2 | strings) else empty end" 2> /dev/null
}
