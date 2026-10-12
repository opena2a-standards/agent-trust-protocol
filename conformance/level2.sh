#!/usr/bin/env bash
# ATP Level 2 Conformance Test (extends Level 1)
# Usage: ./level2.sh https://api.oa2a.org

BASE_URL="${1:?Usage: $0 <authority-url>}"

# Run Level 1 first
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$SCRIPT_DIR/level1.sh" "$BASE_URL"
L1_RESULT=$?

# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

echo ""
echo "=== Level 2: Auditable Trust ==="

# T2.1: Transparency log endpoint exists. As in level1.sh, every request goes
# through fetch (lib.sh).
fetch LOG "$BASE_URL/api/v1/transparency/trust-proofs?limit=5" &&
  check "$LOG" '{"body is a JSON array or object": (type == "array" or type == "object")}'
test_case "Transparency log endpoint returns data" "$?"

# T2.2: Log entries (a bare array or an object's entries) have required fields
check "$LOG" '(if type == "array" then . elif type == "object" then .entries else null end) as $entries
  | ($entries | type == "array") as $listed
  | {
      "at least one entry": ($listed and ($entries | length > 0)),
      "every entry has an integer logIndex >= 0":
        ($listed and ($entries | all(.[]; type == "object" and (.logIndex | type_ok("integer") and . >= 0)))),
      "every entry has an RFC 3339 timestamp":
        ($listed and ($entries | all(.[]; type == "object" and (.timestamp | is_time)))),
      "every entry has an entryType":
        ($listed and ($entries | all(.[]; type == "object" and (.entryType | type == "string" and length > 0))))
    }'
test_case "Log entries have structure" "$?"

# T2.3: Revocations endpoint returns a Section 8.1 response that matches the schema
fetch REV "$BASE_URL/api/v1/trust/revocations?since=2026-01-01T00:00:00Z" &&
  check "$REV" 'members_ok($revocation_schema; $revocation_schema.required)
    + {"body matches schemas/revocation-list-v1.schema.json": schema_ok($revocation_schema; $revocation_schema)}'
test_case "Revocations endpoint returns data" "$?"

echo ""
echo "=== Level 2 Results: $PASS passed, $FAIL failed ==="
TOTAL_FAIL=$((L1_RESULT + FAIL))
exit $TOTAL_FAIL
