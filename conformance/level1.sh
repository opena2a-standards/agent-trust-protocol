#!/usr/bin/env bash
# ATP Level 1 Conformance Test
# Usage: ./level1.sh https://api.oa2a.org

BASE_URL="${1:?Usage: $0 <authority-url>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

DID_DOC=""
PROOF=""
VERIFY=""

# Test 1: Discovery endpoint exists
echo "=== Level 1: Basic Trust ==="

# T1.1: /.well-known/atp returns valid JSON
DISCOVERY=$(curl -sf "$BASE_URL/.well-known/atp") || DISCOVERY=""
check "$DISCOVERY" '{"body is a JSON object": (type == "object")}'
test_case "Discovery endpoint returns JSON" "$?"

# T1.2: Discovery has required fields, each checked on its own against the schema
check "$DISCOVERY" 'members_ok($discovery_schema; ["authorityDid", "version", "endpoints"])'
test_case "Discovery has authorityDid, version, endpoints" "$?"

# T1.3: Discovery has conformance level
check "$DISCOVERY" 'members_ok($discovery_schema; ["conformanceLevel"])'
test_case "Conformance level >= 1" "$?"

# T1.4: DID resolution works for the registry's own DID
AUTHORITY_DID=$(field "$DISCOVERY" '.authorityDid')
if [ -n "$AUTHORITY_DID" ]; then
  DID_DOC=$(curl -sf "$BASE_URL/api/v1/did/$AUTHORITY_DID") || DID_DOC=""
  check "$DID_DOC" '{"body is a JSON object": (type == "object")}'
else
  unmet "discovery has no authorityDid"
fi
test_case "DID resolution returns document" "$?"

# T1.5: DID Document has @context
check "$DID_DOC" '{"@context": (type == "object" and .["@context"] != null)}'
test_case "DID Document has @context" "$?"

# T1.6: DID Document has verificationMethod
check "$DID_DOC" '{"verificationMethod is a non-empty array": (type == "object" and (.verificationMethod | type == "array" and length > 0))}'
test_case "DID Document has verificationMethod" "$?"

# T1.7: Trust proof endpoint returns a proof for the authority DID
PROOF_ENDPOINT=$(field "$DISCOVERY" '.endpoints.trustProof')
if [ -n "$AUTHORITY_DID" ]; then
  PROOF=$(curl -sf "$BASE_URL${PROOF_ENDPOINT:-/api/v1/trust/proof}?did=$AUTHORITY_DID") || PROOF=""
  check "$PROOF" '{"body is a JSON object": (type == "object"), "did is the authority DID": (type == "object" and .did == $did)}' \
    --arg did "$AUTHORITY_DID"
else
  unmet "discovery has no authorityDid"
fi
test_case "Trust proof endpoint returns proof" "$?"

# T1.8: Trust proof has required fields, each checked on its own against the schema
check "$PROOF" 'members_ok($proof_schema; ["did", "trustLevel", "trustScore", "verdict", "issuedAt", "expiresAt", "issuerDid"])'
test_case "Trust proof has all required fields" "$?"

# T1.9: Trust proof has signature
check "$PROOF" 'members_ok($proof_schema; ["signatures"])'
test_case "Trust proof has at least one signature" "$?"

# T1.10: Trust proof not expired, compared as a time
check "$PROOF" '{"expiresAt is an RFC 3339 time after now": (type == "object" and (.expiresAt | rfc3339 | . != null and . > now))}'
test_case "Trust proof not expired" "$?"

# T1.11: Trust level is valid (an integer, 0-4)
check "$PROOF" 'members_ok($proof_schema; ["trustLevel"])'
test_case "Trust level is 0-4" "$?"

# T1.12: Trust score is valid (a number, 0.0-1.0)
check "$PROOF" 'members_ok($proof_schema; ["trustScore"])'
test_case "Trust score is 0.0-1.0" "$?"

# T1.13: Verify endpoint works
if check "$PROOF" '{"a trust proof to send": (type == "object")}'; then
  VERIFY=$(curl -sf -X POST "$BASE_URL/api/v1/trust/verify" \
    -H "Content-Type: application/json" \
    -d "$PROOF") || VERIFY=""
  check "$VERIFY" '{"body is a JSON object": (type == "object")}'
else
  unmet "no trust proof to send"
fi
test_case "Verify endpoint accepts proof" "$?"

# T1.14: Verification returns valid=true
check "$VERIFY" '{"valid is true": (type == "object" and .valid == true)}'
test_case "Verification result is valid=true" "$?"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
