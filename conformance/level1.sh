#!/usr/bin/env bash
# ATP Level 1 Conformance Test
# Usage: ./level1.sh https://api.oa2a.org

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
require_authority_url "${1:-}"
BASE_URL="$1"

DID_DOC=""
PROOF=""
VERIFY=""

# Test 1: Discovery endpoint exists
echo "=== Level 1: Basic Trust ==="

# T1.1: /.well-known/atp returns valid JSON. Every request goes through fetch
# (lib.sh), which passes the curl options each one needs.
fetch DISCOVERY "$BASE_URL/.well-known/atp" &&
  check "$DISCOVERY" '{"body is a JSON object": (type == "object")}'
test_case "Discovery endpoint returns JSON" "$?"

# T1.2: Discovery has required fields, each checked on its own against the schema
check "$DISCOVERY" 'members_ok($discovery_schema; ["authorityDid", "version", "endpoints"])'
test_case "Discovery has authorityDid, version, endpoints" "$?"

# T1.3: Discovery has conformance level (an integer, 1-3)
check "$DISCOVERY" 'members_ok($discovery_schema; ["conformanceLevel"])'
test_case "Conformance level is 1-3" "$?"

# T1.4: DID resolution works for the registry's own DID. The DID goes into the
# path, and into the T1.7 query, percent-encoded, so a "/", "#", "?" or space in
# it cannot change the request.
AUTHORITY_DID=$(field "$DISCOVERY" '.authorityDid')
DID_IN_URL=$(in_url "$AUTHORITY_DID")
if [ -n "$AUTHORITY_DID" ]; then
  fetch DID_DOC "$BASE_URL/api/v1/did/$DID_IN_URL" &&
    check "$DID_DOC" '{"body is a JSON object": (type == "object")}'
else
  unmet "discovery has no authorityDid"
fi
test_case "DID resolution returns document" "$?"

# T1.5: DID Document has @context (a non-empty string or a non-empty array)
check "$DID_DOC" '{"@context is a non-empty string or array":
  (type == "object" and (.["@context"] | (type == "string" or type == "array") and length > 0))}'
test_case "DID Document has @context" "$?"

# T1.6: DID Document has verificationMethod
check "$DID_DOC" '{"verificationMethod is a non-empty array": (type == "object" and (.verificationMethod | type == "array" and length > 0))}'
test_case "DID Document has verificationMethod" "$?"

# T1.7: Trust proof endpoint returns a proof for the authority DID. A declared
# endpoints.trustProof is appended to the authority URL, so it must be a path:
# a value such as "@other.example/..." would send the request to another host.
# A "#" would end the path and drop the did parameter, and curl rejects a URL
# that holds whitespace or a control character. The did parameter is appended
# here, after "&" when the endpoint has a query: curl -G would add it, but it
# also removes dot segments, whatever --path-as-is says.
PROOF_ENDPOINT=$(field "$DISCOVERY" '.endpoints.trustProof')
PROOF_URL="$BASE_URL${PROOF_ENDPOINT:-/api/v1/trust/proof}"
case "$PROOF_URL" in *\?*) PROOF_URL+="&" ;; *) PROOF_URL+="?" ;; esac
BREAKS_URL='[#[:space:][:cntrl:]]'
if [ -z "$AUTHORITY_DID" ]; then
  unmet "discovery has no authorityDid"
elif [ -n "$PROOF_ENDPOINT" ] && [ "${PROOF_ENDPOINT:0:1}" != "/" ]; then
  unmet "endpoints.trustProof does not start with /"
elif [[ "$PROOF_ENDPOINT" =~ $BREAKS_URL ]]; then
  unmet "endpoints.trustProof holds #, whitespace or a control character"
else
  fetch PROOF "${PROOF_URL}did=$DID_IN_URL" &&
    check "$PROOF" '{"body is a JSON object": (type == "object"), "did is the authority DID": (type == "object" and .did == $did)}' \
      --arg did "$AUTHORITY_DID"
fi
test_case "Trust proof endpoint returns proof" "$?"

# T1.8: Trust proof has required fields, each checked on its own against the schema
check "$PROOF" 'members_ok($proof_schema; ["did", "trustLevel", "trustScore", "verdict", "issuedAt", "expiresAt", "issuerDid"])'
test_case "Trust proof has all required fields" "$?"

# T1.9: Trust proof has the Ed25519 authority signature Section 4.4 step 4
# requires; neither an ML-DSA-65 signature nor a Sigstore co-signature stands in
# for it.
check "$PROOF" 'members_ok($proof_schema; ["signatures"])'
test_case "Trust proof has an Ed25519 authority signature" "$?"

# T1.10: Trust proof not expired, compared as a time
check "$PROOF" '{"expiresAt is an RFC 3339 time after now": (type == "object" and (.expiresAt | rfc3339 | . != null and . > now))}'
test_case "Trust proof not expired" "$?"

# T1.11: Trust level is valid (an integer, 0-4). Like JSON Schema's integer
# type, it accepts a zero fraction: 4.0 is the integer 4.
check "$PROOF" 'members_ok($proof_schema; ["trustLevel"])'
test_case "Trust level is 0-4" "$?"

# T1.12: Trust score is valid (a number, 0.0-1.0)
check "$PROOF" 'members_ok($proof_schema; ["trustScore"])'
test_case "Trust score is 0.0-1.0" "$?"

# T1.13: Verify endpoint works
if check "$PROOF" '{"a trust proof to send": (type == "object")}'; then
  fetch VERIFY "$BASE_URL/api/v1/trust/verify" -X POST \
    -H "Content-Type: application/json" \
    -d "$PROOF" &&
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
