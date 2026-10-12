# Helpers shared by level1.sh and level2.sh; sourced, not run.

CONFORMANCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMAS_DIR="$CONFORMANCE_DIR/../schemas"

# A missing tool or schema exits SETUP_ERROR, outside the range of failed-test
# counts the scripts exit with (69 is EX_UNAVAILABLE in sysexits.h).
SETUP_ERROR=69
for tool in curl jq; do
  command -v "$tool" > /dev/null || { echo "error: $tool is required" >&2; exit "$SETUP_ERROR"; }
done
# Every request has a time limit in seconds: ATP_CONNECT_TIMEOUT to connect and
# ATP_MAX_TIME in all. curl counts a limit in whole milliseconds and reads 0 as
# no limit (--max-time) or as its own default (--connect-timeout), so a limit is
# at least 0.001: a digit other than 0 before the point or in the first three
# places after it.
for limit in ATP_CONNECT_TIMEOUT ATP_MAX_TIME; do
  [[ "${!limit:-1}" =~ ^[0-9]+([.][0-9]+)?$ && "${!limit:-1}" =~ ^0*[1-9]|[.][0-9]{0,2}[1-9] ]] || {
    echo "error: $limit must be a number of seconds, at least 0.001" >&2
    exit "$SETUP_ERROR"
  }
done
CONNECT_TIMEOUT="${ATP_CONNECT_TIMEOUT:-10}"
MAX_TIME="${ATP_MAX_TIME:-30}"
for schema in discovery-v1 trust-proof-v1 revocation-list-v1; do
  [ -r "$SCHEMAS_DIR/$schema.schema.json" ] || {
    echo "error: $SCHEMAS_DIR/$schema.schema.json not found; run the script from a checkout of the repository" >&2
    exit "$SETUP_ERROR"
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

# fetch NAME URL [curl options]: set NAME to the body curl receives for URL, or
# to nothing when the request fails. Fail with a reason as the next test_case's
# detail when curl rejects the URL or gets no answer within the time limit;
# otherwise succeed, and the check of NAME says what the body lacks.
#
# Every request turns URL globbing off (-g): a URL holds the authority URL and
# values the authority serves, and curl would otherwise read {a,b} and [x-y] in
# it as patterns and send one request per expansion. --path-as-is sends . and ..
# segments as written instead of removing them, and --url keeps a URL that
# starts with - from being read as an option.
fetch() {
  local name="$1" url="$2" body status
  shift 2
  body=$(curl -gsf --path-as-is --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" "$@" --url "$url")
  status=$?
  [ "$status" = 0 ] || body=""
  printf -v "$name" '%s' "$body"
  case "$status" in
    3) unmet "the authority URL is not a valid URL" ;;
    28) unmet "no answer within the time limit: $CONNECT_TIMEOUT s to connect, $MAX_TIME s in all" ;;
  esac
}

# in_url VALUE: print VALUE percent-encoded as jq's @uri encodes it, except for
# ":" and "@", which a path segment and a query carry as written (RFC 3986
# Section 3.3). A DID made of the characters the schemas allow, other than "/"
# and "#", is sent as written, and no value can end the path or the query.
in_url() {
  jq -rn --arg value "$1" '$value | @uri | gsub("%3A"; ":") | gsub("%40"; "@")'
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
# with its NUL characters removed (a shell variable cannot hold them), or nothing.
field() {
  printf '%s' "$1" |
    jq -rs 'if length == 1 then .[0] | try ('"$2"' | strings | split("\u0000") | join("")) else empty end' 2> /dev/null
}
