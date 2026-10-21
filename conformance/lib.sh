# Helpers shared by level1.sh and level2.sh; sourced, not run.

CONFORMANCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMAS_DIR="$CONFORMANCE_DIR/../schemas"

# A missing tool or schema exits SETUP_ERROR, outside the range of failed-test
# counts the scripts exit with (69 is EX_UNAVAILABLE in sysexits.h), and a run
# without an authority URL exits USAGE_ERROR, also outside it (64 is EX_USAGE).
SETUP_ERROR=69
USAGE_ERROR=64
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

# require_authority_url URL: exit USAGE_ERROR with the usage line when URL, the
# one argument of the script, is missing or empty. bash's own ${1:?} would exit
# 1, which reads as one failed test.
require_authority_url() {
  [ -n "$1" ] || { echo "Usage: $0 <authority-url>" >&2; exit "$USAGE_ERROR"; }
}

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

# Section 7.1 transport rule: a request goes only under an https URL, or under
# an http URL whose host is a loopback address literal, an IPv4 address in
# 127.0.0.0/8 written as four decimal numbers or [::1]. The name localhost is
# not one: a name is resolved, and can resolve to another machine.
OCTET='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
HTTPS_URL='^[Hh][Tt][Tt][Pp][Ss]://'
LOOPBACK_HTTP_URL='^[Hh][Tt][Tt][Pp]://(127\.'"$OCTET"'\.'"$OCTET"'\.'"$OCTET"'|\[::1\])(:[0-9]*)?([/?#]|$)'

# transport_allowed URL: succeed when the Section 7.1 transport rule allows a
# request under URL.
transport_allowed() {
  [[ "$1" =~ $HTTPS_URL || "$1" =~ $LOOPBACK_HTTP_URL ]]
}

# fetch NAME URL [curl options]: set NAME to the body curl receives for URL, or
# to nothing when the request fails. Fail with a reason as the next test_case's
# detail, without a request, when the transport rule refuses URL, and with one
# when curl rejects the URL or gets no answer within the time limit; otherwise
# succeed, and the check of NAME says what the body lacks.
#
# Every request turns URL globbing off (-g): a URL holds the authority URL and
# values the authority serves, and curl would otherwise read {a,b} and [x-y] in
# it as patterns and send one request per expansion. --path-as-is sends . and ..
# segments as written instead of removing them, and --url keeps a URL that
# starts with - from being read as an option. -q, which has to come first, keeps
# curl from reading a .curlrc, which could turn off the certificate check or
# turn on following redirects. An http URL, which names a loopback address, is
# requested with no proxy, so the request goes to that address and not to a
# proxy that would request it from its own machine.
fetch() {
  local name="$1" url="$2" body status direct=()
  shift 2
  if ! transport_allowed "$url"; then
    printf -v "$name" '%s' ""
    unmet "the authority URL is neither https nor http to a loopback address literal (Section 7.1)"
    return
  fi
  [[ "$url" =~ $HTTPS_URL ]] || direct=(--noproxy '*')
  body=$(curl -q -gsf --path-as-is --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
    "${direct[@]}" "$@" --url "$url")
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
