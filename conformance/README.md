# ATP Conformance Test Suite

Tests that verify a **running ATP authority** conforms to the [Agent Trust Protocol specification](../ATP-SPEC.md).

This is the live-endpoint half of ATP conformance. The other half — byte-stable, SHA-256-pinned wire-format fixtures with parity-gated Go and Python reference verifiers — lives at [`opena2a-standards/atp-conformance`](https://github.com/opena2a-standards/atp-conformance). See ATP-SPEC §2.1 for the per-level fixture traceability table. Fixtures prove wire-format interoperability; these scripts prove an operating deployment.

## Prerequisites

- `bash` 4+
- `curl`
- `jq` 1.6+
- A checkout of this repository: the scripts read `conformance/lib.sh`, `conformance/checks.jq` and the JSON Schemas in `schemas/`
- A running ATP authority (e.g., `https://api.oa2a.org`)

## Conformance Levels

The test suite mirrors the three conformance levels defined in ATP-SPEC.md Section 2:

| Level | Script | What it tests |
|-------|--------|---------------|
| 1 | `level1.sh` | Basic Trust -- discovery endpoint, DID resolution, trust proof signing/verification |
| 2 | `level2.sh` | Auditable Trust -- transparency log, revocation infrastructure (includes all Level 1 tests) |
| 3 | *(planned)* | Decentralized Trust -- federation protocol, multi-authority co-signing |

## Usage

```bash
# Test Level 1 conformance
./conformance/level1.sh https://api.oa2a.org

# Test Level 2 conformance (runs Level 1 first, then Level 2 tests)
./conformance/level2.sh https://api.oa2a.org
```

Both scripts exit with the number of failed tests as the exit code (0 = all passed). When `curl`, `jq` or a schema file is missing, `ATP_CONNECT_TIMEOUT` or `ATP_MAX_TIME` is not a number of at least 0.001, or `ATP_MAX_BODY_BYTES` is not a whole number from 1 to 999999999999999999, they exit 69 before running any test, a code no failed-test count reaches. Run without an authority URL, or with an empty one, they print the usage line and exit 64, also before any test. A failed test names what is not met:

```
FAIL: Trust proof has all required fields (not met: verdict, issuedAt)
```

Each request has a time limit: 10 seconds to connect and 30 seconds in all. Set `ATP_CONNECT_TIMEOUT` and `ATP_MAX_TIME` to other numbers of seconds to change them. A limit is at least 0.001 seconds: `curl` counts it in whole milliseconds, and 0 would remove the overall limit and put the connect limit back to `curl`'s own default, so `0`, or a value under a millisecond, is refused. A request that reaches a limit fails its test, and the failure names the limits:

```
FAIL: Discovery endpoint returns JSON (no answer within the time limit: 10 s to connect, 30 s in all)
```

Each response body has a size limit: 1048576 bytes (1 MiB). Set `ATP_MAX_BODY_BYTES` to another number of bytes to change it, for an authority whose revocation response is larger, for example. It is a whole number from 1 to 999999999999999999, read as decimal after any leading zeros; `0`, a limit that leaves room for no body but an empty one, is refused. The scripts keep at most one byte more than the limit of a body and then stop reading it, which ends the request, so a larger body, whether it is sent with a `Content-Length`, in chunks or ended by closing the connection, is not read to its end. It fails its test, and the failure names the limit:

```
FAIL: Discovery endpoint returns JSON (the body is larger than the size limit: 1048576 bytes)
```

## Test Coverage

A test that names several members checks each one on its own. "Matches the schema" means the member's value is valid against its property in the named file under `schemas/`; timestamps must be RFC 3339 (a day of its month in a year from 0000 to 9999, an hour from 00 to 23, a minute and a second from 00 to 59, a UTC offset from 00:00 to 23:59, and nothing after the timestamp, not even a newline) and are compared as times, whatever their UTC offset. `checks.jq` counts the seconds of a timestamp itself instead of through `jq`'s `mktime`, which with jq 1.8.1 on macOS refuses a year before 1900.

Every request follows the Section 7.1 transport rule. A request is sent only under an `https` authority URL, or under an `http` one whose host is a loopback address literal: an IPv4 address in `127.0.0.0/8` written as four decimal numbers, such as `127.0.0.1`, or `[::1]`, for an authority on the same machine. The name `localhost` is not one, since a name is resolved and can resolve to another machine, and neither is `127.1`. Under any other authority URL, such as `http://localhost:8080` or `127.0.0.1:8080` without a scheme, no request is sent, every test fails, and T1.1, T2.1 and T2.3 say `the authority URL is neither https nor http to a loopback address literal (Section 7.1)`. `curl` runs with `-q`, so it reads no `.curlrc`, which could turn off its certificate check or turn on following redirects. A request under an `http` authority URL is sent with no proxy, so it goes to the loopback address and not through a proxy the environment names.

`curl` runs with URL globbing off (`-g`): it does not expand `{a,b}` or `[x-y]` in the authority URL, in `authorityDid` or in `endpoints.trustProof`, so a URL that holds one stays one URL and is not requested once per expansion. An `https` authority URL with a brace list or bracket range in its host or port, such as `https://127.0.0.[1-1]:8080` or `https://127.0.0.1:{8080}`, is not a valid URL: no request is sent, every test fails, and each test that sends a request says `the authority URL is not a valid URL`. An `http` one with a pattern in its host or port fails the transport rule first, and the tests give that rule's reason. `curl` also runs with `--path-as-is`, so `.` and `..` segments in the authority URL, in `authorityDid` and in `endpoints.trustProof` are sent as written, not removed.

### Level 1: Basic Trust (14 tests)

| ID | Test |
|----|------|
| T1.1 | `/.well-known/atp` returns a JSON object. The test fails without a request when the authority URL is neither `https` nor `http` to a loopback address literal (Section 7.1) |
| T1.2 | Discovery document has `authorityDid`, `version` and `endpoints`, each matching `discovery-v1.schema.json` |
| T1.3 | `conformanceLevel` is present and matches `discovery-v1.schema.json` (an integer from 1 to 3) |
| T1.4 | DID resolution returns a JSON document for the authority's own DID, requested at `/api/v1/did/` followed by the DID percent-encoded (as jq's `@uri` encodes it, except for `:` and `@`), so a `/`, `#`, `?` or space in the DID does not change the request |
| T1.5 | DID Document has `@context`, a non-empty string or a non-empty array |
| T1.6 | DID Document has a non-empty `verificationMethod` array |
| T1.7 | Trust proof endpoint returns a JSON proof whose `did` is the authority DID. The request goes to `endpoints.trustProof` appended to the authority URL (`/api/v1/trust/proof` when it is absent, empty or not a string), with the `did` query parameter percent-encoded as in T1.4 and added after `&` when the endpoint has a query. The test fails without a request when the value is a non-empty string that does not start with `/`, or holds `#`, whitespace or a control character. The script reads the value with its NUL characters and trailing newlines removed |
| T1.8 | Trust proof has all required fields (`did`, `trustLevel`, `trustScore`, `verdict`, `issuedAt`, `expiresAt`, `issuerDid`), each matching `trust-proof-v1.schema.json` |
| T1.9 | Trust proof has an Ed25519 authority signature: `signatures` matches `trust-proof-v1.schema.json`, so every entry is a well-formed authority signature or Section 4.3.1 Sigstore co-signature, and at least one is an Ed25519 authority signature (Section 4.4 step 4). A proof whose only signatures are ML-DSA-65 signatures or Sigstore co-signatures fails |
| T1.10 | Trust proof is not expired: `expiresAt` is an RFC 3339 time later than now |
| T1.11 | Trust level is an integer from 0 to 4. As in JSON Schema, a value written with a zero fraction is an integer: `4.0` passes as the trust level 4, which the Section 4.3 canonical string writes as `4` (see `trust-proof-v1.schema.json`) |
| T1.12 | Trust score is a number from 0.0 to 1.0 |
| T1.13 | Verify endpoint accepts the trust proof and returns a JSON object |
| T1.14 | Verification result is `valid=true` |

Tests T1.4 to T1.14 fail when there is nothing to check: no `authorityDid` in the discovery document, or no proof returned.

### Level 2: Auditable Trust (3 additional tests)

| ID | Test |
|----|------|
| T2.1 | Transparency log endpoint returns a JSON array or object |
| T2.2 | The log returns at least one entry (a bare array, or an object's `entries`), and every entry has an integer `logIndex` >= 0, an RFC 3339 `timestamp` and an `entryType` |
| T2.3 | Revocations endpoint returns a Section 8.1 response: `revocations` and `nextSince` present, and the body valid against `revocation-list-v1.schema.json` |

## Self-test

```bash
python3 scripts/test_checks.py
```

Runs both scripts against `scripts/fixture_authority.py`, a local authority that serves the specification's own examples, and expects all 17 tests to pass. It then removes or corrupts one member at a time (an HTML discovery body, a proof without `verdict`, an `expiresAt` of `"never"`, a log entry that is a string, a revocation `reason` in free text, and others) and expects exactly the tests that check that member to fail, that a missing `jq` or schema file, a time limit that is not a number or is under a millisecond, or a size limit that is not a whole number from 1 to 999999999999999999, exits 69 with one error line, and that a run without an authority URL exits 64 with the usage line. It reads the requests the fixture authority received to check which path T1.7 requested for an `endpoints.trustProof` that is a number, ends in a newline, holds a NUL character (with nothing printed on stderr) or has a query; that a bracketed `endpoints.trustProof` or `authorityDid` and braces in the authority URL each arrive as written, in one request; that `.` and `..` segments arrive as written; that an `authorityDid` holding `#`, `?`, `/`, `%` or a space arrives percent-encoded; and that no request is sent for an `endpoints.trustProof` that does not start with `/` (a host suffix such as `.attacker.example/...`, or a path written without its leading slash) or holds `#`, whitespace or a control character, or for an authority URL with a pattern in its host or port. For the Section 7.1 transport rule, it checks which authority URLs `transport_allowed` in `lib.sh` allows and refuses, that no request is sent under `http://localhost`, `http://LOCALHOST`, `http://127.1` or `http://127.0.0.01` with the fixture authority's port, or under `127.0.0.1` and that port without a scheme, all of which `curl` reaches the fixture authority under when it requests them, that a request under the fixture authority's `http` URL does not go through the proxy `http_proxy` names, and that a `.curlrc` that sets the request method changes no request. A local server that accepts connections and never answers checks that each request stops at `ATP_MAX_TIME`. Another, which answers every request with one body, checks that a body of the size limit passes and one of a byte more fails, sent with a `Content-Length`, in chunks and ended by closing the connection, under the default limit and under `ATP_MAX_BODY_BYTES`, and that the scripts stop reading a 64 MiB body before the server has written all of it. It also checks that `checks.jq` agrees with a JSON Schema validator on the specification's examples and on edits of them: each member removed, each member replaced by one of a fixed set of values (`null`, `true`, `-1`, `1.5`, `"x"`, `[]`, `{}`, a few malformed timestamps, one at hour 24 and one before 1900), and one extra top-level member added; and that `rfc3339` gives the epoch seconds worked out apart from it, for timestamps from year 0000 to year 9999. Needs `bash`, `curl`, `jq` and the Python `jsonschema` package.

## Adding Tests

Each test runs a check, then reports it with the `test_case` helper:

```bash
check "$PROOF" 'members_ok($proof_schema; ["verdict"])'
test_case "Description of what is being tested" "$?"
```

`check BODY FILTER` passes when `BODY` is one JSON value and every condition in the object `FILTER` returns is true; it sets the detail `test_case` prints on failure. Filters can use the definitions in `checks.jq` (`members_ok`, `schema_ok`, `rfc3339`, `is_time`, `type_ok`) and the schemas as `$discovery_schema`, `$proof_schema` and `$revocation_schema`. The second argument to `test_case` is the exit code of the check (0 = pass, non-zero = fail).

A test that sends a request does so with `fetch NAME URL [curl options]` from `lib.sh`, which passes the `curl` options every request needs, sets `NAME` to the body, and fails with a named reason when the transport rule refuses the URL (without a request), the URL is not valid, the request reaches a time limit or the body is larger than the size limit:

```bash
fetch LOG "$BASE_URL/api/v1/transparency/trust-proofs?limit=5" &&
  check "$LOG" '{"body is a JSON array or object": (type == "array" or type == "object")}'
test_case "Transparency log endpoint returns data" "$?"
```

## CI Integration

```bash
./conformance/level1.sh https://api.oa2a.org
if [ $? -ne 0 ]; then
  echo "ATP Level 1 conformance failed"
  exit 1
fi
```
