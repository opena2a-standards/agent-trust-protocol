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

Both scripts exit with the number of failed tests as the exit code (0 = all passed). When `curl`, `jq` or a schema file is missing they exit 69 before running any test, a code no failed-test count reaches. A failed test names what is not met:

```
FAIL: Trust proof has all required fields (not met: verdict, issuedAt)
```

## Test Coverage

A test that names several members checks each one on its own. "Matches the schema" means the member's value is valid against its property in the named file under `schemas/`; timestamps must be RFC 3339 (a UTC offset from 00:00 to 23:59, and nothing after the timestamp, not even a newline) and are compared as times, whatever their UTC offset.

### Level 1: Basic Trust (14 tests)

| ID | Test |
|----|------|
| T1.1 | `/.well-known/atp` returns a JSON object |
| T1.2 | Discovery document has `authorityDid`, `version` and `endpoints`, each matching `discovery-v1.schema.json` |
| T1.3 | `conformanceLevel` is present and matches `discovery-v1.schema.json` (an integer from 1 to 3) |
| T1.4 | DID resolution returns a JSON document for the authority's own DID |
| T1.5 | DID Document has `@context`, a non-empty string or a non-empty array |
| T1.6 | DID Document has a non-empty `verificationMethod` array |
| T1.7 | Trust proof endpoint returns a JSON proof whose `did` is the authority DID. The request goes to `endpoints.trustProof` appended to the authority URL (`/api/v1/trust/proof` when it is absent, empty or not a string), and the test fails without a request when it is a non-empty string that does not start with `/`. The script reads the value with its NUL characters and trailing newlines removed |
| T1.8 | Trust proof has all required fields (`did`, `trustLevel`, `trustScore`, `verdict`, `issuedAt`, `expiresAt`, `issuerDid`), each matching `trust-proof-v1.schema.json` |
| T1.9 | Trust proof has at least one signature (`signatures` matches `trust-proof-v1.schema.json`) |
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

Runs both scripts against `scripts/fixture_authority.py`, a local authority that serves the specification's own examples, and expects all 17 tests to pass. It then removes or corrupts one member at a time (an HTML discovery body, a proof without `verdict`, an `expiresAt` of `"never"`, a log entry that is a string, a revocation `reason` in free text, and others) and expects exactly the tests that check that member to fail, and that a missing `jq` or schema file exits 69. It also checks that `checks.jq` agrees with a JSON Schema validator on the specification's examples and on edits of them: each member removed, each member replaced by one of a fixed set of values (`null`, `true`, `-1`, `1.5`, `"x"`, `[]`, `{}` and a few malformed timestamps), and one extra top-level member added. Needs `bash`, `curl`, `jq` and the Python `jsonschema` package.

## Adding Tests

Each test runs a check, then reports it with the `test_case` helper:

```bash
check "$PROOF" 'members_ok($proof_schema; ["verdict"])'
test_case "Description of what is being tested" "$?"
```

`check BODY FILTER` passes when `BODY` is one JSON value and every condition in the object `FILTER` returns is true; it sets the detail `test_case` prints on failure. Filters can use the definitions in `checks.jq` (`members_ok`, `schema_ok`, `rfc3339`, `is_time`, `type_ok`) and the schemas as `$discovery_schema`, `$proof_schema` and `$revocation_schema`. The second argument to `test_case` is the exit code of the check (0 = pass, non-zero = fail).

## CI Integration

```bash
./conformance/level1.sh https://api.oa2a.org
if [ $? -ne 0 ]; then
  echo "ATP Level 1 conformance failed"
  exit 1
fi
```
