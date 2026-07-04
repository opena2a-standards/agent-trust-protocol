# ATP Conformance Test Suite

Tests that verify a **running ATP authority** conforms to the [Agent Trust Protocol specification](../ATP-SPEC.md).

This is the live-endpoint half of ATP conformance. The other half — byte-stable, SHA-256-pinned wire-format fixtures with parity-gated Go and Python reference verifiers — lives at [`opena2a-standards/atp-conformance`](https://github.com/opena2a-standards/atp-conformance). See ATP-SPEC §2.1 for the per-level fixture traceability table. Fixtures prove wire-format interoperability; these scripts prove an operating deployment.

## Prerequisites

- `bash` 4+
- `curl`
- `jq`
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

Both scripts exit with the number of failed tests as the exit code (0 = all passed).

## Test Coverage

### Level 1: Basic Trust (14 tests)

| ID | Test |
|----|------|
| T1.1 | `/.well-known/atp` returns valid JSON |
| T1.2 | Discovery document has `authorityDid`, `version`, `endpoints` |
| T1.3 | `conformanceLevel >= 1` |
| T1.4 | DID resolution returns a document for the authority's own DID |
| T1.5 | DID Document has `@context` |
| T1.6 | DID Document has at least one `verificationMethod` |
| T1.7 | Trust proof endpoint returns a proof for the authority DID |
| T1.8 | Trust proof has all required fields (`did`, `trustLevel`, `trustScore`, `verdict`, `issuedAt`, `expiresAt`, `issuerDid`) |
| T1.9 | Trust proof has at least one signature |
| T1.10 | Trust proof is not expired |
| T1.11 | Trust level is 0-4 |
| T1.12 | Trust score is 0.0-1.0 |
| T1.13 | Verify endpoint accepts a trust proof |
| T1.14 | Verification result is `valid=true` |

### Level 2: Auditable Trust (3 additional tests)

| ID | Test |
|----|------|
| T2.1 | Transparency log endpoint returns data |
| T2.2 | Log entries have expected structure |
| T2.3 | Revocations endpoint returns data |

## Adding Tests

Each test uses the `test_case` helper:

```bash
test_case "Description of what is being tested" "$?"
```

The second argument is the exit code of the preceding command (0 = pass, non-zero = fail).

## CI Integration

```bash
./conformance/level1.sh https://api.oa2a.org
if [ $? -ne 0 ]; then
  echo "ATP Level 1 conformance failed"
  exit 1
fi
```
