# Reference implementation: recorded response

The [README](../README.md#reference-implementation) gives the request. This page keeps a response the reference trust authority returned to it, and a run of the conformance scripts against the authority, each with the date it was recorded. Signature and key values are shown as `...`.

Verified working request and response (October 2026):

```bash
curl "https://api.oa2a.org/api/v1/trust/proof?did=did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem"
```

Returns a hybrid Ed25519 plus ML-DSA-65 signed trust proof:

```json
{
  "algorithm": "ed25519",
  "proof": {
    "did": "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
    "trustLevel": 2,
    "trustScore": 0.7432,
    "verdict": "listed",
    "issuedAt": "2026-10-12T02:57:21.581346834Z",
    "expiresAt": "2026-10-13T02:57:21.581346834Z",
    "issuerDid": "did:opena2a:registry:opena2a.org",
    "signatures": [
      { "keyVersion": 1, "algorithm": "ed25519", "value": "..." },
      { "keyVersion": 1, "algorithm": "ML-DSA-65", "value": "..." }
    ],
    "signature": "..."
  },
  "publicKey": "..."
}
```

## Conformance run

`conformance/level2.sh`, which runs `conformance/level1.sh` first, run against the reference authority on 2026-10-21 at 07:21 UTC:

```bash
./conformance/level2.sh https://api.oa2a.org
```

```
=== Level 1: Basic Trust ===
PASS: Discovery endpoint returns JSON
PASS: Discovery has authorityDid, version, endpoints
PASS: Conformance level is 1-3
PASS: DID resolution returns document
PASS: DID Document has @context
PASS: DID Document has verificationMethod
FAIL: Trust proof endpoint returns proof (no JSON body)
FAIL: Trust proof has all required fields (no JSON body)
FAIL: Trust proof has an Ed25519 authority signature (no JSON body)
FAIL: Trust proof not expired (no JSON body)
FAIL: Trust level is 0-4 (no JSON body)
FAIL: Trust score is 0.0-1.0 (no JSON body)
FAIL: Verify endpoint accepts proof (no trust proof to send)
FAIL: Verification result is valid=true (no JSON body)

=== Results: 6 passed, 8 failed ===

=== Level 2: Auditable Trust ===
FAIL: Transparency log endpoint returns data (no JSON body)
FAIL: Log entries have structure (no JSON body)
FAIL: Revocations endpoint returns data (not met: nextSince, body matches schemas/revocation-list-v1.schema.json)

=== Level 2 Results: 0 passed, 3 failed ===
```

It passed 6 of the 17 tests and exited 11, the number of failed tests. The authority's discovery document declares `conformanceLevel` 1. The answers behind the failures, requested the same day:

- T1.7 to T1.14: the discovery document's `authorityDid` is `did:atp:authority:opena2a.org`, and `GET /api/v1/trust/proof?did=did:atp:authority:opena2a.org` answers HTTP 400 with `{"error":"invalid DID: must start with did:opena2a:"}`, so the script fetches no trust proof, and the tests that check one fail.
- T2.1 and T2.2: the script requests the log at `/api/v1/transparency/trust-proofs`, which answers HTTP 404. The discovery document lists the log as `endpoints.transparencyLog`, `/api/v1/registry/transparency/trust-proofs`, which answered with log entries.
- T2.3: `GET /api/v1/trust/revocations?since=2026-01-01T00:00:00Z` answers `{"revocations":[]}`, which has no `nextSince`.
