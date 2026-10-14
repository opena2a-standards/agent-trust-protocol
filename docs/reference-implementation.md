# Reference implementation: recorded response

The [README](../README.md#reference-implementation) gives the request. This page keeps a response the reference trust authority returned to it, with the date it was recorded. Signature and key values are shown as `...`.

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
