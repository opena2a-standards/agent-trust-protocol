> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
# Agent Trust Protocol (ATP)

An open standard for verifiable trust assertions about AI agents.

ATP enables any party to answer "Should I trust this agent?" with a cryptographically verifiable, auditable, and decentralized response.

## Quick Start

```bash
# Query an agent's trust proof (returns hybrid Ed25519 + ML-DSA-65 signed proof)
curl "https://api.oa2a.org/api/v1/trust/proof?did=did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem" \
  | jq '.proof' > proof.json

# Verify the proof against the issuer (returns {"valid":true,...})
curl -X POST https://api.oa2a.org/api/v1/trust/verify \
  -H "Content-Type: application/json" \
  -d @proof.json

# Discover the trust authority (current endpoint; will migrate to /.well-known/atp)
curl https://api.oa2a.org/.well-known/opena2a
```

## Specification

[ATP-SPEC.md](ATP-SPEC.md) — the full protocol specification (v1.0.0-rc1).

## Conformance Levels

| Level | Name | What It Means |
|-------|------|---------------|
| 1 | Basic Trust | DID + signed proofs. Single authority. |
| 2 | Auditable Trust | + transparency log. Tamper-evident. |
| 3 | Decentralized Trust | + federation consensus. Multi-authority. |

## Interoperability

ATP is designed to complement:
- [Google A2A Protocol](https://github.com/google/A2A) — trust proof in agent cards
- [SLSA](https://slsa.dev) — provenance level factors into trust score
- [Sigstore](https://sigstore.dev) — keyless co-signing of trust proofs
- [Certificate Transparency (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962) — compatible log structure
- [W3C DID Core](https://www.w3.org/TR/did-core/) — agent identifiers

## Reference Implementation

The [OpenA2A Registry](https://github.com/opena2a-org/opena2a-registry) implements ATP at Level 2 conformance. The reference trust authority is live at `api.oa2a.org`.

Verified working request and response (April 2026):

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
    "issuedAt": "2026-04-28T13:32:11Z",
    "expiresAt": "2026-04-29T13:32:11Z",
    "issuerDid": "did:opena2a:registry:opena2a.org",
    "signatures": [
      { "keyVersion": 1, "algorithm": "ed25519", "value": "..." },
      { "keyVersion": 0, "algorithm": "ml-dsa-65", "value": "..." }
    ]
  },
  "publicKey": "..."
}
```

The proof carries both an Ed25519 signature for fast local verification today and an ML-DSA-65 signature (FIPS 204, post-quantum) for forward compatibility. Local verification requires no further network calls.

## Related Standards

- [AIP (Agent Identity Protocol)](https://github.com/opena2a-org/agent-identity-protocol) — identity + capabilities
- [OASB (Open Agent Security Benchmark)](https://github.com/opena2a-org/oasb) — security controls

## License

Apache-2.0
