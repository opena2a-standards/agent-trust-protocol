> **OpenA2A specs** · [did:opena2a](https://github.com/opena2a-standards/did-method-opena2a) · [AIP](https://github.com/opena2a-standards/agent-identity-protocol) · [ATX](https://github.com/opena2a-standards/atx-spec) · **ATP** · [AAP](https://github.com/opena2a-standards/agent-authorization-protocol) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [all specs ↗](https://specs.opena2a.org)

# Agent Trust Protocol (ATP)

An open standard for verifiable trust assertions about AI agents. The agent-specific credential format defined by ATP is the Agent Trust eXtension (ATX).

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

# Discover the trust authority (/.well-known/opena2a is a legacy alias for the same document)
curl https://api.oa2a.org/.well-known/atp
```

## Use cases

### Should I trust this agent right now, and who says so

Before you let an agent in or install an MCP server, you want a signed statement from a party you can identify, not a star rating on a listing page. You also want to check that statement yourself, with the authority's published key, so a compromised listing cannot forge it.

ATP defines the trust proof: a short-lived signed statement of an agent's trust level, score and verdict, signed with Ed25519 (and with ML-DSA-65 as well in hybrid mode), valid for at most 24 hours, and verifiable against the authority's published keys.

What you can do today: the Quick Start above fetches a live proof from the reference authority and checks it. On 2026-10-08 the verify call returned `{"valid":true,"expired":false,"issuerOk":true,"signatureOk":true}`, and the authority's discovery document also answered at `https://api.oa2a.org/.well-known/atp`.

Where it stops today: `POST /api/v1/trust/verify` asks the authority to check its own proof, which puts the authority on the verification path. The conformance verifiers check the same proof shape locally with the published key, and that is the path a relying party should build on.

### Your auditor asks whether this agent was trusted at 02:14

After an incident you have to prove what the trust state was at the moment the agent acted. Ordinary application logs can be edited by the same incident, so a reconstruction from them is an assertion, not evidence.

ATP records every trust proof issuance and revocation in an append-only Merkle tree compatible with RFC 6962. The authority publishes Signed Tree Heads, and an auditor checks inclusion proofs for single entries and consistency proofs between tree sizes, so an entry that was removed or rewritten is detectable.

What you can do today: the conformance suite carries a Signed Tree Head, a valid inclusion proof, a valid consistency proof and the tampered-path rejections for both.

```
git clone https://github.com/opena2a-standards/atp-conformance
cd atp-conformance/verifiers/go
go run . ../../fixtures
# summary: 14 pass, 0 fail (14 fixtures)
```

Where it stops today: the transparency-log read endpoint that ATP-SPEC names for the reference authority, `/api/v1/transparency/trust-proofs`, answered HTTP 404 on 2026-10-08, so the live log cannot yet be audited from outside.

### You revoke an agent once and need every verifier to stop trusting it

A compromised agent holds a credential that is still valid. You need every verifier to stop honoring it, including verifiers run by other organizations that never call you.

ATP Section 8.1 defines the revocation list that verifiers fetch and cache. An entry whose timestamp cannot be parsed rejects the whole response, because silently skipping one entry would keep a revoked agent trusted.

What you can do today:

```
curl https://api.oa2a.org/api/v1/trust/revocations
```

The conformance suite pins the Section 8.1 body (`fixtures/revocation-list-valid.json`) and the malformed-timestamp rejection.

Where it stops today: the revocation response body is not signed; its authenticity rides on the transport. The reference authority publishes the list for polling and does not push it to federation peers.

Why you can check this yourself: [`ATP-SPEC.md`](ATP-SPEC.md); [atp-conformance](https://github.com/opena2a-standards/atp-conformance), 14 byte-pinned fixtures with Go and Python verifiers; the live-endpoint scripts [`conformance/level1.sh`](conformance/level1.sh) and [`conformance/level2.sh`](conformance/level2.sh) that exercise a running authority; and the reference authority's live endpoints at `api.oa2a.org` (`/.well-known/atp`, `/api/v1/trust/proof`, `/api/v1/trust/verify`, `/api/v1/trust/revocations`).

## Specification

[ATP-SPEC.md](ATP-SPEC.md) — the full protocol specification (v1.0.0-rc1).

## Conformance Levels

| Level | Name | What It Means |
|-------|------|---------------|
| 1 | Basic Trust | DID + signed proofs. Single authority. |
| 2 | Auditable Trust | + transparency log. Tamper-evident. |
| 3 | Decentralized Trust | + federation consensus. Multi-authority. |

## Agent Trust eXtension (ATX)

The Agent Trust eXtension (ATX) is the credential format defined by ATP for AI agents specifically. ATX builds on the base ATP trust proof and adds agent-specific claims that generic credential formats do not encode.

### Schema

| Field | Status | Description |
|-------|--------|-------------|
| did, trustLevel, trustScore, verdict, issuedAt, expiresAt, issuerDid, signatures | Shipped (v1.0.0-rc1) | Base trust proof. See examples/. |
| capabilities | Proposed (v1.1) | Declared capability set the agent is authorized to perform. |
| buildAttestation | Proposed (v1.1) | SLSA-compatible build provenance digest. |
| behavioralProfile | Proposed (v1.1) | Observed behavior baseline. Checksum and observation window. |
| scanSummary | Proposed (v1.1) | HackMyAgent and equivalent scanner results at issuance time. |

### Why ATX

DIDs answer who an agent is. ATX answers what the agent is authorized to do, what its provenance is, what its observed behavior looks like, and what scanners have verified it. The W3C Verifiable Credentials Data Model 2.0 supports the issuer, subject, and claims pattern. ATX uses that pattern with agent-specific claims tuned for short TTLs, behavioral attestation, and continuous re-verification.

ATX is the credential primitive the agent internet needs. ATP is the protocol that defines it.

## Interoperability

ATP is designed to complement:
- [Google A2A Protocol](https://github.com/google/A2A): trust proof in agent cards
- [SLSA](https://slsa.dev): provenance level factors into trust score
- [Sigstore](https://sigstore.dev): keyless co-signing of trust proofs
- [Certificate Transparency (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962): compatible log structure
- [W3C DID Core](https://www.w3.org/TR/did-core/): agent identifiers
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/): ATX is structurally compatible

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

This hybrid proof carries both an Ed25519 signature for fast local verification today and an ML-DSA-65 signature (FIPS 204, post-quantum) for forward compatibility. Local verification requires no further network calls.

## Related Standards

- [AIP (Agent Identity Protocol)](https://github.com/opena2a-org/agent-identity-protocol) — identity + capabilities
- [OASB (Open Agent Security Benchmark)](https://github.com/opena2a-org/oasb) — security controls

## License

Apache-2.0
