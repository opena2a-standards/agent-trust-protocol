# Agent Trust Protocol (ATP)

## A Standard for Verifiable Trust Assertions About AI Agents

**Version:** 1.0.0-rc1
**Authors:** OpenA2A
**Date:** April 2026

> **Note (2026-04-28).** v1.0.0-rc1 reconciles the DID method prefix from `did:atp:` (used in v1.0.0-draft) to `did:opena2a:` to match the production reference implementation at `api.oa2a.org`. No other normative changes from v1.0.0-draft.

---

## Abstract

The Agent Trust Protocol (ATP) defines a standard for expressing, verifying, and distributing trust assertions about AI agents. It enables any party to answer the question: "Should I trust this agent?" with a cryptographically verifiable, auditable, and decentralized response.

ATP is designed for a world where millions of AI agents operate across organizational boundaries — MCP servers handling filesystem access, A2A agents delegating tasks to each other, autonomous agents making decisions on behalf of users. Each of these interactions requires a trust decision. ATP provides the infrastructure for making that decision reliably.

This specification defines:

1. **Agent Identifiers** — how agents are named and resolved (Section 3)
2. **Trust Proofs** — how trust assertions are signed and verified (Section 4)
3. **Transparency Log** — how trust changes are recorded and audited (Section 5)
4. **Federation** — how multiple trust authorities reach consensus (Section 6)
5. **Discovery** — how clients find and interact with trust authorities (Section 7)
6. **Revocation** — how trust assertions are invalidated (Section 8)

ATP is designed to complement, not replace, existing standards:

- **Google A2A Protocol** — ATP provides the trust layer that A2A lacks. An A2A agent can include its ATP trust proof in the agent card so that other agents can verify trust before delegating tasks.
- **SLSA (Supply Chain Levels for Software Artifacts)** — ATP trust scoring incorporates SLSA provenance levels. An agent built with SLSA Level 3 provenance receives higher ATP trust.
- **Sigstore** — ATP trust proofs can be co-signed using Sigstore keyless signing. Agents signed via Sigstore receive an attestation that factors into their ATP trust score.
- **Certificate Transparency (RFC 6962)** — ATP's transparency log is structurally compatible with CT. Monitors that verify CT logs can be adapted to verify ATP logs with minimal changes.
- **W3C DID Core** — ATP agent identifiers are valid DIDs resolvable to DID Documents.

---

## 1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

| Term | Definition |
|------|-----------|
| **Agent** | An AI system that performs actions: MCP server, A2A agent, autonomous agent, skill, or AI tool. |
| **Trust Authority** | A server that issues, stores, and verifies ATP trust proofs. |
| **Trust Proof** | A signed assertion about an agent's trust level, issued by a trust authority. |
| **Trust Level** | An integer 0-4 representing the degree of trust. |
| **Transparency Log** | An append-only Merkle tree recording all trust proof issuances and revocations. |
| **Federation** | A network of trust authorities that co-sign trust proofs and sync trust data. |
| **Monitor** | An independent party that audits the transparency log for inconsistencies. |

---

## 2. Conformance Levels

ATP defines three conformance levels. Implementations MUST declare which level they conform to.

### Level 1: Basic Trust (single authority)

An implementation that issues signed trust proofs for agents and resolves agent DIDs. Suitable for a single organization managing its own agents.

Requirements:
- Agent DID resolution (Section 3)
- Trust proof signing and verification (Section 4)
- Discovery endpoint (Section 7)

### Level 2: Auditable Trust (single authority + transparency)

An implementation that additionally logs all trust proof operations in an append-only transparency log. Suitable for a public trust authority that must be auditable.

Requirements:
- All Level 1 requirements
- Transparency log (Section 5)
- Inclusion proof generation and verification
- Revocation infrastructure (Section 8)

### Level 3: Decentralized Trust (federation)

An implementation that participates in a federation of trust authorities, where trust elevation requires multi-authority consensus. Suitable for ecosystem-wide trust infrastructure.

Requirements:
- All Level 2 requirements
- Federation protocol (Section 6)
- Multi-authority co-signing for trust level 3+
- Cross-authority revocation propagation

---

## 3. Agent Identifiers

### 3.1 DID Format

Every agent in ATP is identified by a Decentralized Identifier (DID) conforming to W3C DID Core.

```
did:opena2a:<agent_type>:<agent_name>
```

Where:
- `agent_type` is one of: `mcp_server`, `a2a_agent`, `skill`, `ai_tool`, `llm`
- `agent_name` is the package name, URL-encoded if it contains special characters

Examples:
```
did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem
did:opena2a:a2a_agent:google/weather-agent
did:opena2a:skill:deployment-helper
did:opena2a:ai_tool:langchain
```

Trust authorities themselves have DIDs:
```
did:opena2a:authority:opena2a.org
did:opena2a:authority:trust.google.com
did:opena2a:authority:security.azure.com
```

### 3.2 DID Document

Resolving a DID MUST return a DID Document conforming to the following structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
  "verificationMethod": [{
    "id": "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:opena2a:authority:opena2a.org",
    "publicKeyMultibase": "z6Mkf5rGMoatrSj1f..."
  }],
  "service": [
    {
      "id": "#trust-lookup",
      "type": "AgentTrustLookup",
      "serviceEndpoint": "https://api.oa2a.org/api/v1/trust/query?name=..."
    },
    {
      "id": "#trust-proof",
      "type": "AgentTrustProof",
      "serviceEndpoint": "https://api.oa2a.org/api/v1/trust/proof?did=..."
    },
    {
      "id": "#transparency-log",
      "type": "TransparencyLog",
      "serviceEndpoint": "https://api.oa2a.org/api/v1/transparency/trust-proofs"
    }
  ],
  "created": "2026-01-15T10:30:00Z",
  "updated": "2026-03-22T14:00:00Z"
}
```

The `controller` field indicates which trust authority manages this agent's trust assertions. The `verificationMethod` contains the public key used to verify trust proofs for this agent.

### 3.3 DID Resolution

A trust authority MUST provide a DID resolution endpoint:

```
GET /api/v1/did/{did}
```

The `{did}` parameter is the full DID string. Because DIDs contain colons, implementations MUST handle URL-encoded colons or use a wildcard path matcher.

Response: the DID Document as JSON with `Content-Type: application/did+json`.

### 3.4 Integration with A2A Agent Cards

A2A agents that participate in ATP SHOULD include their DID and a current trust proof in their agent card (`/.well-known/agent.json`):

```json
{
  "name": "Weather Agent",
  "description": "Provides weather forecasts",
  "url": "https://weather.example.com",
  "capabilities": ["weather_lookup"],
  "atp": {
    "did": "did:opena2a:a2a_agent:weather-agent",
    "trustProof": { ... },
    "trustAuthorityDid": "did:opena2a:authority:opena2a.org"
  }
}
```

An A2A client receiving a task delegation SHOULD verify the delegating agent's trust proof before accepting the task.

---

## 4. Trust Proofs

### 4.1 Trust Levels

ATP defines five trust levels:

| Level | Name | Meaning | Requirements |
|-------|------|---------|-------------|
| 0 | Blocked | Known malicious or critically vulnerable | Active threat or critical unpatched vulnerability |
| 1 | Warning | Significant security concerns | High-severity findings, behavioral violations |
| 2 | Listed | Indexed, not yet evaluated | Exists in a package registry, no security assessment |
| 3 | Scanned | Passed automated security assessment | Static + semantic analysis passed, SLSA L1+ |
| 4 | Verified | Full verification, multi-authority consensus | Publisher verified, 30+ days observed, federation co-signed |

Trust levels 0-2 can be assigned by a single trust authority. Trust levels 3-4 MUST be co-signed by at least one additional authority in Level 3 conforming implementations (Section 6).

### 4.2 Trust Proof Format

A trust proof is a signed assertion about an agent's trust level:

```json
{
  "did": "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
  "trustLevel": 3,
  "trustScore": 0.82,
  "verdict": "passed",
  "issuedAt": "2026-03-22T14:00:00Z",
  "expiresAt": "2026-03-23T14:00:00Z",
  "issuerDid": "did:opena2a:authority:opena2a.org",
  "signatures": [
    {
      "keyId": "did:opena2a:authority:opena2a.org#key-v3",
      "algorithm": "Ed25519",
      "value": "base64-encoded-signature"
    }
  ],
  "transparencyLogIndex": 1847293,
  "slsaLevel": 2,
  "scanSummary": {
    "checksRun": 199,
    "criticalFindings": 0,
    "highFindings": 1,
    "lastScanned": "2026-03-22T12:00:00Z"
  }
}
```

### 4.3 Signing

Trust proofs MUST be signed using Ed25519 (RFC 8032).

The signature MUST be computed over a canonical byte representation of the proof payload, NOT over a JSON serialization (JSON field ordering is non-deterministic). The canonical representation is:

```
canonical = "{did}|{trustLevel}|{trustScore:.6f}|{verdict}|{issuedAt RFC3339}|{expiresAt RFC3339}|{issuerDid}"
signature = Ed25519.Sign(privateKey, canonical)
```

Implementations SHOULD also support hybrid Ed25519 + ML-DSA-65 (FIPS 204) dual signatures for post-quantum readiness. In hybrid mode, both signatures MUST be present and both MUST verify:

```json
"signatures": [
  {
    "keyId": "did:opena2a:authority:opena2a.org#key-v3",
    "algorithm": "Ed25519",
    "value": "base64-ed25519-signature"
  },
  {
    "keyId": "did:opena2a:authority:opena2a.org#pqc-v1",
    "algorithm": "ML-DSA-65",
    "value": "base64-mldsa65-signature"
  }
]
```

### 4.4 Verification

A verifier MUST perform the following checks in order:

1. **Expiry:** `expiresAt` MUST be in the future. Expired proofs MUST be rejected.
2. **Issuer:** `issuerDid` MUST resolve to a known trust authority.
3. **Key lookup:** `signatures[*].keyId` MUST resolve to a valid, non-revoked public key.
4. **Signature:** At least one signature MUST verify against the canonical payload.
5. **Semantic validation:**
   - `trustLevel` MUST be 0-4
   - `trustScore` MUST be 0.0-1.0
   - `verdict` MUST be one of: `passed`, `warning`, `blocked`, `listed`, `verified`, `unknown`
   - `issuedAt` MUST be before `expiresAt`
6. **Transparency log (Level 2+):** If `transparencyLogIndex` is present, the verifier SHOULD verify inclusion against the authority's transparency log.
7. **Multi-signature (Level 3):** For trust levels 3-4, at least two signatures from distinct authorities MUST be present.

### 4.5 Proof Retrieval

```
GET /api/v1/trust/proof?did={did}
```

Returns the current trust proof for the given DID. The proof MUST be cached by the authority for its validity period (default: 24 hours). Clients SHOULD cache proofs locally and reuse them within the validity window.

```
POST /api/v1/trust/verify
Content-Type: application/json

{ ...trust proof... }
```

Verifies a trust proof against the authority's public keys and transparency log. Returns verification result.

---

## 5. Transparency Log

### 5.1 Structure

The ATP transparency log is an append-only Merkle tree compatible with RFC 6962 (Certificate Transparency).

Each leaf in the tree represents a trust event:

```json
{
  "logIndex": 1847293,
  "timestamp": "2026-03-22T14:00:00Z",
  "entryType": "trust_proof_issued",
  "agentDid": "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem",
  "trustLevel": 3,
  "trustScore": 0.82,
  "proofHash": "SHA256:abc123...",
  "signingKeyId": "did:opena2a:authority:opena2a.org#key-v3",
  "previousHash": "SHA256:def456..."
}
```

Entry types:
- `trust_proof_issued` — new trust proof created
- `trust_proof_revoked` — existing proof invalidated
- `trust_level_changed` — agent's trust level changed
- `key_rotated` — signing key added or retired
- `key_revoked` — signing key compromised and invalidated
- `authority_joined` — new trust authority joined federation
- `authority_suspended` — trust authority suspended from federation

### 5.2 Leaf Hash

```
leaf_hash = SHA-256(0x00 || timestamp || entry_type || entry_data)
```

The `0x00` prefix distinguishes leaf hashes from internal node hashes (RFC 6962 Section 2.1).

### 5.3 Merkle Tree Hash

```
MTH({}) = SHA-256()                                    (empty tree)
MTH({d0}) = SHA-256(0x00 || d0)                        (one entry)
MTH(D) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))  (n > 1)
```

Where `k` is the largest power of 2 less than `n`. This matches RFC 6962 Section 2.1.

### 5.4 Inclusion Proof

A client can verify that a specific trust proof was logged:

```
GET /api/v1/transparency/proof/{logIndex}
```

Returns the Merkle audit path from the leaf to the current tree root. The client reconstructs the root hash using the path and compares against the published root.

### 5.5 Consistency Proof

A monitor can verify that the log is append-only (no entries were deleted or modified):

```
GET /api/v1/transparency/consistency?from={oldSize}&to={newSize}
```

Returns the consistency proof between two tree states. Compatible with RFC 6962 Section 2.1.2.

### 5.6 Signed Tree Head

The trust authority MUST periodically publish a Signed Tree Head (STH):

```json
{
  "treeSize": 1847294,
  "timestamp": "2026-03-22T14:00:00Z",
  "rootHash": "SHA256:789abc...",
  "signature": "base64-ed25519-signature-over-rootHash"
}
```

The STH SHOULD be published at least every hour. Monitors fetch the STH and verify consistency with their last-known state.

### 5.7 External Anchoring

A Level 2+ trust authority SHOULD periodically anchor the tree root to an external timestamping source:

- **RFC 3161 Timestamping Authority** — standard, widely available, low cost
- **Public blockchain** — one transaction per day containing the root hash
- **Certificate Transparency log** — submit the STH as a pre-certificate

This provides temporal binding: proof that "at time T, the transparency log was in state X" from an independent third party.

---

## 6. Federation

### 6.1 Authority Tiers

| Tier | Role | Requirements |
|------|------|-------------|
| **Canonical** | Primary authority, proposes trust changes | Level 2+ conformance, operates transparency log |
| **Verified** | Independent authority, co-signs trust proofs | Level 2+ conformance, independent infrastructure, minimum 30 days operational |
| **Community** | Contributes scan data, lower signing weight | Level 1+ conformance |

### 6.2 Trust Elevation Protocol

For Level 3 conforming implementations, trust level 3+ requires multi-authority consensus:

```
1. Canonical authority scans agent, determines trust level 3
2. Canonical publishes trust_change_proposal to federation

   POST /federation/v1/proposals
   {
     "agentDid": "did:opena2a:mcp_server:example",
     "proposedLevel": 3,
     "evidence": {
       "scanResults": { ... },
       "contentHash": "SHA256:...",
       "slsaLevel": 2
     },
     "proposerDid": "did:opena2a:authority:opena2a.org",
     "expiresAt": "2026-03-23T14:00:00Z"
   }

3. Verified authorities independently evaluate the agent
4. If they agree, they co-sign:

   POST /federation/v1/proposals/{id}/sign
   {
     "signerDid": "did:opena2a:authority:trust.google.com",
     "agrees": true,
     "signature": "base64-signature-over-proposal"
   }

5. When 2+ authorities have co-signed, the trust proof is
   issued with multiple signatures and distributed to all nodes
```

### 6.3 Emergency Block

Any Verified authority MAY unilaterally block an agent (trust level 0):

```
POST /federation/v1/blocks
{
  "agentDid": "did:opena2a:mcp_server:malicious-package",
  "reason": "Active data exfiltration detected",
  "evidence": { ... },
  "blockerDid": "did:opena2a:authority:opena2a.org"
}
```

Blocks propagate to all federation members immediately. Other authorities MAY contest a block within 72 hours. If contested, the agent remains blocked until the dispute is resolved by majority vote.

### 6.4 Sync Protocol

Federation members sync trust data via delta exchange:

```
GET /federation/v1/deltas?since={ISO8601}&limit={n}
Authorization: Bearer {federation-api-key}
```

Returns trust score changes since the given timestamp. Each delta includes the transparency log index for verification.

---

## 7. Discovery

### 7.1 Well-Known Endpoint

A trust authority MUST serve a discovery document at:

```
GET /.well-known/atp
```

```json
{
  "authorityDid": "did:opena2a:authority:opena2a.org",
  "version": "1.0",
  "conformanceLevel": 3,
  "endpoints": {
    "didResolve": "/api/v1/did/{did}",
    "trustProof": "/api/v1/trust/proof",
    "trustVerify": "/api/v1/trust/verify",
    "trustBatch": "/api/v1/trust/batch",
    "transparencyLog": "/api/v1/transparency/trust-proofs",
    "transparencyProof": "/api/v1/transparency/proof/{index}",
    "transparencySTH": "/api/v1/transparency/sth",
    "revocations": "/api/v1/trust/revocations",
    "federation": "/federation/v1/proposals"
  },
  "publicKeys": [
    {
      "keyId": "#key-v3",
      "algorithm": "Ed25519",
      "publicKeyMultibase": "z6Mkf5rGMoatrSj1f...",
      "status": "active",
      "validFrom": "2026-03-01T00:00:00Z"
    }
  ],
  "supportedMethods": ["did:atp"],
  "capabilities": [
    "trust-proof",
    "transparency-log",
    "federation",
    "revocation",
    "batch-query",
    "sse-events"
  ],
  "federationPeers": [
    "did:opena2a:authority:trust.google.com",
    "did:opena2a:authority:security.azure.com"
  ]
}
```

### 7.2 Batch Queries

For efficiency, clients SHOULD use batch queries when verifying multiple agents:

```
POST /api/v1/trust/batch
Content-Type: application/json

{
  "agents": [
    {"did": "did:opena2a:mcp_server:server-a"},
    {"did": "did:opena2a:a2a_agent:agent-b"},
    {"did": "did:opena2a:skill:skill-c"}
  ]
}
```

Maximum 100 agents per batch request.

### 7.3 Real-Time Events

Trust authorities SHOULD provide Server-Sent Events (SSE) for real-time trust changes:

```
GET /api/v1/trust/events?types=trust_changed,revocation&agents={did1},{did2}
```

Event types: `trust_changed`, `revocation`, `block`, `key_rotated`.

---

## 8. Revocation

### 8.1 Trust Proof Revocation

A trust authority MUST provide a revocation endpoint:

```
GET /api/v1/trust/revocations?since={ISO8601}
```

Returns all revocations since the given timestamp:

```json
{
  "revocations": [
    {
      "agentDid": "did:opena2a:mcp_server:compromised-package",
      "revokedAt": "2026-03-22T15:00:00Z",
      "reason": "Supply chain compromise detected",
      "transparencyLogIndex": 1847300,
      "revokedByKeyId": "did:opena2a:authority:opena2a.org#key-v3"
    }
  ],
  "nextSince": "2026-03-22T15:00:00Z"
}
```

Clients SHOULD poll this endpoint periodically (RECOMMENDED: every 5 minutes) and compare against locally cached trust proofs.

### 8.2 Key Revocation

When a signing key is compromised:

1. The authority MUST log a `key_revoked` entry in the transparency log
2. The authority MUST update `/.well-known/atp` to remove the revoked key
3. The authority MUST notify all federation peers
4. All trust proofs signed exclusively by the revoked key become untrusted
5. Trust proofs with multi-authority signatures remain valid if at least one non-revoked signature exists

### 8.3 Emergency Revocation via Federation

Any Verified federation member MAY request emergency revocation of another authority's key if they have evidence of compromise. This requires agreement from 2+ other Verified members.

---

## 9. Privacy Considerations

### 9.1 Query Privacy

Trust authorities that process individual trust lookups learn which agents each client cares about. This is competitive intelligence.

Implementations SHOULD support one or more privacy mechanisms:

- **Client-side caching:** Trust proofs have a validity period (default 24 hours). Clients cache and reuse without querying.
- **Batch queries:** Reduces per-agent query fingerprinting.
- **k-anonymity:** Client sends a DID prefix; authority returns all matching proofs. Client selects the relevant one locally.
- **Signed proof bundles:** Authority periodically publishes all trust proofs as a signed bundle. Clients download the bundle and query locally.

### 9.2 Transparency Log Privacy

The transparency log is public by design. It records WHICH agents were evaluated and WHAT trust levels they received, but it does NOT record WHO queried them.

---

## 10. Security Considerations

### 10.1 Threat Model

ATP assumes the following threats and provides the corresponding defenses:

| Threat | Defense | Conformance Level |
|--------|---------|-------------------|
| Signing key compromise | Multi-key threshold signing | Level 1+ |
| Silent trust manipulation | Transparency log with Merkle proofs | Level 2+ |
| Single point of failure | Federation consensus | Level 3 |
| Revocation failure | Revocation API + federation propagation | Level 2+ |
| Quantum threat | Hybrid Ed25519 + ML-DSA-65 signatures | Optional |
| Query surveillance | Privacy mechanisms (Section 9) | RECOMMENDED |

### 10.2 Trust Proof Validity

Trust proofs MUST have a maximum validity period of 24 hours. This limits the window of exposure if a key is compromised or an agent's trust status changes.

### 10.3 Canonical Serialization

Implementations MUST NOT sign JSON-serialized payloads directly. JSON serialization is non-deterministic (field ordering, floating-point precision). The canonical payload format defined in Section 4.3 MUST be used.

---

## 11. IANA Considerations

This specification defines:

- **DID Method:** `did:atp` — Decentralized Identifier method for AI agents
- **Well-Known URI:** `/.well-known/atp` — Trust authority discovery
- **Media Type:** `application/atp+json` — ATP trust proof format

---

## 12. References

- RFC 2119 — Key words for use in RFCs
- RFC 6962 — Certificate Transparency
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 3161 — Internet X.509 PKI Time-Stamp Protocol
- W3C DID Core — Decentralized Identifiers v1.0
- SLSA — Supply-chain Levels for Software Artifacts
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- Google A2A Protocol — Agent-to-Agent communication specification
- OASB — Open Agent Security Benchmark

---

## Appendix A: Reference Implementation

The OpenA2A Registry (`github.com/opena2a-org/opena2a-registry`) is the reference implementation of ATP at Conformance Level 2, with Level 3 federation in development.

| Component | Implementation |
|-----------|---------------|
| DID resolution | `internal/application/did_service.go` |
| Trust proof signing | `internal/application/trust_proof_service.go` |
| Transparency log | `internal/application/transparency_service.go` |
| Federation domain | `internal/domain/federation.go` |
| Discovery endpoint | `/.well-known/opena2a` (to be migrated to `/.well-known/atp`) |
| Hybrid PQC signatures | `internal/security/hybrid_signature.go` |

## Appendix B: Integration Examples

### B.1 A2A Agent Verifying a Peer

```python
import atp

# Before accepting a delegated task from another agent
proof = atp.get_trust_proof("did:opena2a:a2a_agent:requester-agent")

if not atp.verify(proof):
    reject_task("Trust proof verification failed")

if proof.trust_level < 3:
    reject_task(f"Insufficient trust: level {proof.trust_level}, require 3+")

accept_task()
```

### B.2 MCP Client Checking Server Trust

```typescript
// Before connecting to an MCP server
const proof = await atp.getTrustProof(
  "did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem"
);

if (!atp.verify(proof)) {
  throw new Error("MCP server trust proof invalid");
}

if (proof.trustLevel === 0) {
  throw new Error(`BLOCKED: ${proof.verdict}`);
}

// Proceed with connection
const client = new MCPClient(serverUrl);
```

### B.3 CI/CD Pipeline Gate

```yaml
# GitHub Actions
- name: Verify agent trust
  run: |
    npx opena2a-cli trust verify \
      --did "did:opena2a:mcp_server:${{ inputs.mcp-server }}" \
      --min-level 3 \
      --require-federation
```
