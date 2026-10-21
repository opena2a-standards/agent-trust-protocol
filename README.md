# Agent Trust Protocol (ATP)

> **OpenA2A specs** · [did:opena2a](https://github.com/opena2a-standards/did-method-opena2a) · [AIP](https://github.com/opena2a-standards/agent-identity-protocol) · [ATX](https://github.com/opena2a-standards/atx-spec) · **ATP** · [AAP](https://github.com/opena2a-standards/agent-authorization-protocol) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [all specs ↗](https://specs.opena2a.org)

An open standard for verifiable trust assertions about AI agents. The agent-specific credential format defined by ATP is the Agent Trust eXtension (ATX).

ATP enables any party to answer "Should I trust this agent?" with a cryptographically verifiable and auditable response. A decentralized response, co-signed by several trust authorities (federation, conformance Level 3), is specified and not yet demonstrated: no second authority co-signs proofs yet, and no conformance fixture covers a co-signed proof.

## Quick Start

Start with [ATP-SPEC.md Section 4](ATP-SPEC.md#4-trust-proofs), which defines the trust proof these requests fetch and verify against the reference authority:

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

## Specification

[ATP-SPEC.md](ATP-SPEC.md) — the full protocol specification.

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
| did, trustLevel, trustScore, verdict, issuedAt, expiresAt, issuerDid, signatures | Shipped (Section 4.3 canonical string and its signatures) | Base trust proof. See examples/. |
| capabilities | ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2) | Declared capability set the agent is authorized to perform. |
| buildAttestation | ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2) | SLSA-compatible build provenance digest. |
| behavioralProfile | ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2) | Observed behavior baseline. Checksum and observation window. |
| scanSummary | ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2) | HackMyAgent and equivalent scanner results at issuance time. |
| declaredPurpose | ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2) | Optional structured declaration of what the agent is for. |

`declaredPurpose` is an identity and attestation claim, never an authorization input.

The ATX v1.1 fields are signed inside the ATX credential's `JCS(TBS)`, never in the trust proof's canonical string (ATP-SPEC.md Section 4.3). A trust proof and an ATX credential are two signed artifacts with two canonical forms; see ATP-SPEC.md Section 4.6.

### Verifiable Credential form

An ATX credential is not a Verifiable Credentials Data Model 2.0 document as issued: it has no `@context`, `type`, `issuer` or `credentialSubject`. [ATP-SPEC.md Section 4.6](./ATP-SPEC.md#verifiable-credential-form) maps each ATX member to that structure: `issuerDid` to `issuer`, `did` to `credentialSubject.id`, `issuedAt` and `expiresAt` to `validFrom` and `validUntil`, and each claim under `credentialSubject`.

[`examples/atx-vc-example.json`](./examples/atx-vc-example.json) is [`examples/atx-example.json`](./examples/atx-example.json) in that form. CI validates it against [`schemas/atx-vc-v1.schema.json`](./schemas/atx-vc-v1.schema.json) and against the mapping table. To run the same check (needs the Python `jsonschema` package):

```bash
python3 scripts/validate_examples.py
```

The mapped form is not secured by a Verifiable Credentials securing mechanism. Its ATX signatures are verified on the ATX credential the mapping recovers.

## Reference Implementation

The OpenA2A Registry runs the reference trust authority, live at `api.oa2a.org`. Its source code is not public, and [ATP-SPEC Appendix A](ATP-SPEC.md#appendix-a-reference-implementation) maps each component to the public endpoint that demonstrates it. Run against it, the conformance scripts pass the discovery and DID resolution tests (T1.1 to T1.6) and fail the trust proof, verification, transparency log and revocation tests (T1.7 to T1.14 and T2.1 to T2.3); its discovery document declares conformance level 1. [docs/reference-implementation.md](docs/reference-implementation.md#conformance-run) records the run and the answers behind each failure.

```bash
curl "https://api.oa2a.org/api/v1/trust/proof?did=did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem"
```

Returns a hybrid Ed25519 plus ML-DSA-65 signed trust proof; [docs/reference-implementation.md](docs/reference-implementation.md) shows a recorded response.

This hybrid proof carries both an Ed25519 signature for fast local verification today and an ML-DSA-65 signature (FIPS 204, post-quantum) for forward compatibility. `proof.signature` repeats the Ed25519 value from `signatures`. Local verification requires no further network calls.

## Documentation

- [ATP-SPEC.md](ATP-SPEC.md): the protocol specification
- [docs/use-cases.md](docs/use-cases.md): three use cases, what works today and where each stops, and why ATX
- [docs/interoperability.md](docs/interoperability.md): the standards ATP is designed to complement
- [docs/reference-implementation.md](docs/reference-implementation.md): a recorded reference authority response and conformance run
- [conformance/README.md](conformance/README.md): the live-endpoint conformance scripts
- [CHANGELOG.md](CHANGELOG.md): changes to the specification
- [AIP (Agent Identity Protocol)](https://github.com/opena2a-org/agent-identity-protocol) — identity + capabilities
- [OASB (Open Agent Security Benchmark)](https://github.com/opena2a-org/oasb) — security controls

## License

Apache-2.0
