# Use cases

This page states each use case as it stands today: what you can do, where it stops, and the dated observations, counts and background under the use case each one qualifies.

## Should I trust this agent right now, and who says so

Before you let an agent in or install an MCP server, you want a signed statement from a party you can identify, not a star rating on a listing page. You also want to check that statement yourself, with the authority's published key, so a compromised listing cannot forge it.

ATP defines the trust proof: a short-lived signed statement of an agent's trust level, score and verdict, signed with Ed25519 (and with ML-DSA-65 as well in hybrid mode), valid for at most 24 hours, and verifiable against the authority's published keys.

What you can do today: the [Quick Start](../README.md#quick-start) fetches a live proof from the reference authority and checks it. On 2026-10-08 the verify call returned `{"valid":true,"expired":false,"issuerOk":true,"signatureOk":true}`, and the authority's discovery document also answered at `https://api.oa2a.org/.well-known/atp`.

Where it stops today: `POST /api/v1/trust/verify` asks the authority to check its own proof, which puts the authority on the verification path. The conformance verifiers check the same proof shape locally with the published key, and that is the path a relying party should build on.

## Your auditor asks whether this agent was trusted at 02:14

After an incident you have to prove what the trust state was at the moment the agent acted. Ordinary application logs can be edited by the same incident, so a reconstruction from them is an assertion, not evidence.

ATP records every trust proof issuance, and the revocation of every logged trust proof or credential, in an append-only Merkle tree compatible with RFC 6962. The authority publishes Signed Tree Heads, and an auditor checks inclusion proofs for single entries and consistency proofs between tree sizes, so an entry that was removed or rewritten is detectable.

What you can do today: the conformance suite carries a Signed Tree Head, a valid inclusion proof, a valid consistency proof and the tampered-path rejections for both.

```
git clone https://github.com/opena2a-standards/atp-conformance
cd atp-conformance/verifiers/go
go run . ../../fixtures
# summary: 14 pass, 0 fail (14 fixtures)
```

The verifier prints each fixture's expected and observed result, then a summary line of passes and failures.

Where it stops today: the transparency-log read endpoint that ATP-SPEC names for the reference authority, `/api/v1/transparency/trust-proofs`, answered HTTP 404 on 2026-10-08, so the live log cannot yet be audited from outside.

## You revoke an agent once and need every verifier to stop trusting it

A compromised agent holds a credential that is still valid. You need every verifier to stop honoring it, including verifiers run by other organizations that never call you.

ATP Section 8.1 defines the revocation list that verifiers fetch and cache. An entry whose timestamp cannot be parsed rejects the whole response, because silently skipping one entry would keep a revoked agent trusted.

What you can do today:

```
curl https://api.oa2a.org/api/v1/trust/revocations
```

The conformance suite pins the malformed-timestamp rejection and a Section 8.1 body, `fixtures/revocation-list-valid.json`, whose free-text `reason` predates the Section 8.1.1 codes and is not a Section 8.1.1 code: the current schema refuses it, and a client processes it as `unspecified`.

Where it stops today: the revocation response body is not signed; its authenticity rides on the transport. The reference authority publishes the list for polling and does not push it to federation peers. No fixture yet pins a registered reason code or an entry without `transparencyLogIndex` ([`ATP-SPEC.md`](../ATP-SPEC.md) Section 2.1 lists what fixtures do not cover).

Why you can check this yourself: [`ATP-SPEC.md`](../ATP-SPEC.md); [atp-conformance](https://github.com/opena2a-standards/atp-conformance), 14 byte-pinned fixtures with Go and Python verifiers; the live-endpoint scripts [`conformance/level1.sh`](../conformance/level1.sh) and [`conformance/level2.sh`](../conformance/level2.sh) that exercise a running authority; and the reference authority's live endpoints at `api.oa2a.org` (`/.well-known/atp`, `/api/v1/trust/proof`, `/api/v1/trust/verify`, `/api/v1/trust/revocations`).

## Why ATX

DIDs answer who an agent is. ATX answers what the agent is authorized to do, what its provenance is, what its observed behavior looks like, and what scanners have verified it. The W3C Verifiable Credentials Data Model 2.0 supports the issuer, subject, and claims pattern. ATX uses that pattern with agent-specific claims tuned for short TTLs, behavioral attestation, and continuous re-verification.

ATX is the credential primitive the agent internet needs. ATP is the protocol that defines it.
