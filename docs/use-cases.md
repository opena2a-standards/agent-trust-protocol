# Use cases: recorded observations

The [README](../README.md#use-cases) states each use case as it stands today. This page keeps the dated observations, counts and background that left the README's text, as written, under the use case each one qualifies.

## Should I trust this agent right now, and who says so

What you can do today: the [Quick Start](../README.md#quick-start) fetches a live proof from the reference authority and checks it. On 2026-10-08 the verify call returned `{"valid":true,"expired":false,"issuerOk":true,"signatureOk":true}`, and the authority's discovery document also answered at `https://api.oa2a.org/.well-known/atp`.

## Your auditor asks whether this agent was trusted at 02:14

```
git clone https://github.com/opena2a-standards/atp-conformance
cd atp-conformance/verifiers/go
go run . ../../fixtures
# summary: 14 pass, 0 fail (14 fixtures)
```

Where it stops today: the transparency-log read endpoint that ATP-SPEC names for the reference authority, `/api/v1/transparency/trust-proofs`, answered HTTP 404 on 2026-10-08, so the live log cannot yet be audited from outside.

## You revoke an agent once and need every verifier to stop trusting it

The conformance suite pins the malformed-timestamp rejection and a Section 8.1 body, `fixtures/revocation-list-valid.json`, whose free-text `reason` predates the Section 8.1.1 codes: the current schema refuses it, and a client processes it as `unspecified`.

Why you can check this yourself: [`ATP-SPEC.md`](../ATP-SPEC.md); [atp-conformance](https://github.com/opena2a-standards/atp-conformance), 14 byte-pinned fixtures with Go and Python verifiers; the live-endpoint scripts [`conformance/level1.sh`](../conformance/level1.sh) and [`conformance/level2.sh`](../conformance/level2.sh) that exercise a running authority; and the reference authority's live endpoints at `api.oa2a.org` (`/.well-known/atp`, `/api/v1/trust/proof`, `/api/v1/trust/verify`, `/api/v1/trust/revocations`).

## Why ATX

DIDs answer who an agent is. ATX answers what the agent is authorized to do, what its provenance is, what its observed behavior looks like, and what scanners have verified it. The W3C Verifiable Credentials Data Model 2.0 supports the issuer, subject, and claims pattern. ATX uses that pattern with agent-specific claims tuned for short TTLs, behavioral attestation, and continuous re-verification.
