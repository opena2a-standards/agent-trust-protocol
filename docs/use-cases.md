# Use cases

This page states each use case as it stands today: what you can do, where it stops, and the dated observations, counts and background under the use case each one qualifies. It opens with who reads the specification and where each reader's question is answered.

## Who reads this

Each row names a reader, the question that brings them here and the text that answers it. An `ATP-SPEC.md:N` reference is the line in `ATP-SPEC.md` at the commit that added this table; the section link stays stable when lines move.

| Reader | The question they bring | Where it is answered |
|---|---|---|
| Security leader or CISO | Which trust authorities may our agents rely on, at what level, and which threats does that level leave open? | [You have to say which trust authorities your agents may rely on](#you-have-to-say-which-trust-authorities-your-agents-may-rely-on); the conformance levels of [Section 2](../ATP-SPEC.md#2-conformance-levels) (`ATP-SPEC.md:54`); the threat model of [Section 10.1](../ATP-SPEC.md#101-threat-model) (`ATP-SPEC.md:1330`) |
| IAM professional or identity architect | Is a trust proof one more token to manage, and how does it relate to the DIDs and Verifiable Credentials I handle? | [Your identity team asks how a trust proof relates to DIDs and credentials](#your-identity-team-asks-how-a-trust-proof-relates-to-dids-and-credentials); agent identifiers, [Section 3](../ATP-SPEC.md#3-agent-identifiers) (`ATP-SPEC.md:116`); the [Verifiable Credential form](../ATP-SPEC.md#verifiable-credential-form) of Section 4.6 (`ATP-SPEC.md:617`); the standards ATP is designed to complement, [`docs/interoperability.md`](interoperability.md) |
| Platform or security engineer | How do I check proofs and the revocation list, and what does a failure look like? | [Should I trust this agent right now](#should-i-trust-this-agent-right-now-and-who-says-so); [You revoke an agent once](#you-revoke-an-agent-once-and-need-every-verifier-to-stop-trusting-it); the ordered checks of [Section 4.4](../ATP-SPEC.md#44-verification) (`ATP-SPEC.md:449`); revocation, [Section 8.1](../ATP-SPEC.md#81-trust-proof-revocation) (`ATP-SPEC.md:1201`); validity and clock skew, [Section 10.2](../ATP-SPEC.md#102-trust-proof-validity) (`ATP-SPEC.md:1345`) |
| Agent developer or implementer | What do I implement first, and how do I show it conforms? | Level 1 of [Section 2](../ATP-SPEC.md#level-1-basic-trust-single-authority) (`ATP-SPEC.md:58`); the fixture table and the pinned-verdict rule of [Section 2.1](../ATP-SPEC.md#21-conformance-testing) (`ATP-SPEC.md:87`, `ATP-SPEC.md:91`); the live-endpoint scripts in [`conformance/`](../conformance/README.md) |
| GRC, audit or compliance reader | What was an agent's trust state at a given moment, and which record proves it? | [Your auditor asks whether this agent was trusted at 02:14](#your-auditor-asks-whether-this-agent-was-trusted-at-0214); the transparency log of [Section 5](../ATP-SPEC.md#5-transparency-log) (`ATP-SPEC.md:658`) and its Signed Tree Head, [Section 5.6](../ATP-SPEC.md#56-signed-tree-head) (`ATP-SPEC.md:855`). The specification maps to no control framework; OASB appears only in the references of [Section 12](../ATP-SPEC.md#12-references) |
| Standards reviewer (IETF or AIW participant) | What does ATP add to the standards it names, and how mature is the text? | the standards ATP is designed to complement, in the abstract (`ATP-SPEC.md:28`) and [`docs/interoperability.md`](interoperability.md); [Section 11](../ATP-SPEC.md#11-iana-considerations) (`ATP-SPEC.md:1373`); the version line at the top of [`ATP-SPEC.md`](../ATP-SPEC.md) and [`CHANGELOG.md`](../CHANGELOG.md); the [README](../README.md), which says that Level 3 federation is specified and not yet demonstrated |

### The readers

- **Security leader or CISO**
  - Who: accountable for the organization's security risk, and for which agents and vendors may act on its systems.
  - Why they open it: the organization's agents are about to act on trust proofs from an authority it does not run.
  - What they decide: which conformance level to require of the authorities their agents rely on, and which threats that level leaves open.
  - How they verify: the level an authority declares in its discovery document, the pinned fixture verdicts for that level, and a run of the live-endpoint scripts against the running authority.
- **IAM professional or identity architect**
  - Who: runs the identity systems the organization already has, such as OAuth 2.0 and OpenID Connect, X.509 certificates, workload identity such as SPIFFE, DIDs and privileged access management.
  - Why they open it: they need to know whether a trust proof is one more token to manage or a statement that fits the DIDs and credentials they already handle.
  - What they decide: where proofs are fetched and checked, which authority keys to trust, and whether to carry ATX in its Verifiable Credential form.
  - How they verify: Sections 3 and 4.6, and `python3 scripts/validate_examples.py`, which checks the Verifiable Credential mapping.
- **Platform or security engineer**
  - Who: deploys, operates and monitors the components that check agents at runtime, and is paged when they fail.
  - Why they open it: they run the verifier and the revocation-list polling and need to know what fails and how it shows.
  - What they decide: how long to cache a proof (24 hours at most), how often to refresh the discovery document (its copy may be at most one hour old), how often to poll the revocation list, and how much clock skew to allow (60 seconds at most).
  - How they verify: the atp-conformance fixtures, and the live-endpoint scripts in `conformance/` against the authority they rely on.
- **Agent developer or implementer**
  - Who: writes the trust authority, the verifier or the agent that presents a proof.
  - Why they open it: they have to issue or check proofs that other implementations accept.
  - What they decide: which conformance level to implement and declare.
  - How they verify: the pinned verdict on every fixture covering that level (Section 2.1), and `level1.sh` or `level2.sh` against their running authority.
- **GRC, audit or compliance reader**
  - Who: maps controls to evidence and reads the records an auditor asks for.
  - Why they open it: an auditor asks what an agent's trust state was when it acted.
  - What they decide: whether transparency-log inclusion and consistency proofs are evidence they accept, and which control each supports.
  - How they verify: the transparency fixtures of atp-conformance, and inclusion proofs checked against a Signed Tree Head where the authority serves its log for reading.
- **Standards reviewer (IETF or AIW participant)**
  - Who: a participant in an IETF or AIW discussion who judges whether a problem needs new work.
  - Why they open it: to see what ATP adds beside A2A, SLSA, Sigstore, Certificate Transparency and W3C DID Core, which it is designed to complement.
  - What they decide: whether to review, implement or co-author it, and what to ask the editors to change.
  - How they verify: the version line of `ATP-SPEC.md`, the conformance suite, and whether a second authority or an independent implementation exists.

## Should I trust this agent right now, and who says so

Before you let an agent in or install an MCP server, you want a signed statement from a party you can identify, not a star rating on a listing page. You also want to check that statement yourself, with the authority's published key, so a compromised listing cannot forge it.

ATP defines the trust proof: a short-lived signed statement of an agent's trust level, score and verdict, signed with Ed25519 (and with ML-DSA-65 as well in hybrid mode), valid for at most 24 hours, and verifiable against the authority's published keys.

What you can do today: the [Quick Start](../README.md#quick-start) fetches a live proof from the reference authority and checks it. On 2026-10-08 the verify call returned `{"valid":true,"expired":false,"issuerOk":true,"signatureOk":true}`, and the authority's discovery document also answered at `https://api.oa2a.org/.well-known/atp`.

Where it stops today: `POST /api/v1/trust/verify` asks the authority to check its own proof, which puts the authority on the verification path. The conformance verifiers check the same proof shape locally with the published key, and that is the path a relying party should build on.

Who acts: the platform or security engineer who checks a proof before an agent or MCP server is let in, and the developer whose client fetches it.

Spec text: the trust proof format and signing of [Section 4.2](../ATP-SPEC.md#42-trust-proof-format) (`ATP-SPEC.md:265`) and [Section 4.3](../ATP-SPEC.md#43-signing) (`ATP-SPEC.md:303`); the checks a verifier MUST perform in order, [Section 4.4](../ATP-SPEC.md#44-verification) (`ATP-SPEC.md:449`); and the 24-hour maximum validity of [Section 10.2](../ATP-SPEC.md#102-trust-proof-validity) (`ATP-SPEC.md:1347`).

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

Who acts: the auditor or GRC reader, and the trust authority that keeps the log.

Spec text: the transparency log of [Section 5](../ATP-SPEC.md#5-transparency-log) (`ATP-SPEC.md:658`), its inclusion and consistency proofs, [Section 5.4](../ATP-SPEC.md#54-inclusion-proof) (`ATP-SPEC.md:759`) and [Section 5.5](../ATP-SPEC.md#55-consistency-proof) (`ATP-SPEC.md:805`), and its Signed Tree Head, [Section 5.6](../ATP-SPEC.md#56-signed-tree-head) (`ATP-SPEC.md:855`). The log is a requirement of [Level 2](../ATP-SPEC.md#level-2-auditable-trust-single-authority--transparency) (`ATP-SPEC.md:67`).

## You revoke an agent once and need every verifier to stop trusting it

A compromised agent holds a credential that is still valid. You need every verifier to stop honoring it, including verifiers run by other organizations that never call you.

ATP Section 8.1 defines the revocation list that verifiers fetch and cache. An entry whose timestamp cannot be parsed rejects the whole response, because silently skipping one entry would keep a revoked agent trusted.

What you can do today:

```
curl https://api.oa2a.org/api/v1/trust/revocations
```

The conformance suite pins the malformed-timestamp rejection and a Section 8.1 body, `fixtures/revocation-list-valid.json`, whose free-text `reason` predates the Section 8.1.1 codes and is not a Section 8.1.1 code: the current schema refuses it, and a client processes it as `unspecified`.

Where it stops today: the revocation response body is not signed; its authenticity rides on the transport. The reference authority publishes the list for polling and does not push it to federation peers. No fixture yet pins a registered reason code or an entry without `transparencyLogIndex` ([`ATP-SPEC.md`](../ATP-SPEC.md) Section 2.1 lists what fixtures do not cover).

Who acts: the security engineer who revokes the agent, and every verifier that relies on the authority.

Spec text: the revocation list of [Section 8.1](../ATP-SPEC.md#81-trust-proof-revocation) (`ATP-SPEC.md:1201`) and its reason codes, [Section 8.1.1](../ATP-SPEC.md#811-revocation-reason-registry) (`ATP-SPEC.md:1265`); key revocation, [Section 8.2](../ATP-SPEC.md#82-key-revocation) (`ATP-SPEC.md:1293`); and the revocation push between federated authorities, [Section 6.4.2](../ATP-SPEC.md#642-revocation-push) (`ATP-SPEC.md:966`).

## You have to say which trust authorities your agents may rely on

Your agents are about to act on trust proofs from an authority you do not run. One authority signs proofs and keeps no public record. Another records every proof it issues in a log that anyone can audit. A third will not vouch at the highest levels until a second, independent authority co-signs. You have to say which of these is acceptable before anyone relies on them.

Who acts: the security leader, writing the requirement for the authorities the organization's agents may rely on.

Without the specification: "trusted by our registry" means whatever the registry's operator says it means, and nothing distinguishes an authority that keeps an audit trail from one that does not.

What the specification does: every implementation MUST declare the conformance level it meets ([Section 2](../ATP-SPEC.md#2-conformance-levels), `ATP-SPEC.md:56`). Level 1 signs proofs and resolves agent DIDs; Level 2 adds the transparency log and revocation; Level 3 adds federation, with co-signing by several authorities for trust level 3 and above. The threat model of [Section 10.1](../ATP-SPEC.md#101-threat-model) (`ATP-SPEC.md:1330`) names each threat with its defense and the level that provides it: silent trust manipulation needs Level 2 (`ATP-SPEC.md:1339`), and removing the single point of failure needs Level 3 (`ATP-SPEC.md:1340`). An implementation claiming a level MUST produce the pinned verdict on every fixture covering that level ([Section 2.1](../ATP-SPEC.md#21-conformance-testing), `ATP-SPEC.md:91`), and a public authority SHOULD also pass the live-endpoint scripts (`ATP-SPEC.md:112`). A proof is valid for 24 hours at most ([Section 10.2](../ATP-SPEC.md#102-trust-proof-validity), `ATP-SPEC.md:1347`), which bounds how long a stale statement can be used.

What to require, in the specification's terms: the level the authority declares in its discovery document, the pinned verdicts for that level, and a passing run of the live-endpoint scripts for that level against the running authority.

How to see it work: an authority declares its level in its discovery document. On 2026-10-30 the reference authority answered:

```sh
curl -s https://api.oa2a.org/.well-known/atp | jq .conformanceLevel
# 1
```

A verifier refuses a proof from an issuer it does not trust, and a proof whose validity window is longer than 24 hours:

```sh
git clone https://github.com/opena2a-standards/atp-conformance
cd atp-conformance/verifiers/go
go run . ../../fixtures/trust-proof-untrusted-issuer.json ../../fixtures/trust-proof-window-exceeds-max.json
```

Output at atp-conformance commit `24187d4`, run on 2026-10-30:

```
PASS  ../../fixtures/trust-proof-untrusted-issuer.json  [trustProof]
       expected: REJECT [UNTRUSTED_ISSUER]
       observed: REJECT[UNTRUSTED_ISSUER: issuer DID did:opena2a:authority:opena2a.org is not in the verifier's trusted set]
PASS  ../../fixtures/trust-proof-window-exceeds-max.json  [trustProof]
       expected: REJECT [SEMANTIC_INVALID]
       observed: REJECT[SEMANTIC_INVALID: validity window exceeds 24 hours]

summary: 2 pass, 0 fail (2 fixtures)
```

Out of scope: Level 3 is specified and not demonstrated, because no second authority co-signs proofs yet (see the [README](../README.md)); the live-endpoint scripts have no Level 3 script ([`conformance/README.md`](../conformance/README.md)). Which authorities to trust is the relying party's decision; the specification defines how a proof from one is checked, not who should be trusted.

## Your identity team asks how a trust proof relates to DIDs and credentials

Your identity team already resolves DIDs for some partners and is evaluating W3C Verifiable Credentials. Before agreeing to consume ATP trust proofs, they want to know whether a proof is one more token format to manage or something that fits what they already handle.

Who acts: the IAM professional or identity architect.

Without the specification: each registry names agents its own way and answers in its own format, so a consumer writes and maintains a separate integration for each one.

What the specification does: every agent is named by a DID conforming to W3C DID Core ([Section 3.1](../ATP-SPEC.md#31-did-format), `ATP-SPEC.md:118`) that resolves to a DID Document ([Section 3.2](../ATP-SPEC.md#32-did-document), `ATP-SPEC.md:151`). A trust proof is a signed assertion about an agent's trust level, issued by a trust authority (Section 1), and a verifier MUST check its expiry, that its issuer resolves to a known trust authority, that each signing key is valid and not revoked, and every declared signature, in that order ([Section 4.4](../ATP-SPEC.md#44-verification), `ATP-SPEC.md:449`). An A2A agent that participates in ATP SHOULD carry its DID and a current proof in its agent card ([Section 3.4](../ATP-SPEC.md#34-integration-with-a2a-agent-cards), `ATP-SPEC.md:204`). The ATX credential maps member for member onto the W3C Verifiable Credentials Data Model 2.0: `issuerDid` to `issuer`, `did` to `credentialSubject.id`, and `issuedAt` and `expiresAt` to `validFrom` and `validUntil` ([Verifiable Credential form](../ATP-SPEC.md#verifiable-credential-form), Section 4.6, `ATP-SPEC.md:617`).

How to see it work: the repository validates the Verifiable Credential form of its ATX example against the schema and the mapping table. From a clone of this repository, with the Python `jsonschema` package installed:

```sh
python3 scripts/validate_examples.py | grep -E "atx-vc|mapped examples"
```

Output on 2026-10-30, at the commit that added this use case:

```
schema OK      schemas/atx-vc-v1.schema.json
example OK     examples/atx-vc-example.json
all schemas and mapped examples valid
```

Out of scope: the specification defines no mapping onto OAuth 2.0, OpenID Connect, SPIFFE or an X.509 certificate profile. The mapped Verifiable Credential form is not secured by a Verifiable Credentials securing mechanism; its ATX signatures are verified on the ATX credential the mapping recovers.

## Why you can check this yourself

Why you can check this yourself: [`ATP-SPEC.md`](../ATP-SPEC.md); [atp-conformance](https://github.com/opena2a-standards/atp-conformance), 14 byte-pinned fixtures with Go and Python verifiers; the live-endpoint scripts [`conformance/level1.sh`](../conformance/level1.sh) and [`conformance/level2.sh`](../conformance/level2.sh) that exercise a running authority; and the reference authority's live endpoints at `api.oa2a.org` (`/.well-known/atp`, `/api/v1/trust/proof`, `/api/v1/trust/verify`, `/api/v1/trust/revocations`).

## Why ATX

DIDs answer who an agent is. ATX answers what the agent is authorized to do, what its provenance is, what its observed behavior looks like, and what scanners have verified it. The W3C Verifiable Credentials Data Model 2.0 supports the issuer, subject, and claims pattern. ATX uses that pattern with agent-specific claims tuned for short TTLs, behavioral attestation, and continuous re-verification.

ATX is the credential primitive the agent internet needs. ATP is the protocol that defines it.
