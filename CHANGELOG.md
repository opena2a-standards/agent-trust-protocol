# Changelog

All notable changes to the Agent Trust Protocol specification are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the OpenA2A spec-family ladder `MAJOR.MINOR.PATCH-{draft|rcN|final}`.

## [Unreleased]

### Added

- Version header 1.1.0-draft: the 1.1 revision series is open on main.
- Section 5.1.1: the entry type registry, the one home of the transparency-log entry types
  for the family. Twelve registered names with bytes 0x01 to 0x0C (the seven rc1 types,
  `atx_issued`, `atx_revoked`, `work_attestation`, `work_attestation_superseded`,
  `work_attestation_refuted`), 0x0D to 0x7F unassigned, 0x80 to 0xFE private use (opaque to
  verifiers), closed per-type `data` members. `registries/transparency-entry-types.json` is
  generated from the table (name and byte uniqueness checked in CI).
- Section 5.2: the leaf hash is `SHA-256(0x00 || timestamp || entry_type_byte || JCS(data))`
  with the log-assigned members outside it; a log built before this revision publishes
  `leafFormatSince` (Section 7.1, discovery schema) as the boundary below which inclusion is
  verified against the served leaf hash only and reported as such.
- Section 2.1: leaf recomputation from a served entry listed as not yet covered by fixtures.
- Section 6.4.2: the inter-node revocation push. On each revocation entry the issuing
  authority POSTs the Section 8.1 object to every active peer (delivery attempted within 5
  seconds, completed within 60 seconds, acknowledged only after durable record, peer flagged
  unreachable after 30 seconds); a receiver persists a per-sender cursor, pulls after any gap
  and every 5 minutes without a push, and applies entries idempotently. The 6.4 delta feed is
  now 6.4.1. Section 8.1 states that a subscribed client still polls. The signed Section 8.1
  object (which the push then carries by reference) lands with the 1.1 signing revision.
- Section 4.4 step 5: a declared validity window longer than the Section 10.2 maximum is a
  verifier MUST-REJECT. `expiresAt` MUST NOT be more than 24 hours after `issuedAt`; a proof
  declaring a longer window is rejected with category `SEMANTIC_INVALID`, with no skew
  tolerance (the Section 10.2 skew bound never extends the window). Section 10.2 names the
  step that enforces it. The Section 2.1 fixture table gains
  `trust-proof-window-exceeds-max.json` (REJECT[SEMANTIC_INVALID]).

- One home per shared definition, marked for the family drift gate: Section 4.1
  is the home of the trust level numbers and names and of the 0.0-1.0 score scale
  (with the frozen ATX 1.1 wire exception recorded there); Section 4.2 states that
  `verdict` is the proof-outcome axis, distinct from level names; Section 10.2 carries
  the family clock-skew bound (60 seconds, symmetric, never extending a TTL).
  `registries/trust-levels.json` is generated from the Section 4.1 table by
  `scripts/gen_registries.py`, checked in CI.

### Changed

- Section 4.6: the five agent-specific claims (`capabilities`, `buildAttestation`,
  `behavioralProfile`, `scanSummary`, `declaredPurpose`) are no longer "Proposed (v1.1)";
  their status is "ATX v1.1 (signed in the ATX TBS)", which is what the reference issuer
  signs (atx-spec core.md Section 1.3a.2, field for field). The Section 4.2 note and the
  trust-proof schema description say the same; `slsaLevel` is illustrative and signed nowhere.
  A trust proof and an ATX credential are two signed artifacts with two canonical forms.
- Section 4.4 step 4: every declared signature entry verifies, and an ML-DSA-65 entry
  requires a verifying Ed25519 entry (the family signature gate, AAP Section 9.4);
  previously "at least one signature". Step 5 cites the Section 4.1 scale.
- Section 3.1: the DID form for signed artifacts cites the did:opena2a method
  specification (unescaped form, compare after normalization) instead of restating it.
- Examples: `did:opena2a:a2a_agent:` literals use the `agent` resource type (digits are
  not legal in a resource type; `a2a_agent` is the deprecated alias).

- §5.4 Inclusion Proof and §5.5 Consistency Proof: normative JSON response
  bodies pinned (previously endpoint-plus-prose only). The §5.4 body embeds
  the §5.6 signed tree head and is verified in two ordered rules (STH
  signature, then RFC 9162 §2.1.3.2 root recomputation → `PROOF_INVALID`);
  the §5.5 body carries both tree heads and the RFC 9162 §2.1.4.2 check.
  The examples are the exact bytes of the new atp-conformance
  `transparency-inclusion-proof-valid` / `transparency-consistency-proof-valid`
  fixtures (the §5.6 ratification pattern: spec example == fixture payload).
- §8.1: the revocation response body gains a machine-readable schema and a
  clients-MUST-reject-malformed-timestamps rule; documented that the body is
  unsigned (authenticity rides on transport + per-entry
  `transparencyLogIndex`), with response signing recorded as an open
  hardening question.
- `schemas/inclusion-proof-v1.schema.json`,
  `schemas/consistency-proof-v1.schema.json`,
  `schemas/revocation-list-v1.schema.json`; `examples-map.json` now validates
  the §5.4/§5.5/§8.1 examples on every push/PR.
  `scripts/validate_examples.py` resolves cross-schema `$ref`s (the proofs
  embed `signed-tree-head-v1`) from a local registry keyed by `$id` — never
  over the network.

- `schemas/trust-proof-v1.schema.json`, `schemas/signed-tree-head-v1.schema.json`,
  `schemas/discovery-v1.schema.json`: machine-readable JSON Schemas
  (draft 2020-12) for the three fixture-backed ATP wire structures, derived
  from §4.2/§5.6/§7.1 with the atp-conformance fixtures as ground truth (all
  seven fixture payloads validate).
- `scripts/validate_examples.py` + `schemas/examples-map.json` + CI workflow:
  schemas metaschema-checked and the §4.2/§5.6/§7.1 examples validated on
  every push/PR.
- §5.6: `signedBy` (fragment-qualified key reference) ratified into the STH —
  first pinned by the conformance suite; the signature is computed over the 32
  raw bytes decoded from `rootHash`.
- §7.1: suite-pinned wire shapes ratified as normative — `transparencySth`
  endpoint key casing, `publicKeyHex` key material with per-key `status` /
  `validFrom`, full-DID `keyId` values, `supportedMethods: ["did:opena2a"]`;
  required-member set documented (`authorityDid`, `version`, `endpoints`,
  `publicKeys`).
- §2.1 Conformance testing: per-level traceability table mapping every
  `atp-conformance` byte-stable fixture to the spec section it tests and its
  pinned verdict; explicit list of requirements not yet fixture-covered;
  relationship between the fixture suite and the in-repo live-endpoint scripts.
- §7.1 legacy-path migration rule: `/.well-known/atp` is normative; the
  reference implementation's `/.well-known/opena2a` is a legacy path that must
  gain the normative alias before v1.0.0-final; consumer fallback and
  identical-document requirements specified. Appendix A row updated to match.
- This changelog.

### Changed

- §4.2/§5.6/§7.1 example blocks now carry conformance-fixture bytes (artifacts
  that verify against the reference verifiers) instead of placeholders; the
  Proposed v1.1 fields (`slsaLevel`, `scanSummary`) moved out of the §4.2
  example, which now shows exactly the rc1 canonical-form-covered shape.
- §3.1/§3.4 examples and §11: `a2a_agent` example tokens replaced with the
  registered `agent` type (`a2a_agent` documented as a deprecated legacy
  alias); the type list now defers to the did-method-opena2a registry; the two
  leftover `did:atp` references from v1.0.0-draft corrected to `did:opena2a`.

## [1.0.0-rc1] - 2026-04-28

### Changed

- DID method prefix reconciled from `did:atp:` (v1.0.0-draft) to
  `did:opena2a:` to match the production reference implementation. No other
  normative changes. (#1)

### Added (post-rc1 documentation, 2026-05-19 → 2026-06-08)

- ATX introduced as the named credential format; W3C VC interop notes;
  §4.6 Agent Trust eXtension section and v1.1-draft example file. (#2, #3)
- `declaredPurpose` documented as a proposed v1.1 ATX claim, aligned with
  ATX 1.1 §1.5. (#4)
- OpenA2A specs family header.

## [1.0.0-draft] - 2026-03-22

### Added

- Initial specification: terminology, conformance levels, agent identifiers
  (DID format/document/resolution, A2A agent-card integration), trust proofs
  (format, signing, verification, retrieval), transparency log (RFC 6962
  Merkle tree, STH, proofs, external anchoring), federation (tiers, trust
  elevation, emergency block, sync), discovery, revocation, security
  considerations.
- Live-endpoint conformance scripts for Levels 1 and 2.
- Integration examples for A2A, MCP, and CI/CD.
