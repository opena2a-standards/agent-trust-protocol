# Changelog

All notable changes to the Agent Trust Protocol specification are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the OpenA2A spec-family ladder `MAJOR.MINOR.PATCH-{draft|rcN|final}`.

## [Unreleased]

### Added

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
