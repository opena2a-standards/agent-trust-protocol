# Changelog

All notable changes to the Agent Trust Protocol specification are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the OpenA2A spec-family ladder `MAJOR.MINOR.PATCH-{draft|rcN|final}`.

## [Unreleased]

### Added

- §2.1 Conformance testing: per-level traceability table mapping every
  `atp-conformance` byte-stable fixture to the spec section it tests and its
  pinned verdict; explicit list of requirements not yet fixture-covered;
  relationship between the fixture suite and the in-repo live-endpoint scripts.
- §7.1 legacy-path migration rule: `/.well-known/atp` is normative; the
  reference implementation's `/.well-known/opena2a` is a legacy path that must
  gain the normative alias before v1.0.0-final; consumer fallback and
  identical-document requirements specified. Appendix A row updated to match.
- This changelog.

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
