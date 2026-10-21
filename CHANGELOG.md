# Changelog

All notable changes to the Agent Trust Protocol specification are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the OpenA2A spec-family ladder `MAJOR.MINOR.PATCH-{draft|rcN|final}`.

## [Unreleased]

### Added

- `clients/python`: `verify_trust_proof` applies Section 4.4 step 7 (conformance Level 3)
  when it is given `second_authorities`, which maps the DID of each authority the verifier
  knows as a second authority to that authority's Section 7.1 `publicKeys` entries. A
  signature whose `keyId` names one of those DIDs resolves only among that authority's
  entries, so a key the issuer lists under the co-signer's `keyId` does not verify the
  co-signer's entry. A proof at trust level 3 or 4 is then rejected with `SIGNATURE_INVALID`
  unless an Ed25519 signature verified under a key of one of those authorities, and that
  authority shares no public key with the issuer's entries in `keys`. Without
  `second_authorities` step 7 is not checked, as before, and the 14 fixture copies keep their
  pinned verdicts. The tests cover a proof two authorities sign at trust levels 3 and 4, the
  issuer's entry twice, a second key of the issuer, a signer outside the mapping, a key shared
  with the issuer (also in upper-case hex, and revoked), a forged and an unlisted co-signer
  key, ML-DSA-65 entries, `AtpClient.verify` with one authority's discovery document, and the
  Section 4.4.1 proof under the keys of its table, which fails step 7 without the co-signer's
  entry. `clients/README.md` documents the parameter. A second authority deployed under its
  own keys, and a proof it co-signs pinned in the atp-conformance suite, are not yet done.
- `clients/python`: a Python client, installed with `pip install ./clients/python` (not
  published). `AtpClient` fetches the discovery document (falling back to
  `/.well-known/opena2a` on 404) and a trust proof (unwrapped from `proof`, refused when it is
  about another DID), and verifies the proof offline with the discovery document's keys. The
  verify functions check a trust proof (Section 4.4 steps 1 to 5, Ed25519 and ML-DSA-65,
  without the issuer key set count of step 4), a discovery document, a signed tree head,
  inclusion and consistency proofs (RFC 9162) and a revocation response, and return a reject
  category and reason. Text a reason takes from the input, such as a DID, a `keyId`, an
  algorithm or a `verdict`, is unchanged when it is printable ASCII without a space, a quote
  or a backslash, and in JSON string form otherwise, and an `endpoints` member name that is
  not an identifier is written `endpoints["name"]`: for `"endpoints": {"x\ny": "z"}` the
  reason is `endpoints["x\ny"] does not start with /`, with no line break in it.
  `verify_discovery` refuses with `PARSE_ERROR`, naming the member, an
  `endpoints` value that is not a string, does not start with `/`, or holds `#`, whitespace
  or a control character (Section 7.1). A trust proof whose `did`, `verdict` or `issuerDid`
  holds a lone surrogate, which UTF-8 cannot encode, and a discovery document with a
  `publicKeys` entry whose `algorithm` is a JSON array or object are refused with
  `PARSE_ERROR`, naming the member. The client does not count a Section 7.1.1 issuer
  key set, so `verify_discovery` refuses a discovery document that carries `issuerKeySet` with
  `SIGNATURE_INVALID` and `AtpClient.verify` verifies no proof of an authority that declares
  one; `verify_trust_proof` receives keys without the set and is for an authority that
  declares none. `clients/fixtures` holds byte copies of the 14 atp-conformance fixtures with
  their SHA-256 manifest; the tests check the copies against it and that the client gives each
  fixture its pinned verdict and category. `clients/README.md` documents the client and the
  fixture copies.
- `clients/typescript`: a TypeScript client, `@opena2a/atp-client`, built in that directory
  with `npm ci` and `npm run build` and added to a project with
  `npm install <path to clients/typescript>` (not published). It has the Python client's
  functions, named in camelCase (`getTrustProof`, `verify`, `verifyTrustProof` and the
  others), and no runtime dependencies: it checks Ed25519 and ML-DSA-65 signatures with the
  Node.js `crypto` module. It does not make two of the Python client's checks:
  `verifyTrustProof` has no counterpart of `second_authorities`, so it never applies
  Section 4.4 step 7, and `verifyDiscovery` accepts any non-empty string as an `endpoints`
  value, where `verify_discovery` requires a Section 7.1 path. It writes `trustScore` into
  the canonical string from the number's exact binary value with a tie to even, as `%.6f`
  does, where `toFixed(6)` rounds a tie up; it counts transparency log positions with
  `BigInt`, so a proof from a log of more than 2^32 entries verifies; and it refuses a `did`,
  `verdict` or `issuerDid` that holds a lone surrogate, which UTF-8 cannot encode, with
  `PARSE_ERROR`, as the Python client does. `getTrustProof` throws a `TypeError` for a `did`
  that holds a lone surrogate, before it sends a request. Its tests check the 14 fixture
  copies against their manifest and that the client gives each fixture its pinned verdict and
  category; `npm test` builds and runs them, and on a Node.js that cannot generate ML-DSA-65
  keys, as 22.23.3 cannot, skips the one test that generates them and prints why.
  `clients/README.md` documents both clients.
- Version header 1.1.0-draft: the 1.1 revision series is open on main.
- Section 4.4.1: a two-authority proof for Level 3. It is the Section 4.2 proof with an
  Ed25519 entry of `did:opena2a:authority:cosigner.example` added over the same Section 4.3
  canonical string, and a table gives the public key each `keyId` names. Both keys are
  fixture keys: the issuer's is the Section 7.1 example's `#key-1`, the RFC 8032 Section 7.1
  TEST 1 key, and the co-signer's is the TEST 2 key, and RFC 8032 publishes the secret key of
  each. The proof shows the wire form and the step 7 rule, not a federation in operation, and
  it is not a conformance-suite fixture. `scripts/validate_examples.py` verifies both Ed25519
  signatures with RFC 8032 verification written in Python integers, so CI still installs no
  package beyond `jsonschema`, and checks that the proof passes Section 4.4 steps 3, 4 and 7
  under the table's keys and fails step 7 with the entries of `issuerDid` alone; the examples
  map validates the block against the trust-proof schema. `scripts/test_checks.py` covers the
  rule's refusals (the issuer's entry twice, one key under two DIDs, a second DID sharing a
  key with the issuer, a second key of the issuer, a changed signature, a key the verifier
  does not know, an entry of another algorithm) and the verification's (a changed message,
  an S not below the group order, an encoding of no point, a wrong length), and its
  `checks.jq` agreement test now runs on the proof and its edits as well. The abstract, the
  README headline and the Section 2.1 coverage list point to the proof; federation stays
  specified and not yet demonstrated, since no second authority co-signs proofs.
- Section 4.3.1: the Sigstore co-signature the abstract and README listed, which the
  trust-proof schema refused. It is a `signatures[]` entry with `algorithm: "Sigstore"`,
  `keyId` set to the certificate identity, and a Sigstore v0.3 `bundle` (message signature
  over the Section 4.3 canonical string, signing certificate, at least one `hashedrekord`
  Rekor entry with an inclusion proof) in place of `value`. A verifier checks the message
  digest and signature, Rekor inclusion and signing time, the Fulcio chain, and the
  certificate identity against identities it configures itself for the issuer, never ones
  the proof supplies; any failure is `SIGNATURE_INVALID`. The co-signature does not replace
  the Ed25519 signature and does not count toward step 7 or Section 6 co-signing. Section
  4.4 steps 3, 4 and 7 point to it, and step 4 requires every proof to carry a verifying
  Ed25519 entry whose `keyId` resolves to a key of `issuerDid`, which a Sigstore entry never
  satisfies. `schemas/trust-proof-v1.schema.json` gains the entry as a second
  `signatures[]` branch and requires every proof to carry at least one authority signature
  (`contains`, which `conformance/checks.jq` now implements, so T1.9 fails a proof whose only
  signatures are Sigstore entries). The 4.3.1 example is validated in CI, and
  `validate_examples.py` checks that the schema refuses an entry without a bundle, with a
  `value` beside it, in another bundle version, with a DSSE envelope, a public key or a
  certificate chain, or without a Rekor entry carrying an inclusion proof, and a proof whose
  only signatures are Sigstore entries. Section 2.1 lists co-signature verification as not
  yet covered by byte-stable fixtures.
- Section 7.1.1: the issuer key set, the multi-key threshold signing the Section 10.1 threat
  model once listed without defining it. A discovery document MAY carry `issuerKeySet`, an
  m-of-n set of the authority's Ed25519 keys: `threshold` is m, and `keyIds` lists the n keys,
  each the `keyId` of an Ed25519 entry of `publicKeys`, none twice and no two with the same
  `publicKeyHex`, with m at most n. Section 4.4 step 4 requires a proof of an authority that
  declares a set to be signed by at least `threshold` distinct keys of it: a key counts once
  however many entries carry its `keyId`, an entry outside the set, an ML-DSA-65 entry and a
  Sigstore entry count toward no key, and a proof short of the threshold is rejected with
  `SIGNATURE_INVALID`, as is every proof of an authority whose set breaks the rules. Keys of
  one set never count as the distinct authorities of step 7. An authority publishes a set,
  raises its threshold or removes a key only when every proof it served in the previous 24
  hours meets the new set; a key it revokes leaves the set at once. The Section 10.1 row for
  signing key compromise names the set beside key revocation and the 24-hour validity.
  `schemas/discovery-v1.schema.json` gains the member; `scripts/validate_examples.py` checks
  each mapped discovery example the schema accepts against the rules the schema cannot
  express, and the Section 7.1.1 example, a 2-of-3 set, is validated in CI. Section 2.1 lists
  the count as not yet covered by fixtures.
- Section 4.4.2: a proof that meets an issuer key set, and two edits of it that the count
  rejects. Two keys of the 2-of-3 set of the Section 7.1.1 example, `#key-1` and `#key-2`,
  sign it over the Section 4.3 canonical string. The example's three keys are the RFC 8032
  Section 7.1 TEST 2, TEST 3 and TEST SHA(abc) keys, and RFC 8032 publishes their secret keys,
  so the proof shows the wire form and the count, not a key set in operation. Without its
  `#key-2` entry, and with its `#key-1` entry in place of that entry (one `keyId` twice, which
  counts once), one key of the set signed it, and Section 4.4 step 4 rejects it.
  `scripts/validate_examples.py` verifies both signatures under the keys of the Section 7.1.1
  example, and checks that the proof meets the set and that each edit breaks the count and no
  other rule of steps 3, 4 and 7; the examples map validates the block against the
  trust-proof schema, and `schemas/discovery-v1.schema.json` joins the schemas the checks read
  by name, so a run without it is one failure line. `scripts/test_checks.py` covers the count
  (a key counts once however many entries carry it, and when any one of them verifies; an
  entry that does not verify, an entry outside the set, an ML-DSA-65 entry and a Sigstore
  entry count toward no key; a threshold of 1 is met by one key and a threshold of 3 is not
  met by two; no proof meets a set that breaks a Section 7.1.1 rule, and every proof meets a
  document without a set), and its `checks.jq` agreement test runs on the proof. Sections 4.4
  and 7.1.1 point to the proof, and Section 2.1 still lists the three cases as not yet covered
  by suite fixtures.
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
- Section 4.6 "Verifiable Credential Form": the mapping from an ATX credential to the W3C
  Verifiable Credentials Data Model 2.0 structure, one table row per member (`issuerDid` to
  `issuer`, `did` to `credentialSubject.id`, `issuedAt` and `expiresAt` to `validFrom` and
  `validUntil`, each claim under `credentialSubject`, `version` and `signatures` unchanged at
  the top level, constant `@context` and `type`). The section says what the mapped form is
  not: no Verifiable Credentials securing mechanism secures it, and its ATX signatures are
  verified on the ATX credential the mapping recovers. `examples/atx-vc-example.json` is
  `examples/atx-example.json` in that form and `schemas/atx-vc-v1.schema.json` is its shape.
  `scripts/validate_examples.py` reads the table from the specification and fails when the
  example differs from the table applied to the ATX example; an `examples-map.json` entry
  without a heading maps a whole JSON file, and a mapped file that is missing is one failure.
  An ATX example that is missing or not a JSON object stays one failure of the ATX check: the
  form is reported as not compared. The README called ATX "structurally compatible"
  with that data model and gave no mapping and no example; it now links the table, the
  example and the schema.

- One home per shared definition, marked for the family drift gate: Section 4.1
  is the home of the trust level numbers and names and of the 0.0-1.0 score scale
  (with the frozen ATX 1.1 wire exception recorded there); Section 4.2 states that
  `verdict` is the proof-outcome axis, distinct from level names; Section 10.2 carries
  the family clock-skew bound (60 seconds, symmetric, never extending a TTL).
  `registries/trust-levels.json` is generated from the Section 4.1 table by
  `scripts/gen_registries.py`, checked in CI.

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
  `transparencyLogIndex` where an entry carries one), with response signing
  recorded as an open hardening question.
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
  eight fixture payloads validate: six trust proofs, `discovery-valid` and
  `transparency-log-sth`).
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
  reference implementation's `/.well-known/opena2a` is a legacy path it serves
  as an optional alias of the normative one; consumer fallback until
  v1.1.0-final and identical-document requirements specified. Appendix A row
  updated to match.
- This changelog.

### Changed

- Section 4.4 step 7 names its reject category: a proof that fails the step is rejected with
  `SIGNATURE_INVALID`, the category of the step 4 rejections. Step 7 named no category.
  Section 4.4.1 names the Python client's step 7 check beside `scripts/validate_examples.py`.
- Section 4.4 step 7: the two-authority rule says when two signatures come from distinct
  authorities. They are two Ed25519 entries that verify in step 4, one under a key of
  `issuerDid` and one under a key of a second known trust authority, which the verifier knows
  from its own configuration and never because the proof or the issuer's discovery document
  names it. Two authorities are distinct only when their DIDs differ and no public key is a
  key of both, so a key published under two DIDs never counts as a second authority, and an
  ML-DSA-65 entry is not a second authority. Step 7 required "at least two signatures from
  distinct authorities" without saying when two authorities are distinct.
- Abstract and README headline: the trust response is cryptographically verifiable and
  auditable; a decentralized response (Section 6 federation, conformance Level 3) is stated
  as specified and not yet demonstrated, since no second authority co-signs proofs and no
  conformance fixture covers a co-signed proof. `scripts/validate_examples.py` fails a
  README.md or ATP-SPEC.md paragraph that calls ATP decentralized without saying so.
- Section 8.1: `transparencyLogIndex` is OPTIONAL per revocation entry; it was REQUIRED, so
  an authority revoking an agent it had logged nothing for (registered and revoked before
  its first proof) had to fabricate an index or omit the revocation, and omitting it kept
  the agent trusted at every verifier. The index is the log index of the revocation's own
  `trust_proof_revoked` or `atx_revoked` entry; an authority that logged a trust proof or
  credential for the agent MUST log the revocation and carry the index, so an entry without
  it revokes an agent with nothing logged. A client applies such an entry like any other,
  requires no inclusion proof for it, and never rejects the entry or the response for the
  missing index. Section 4.4 tells a verifier that step 3 is key revocation (Section 8.2)
  and that a Section 8.1 entry applies with or without the index. Section 6.4.2 pushes
  index-less revocations too and keys their idempotent apply on `agentDid` and `revokedAt`.
  `schemas/revocation-list-v1.schema.json` no longer requires the member, and
  `scripts/validate_examples.py` fails when the schema refuses an entry without it, accepts
  an index that is not an integer >= 0, or stops requiring another entry member. Section
  2.1 lists index-less entries as not yet fixture-covered.
- Section 4.6: the five agent-specific claims (`capabilities`, `buildAttestation`,
  `behavioralProfile`, `scanSummary`, `declaredPurpose`) are no longer "Proposed (v1.1)";
  their status is "ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2)", which is
  what the reference issuer signs (atx-spec core.md Section 1.3a.2, field for field). The Section 4.2 note and the
  trust-proof schema description say the same; `slsaLevel` is illustrative and signed nowhere.
  A trust proof and an ATX credential are two signed artifacts with two canonical forms.
- Section 4.6 schema table and the README ATX table: the base trust proof row's status is
  "Shipped (Section 4.3 canonical string and its signatures)", saying what is signed and
  where as the ATX v1.1 rows do; it was "Shipped (v1.0.0-rc1)". The release that shipped
  the base trust proof stays in the Section 4.6 text above the table.
- Section 4.4 step 4: every declared signature entry verifies, and an ML-DSA-65 entry
  requires a verifying Ed25519 entry (the family signature gate, AAP Section 9.4);
  previously "at least one signature". Step 5 cites the Section 4.1 scale.
- Section 3.1: the DID form for signed artifacts cites the did:opena2a method
  specification (unescaped form, compare after normalization) instead of restating it.
- Examples: `did:opena2a:a2a_agent:` literals use the `agent` resource type (digits are
  not legal in a resource type; `a2a_agent` is the deprecated alias).
- Section 8.1: `reason` is a registered code, no longer free text. The new Section 8.1.1
  registry holds `unspecified`, `content_hash_violation`, `security_incident`, `manual` and
  `expiry_reissuance_failed`, plus a private-use `x-` grammar (1 to 32 of `a-z`, `0-9`,
  `_`); no other value is a reason, so operator prose never reaches the unauthenticated,
  cross-organization response. A client applies a revocation whatever its `reason` and
  processes a code it does not recognise, or pre-1.1 free text, as `unspecified`. The
  `reason` of a `trust_proof_revoked` or `atx_revoked` log entry is the same code (Section
  5.1.1). The Section 8.1 example now reads `security_incident`;
  `schemas/revocation-list-v1.schema.json` admits only the registered codes and the
  private-use grammar; `registries/revocation-reasons.json` is generated from the table, and
  `scripts/validate_examples.py` fails when the schema's codes and the table differ or the
  schema accepts free text. Section 2.1 lists reason codes as not yet fixture-covered.
- §4.2/§5.6 example blocks now carry conformance-fixture bytes (artifacts
  that verify against the reference verifiers) instead of placeholders; the
  Proposed v1.1 fields (`slsaLevel`, `scanSummary`) moved out of the §4.2
  example, which now shows the seven rc1 canonical-form fields, `signatures`
  and `transparencyLogIndex`. The §7.1 example is illustrative: it differs
  from the `discovery-valid` fixture in `conformanceLevel` (3 against 2),
  `capabilities` (6 against 4), the `federation` endpoint and `federationPeers`
  (the fixture has neither) and its keys (1 against 2), and §7.1 says so.
- §3.1/§3.4 examples and §11: `a2a_agent` example tokens replaced with the
  registered `agent` type (`a2a_agent` documented as a deprecated legacy
  alias); the type list now defers to the did-method-opena2a registry; the two
  leftover `did:atp` references from v1.0.0-draft corrected to `did:opena2a`.
- README shortened to eight sections, with no dated observation or fixture count in its
  text and no version beside the link in its Specification section; its reference text
  moved, as written. The
  Interoperability list is in `docs/interoperability.md`; the dated observations, the fixture
  counts, the background of the revocation fixture's free-text `reason` and the full Why ATX
  paragraph are in `docs/use-cases.md`; the recorded reference authority response is in
  `docs/reference-implementation.md`. Related Standards joined a Documentation list that
  links each page, and the Quick Start opens with a link to Section 4.
  `scripts/test_checks.py` reads the Verifiable Credential claim from
  `docs/interoperability.md`.
- README shortened to seven sections, with the ecosystem line under the title. The Use cases
  section and the Why ATX subsection moved, as written, into `docs/use-cases.md`, which now
  holds each use case in full; the `declaredPurpose` row's authorization caveat is a sentence
  under the ATX table.
- Section 7.1: each `endpoints` value is a path on the authority, not a URL. It starts with
  `/` and holds no `#`, whitespace or control character; a client appends it to the
  authority URL and MUST NOT request a value that does not start with `/`, which would name
  another host (`.attacker.example/x` or `@attacker.example/x` after
  `https://api.oa2a.org`). `schemas/discovery-v1.schema.json` described `endpoints` as a
  path/URL map and now describes a path map; the schema does not yet refuse a value that is
  not a path. T1.7 already failed, without a request, on an `endpoints.trustProof` that does
  not start with `/`.
- Section 7.1: the authority URL is an `https` URL. An authority serves the discovery
  document and every endpoint over HTTPS and SHOULD send `Strict-Transport-Security`; a
  client sends no request under another scheme, follows no redirect to one and verifies the
  authority's certificate (RFC 9110 Section 4.3.4). An `http` authority URL whose host is a
  loopback address literal (`127.0.0.0/8` or `::1`; the name `localhost` is not one) is the
  one exception. A verifier uses no copy of the discovery document more than 3600 seconds
  old, counting the response's `Age` header (RFC 9111 Section 5.1), to verify a proof or
  signature of the authority, SHOULD obtain the document again every 5 minutes (the Section
  8.1 polling interval), and accepts no proof of an authority whose document it cannot obtain
  within that hour. An authority SHOULD send a `Cache-Control` `max-age` of at most 3600 and
  SHOULD publish a key at least an hour before it signs with it. Section 7.1.1 and Section
  8.1 name this transport, Section 8.2 step 2 states when a revoked key leaves a verifier's
  copy, Section 10.1 states that bound and adds a row for substitution of the discovery
  document in transit, and Section 2.1 lists both rules among those no fixture covers. The
  specification named no transport and no age before.
- README: the Reference Implementation section said the OpenA2A Registry implements ATP at
  Level 2 conformance. It now names the conformance tests the reference authority passes (T1.1
  to T1.6) and fails (T1.7 to T1.14 and T2.1 to T2.3), and says that its discovery document
  declares conformance level 1. `docs/reference-implementation.md` records the run of
  2026-10-21 and the answers behind each failure: the proof endpoint refuses the
  authority's own `did:atp:` DID with HTTP 400, the log is not served at the path `level2.sh`
  requests, and the revocation response has no `nextSince`. `scripts/test_checks.py` fails
  when the README's ranges differ from the recorded run or the section names a conformance
  level.

### Fixed

- Appendix B.1 and B.2 and the A2A and MCP integration guides: their `requests` and `fetch`
  calls followed redirects, the default of both libraries, so a 301 to an `http` URL sent
  the next request there, which Section 7.1 forbids. Given a 301 to `http` on both of its
  requests, B.1 returned the proof that the `http` answers carried. Each of the 13 calls now
  refuses a redirect: the Python calls pass `allow_redirects=False` and the TypeScript calls
  `redirect: "error"`. A redirect fails B.1's status check, so the peer is rejected, and
  makes B.2's `fetch` reject, so no connection is made; the guide samples raise
  `requests.HTTPError`, return an untrusted result or reject, the agent card and task
  requests included. The guides and Appendix B state the rule. The cURL commands of the
  guides pass no `-L` and are unchanged. `scripts/check_guides.py` adds a case for
  each call that answers it with a 301 to the same URL under `http`, its `requests` and
  `fetch` stubs follow a redirect as those libraries do by default, and a case fails when
  its block sends a request to a URL that is not `https`; `scripts/test_checks.py` covers
  it.
- `clients/python`: `AtpClient` follows Section 7.1 for its base URL and its copy of the
  discovery document. It accepted `http://authority.example` and `http://localhost:8080`;
  a base URL is now an `https` URL, or an `http` URL whose host is a loopback address literal
  (an IPv4 address in `127.0.0.0/8` or the IPv6 address `::1`); otherwise the constructor
  raises `ValueError` naming Section 7.1. A request under an `http` URL is sent directly, not
  through a proxy set in the environment. The client fetched the discovery document once and
  kept it, so a key the authority removed (Section 8.2) kept verifying; it now requests the
  document again once its copy is more than `refresh_after` seconds old (300 by default, the
  Section 8.1 polling interval; at most 3600), counts the answer's `Age` header in the age of
  a copy, and raises `AtpError` from `get_discovery` and `verify`, instead of returning a
  result, when a new copy cannot be had: the request failed, or the copy arrived more than
  3600 seconds old (`MAX_DISCOVERY_AGE`) or with an `Age` that is not a number of seconds. A
  stored copy passed as `discovery` takes its age as `discovery_age`. `timeout` bounded each
  socket operation, so an answer body of 353 bytes sent one byte at a time, 0.3 seconds
  apart, took 107 seconds under `timeout=1`; it now bounds the whole request, and the client
  closes the connection when it expires. The client read the whole answer body, 20 MB in the
  reproduction; a body longer than `MAX_RESPONSE_BYTES` (1,048,576 bytes) now raises
  `AtpError`. The tests cover a 20 MB answer, answers of exactly the bound and one byte past
  it, answers sent a byte at a time, 0.1 seconds apart, from their status line and from their
  body, the second also over `https`, a local `https` authority with its certificate trusted
  and not trusted, the accepted and refused base URLs, a proxy set in the environment, a key
  removed between two `verify` calls, `Age` values of 290, 301, 3600 and 3601 and malformed
  ones, a failed request for a new copy, and stored copies 290 and 3601 seconds old.
  `clients/README.md` documents the behavior, and that the TypeScript client fetches the
  discovery document once, accepts an `http` base URL whose host is not a loopback address
  and does not bound an answer body.
- Appendix B.1 and B.2: the examples imported an `atp` client library that does not exist
  (the PyPI package of that name is unrelated), so neither ran. They now call the Section
  4.5 endpoints of a configured authority with `requests` and `fetch`: fetch the proof,
  take it from under `proof` in the response, refuse a proof about another DID, an expired
  proof, one the verify endpoint does not accept, and one without an integer `trustLevel`
  0-4. The appendix states that ATP defines no client library and that an offline verifier
  performs the Section 4.4 steps itself. `scripts/check_guides.py` runs B.1 and B.2 against
  the recorded responses (B.3 runs the opena2a CLI and is not run).
- Integration guides (`examples/`): the samples read the trust level from the top level of
  the `GET /api/v1/trust/proof` response, where it is absent; the fields sit under `proof`.
  For a server at level 2 under threshold 3, the CI gate printed `Trust level: null`, then
  `Trust gate passed.`, and exited 0. Every sample now reads `proof` and refuses an agent
  whose level is not an integer 0-4. The CI guide's checks live in one gate script,
  `atp-trust-gate.sh`, that every workflow runs: it also refuses an expired proof and an
  agent on the Section 8.1 revocation list, and exits with the documented codes (0 passed,
  1 refused, 2 authority unreachable; no script returned 2 before). The batch script keeps
  its failure flag out of a pipeline subshell, matches answers by DID and exits 2 when the
  authority rejects the request. The trust monitor sends `since` as a date, the format the
  advisories endpoint takes. The A2A samples read the level from the signed proof, not the
  card's unsigned copy, and verify against the authority the verifier is configured with,
  not the card's own `verifyAt`. The proof refresh helper stores the proof, not the
  response envelope that verify rejects. `scripts/check_guides.py` runs every guide block
  against responses recorded from the reference authority (`scripts/guide_responses.json`)
  and fails on a block that no case runs; `scripts/test_checks.py` covers it.
- Section 4.3: the canonical string named `{issuedAt RFC3339}` and `{expiresAt RFC3339}`
  without saying which RFC 3339 form, so a verifier that built it from a proof served with
  fractional seconds (`2026-10-12T02:57:21.581346834Z`) rejected a valid proof. The section
  now states the form: UTC, whole seconds with fractional seconds dropped (not rounded), `Z`
  suffix. An authority MUST serve both members in the form it signed, and a verifier MUST
  reduce each served timestamp to that form before it builds the string. A table gives the
  signed form of four served timestamps, and `scripts/validate_examples.py` fails when a row
  disagrees with the rule or no row serves fractional seconds. Section 2.1 lists a proof
  served with fractional-second timestamps as not yet covered by fixtures.
- Section 4.2: the example trust proof declared a validity window of more than 26,000 days
  (`expiresAt` 2099-12-31), which Section 4.4 step 5 rejects under the Section 10.2 24-hour
  maximum. It now carries the current `trust-proof-baseline` fixture bytes: issued
  2026-05-23T12:00:00Z, expiring 2026-05-24T06:00:00Z (18 hours), signed by the same
  `#key-1` over the new canonical string. `scripts/validate_examples.py` now checks a trust
  proof example's validity window as well as its shape, so an example outside the maximum
  fails CI.
- LICENSE: restored the canonical Apache License 2.0 text. Clause 6 had dropped "reasonable
  and customary use in", clause 9 read "Support" for "Additional Liability", and the leading
  blank line and appendix wrapping differed; the appendix copyright line is now the only
  change from the published text. `scripts/check_license.py` compares the file, with that
  line put back to its placeholder, against the SHA-256 of the canonical text.
- README: the Quick Start discovery command requested `/.well-known/opena2a`; it now requests
  the Section 7.1 normative path `/.well-known/atp`, and the legacy alias is named in a comment
  only. `scripts/validate_examples.py` fails when a command in a README code block requests
  any other well-known path.
- README: the trust proof was described as signed with Ed25519 and ML-DSA-65, which reads as a
  mandatory second signature; it now states Section 4.3: Ed25519 is required and ML-DSA-65 is
  the second signature of the optional hybrid mode. `scripts/validate_examples.py` fails on a
  README sentence that names ML-DSA-65 without hybrid mode.
- Section 3.4 and the A2A integration guide placed the A2A agent card at
  `/.well-known/agent.json`, a path the A2A specification no longer names. Both now name
  `/.well-known/agent-card.json`, in the Section 3.4 sentence and in the guide's overview and
  its Python, TypeScript and cURL examples, and `scripts/check_guides.py` serves the recorded
  card at that path. `scripts/validate_examples.py` fails when ATP-SPEC.md, README.md or a
  guide under `examples/` names the retired path.
- `scripts/check_license.py` reads LICENSE byte for byte, so a copy with CRLF line endings
  fails, and reports a path it cannot read in one line with exit 1 instead of a traceback.
- `scripts/validate_examples.py` README checks: a sentence wrapped across lines is checked
  whole (its paragraph's lines are joined before it is split into sentences), and a code
  block closes only on a fence of its own character at least as long as the opening one, so
  a fence inside a longer fence no longer swaps prose and code for the rest of the README.
  `scripts/test_checks.py` covers both scripts.
- `.gitignore` excludes `__pycache__/`, which running the scripts leaves behind.
- `scripts/validate_examples.py` probes `transparencyLogIndex` with a boolean, an array and an
  object as well as a negative integer, a number, a string and null, so a schema whose index
  type is widened to any of them fails. `scripts/test_checks.py` covers the valid-index and
  invalid-index probes (`minimum` removed, `type` set to `number`, `minimum` set to 1, the type
  widened) and the `index FAIL` result of the script.
- `scripts/test_checks.py` also covers the string and null `transparencyLogIndex` probes and
  the valid index 1847300 (a schema with `maximum` below it fails), so removing any of those
  probes from `scripts/validate_examples.py` fails a test.
- Section 1 and the README: the transparency log was described as recording every revocation,
  but Section 8.1 allows a revocation entry with no log record. Both now say the log records
  the revocation of a logged trust proof or credential, and Section 1 names the exception.
- Conformance scripts: an authority that omitted what a test's row names still passed it, so
  one with no `authorityDid` or `version`, a proof without `did`, `trustLevel`, `verdict` or
  `issuedAt`, an `expiresAt` of `"never"` and a non-JSON revocations body scored 14 of 14 and
  3 of 3. Each test now fails when its row's subject is missing or invalid, and says what is
  not met. T1.2 and T1.8 check every named member on its own against `schemas/` (the
  `jq -e` list tested only its last member); T1.1, T1.4, T1.7 and T1.13 require a JSON body
  (T1.1 passed on an HTML page); T1.7 requires the proof's `did` to be the authority DID;
  T1.10 compares `expiresAt` as a time, not as a string; T1.3, T1.11 and T1.12 require a
  number in range (T1.11 passed on an empty value when no proof was fetched); T1.6 and T1.9
  require arrays; T2.2 requires every log entry to carry `logIndex`, `timestamp` and
  `entryType` (`{"entries":["FAKE"]}` passed); T2.3 validates the response against
  `schemas/revocation-list-v1.schema.json` (any 2xx body passed). The checks live in
  `conformance/checks.jq` and `conformance/lib.sh`. `scripts/test_checks.py` runs both
  scripts against `scripts/fixture_authority.py`, which serves the specification's examples
  (all 17 tests pass), with one member removed or corrupted at a time (exactly the tests that
  check it fail), and checks that `checks.jq` agrees with a JSON Schema validator.
- README ATX table, `examples/atx-example.json` and `schemas/trust-proof-v1.schema.json`
  still labelled the ATX v1.1 fields "Proposed (v1.1)", the status Section 4.6 retired, and
  the README table left out `declaredPurpose`. The README table now lists all five fields
  with the Section 4.6 status "ATX v1.1 (signed in the ATX TBS, atx-spec Section 1.3a.2)", the
  example comment and the schema's `scanSummary` description say the same, and the schema describes `slsaLevel` as
  illustrative and signed nowhere, as Section 4.2 does. `scripts/validate_examples.py` fails
  when a README ATX row is missing, extra or differs in status from the Section 4.6 table,
  when the example lacks an ATX v1.1 field, when the schema describes one as anything but
  ATX v1.1, or when any of the three files says "Proposed v1.1"; `scripts/test_checks.py`
  covers each case.
- Section 2.1 called the suite's `notCovered` list authoritative, though that list can lag
  the specification and leave out requirements Section 2.1 lists; the Section 2.1 list is now
  the authoritative one and says the suite's list can lag it. The README said the suite pins the Section 8.1 body,
  the Section 2.1 table listed `revocation-list-valid.json` as a structural ACCEPT and the
  revocation schema called that fixture its ground truth, yet the fixture's free-text
  `reason` predates the Section 8.1.1 codes and the schema refuses it. All three now say so,
  and that a client processes the reason as `unspecified`; the README names the reason-code
  and index-less cases no fixture pins yet. `scripts/validate_examples.py` fails when the
  Section 2.1 list does not say it is authoritative, or when a prose sentence in the
  specification or README, or a sentence of the schema description, cites the fixture
  without Section 8.1.1; `scripts/test_checks.py` covers each case.
- Appendix A and the README linked the reference implementation's repository, which is not
  public (an anonymous request gets HTTP 404), and Appendix A mapped five of its six components
  to source files in it. Both now say the source is not public, and Appendix A maps each component to
  the public endpoint at `api.oa2a.org` that demonstrates it, with the status an anonymous
  request received on 2026-10-11 (the transparency-log endpoints answer 404 and federation
  sync 401). `scripts/validate_examples.py` fails on a link to a repository listed as not
  public and on an Appendix A row that names no `/api/` or `/.well-known/` endpoint.
- Statements that did not match the files they describe. The Section 4.6 note said the
  Section 4.2 example shows `scanSummary`; it shows `transparencyLogIndex` only. Section 7.1
  gave the `discovery-valid` fixture's ML-DSA-65 key as "~2.6 KB hex" and implied it was the
  example's only difference; the key is 3,904 hex characters (1,952 bytes) and Section 7.1
  now lists every difference. Section 8.1.1 said its codes are the atx-spec Section 3.3
  triggers; that section names the triggers in prose, so Section 8.1.1 now maps each code to
  its trigger and says the shared bytes come from the `atx_revoked` entry's `reason` being a
  Section 8.1.1 code. Section 11 defined `application/atp+json`, which nothing serves or
  sends; it now registers no media type and names `application/json`. Two entries above
  are corrected: the §7.1 example is not fixture bytes, and eight fixture payloads validate,
  not seven. `scripts/validate_examples.py` fails when a sentence says a section's example
  shows a member it lacks, or Section 11 names a media type no `Content-Type` carries.
- README: the Specification section named ATP-SPEC.md v1.0.0-rc1; it now names the header
  version, 1.1.0-draft, and `scripts/validate_examples.py` fails when a README line that
  links ATP-SPEC.md names any other version. The reference implementation's sample trust
  proof was an April 2026 response; it is now the October 2026 one, which adds a
  `proof.signature` member (the Ed25519 value repeated) and labels the second signature
  `{"keyVersion":1,"algorithm":"ML-DSA-65"}`. The README signing check no longer reads the
  lines of a JSON code block as sentences, so the sample's algorithm name is not reported as
  ML-DSA-65 without hybrid mode; lines of other code blocks are still checked.
- Section 10.1: the threat model listed "multi-key threshold signing" as the Level 1 defense
  against signing key compromise, and the specification defined no threshold signing. The
  row now names the defenses the specification defines: key revocation (Section 8.2, enforced
  at Section 4.4 step 3), the 24-hour proof validity maximum (Section 10.2) and the Section
  7.1.1 issuer key set (see Added). Every other defense in the table now cites its section
  too. `scripts/validate_examples.py` fails when a defense cites no section or cites one that
  is not a heading of the specification.
- Conformance scripts, follow-up: T1.5 requires `@context` to be a non-empty string or array
  (`false` passed). An RFC 3339 timestamp needs a UTC offset from 00:00 to 23:59 and nothing
  after it, so `+99:99` and a trailing newline no longer pass T1.8, T1.10, T2.2 and T2.3.
  T1.7 fails without sending a request when `endpoints.trustProof` is a non-empty string that
  does not start with `/` (the script reads it with its NUL characters and trailing newlines
  removed); a value such as `@other.example/api/v1/trust/proof` sent it to another host. T1.3 is
  labelled "Conformance level is 1-3". A missing `curl`, `jq` or schema file exits 69, not 1,
  which read as one failed test. T1.11 and the `trustLevel` description in
  `schemas/trust-proof-v1.schema.json` state that `4.0` is the integer 4, which the Section
  4.3 canonical string writes as `4`. `scripts/test_checks.py` adds probes for `issuerDid`,
  `entryType`, an empty `verificationMethod`, an extra top-level revocations member, an
  `expiresAt` of February 30, an empty endpoint string and a body holding two JSON values,
  and its date-time check, written apart from `checks.jq`, now also rejects an out-of-range
  UTC offset and a trailing newline, as `checks.jq` does. The conformance README describes the
  schema agreement edits as they are.
- The link check missed a link to a repository that is not public when it ended a sentence
  or carried `.git`; it now reports both and still passes a longer repository name. The
  "Proposed v1.1" check took time quadratic in a run of whitespace after "proposed" and is
  now linear. `scripts/validate_examples.py` printed a traceback when
  `examples/atx-example.json` was missing; it now reports one `atx` failure, and an example
  that is not JSON is one error instead of one per ATX v1.1 field.
  `scripts/test_checks.py` covers each of these, the README and ATP-SPEC.md link scans
  `main()` runs, the three remaining ATX status error branches, and the line a later
  sentence citing the revocation fixture is reported at.
- Appendix A cited Section 6.4 for `/api/v1/federation/sync`, a path that section does not
  define; the row now says the path is the reference authority's own. Section 7.1 said the
  reference implementation must add `/.well-known/atp`, which it now serves alongside
  `/.well-known/opena2a`, and the discovery schema said the reference implementation serves
  endpoints its discovery document does not list; the schema now names the endpoints the
  Section 7.1 example names.
- Conformance scripts: `curl` expanded URL patterns in values the authority serves. An
  `endpoints.trustProof` of `/api/v1/trust/proo[e-f]` sent two requests (`.../prooe` and
  `.../proof`) and T1.7 passed, although the declared path is not served; an `authorityDid`
  ending in `or[f-g]` sent two requests for T1.4 and for T1.7, and both failed with "more than
  one JSON value". Every `curl` call in `conformance/level1.sh` and `conformance/level2.sh`
  now passes `-g` (`--globoff`), so `curl` does not expand `{a,b}` or `[x-y]` in the authority
  URL or in a served value: a URL that holds one stays one URL and is not requested once per
  expansion, and the conformance README says so.
  `scripts/test_checks.py` asserts the requests the fixture authority received for a bracketed
  `endpoints.trustProof`, a bracketed `authorityDid` and braces in the authority URL, and that
  every `curl` call in both scripts passes the option. It also adds the T1.7 probes that were
  missing for how the script reads `endpoints.trustProof`: `42` (not a string, so
  `/api/v1/trust/proof` is requested), a value with a trailing newline and values with a NUL
  character at the start and inside the path, each asserting the path requested.
- The link check missed the SSH form (`git@github.com:`) and the wiki form (`.wiki`,
  `.wiki.git`) of a link to a repository that is not public; it now reports both. The check
  of sentences saying a section shows a member in its example took time quadratic in a line
  that repeats "Section N.N shows" without "in its example"; the scan of such a line is now
  linear: a claim ends with its sentence, at a dot outside a code span, so a member named in
  a later sentence is no longer read as part of the claim. `scripts/validate_examples.py`
  printed a traceback when a schema file was not JSON or when README.md or ATP-SPEC.md was
  missing; each is now one failure line, and the checks that read those files do not run
  until all of them can be read. `scripts/test_checks.py` covers each of these and an ATX
  example that is JSON but not an object, which is one error per ATX v1.1 field.
- Section 7.1 ended the legacy-path fallback at "ATP v1.0.0-final" while the specification
  header is 1.1.0-draft; it now ends at v1.1.0-final, the final release of the series the
  header is on. One entry above is corrected: it said the legacy path must gain the
  normative alias before v1.0.0-final, where Section 7.1 says the reference implementation
  serves it as an optional alias.
- Conformance scripts, follow-up: every request now goes through one `fetch` helper in
  `conformance/lib.sh`. An authority URL with a brace list or bracket range in its host or
  port, which `curl` rejects with globbing off, failed every test with "no JSON body"; the
  tests that send a request now say "the authority URL is not a valid URL", and the
  conformance README says such a URL is rejected. `curl` removed `.` and `..` segments, so an
  `endpoints.trustProof` of `/x/../api/v1/trust/proof` passed T1.7 without a request to the
  declared path; every request now passes `--path-as-is`. `authorityDid` went into the T1.4
  path and the T1.7 query as written, so a `#` dropped the rest of the request; it is now
  percent-encoded (as jq's `@uri` encodes it, except for `:` and `@`), and T1.7 fails without a
  request, naming the reason, when `endpoints.trustProof` holds `#`, whitespace or a control
  character. T1.7 adds the `did` parameter after `&` when the endpoint has a query. Reading an
  `endpoints.trustProof` with a NUL character printed a shell warning on stderr; the NUL is
  now removed in `jq`. No request had a time limit, so an address that does not answer held
  each one for the system connect timeout; each request now stops after 10 seconds to connect
  and 30 seconds in all, set by `ATP_CONNECT_TIMEOUT` and `ATP_MAX_TIME` (a value that is not a
  number exits 69), and the failure names the limits. `scripts/test_checks.py` covers each
  of these, and checks that every `curl` call passes `-g`, `--path-as-is`, `--connect-timeout`
  and `--max-time`.
- `scripts/validate_examples.py` printed a traceback when README.md or ATP-SPEC.md was not
  UTF-8, when `schemas/trust-proof-v1.schema.json` or `schemas/revocation-list-v1.schema.json`
  was missing, when `schemas/examples-map.json` was not JSON or not a list of entries, and
  when a schema file was JSON but not an object or failed the metaschema check. Each is now
  one failure line, and no check runs until every input can be used. A map entry has string
  `file` and `schema` members and may leave out `heading`, which is a string when present;
  an entry naming a schema that is not there, or a heading in a file that is not there, is
  one failure. The link check also reports the API
  (`api.github.com/repos/`), raw-content (`raw.githubusercontent.com`), SSH-with-port and
  `gh repo` forms of a link to a repository that is not public, and no longer reads a host
  such as `notgithub.com` as github.com. The example-claim check ended a claim at any dot
  outside a code span, so "Section 4.2 shows e.g. `x` in its example" was not checked; a
  claim now ends only at a dot followed by whitespace and a capital letter, or at another
  "Section N.N shows", and the module docstring states the claims it does not read. It also
  read the whole document once per claim, so its time grew with the square of the number of
  claims; the section examples are now read in one pass. `scripts/test_checks.py` covers
  each case, asserts that a damaged schema gets no `schema OK` line, and its InputFileTest
  and LegacyPathMilestoneTest docstrings state only what their tests assert.
- Section 4.3.1 co-signature, follow-up: the trust-proof schema's `contains` accepted any
  authority signature, so a proof whose only signature was ML-DSA-65 was schema-valid and
  passed T1.9, though Section 4.4 step 4 rejects it. `contains` now names `ed25519Signature`,
  written out in full because `conformance/checks.jq` reads no keyword beside `$ref`; the
  "at least one authority signature" of the Section 4.3.1 entry under Added is an Ed25519
  one. The schema also required every `tlogEntries` item to be a `hashedrekord` entry with
  an inclusion proof, where Section 4.3.1 requires at least one such entry; it now requires
  one and admits entries of other kinds beside it. T1.9 is now "Trust proof has an Ed25519
  authority signature", in `level1.sh` and the conformance README, because a proof whose
  only signature is a Sigstore co-signature or an ML-DSA-65 signature fails it. A time limit
  of 0, or one under a millisecond, which `curl` reads as no overall limit (`--max-time`) or
  as its own connect default (`--connect-timeout`), now exits 69 like a value that is not a
  number. Section 2.1 lists two Section 4.4 requirements no fixture covers: step 3
  rejecting a proof signed by a revoked authority key, and step 4 rejecting a proof whose
  only Ed25519 entry is signed by a key of a DID other than its `issuerDid`. The abstract no
  longer says that Sigstore signing factors into the trust score, which no section
  specifies. `scripts/validate_examples.py` printed a traceback when the Section 4.3.1
  example block was not JSON; the examples map now reports it as one failure, and the
  co-signature check reports it as not compared. The check also confirms that the schema
  refuses an ML-DSA-65 entry alone, a bundle with a DSSE envelope beside its message
  signature, and a `hashedrekord` entry without an inclusion proof beside an entry of
  another kind. `scripts/test_checks.py` covers each case, tells the two-co-signature probe
  from the one-entry probe, pins the failure count when the ATX example cannot be read,
  reads every `curl` word outside comments for the shared options, and checks that no
  schema keyword sits beside a `$ref`.
- `scripts/validate_examples.py` passed with no example validated when
  `schemas/examples-map.json` was missing; a missing map, and a map that lists no entry, is
  now one failure line, and no check runs. A map heading that is not in its file ended the
  run with an `error:` line that carried the file's path on disk and no failure count. That
  heading, and a heading with no closed `json` code block before the next heading, is now
  one `example FAIL` line that names the file as the map does; the other entries are still
  validated and the run ends with its count. The link check also reports the web-editor
  address (`github.dev/`) of a repository that is not public and a `gh api` command whose
  endpoint (`repos/<name>`) names one, with or without a leading slash, quotes or flags
  before the endpoint; an endpoint on a continuation line is not read.
  `scripts/test_checks.py` covers each case and an examples map that is not UTF-8, fails
  when a section's example is no longer its first `json` code block or a heading label no
  longer keeps its first section, and bounds the two linear-time checks by the ratio of CPU
  time between two input sizes instead of by one second of elapsed time, which a loaded
  machine could exceed.
- Section 4.3.1 co-signature, second follow-up: `scripts/validate_examples.py` printed a
  traceback when the example's Sigstore entry lacked a member its probes edit, such as a
  `bundle` that is not an object. When the schema refuses the example, the examples map
  reports it as one failure and the co-signature check reports it as not compared; when the
  schema admits it (a log entry without `logIndex`, for one), the co-signature check fails
  with one line. `conformance/level2.sh` printed a setup error twice, once from `level1.sh`
  and once from its own setup checks; it now runs the setup checks first, prints the error
  once and exits 69 before running `level1.sh`. `scripts/test_checks.py` checks that each
  setup error is one line, that a co-signature check it does not compare prints no
  `cosign OK` line, and that the schema's `ed25519Signature` is `keySignature` with
  `algorithm` fixed to Ed25519.
- `scripts/fixture_authority.py` printed a traceback when `ATP-SPEC.md` lacked a heading of
  an example it serves; it now exits 1 with one `error:` line that names the heading, and
  with one line that names the decoding error when `ATP-SPEC.md` is not UTF-8. An entry of
  `schemas/examples-map.json`, with or without a heading, whose file is not UTF-8 and is
  read by no other check, such as `examples/atx-vc-example.json` or a Markdown file at the
  repository root other than `ATP-SPEC.md` and `README.md`, ended
  `scripts/validate_examples.py` with a traceback; it is now one counted `example FAIL`
  line, and the other entries are still validated. A Section 4.3.1 heading missing from the
  specification counted as two failures, one from the examples map and one from the
  co-signature check; when the map lists the heading, the co-signature check now reports it
  as not compared, and when the map does not, the co-signature check fails on it, so the
  run counts it once. The link check also reports the `vscode.dev/github/` address of a
  repository that is not public, and a `github.dev` address with a port.
  `scripts/test_checks.py` covers each case.
- `scripts/validate_examples.py` ended with a traceback when one of these files was not
  UTF-8: a Markdown file in `examples/` (read by the A2A agent card check),
  `examples/atx-example.json` (the ATX check) or `registries/revocation-reasons.json` (the
  revocation reason check). Each is now one counted failure of its check, with a line under
  it that names the file, and the other checks run. When the ATX example is not UTF-8 the
  Verifiable Credential form is reported as not compared. A reason registry that is not
  JSON, which also ended the run with a traceback, is one failure of its check too.
  `scripts/fixture_authority.py` printed a traceback when an example it serves was not
  JSON, when its port argument was not a number from 0 to 65535 (`--help`, for one) and
  when it could not listen on the port because another process held it; each is now one
  `error:` line that names the heading or the port, with exit status 1.
  `scripts/test_checks.py` covers each case, and fails when the fixture authority opens a
  socket before it has read its examples.
- `scripts/validate_examples.py` ended with a traceback when
  `registries/revocation-reasons.json` was JSON of another shape than the one
  `scripts/gen_registries.py` writes (`{}`, `[]`, `rows` that is not a list, a row without a
  string `Reason`), or for some of these shapes reported only that the schema codes differ
  from the Section 8.1.1 table; it is now one failure of the revocation reason check, with a
  line under it that names the file and says to run `scripts/gen_registries.py`. It also
  ended with a traceback when `examples/` held a directory whose name ends in `.md`; the A2A
  agent card check no longer reads such a directory. `scripts/gen_registries.py --check`
  ended with a traceback when a registry file was not UTF-8; the one `stale registries` line
  now lists the file, marked `(not UTF-8)`. `scripts/fixture_authority.py` printed a
  traceback with the file's path on disk when `ATP-SPEC.md` was missing, or was a directory;
  it now exits 1 with the line `error: ATP-SPEC.md: missing`. `scripts/test_checks.py`
  covers each case.
- `scripts/validate_examples.py` skipped, with no message, a link in `examples/` whose name
  ends in `.md` and whose target is not there; it is now one failure of the A2A agent card
  check, with a line under it that names the link and says it cannot be read, not a path on
  disk. It ended with a traceback when `schemas/` held a directory whose name ends in
  `.schema.json`; such a directory is not read, and one in place of a schema the checks read
  by name is that schema missing. A link in `schemas/` whose target is not there is one
  `schema INVALID` line, and the checks do not run. It ended with a `KeyError` traceback
  when `schemas/revocation-list-v1.schema.json` was a valid schema with no object schema for
  an entry's `reason` at `properties.revocations.items.properties.reason` (`{"type":
  "object"}`, for one); that is now one failure of the revocation reason check, with a line
  under it that names the schema file, and the revocation index check, which reads the same
  schema, still fails when the schema admits an entry Section 8.1 refuses. A `reason` schema
  whose `anyOf` holds a boolean schema before the enum, or whose enum mixes strings with
  other values, is compared with the Section 8.1.1 table instead of ending with a
  `TypeError`. `scripts/gen_registries.py` ended with a traceback that printed the file's
  path on disk when `ATP-SPEC.md` was missing or a directory, and with a
  `UnicodeDecodeError` traceback when it was not UTF-8; in either mode it now exits 1 with
  one line, `error: ATP-SPEC.md: missing` or `error: ATP-SPEC.md: not UTF-8: ...`.
  `.gitignore` lists `.env`, `.env.*` (keeping `.env.example`), `secrets.json`, `*.pem` and
  `*.key`, so a local credential file is not committed by accident. `scripts/test_checks.py`
  covers each case.
- `scripts/test_checks.py` also covers `local_registry()` in `scripts/validate_examples.py`
  when `schemas/` holds a link whose target is not there: `listed_files()` lists the link,
  and the registry holds the same schemas as it does without the link, so a
  `local_registry()` that reads the link fails a test.
- Conformance scripts: run without an authority URL, or with an empty one,
  `conformance/level1.sh` and `conformance/level2.sh` exited 1 (bash's own `${1:?}` error),
  the code of one failed test; they now print the usage line and exit 64 (EX_USAGE in
  sysexits.h), outside the failed-test range, before any test. `rfc3339` in
  `conformance/checks.jq` read a timestamp through `jq`'s `mktime`, which with jq 1.8.1 and
  1.7.1 on macOS refuses a year before 1900 and 1969-12-31T23:59:59Z (epoch second -1), so an
  `issuedAt` of 1899-12-31T00:00:00Z failed T1.8 and a log entry timestamped
  1969-12-31T23:59:59Z failed T2.2. It now checks the date and time fields by number and
  counts the epoch seconds itself, for years 0000 to 9999. The date-time check in
  `scripts/test_checks.py`, written apart from `checks.jq`, accepted hour 24 on Python 3.14,
  whose `datetime.fromisoformat` reads it as midnight of the next day; it now bounds each
  field by number and the day by `calendar`, and agrees with `rfc3339` on hour 24, a minute
  or second of 60, a day the month lacks, years before 1900, year 0000 and
  1969-12-31T23:59:59Z. `scripts/test_checks.py` checks the epoch seconds `rfc3339` gives
  against values worked out apart from it, probes T1.8 and T2.2 with those timestamps, and
  adds T1.7 probes for an `endpoints.trustProof` that extends the host name
  (`.attacker.example/...`) or lacks its leading slash, each asserting the reason and that
  no request is sent.
- `scripts/validate_examples.py` read a section number or a link fragment on a README line
  that links ATP-SPEC.md as a version of the specification:
  `[ATP-SPEC.md Section 4.3.1](ATP-SPEC.md)` failed as `v4.3.1`, and so did `§4.3.1` and a
  link to `#changes-since-1.0.0-rc1`. The number after `Section` or `Sections` (capital or
  small s) or `§`, each number of a list that follows it, and a link fragment are no longer
  read as versions; a version on the same line still is. `unit_sentences` repeated the
  joining of a paragraph's lines that `join_unit` does; it now calls `join_unit`, so the
  sentence checks and the example-claim check join lines in one place.
  `scripts/test_checks.py` covers each case.
- Integration guides: the A2A Python and TypeScript samples trusted a card whose embedded
  proof was about another DID (`Agent trusted (level 3, score 0.82)`). Both now refuse a card
  without `atp.did`, or whose `trustProof.did` is not `atp.did`, before the expiry check. The
  batch sections of the CI/CD and MCP guides now say that the reference authority answers the
  Section 7.2 body with HTTP 400 (`packages array is required`), as it did on 2026-10-21, and
  to check each agent on its own until it accepts the body. `scripts/check_guides.py` fails
  when a batch section does not say so while `scripts/guide_responses.json` records the
  refusal, or still says so once it does not. Its docstring said that a drifting example
  fails the build, though no workflow in `.github/workflows` runs it; it now says so, and
  when to run it. New cases cover an expired proof in the A2A TypeScript sample, a level 3
  proof with verdict `blocked` in the gate script, a B.2 proof about another DID, and the
  two A2A cards above, and `scripts/test_checks.py` checks that each case fails when its
  guide check is taken out.
- `.pre-push-review-not-required` said that the repository had no build, that
  `scripts/test_checks.py` was the only unit test suite and that nothing was packaged, which
  `clients/python` made false: it is a package that pip builds with setuptools, with its own
  unit test suite. The marker now names the package (`clients/python/pyproject.toml`) with
  the command that installs it, and each unit test suite with the command that runs it. The
  marker test in `scripts/test_checks.py` checked that the sentence was present rather than
  true, so it passed while the sentence was false. It now finds the unit test suites
  (`test*.py` modules) and the package manifests (`pyproject.toml`, `setup.py`,
  `package.json`) in the tree, outside hidden directories, `node_modules`, `build`
  directories and virtual environments, and fails when the marker leaves out a suite or its
  run command, names a suite the tree does not hold, or leaves out a manifest; it also checks
  the client's install and test commands against `clients/README.md`.

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
