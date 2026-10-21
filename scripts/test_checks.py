#!/usr/bin/env python3
"""Regression tests for check_license.py, the README, reference implementation,
specification claim, revocation schema, Sigstore co-signature, two-authority
proof (with its Ed25519 verification), threat model, discovery transport and
maximum age, issuer key set, issuer
key set proof (with the Section 4.4 count), signed timestamp, ATX status, fixture coverage, A2A agent card path and Verifiable
Credential form checks in validate_examples.py, check_guides.py, the
conformance scripts (run against fixture_authority.py; needs bash, curl and
jq), the error fixture_authority.py stops with when it cannot read an example
it serves or listen on its port, the registry generation and --check mode of
gen_registries.py, and the test-suite and package sentences of the
.pre-push-review-not-required marker. Run: python3 scripts/test_checks.py
"""
import base64
import calendar
import contextlib
import copy
import io
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import quote

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import check_guides  # noqa: E402
import check_license  # noqa: E402
import fixture_authority  # noqa: E402
import gen_registries  # noqa: E402
import validate_examples  # noqa: E402
from jsonschema import Draft202012Validator, FormatChecker  # noqa: E402


class CheckLicenseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_repository_license_passes(self):
        self.assertEqual(check_license.check(ROOT / "LICENSE"), [])

    def test_missing_path_is_one_line_error(self):
        missing = self.dir / "missing-license"
        errors = check_license.check(missing)
        self.assertEqual(len(errors), 1)
        self.assertIn("cannot read", errors[0])
        run = subprocess.run(
            [sys.executable, "-B", str(SCRIPTS / "check_license.py"), str(missing)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 1)
        self.assertNotIn("Traceback", run.stderr)
        self.assertEqual(len(run.stderr.strip().splitlines()), 1)

    def test_crlf_line_endings_fail(self):
        crlf = self.dir / "LICENSE"
        crlf.write_bytes((ROOT / "LICENSE").read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(len(check_license.check(crlf)), 1)

    def test_reworded_clause_fails(self):
        edited = self.dir / "LICENSE"
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        edited.write_text(text.replace("Additional Liability", "Support", 1), encoding="utf-8")
        self.assertEqual(len(check_license.check(edited)), 1)


class ReadmeSigningTest(unittest.TestCase):
    def test_repository_readme_passes(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.readme_signing_errors(readme), [])

    def test_sentence_wrapped_after_ml_dsa_passes(self):
        text = (
            "Intro.\n\n"
            "Signed with Ed25519 (and with ML-DSA-65\n"
            "as well in hybrid mode), valid for at most 24 hours.\n"
        )
        self.assertEqual(validate_examples.readme_signing_errors(text), [])

    def test_wrapped_sentence_without_hybrid_reports_its_first_line(self):
        text = "Intro.\n\nFirst sentence. Every proof carries\nan ML-DSA-65 signature.\n"
        errors = validate_examples.readme_signing_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:3:"), errors[0])

    def test_list_items_are_not_joined(self):
        text = "- Ed25519 in hybrid mode\n- an ML-DSA-65 signature\n"
        errors = validate_examples.readme_signing_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:2:"), errors[0])

    def test_json_block_value_is_not_a_sentence(self):
        text = '```json\n{ "keyVersion": 1, "algorithm": "ML-DSA-65", "value": "..." }\n```\n'
        self.assertEqual(validate_examples.readme_signing_errors(text), [])

    def test_comment_in_other_code_block_is_checked(self):
        text = '```json\n{ "algorithm": "ML-DSA-65" }\n```\n\n```bash\n# signed with ML-DSA-65\n```\n'
        errors = validate_examples.readme_signing_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:6:"), errors[0])

    def test_unit_sentences_joins_the_unit_with_join_unit(self):
        """The sentence checks and the example-claim check join a unit's lines
        in one place, join_unit, so a sentence maps to the line it starts on."""
        unit = [(3, "  First sentence wraps"), (4, "onto this line. Second"), (5, "one.")]
        with mock.patch.object(
            validate_examples, "join_unit", wraps=validate_examples.join_unit
        ) as joined:
            found = list(validate_examples.unit_sentences(unit))
        joined.assert_called_once_with(unit)
        self.assertEqual(found, [(3, "First sentence wraps onto this line."), (4, "Second one.")])


class ReadmeSpecVersionTest(unittest.TestCase):
    SPEC = "# Agent Trust Protocol (ATP)\n\n**Version:** 1.1.0-draft\n"

    def test_repository_readme_passes(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.readme_spec_version_errors(readme, spec), [])

    def test_older_version_fails(self):
        text = "Intro.\n\n[ATP-SPEC.md](ATP-SPEC.md) — the full protocol specification (v1.0.0-rc1).\n"
        errors = validate_examples.readme_spec_version_errors(text, self.SPEC)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:3:"), errors[0])

    def test_header_version_passes(self):
        text = "[ATP-SPEC.md](ATP-SPEC.md) — the full protocol specification (v1.1.0-draft).\n"
        self.assertEqual(validate_examples.readme_spec_version_errors(text, self.SPEC), [])

    def test_line_without_spec_link_is_not_checked(self):
        text = "| did, signatures | Shipped (v1.0.0-rc1) | Base trust proof. |\n"
        self.assertEqual(validate_examples.readme_spec_version_errors(text, self.SPEC), [])

    def test_section_numbers_are_not_versions(self):
        for text in (
            "[ATP-SPEC.md Section 4.3.1](ATP-SPEC.md) defines the co-signature.\n",
            "ATP-SPEC.md Sections 4.3.1, 5.1.1 and 8.1.1 hold the registries.\n",
            "See ATP-SPEC.md §4.3.1 and §§ 5.1.1, 8.1.1.\n",
            "ATP-SPEC.md ends with Section 8.1.1.\n",
            "See section 4.3.1 to 4.3.2 of ATP-SPEC.md.\n",
        ):
            with self.subTest(text):
                self.assertEqual(validate_examples.readme_spec_version_errors(text, self.SPEC), [])

    def test_link_fragments_are_not_versions(self):
        for text in (
            "[the co-signature](ATP-SPEC.md#4.3.1-sigstore-co-signature) in ATP-SPEC.md.\n",
            "[changes](CHANGELOG.md#changes-since-1.0.0-rc1) to ATP-SPEC.md.\n",
            "ATP-SPEC.md at https://specs.opena2a.org/atp#v1.0.0-rc1 is the same text.\n",
        ):
            with self.subTest(text):
                self.assertEqual(validate_examples.readme_spec_version_errors(text, self.SPEC), [])

    def test_version_beside_a_section_number_or_fragment_still_fails(self):
        for text in (
            "[ATP-SPEC.md v1.0.0-rc1 Section 4.3.1](ATP-SPEC.md#431-sigstore) defines it.\n",
            "ATP-SPEC.md Section 4.3.1, 1.0.0-rc1 edition.\n",
            "[ATP-SPEC.md](ATP-SPEC.md#4-trust-proofs) (1.0.0-rc1).\n",
        ):
            with self.subTest(text):
                errors = validate_examples.readme_spec_version_errors(text, self.SPEC)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("names the specification v1.0.0-rc1;", errors[0])

    def test_spec_without_version_header_fails(self):
        text = "[ATP-SPEC.md](ATP-SPEC.md) — the full protocol specification (v1.1.0-draft).\n"
        errors = validate_examples.readme_spec_version_errors(text, "# ATP\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("**Version:**", errors[0])


class FederationClaimTest(unittest.TestCase):
    def test_repository_readme_and_spec_pass(self):
        for doc in ("README.md", "ATP-SPEC.md"):
            text = (ROOT / doc).read_text(encoding="utf-8")
            self.assertEqual(validate_examples.federation_claim_errors(text, doc), [], doc)

    def test_unqualified_headline_fails_at_its_line(self):
        text = (
            "# ATP\n\n"
            'ATP enables any party to answer "Should I trust this agent?" with a\n'
            "cryptographically verifiable, auditable, and decentralized response.\n"
        )
        errors = validate_examples.federation_claim_errors(text, "ATP-SPEC.md")
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:3:"), errors[0])

    def test_qualification_elsewhere_in_the_paragraph_passes(self):
        text = (
            "A decentralized response comes from federation.\n"
            "Federation is specified and not yet demonstrated.\n"
        )
        self.assertEqual(validate_examples.federation_claim_errors(text), [])

    def test_qualification_in_another_paragraph_does_not_count(self):
        text = "A decentralized response.\n\nFederation is not yet demonstrated.\n"
        errors = validate_examples.federation_claim_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:1:"), errors[0])

    def test_level_names_identifiers_and_code_are_not_claims(self):
        text = (
            "### Level 3: Decentralized Trust (federation)\n\n"
            "| 3 | Decentralized Trust | + federation consensus. |\n\n"
            "Agents are named by a Decentralized Identifier (DID).\n\n"
            "- W3C DID Core: Decentralized Identifiers v1.0\n\n"
            "```\n# decentralized\n```\n"
        )
        self.assertEqual(validate_examples.federation_claim_errors(text), [])


class TwoAuthorityProofTest(unittest.TestCase):
    """The Section 4.4.1 proof and the Section 4.4 step 7 rule:
    two_authority_errors() accepts the proof under the keys of its table and
    refuses each edit that leaves one authority, an entry it cannot verify or
    a key it does not know, and main() reports the check once."""

    HEADING = validate_examples.TWO_AUTHORITY_HEADING
    LEVEL3 = "ATP-SPEC.md Section 4.4.1 vs Section 4.4 steps 3, 4 and 7"
    SINGLE = validate_examples.SINGLE_AUTHORITY

    def setUp(self):
        self.spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.proof = validate_examples.two_authority_example()
        self.keys, errors = validate_examples.two_authority_keys(self.spec)
        self.assertEqual(errors, [])
        self.issuer, self.cosigner = self.proof["signatures"]
        self.issuer_did = self.proof["issuerDid"]
        self.cosigner_did = validate_examples.key_did(self.cosigner["keyId"])

    def errors(self, signatures=None, keys=None, **members):
        proof = {**self.proof, **members}
        if signatures is not None:
            proof["signatures"] = signatures
        return validate_examples.two_authority_errors(proof, self.keys if keys is None else keys)

    def section_4_2_proof(self):
        return json.loads(
            validate_examples.extract_block(ROOT / "ATP-SPEC.md", "### 4.2 Trust Proof Format")
        )

    def fails_step_4(self, position, key_id):
        return f"signatures[{position}] does not verify under {key_id!r} (step 4)"

    def test_repository_spec_passes(self):
        self.assertEqual(validate_examples.two_authority_check(self.spec), [])
        self.assertEqual(self.errors(), [])

    def test_proof_is_the_section_4_2_proof_with_an_entry_of_a_second_did(self):
        self.assertEqual({**self.proof, "signatures": [self.issuer]}, self.section_4_2_proof())
        self.assertNotEqual(self.cosigner_did, self.issuer_did)
        self.assertEqual(self.cosigner["algorithm"], "Ed25519")
        self.assertIn(self.proof["trustLevel"], (3, 4))

    def test_issuer_key_is_the_key_the_section_7_1_example_publishes(self):
        discovery = json.loads(
            validate_examples.extract_block(ROOT / "ATP-SPEC.md", "### 7.1 Well-Known Endpoint")
        )
        published = {key["keyId"]: bytes.fromhex(key["publicKeyHex"]) for key in discovery["publicKeys"]}
        self.assertEqual(self.keys[self.issuer["keyId"]], published[self.issuer["keyId"]])
        self.assertNotEqual(self.keys[self.cosigner["keyId"]], self.keys[self.issuer["keyId"]])

    def test_section_4_2_proof_fails_step_7_alone(self):
        errors = validate_examples.two_authority_errors(self.section_4_2_proof(), self.keys)
        self.assertEqual(errors, [self.SINGLE])

    def test_entry_of_the_issuer_twice_is_one_authority(self):
        self.assertEqual(self.errors([self.issuer, self.issuer]), [self.SINGLE])

    def test_one_key_under_two_dids_is_one_authority(self):
        keys = {**self.keys, self.cosigner["keyId"]: self.keys[self.issuer["keyId"]]}
        signatures = [self.issuer, {**self.cosigner, "value": self.issuer["value"]}]
        self.assertEqual(self.errors(signatures, keys), [self.SINGLE])

    def test_second_did_sharing_a_key_with_the_issuer_is_one_authority(self):
        for did, key_id in (
            (self.issuer_did, self.cosigner["keyId"]),
            (self.cosigner_did, self.issuer["keyId"]),
        ):
            with self.subTest(did=did):
                keys = {**self.keys, f"{did}#key-2": self.keys[key_id]}
                self.assertEqual(self.errors(keys=keys), [self.SINGLE])

    def test_second_key_of_the_issuer_is_one_authority(self):
        key_id = f"{self.issuer_did}#key-2"
        keys = {
            self.issuer["keyId"]: self.keys[self.issuer["keyId"]],
            key_id: self.keys[self.cosigner["keyId"]],
        }
        signatures = [self.issuer, {**self.cosigner, "keyId": key_id}]
        self.assertEqual(self.errors(signatures, keys), [self.SINGLE])

    def test_changed_co_signature_fails_step_4(self):
        value = base64.b64decode(self.cosigner["value"])
        for position in (0, 31, 32, 63):
            with self.subTest(position=position):
                changed = bytearray(value)
                changed[position] ^= 1
                entry = {**self.cosigner, "value": base64.b64encode(bytes(changed)).decode()}
                self.assertEqual(
                    self.errors([self.issuer, entry]),
                    [self.fails_step_4(1, self.cosigner["keyId"]), self.SINGLE],
                )

    def test_value_that_is_not_base64_fails_step_4(self):
        entry = {**self.cosigner, "value": "not base64!"}
        self.assertEqual(
            self.errors([self.issuer, entry]), [self.fails_step_4(1, self.cosigner["keyId"]), self.SINGLE]
        )

    def test_changed_signed_member_fails_both_signatures(self):
        self.assertEqual(
            self.errors(trustScore=0.826),
            [
                self.fails_step_4(0, self.issuer["keyId"]),
                self.fails_step_4(1, self.cosigner["keyId"]),
                f"no entry verifies under a key of issuerDid {self.issuer_did!r} (step 4)",
            ],
        )

    def test_key_the_verifier_does_not_know_fails_step_3(self):
        keys = {self.issuer["keyId"]: self.keys[self.issuer["keyId"]]}
        self.assertEqual(
            self.errors(keys=keys),
            [
                f"signatures[1]: keyId {self.cosigner['keyId']!r} names no key the verifier knows (step 3)",
                self.SINGLE,
            ],
        )

    def test_entry_of_another_algorithm_is_not_a_second_authority(self):
        sigstore = validate_examples.sigstore_example()["signatures"][1]
        for entry in (sigstore, validate_examples.ML_DSA_SIGNATURE):
            with self.subTest(algorithm=entry["algorithm"]):
                errors = self.errors([self.issuer, entry])
                self.assertEqual(len(errors), 2, errors)
                self.assertTrue(
                    errors[0].startswith(f"signatures[1] is a {entry['algorithm']!r} entry"), errors[0]
                )
                self.assertEqual(errors[1], self.SINGLE)

    def test_proof_without_an_entry_of_the_issuer_fails_step_4(self):
        self.assertEqual(
            self.errors([self.cosigner]),
            [f"no entry verifies under a key of issuerDid {self.issuer_did!r} (step 4)"],
        )

    def test_step_7_applies_at_trust_levels_3_and_4(self):
        # Another trustLevel changes the canonical string, so no signature is verified here.
        with mock.patch.object(validate_examples, "ed25519_verifies", return_value=True):
            for level, expected in ((0, []), (2, []), (3, [self.SINGLE]), (4, [self.SINGLE])):
                with self.subTest(level=level):
                    self.assertEqual(self.errors([self.issuer], trustLevel=level), expected)

    def test_timestamp_that_is_not_rfc3339_is_one_error(self):
        errors = self.errors(issuedAt="never")
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("no Section 4.3 canonical string: "), errors[0])

    def test_check_fails_an_example_below_trust_level_3(self):
        with mock.patch.object(
            validate_examples, "two_authority_example", return_value={**self.proof, "trustLevel": 2}
        ), mock.patch.object(validate_examples, "ed25519_verifies", return_value=True):
            errors = validate_examples.two_authority_check(self.spec)
        self.assertEqual(errors, ["the example's trustLevel 2 is below 3, where step 7 does not apply"])

    def test_check_fails_when_the_entries_of_the_issuer_alone_pass(self):
        with mock.patch.object(validate_examples, "two_authority_errors", return_value=[]):
            errors = validate_examples.two_authority_check(self.spec)
        self.assertEqual(errors, ["the example with the entries of issuerDid alone does not fail step 7"])

    def test_table_row_that_names_no_key_fails_at_its_line(self):
        lines = self.spec.split("\n")
        row = next(i for i, line in enumerate(lines) if line.startswith("| Co-signer |"))
        key = self.keys[self.cosigner["keyId"]].hex()
        not_hex = f"ATP-SPEC.md:{row + 1}: the key of {self.cosigner['keyId']!r} is not 64 lowercase hex digits"
        for line, error in (
            (lines[row].replace(key, key[:-1]), not_hex),
            (lines[row].replace(key, key.upper()), not_hex),
            (
                lines[row].replace("#key-1", ""),
                f"ATP-SPEC.md:{row + 1}: {self.cosigner_did!r} is not a DID URL with a fragment",
            ),
            (
                lines[row].replace(self.cosigner["keyId"], self.issuer["keyId"]),
                f"ATP-SPEC.md:{row + 1}: {self.issuer['keyId']!r} has a row above",
            ),
        ):
            with self.subTest(line=line):
                spec = "\n".join(lines[:row] + [line] + lines[row + 1:])
                self.assertEqual(validate_examples.two_authority_keys(spec)[1], [error])
                self.assertEqual(validate_examples.two_authority_check(spec), [error])

    def test_section_without_a_table_is_one_error(self):
        spec = "\n".join(
            line for line in self.spec.split("\n") if not line.startswith(("| Issuer |", "| Co-signer |"))
        )
        self.assertEqual(
            validate_examples.two_authority_check(spec),
            [f"ATP-SPEC.md: no key rows in a table under {self.HEADING!r}"],
        )

    def main_with_two_authority_example(self, block, mapped=True):
        """Run main() in a copy of the repository whose Section 4.4.1 example
        block is `block`; see main_with_spec()."""
        start = self.spec.index("```json\n", self.spec.index(self.HEADING)) + len("```json\n")
        end = self.spec.index("\n```\n", start)
        return self.main_with_spec(self.spec[:start] + block + self.spec[end:], mapped)

    def main_with_spec(self, spec, mapped=True):
        """Run main() in a copy of the repository whose ATP-SPEC.md is `spec`,
        with or without the Section 4.4.1 examples map entry. Returns the exit
        code, the output lines and those of them that report a failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy(ROOT / "README.md", root / "README.md")
            (root / "ATP-SPEC.md").write_text(spec, encoding="utf-8")
            for directory in ("schemas", "registries", "examples"):
                shutil.copytree(ROOT / directory, root / directory)
            if not mapped:
                map_path = root / "schemas" / "examples-map.json"
                entries = json.loads(map_path.read_text(encoding="utf-8"))
                kept = [entry for entry in entries if entry.get("heading") != self.HEADING]
                self.assertEqual(len(kept), len(entries) - 1)
                map_path.write_text(json.dumps(kept), encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                code = validate_examples.main()
        lines = out.getvalue().splitlines()
        return code, lines, [line for line in lines if "FAIL" in line or "INVALID" in line]

    def test_main_reports_the_check(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 0)
        self.assertIn(f"level3 OK      {self.LEVEL3}\n", out.getvalue())
        self.assertIn(f"example OK     ATP-SPEC.md @ {self.HEADING!r}\n", out.getvalue())

    def test_main_fails_on_two_authority_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "two_authority_check", return_value=["one authority"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn(f"level3 FAIL    {self.LEVEL3}\n    one authority\n", out.getvalue())

    def test_main_fails_on_a_proof_one_authority_signs(self):
        block = json.dumps({**self.proof, "signatures": [self.issuer]}, indent=2)
        code, lines, failed = self.main_with_two_authority_example(block)
        self.assertEqual((code, failed), (1, [f"level3 FAIL    {self.LEVEL3}"]), lines)
        self.assertIn(f"    {self.SINGLE}", lines)

    def test_main_reports_an_example_it_cannot_read_once(self):
        """The examples map validates the block and reports it; the check is
        not compared, not failed a second time."""
        label = f"ATP-SPEC.md @ {self.HEADING!r}"
        schema_failure = f"example FAIL   {label} vs schemas/trust-proof-v1.schema.json"
        for state, block, failure in (
            ("is not JSON", json.dumps(self.proof, indent=2)[:-1], f"example INVALID JSON  {label}: "),
            ("is not a trust proof the schema accepts", "[]", schema_failure),
            ("is not a trust proof the schema accepts", json.dumps({**self.proof, "trustLevel": 5}),
             schema_failure),
        ):
            with self.subTest(state=state, block=block[:20]):
                code, lines, failed = self.main_with_two_authority_example(block)
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith(failure), failed)
                self.assertIn(
                    f"level3 SKIP    {self.LEVEL3}: not compared, the {self.HEADING!r} example {state}", lines
                )
                self.assertEqual([line for line in lines if line.startswith("level3 OK")], [])
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_fails_the_check_on_an_unmapped_example_it_cannot_read(self):
        code, lines, failed = self.main_with_two_authority_example("[]", mapped=False)
        self.assertEqual(code, 1)
        self.assertEqual(failed, [f"level3 FAIL    {self.LEVEL3}"])
        self.assertIn(f"    the {self.HEADING!r} example is not a trust proof the schema accepts", lines)
        self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_reports_a_heading_that_is_not_in_the_spec_once(self):
        not_found = f"ATP-SPEC.md: heading {self.HEADING!r} not found"
        self.assertEqual(self.spec.count(f"\n{self.HEADING}\n"), 1)
        renamed = self.spec.replace(f"\n{self.HEADING}\n", f"\n{self.HEADING} entry\n")
        code, lines, failed = self.main_with_spec(renamed)
        self.assertEqual((code, failed), (1, [f"example FAIL   {not_found}"]), lines)
        self.assertIn(f"level3 SKIP    {self.LEVEL3}: not compared, {not_found}", lines)
        code, lines, failed = self.main_with_spec(renamed, mapped=False)
        self.assertEqual((code, failed), (1, [f"level3 FAIL    {self.LEVEL3}"]), lines)
        self.assertIn(f"    {not_found}", lines)
        self.assertEqual(lines[-1], "1 failure(s)")


class Ed25519Test(unittest.TestCase):
    """validate_examples.ed25519_verifies (RFC 8032 Section 5.1.7) on the
    signatures of the Section 4.4.1 proof, and the Section 4.3 canonical string
    they are over."""

    def setUp(self):
        proof = validate_examples.two_authority_example()
        keys, _ = validate_examples.two_authority_keys((ROOT / "ATP-SPEC.md").read_text(encoding="utf-8"))
        self.message = validate_examples.canonical_string(proof).encode("utf-8")
        self.signed = [(keys[entry["keyId"]], base64.b64decode(entry["value"])) for entry in proof["signatures"]]

    def test_canonical_string(self):
        self.assertEqual(
            self.message.decode("utf-8"),
            "did:opena2a:mcp_server:agent_conformance_test_001|3|0.825000|passed|"
            "2026-05-23T12:00:00Z|2026-05-24T06:00:00Z|did:opena2a:authority:opena2a.org",
        )
        proof = {
            "did": "did:opena2a:agent:a", "trustLevel": 4.0, "trustScore": 0.5, "verdict": "verified",
            "issuedAt": "2026-10-11T20:57:21.5-06:00", "expiresAt": "2026-10-12T02:57:21.999Z",
            "issuerDid": "did:opena2a:authority:b",
        }
        self.assertEqual(
            validate_examples.canonical_string(proof),
            "did:opena2a:agent:a|4|0.500000|verified|2026-10-12T02:57:21Z|2026-10-12T02:57:21Z|"
            "did:opena2a:authority:b",
        )

    def test_signatures_of_the_proof_verify(self):
        for key, signature in self.signed:
            self.assertTrue(validate_examples.ed25519_verifies(key, self.message, signature))

    def test_signature_under_the_other_key_does_not_verify(self):
        (first_key, first), (second_key, second) = self.signed
        self.assertFalse(validate_examples.ed25519_verifies(first_key, self.message, second))
        self.assertFalse(validate_examples.ed25519_verifies(second_key, self.message, first))

    def test_changed_message_does_not_verify(self):
        key, signature = self.signed[0]
        for message in (self.message + b" ", self.message[:-1], self.message.replace(b"|3|", b"|4|")):
            with self.subTest(message=message[-12:]):
                self.assertFalse(validate_examples.ed25519_verifies(key, message, signature))

    def test_s_not_below_the_group_order_does_not_verify(self):
        # [S + L]B is [S]B, so only the range check refuses this signature.
        key, signature = self.signed[0]
        s = int.from_bytes(signature[32:], "little") + validate_examples.ED25519_L
        self.assertFalse(
            validate_examples.ed25519_verifies(key, self.message, signature[:32] + s.to_bytes(32, "little"))
        )

    def test_encoding_of_no_point_does_not_verify(self):
        key, signature = self.signed[0]
        no_x = next(
            y for y in itertools.count(2) if validate_examples.ed25519_point(y.to_bytes(32, "little")) is None
        )
        for name, encoded in (
            ("a y with no x", no_x.to_bytes(32, "little")),
            ("y not below the field prime", validate_examples.ED25519_P.to_bytes(32, "little")),
            ("x = 0 with the sign bit set", (1 | 1 << 255).to_bytes(32, "little")),
        ):
            with self.subTest(name):
                self.assertIsNone(validate_examples.ed25519_point(encoded))
                self.assertFalse(validate_examples.ed25519_verifies(encoded, self.message, signature))
                self.assertFalse(validate_examples.ed25519_verifies(key, self.message, encoded + signature[32:]))

    def test_wrong_lengths_do_not_verify(self):
        key, signature = self.signed[0]
        for public, value in (
            (key[:31], signature), (key + b"\0", signature), (key, signature[:63]), (key, signature + b"\0"),
        ):
            with self.subTest(key=len(public), signature=len(value)):
                self.assertFalse(validate_examples.ed25519_verifies(public, self.message, value))

    def test_base_point_is_the_rfc_8032_generator(self):
        p, base = validate_examples.ED25519_P, validate_examples.ED25519_B
        self.assertEqual(base[1], 4 * pow(5, -1, p) % p)
        self.assertEqual(base[0] % 2, 0)
        identity = validate_examples.ED25519_IDENTITY
        self.assertFalse(validate_examples.ed25519_same(base, identity))
        self.assertTrue(
            validate_examples.ed25519_same(
                validate_examples.ed25519_multiply(validate_examples.ED25519_L, base), identity
            )
        )


class ReadmeDiscoveryTest(unittest.TestCase):
    def test_repository_readme_passes(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.discovery_path_errors(readme), [])

    def test_shorter_fence_inside_longer_fence_keeps_state(self):
        text = (
            "````markdown\n"
            "```\n"
            "````\n"
            "\n"
            "Prose naming https://example.com/.well-known/opena2a in text.\n"
            "\n"
            "```bash\n"
            "curl https://api.oa2a.org/.well-known/opena2a\n"
            "```\n"
        )
        errors = validate_examples.discovery_path_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:8 "), errors[0])

    def test_tilde_fence_closes_only_on_tildes(self):
        text = "~~~bash\n```\ncurl https://api.oa2a.org/.well-known/opena2a\n~~~\n"
        errors = validate_examples.discovery_path_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:3 "), errors[0])

    def test_comment_line_may_name_legacy_alias(self):
        text = "```bash\n# /.well-known/opena2a is a legacy alias\ncurl https://x/.well-known/atp\n```\n"
        self.assertEqual(validate_examples.discovery_path_errors(text), [])


class ReferenceImplementationTest(unittest.TestCase):
    APPENDIX = (
        "## Appendix A: Reference Implementation\n"
        "\n"
        "| Component | Public endpoint | Status |\n"
        "|-----------|-----------------|--------|\n"
        "{rows}"
        "\n"
        "## Appendix B: Integration Examples\n"
        "\n"
        "| Not | Appendix A |\n"
    )

    def test_repository_readme_and_spec_pass(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.unpublished_link_errors(readme, "README.md"), [])
        self.assertEqual(validate_examples.unpublished_link_errors(spec, "ATP-SPEC.md"), [])
        self.assertEqual(validate_examples.reference_endpoint_errors(spec), [])

    def test_link_to_unpublished_repository_fails(self):
        text = "Intro.\n\nThe [Registry](https://github.com/opena2a-org/opena2a-registry) implements ATP.\n"
        errors = validate_examples.unpublished_link_errors(text, "README.md")
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("README.md:3 "), errors[0])

    def test_link_match_ignores_case_and_stops_at_the_repository_name(self):
        upper = "See `GitHub.com/OpenA2A-org/OpenA2A-Registry`.\n"
        self.assertEqual(len(validate_examples.unpublished_link_errors(upper, "ATP-SPEC.md")), 1)
        for text in (
            "The source is at https://github.com/opena2a-org/opena2a-registry.\n",
            "git clone https://github.com/opena2a-org/opena2a-registry.git\n",
            "Clone https://github.com/opena2a-org/opena2a-registry.git.\n",
        ):
            with self.subTest(text=text):
                errors = validate_examples.unpublished_link_errors(text, "README.md")
                self.assertEqual(len(errors), 1, errors)
        for longer in (
            "See https://github.com/opena2a-org/opena2a-registry-web.\n",
            "See https://github.com/opena2a-org/opena2a-registry.v2 for the fork.\n",
            "See https://github.com/opena2a-org/opena2a-registry.github.io.\n",
        ):
            with self.subTest(longer=longer):
                self.assertEqual(validate_examples.unpublished_link_errors(longer, "README.md"), [])

    def test_ssh_and_wiki_forms_of_the_link_fail(self):
        for text in (
            "git clone git@github.com:opena2a-org/opena2a-registry.git\n",
            "Clone `git@github.com:opena2a-org/opena2a-registry`.\n",
            "git clone https://github.com/opena2a-org/opena2a-registry.wiki.git\n",
            "git clone git@github.com:opena2a-org/opena2a-registry.wiki.git\n",
            "The pages are at https://github.com/opena2a-org/opena2a-registry.wiki.\n",
        ):
            with self.subTest(text=text):
                errors = validate_examples.unpublished_link_errors(text, "README.md")
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("links to github.com/opena2a-org/opena2a-registry, which", errors[0])
        for longer in (
            "git clone git@github.com:opena2a-org/opena2a-registry-web.git\n",
            "See https://github.com/opena2a-org/opena2a-registry.wikis.\n",
            "See https://github.com/opena2a-org/opena2a-registry.wiki-archive.\n",
        ):
            with self.subTest(longer=longer):
                self.assertEqual(validate_examples.unpublished_link_errors(longer, "README.md"), [])

    def test_api_raw_port_and_gh_forms_of_the_link_fail(self):
        for text in (
            "curl https://api.github.com/repos/opena2a-org/opena2a-registry\n",
            "curl https://raw.githubusercontent.com/opena2a-org/opena2a-registry/main/x\n",
            "curl https://raw.githubusercontent.com/wiki/opena2a-org/opena2a-registry/Home.md\n",
            "git clone ssh://git@github.com:22/opena2a-org/opena2a-registry.git\n",
            "gh repo clone opena2a-org/opena2a-registry\n",
        ):
            with self.subTest(text=text):
                errors = validate_examples.unpublished_link_errors(text, "README.md")
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("links to github.com/opena2a-org/opena2a-registry, which", errors[0])
        self.assertEqual(
            validate_examples.unpublished_link_errors(
                "curl https://api.github.com/repos/opena2a-org/opena2a-registry-web\n", "README.md"
            ),
            [],
        )

    def test_gh_api_and_github_dev_forms_of_the_link_fail(self):
        for text in (
            "gh api repos/opena2a-org/opena2a-registry\n",
            "gh api /repos/opena2a-org/opena2a-registry/contents/README.md\n",
            'gh api "repos/opena2a-org/opena2a-registry"\n',
            "gh api '/repos/opena2a-org/opena2a-registry'\n",
            "gh api -X GET repos/opena2a-org/opena2a-registry/issues\n",
            'gh api -H "Accept: application/vnd.github+json" /repos/opena2a-org/opena2a-registry\n',
            "Run `gh api --jq .private repos/opena2a-org/opena2a-registry`.\n",
            "gh  api\trepos/OpenA2A-org/OpenA2A-Registry\n",
            "gh api https://api.github.com/repos/opena2a-org/opena2a-registry\n",
            "See https://github.dev/opena2a-org/opena2a-registry.\n",
            "Open github.dev/opena2a-org/opena2a-registry/blob/main/README.md\n",
        ):
            with self.subTest(text=text):
                errors = validate_examples.unpublished_link_errors(text, "README.md")
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("links to github.com/opena2a-org/opena2a-registry, which", errors[0].lower())
        for other in (
            "gh api repos/opena2a-org/opena2a-registry-web\n",
            "gh api repos/opena2a-org/opena2a-registry.github.io/pages\n",
            "gh api orgs/opena2a-org/repos\n",
            "ugh api repos/opena2a-org/opena2a-registry\n",
            "gh apis repos/opena2a-org/opena2a-registry\n",
            "The checkout is at repos/opena2a-org/opena2a-registry.\n",
            "See https://github.dev/opena2a-org/opena2a-registry-web.\n",
            "See https://notgithub.dev/opena2a-org/opena2a-registry.\n",
            "See https://my-github.dev/opena2a-org/opena2a-registry.\n",
        ):
            with self.subTest(other=other):
                self.assertEqual(validate_examples.unpublished_link_errors(other, "README.md"), [])

    def test_vscode_dev_and_web_editor_port_forms_of_the_link_fail(self):
        for text in (
            "See https://vscode.dev/github/opena2a-org/opena2a-registry.\n",
            "Open vscode.dev/github/opena2a-org/opena2a-registry/blob/main/README.md\n",
            "See https://vscode.dev:443/github/opena2a-org/opena2a-registry\n",
            "See https://github.dev:443/opena2a-org/opena2a-registry\n",
            "See HTTPS://VSCode.dev/GitHub/OpenA2A-org/OpenA2A-Registry\n",
        ):
            with self.subTest(text=text):
                errors = validate_examples.unpublished_link_errors(text, "README.md")
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("links to github.com/opena2a-org/opena2a-registry, which", errors[0].lower())
        for other in (
            "See https://vscode.dev/github/opena2a-org/opena2a-registry-web.\n",
            "See https://github.dev:443/opena2a-org/opena2a-registry-web\n",
            "See https://notvscode.dev/github/opena2a-org/opena2a-registry.\n",
            "See https://my-vscode.dev/github/opena2a-org/opena2a-registry.\n",
            "See https://vscode.dev/opena2a-org/opena2a-registry.\n",
        ):
            with self.subTest(other=other):
                self.assertEqual(validate_examples.unpublished_link_errors(other, "README.md"), [])

    def test_each_gh_api_endpoint_on_a_line_is_one_error(self):
        text = (
            "Intro.\n"
            "gh api repos/opena2a-org/opena2a-registry && gh api /repos/opena2a-org/opena2a-registry/tags\n"
        )
        errors = validate_examples.unpublished_link_errors(text, "ATP-SPEC.md")
        self.assertEqual(len(errors), 2, errors)
        for error in errors:
            self.assertTrue(error.startswith("ATP-SPEC.md:2 "), error)

    def test_another_host_ending_in_github_com_is_not_a_link_to_it(self):
        for text in (
            "See notgithub.com/opena2a-org/opena2a-registry.\n",
            "git clone user@mygithub.com:opena2a-org/opena2a-registry\n",
            "See https://my-github.com/opena2a-org/opena2a-registry.\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(validate_examples.unpublished_link_errors(text, "README.md"), [])

    def test_endpoint_rows_pass(self):
        rows = (
            "| DID resolution | `GET /api/v1/did/{did}` | 200 |\n"
            "| Discovery endpoint | `GET /.well-known/atp` | 200 |\n"
        )
        text = self.APPENDIX.format(rows=rows)
        self.assertEqual(validate_examples.reference_endpoint_errors(text), [])

    def test_source_file_row_fails(self):
        rows = (
            "| DID resolution | `GET /api/v1/did/{did}` | 200 |\n"
            "| Trust proof signing | `internal/application/trust_proof_service.go` | |\n"
        )
        errors = validate_examples.reference_endpoint_errors(self.APPENDIX.format(rows=rows))
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:6 "), errors[0])
        self.assertIn("Trust proof signing", errors[0])

    def test_missing_appendix_or_table_fails(self):
        missing = validate_examples.reference_endpoint_errors("## 12. References\n")
        self.assertEqual(len(missing), 1)
        self.assertIn("not found", missing[0])
        empty = validate_examples.reference_endpoint_errors(self.APPENDIX.format(rows=""))
        self.assertEqual(len(empty), 1)
        self.assertIn("no component table", empty[0])

    def test_main_fails_on_reference_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "reference_endpoint_errors", return_value=["row names a file"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("reference FAIL", out.getvalue())
        self.assertIn("row names a file", out.getvalue())

    def test_main_scans_readme_and_spec_for_links(self):
        for name in ("README.md", "ATP-SPEC.md"):
            content = (ROOT / name).read_text(encoding="utf-8")

            def link_errors(text, file_name, name=name, content=content):
                return [f"{file_name}:1 links to a private repository"] if (file_name, text) == (name, content) else []

            out = io.StringIO()
            with self.subTest(name=name), mock.patch.object(
                validate_examples, "unpublished_link_errors", side_effect=link_errors
            ), contextlib.redirect_stdout(out):
                self.assertEqual(validate_examples.main(), 1)
                self.assertIn("reference FAIL", out.getvalue())
                self.assertIn(f"{name}:1 links to a private repository", out.getvalue())


class SpecClaimsTest(unittest.TestCase):
    SPEC = (
        "### 4.2 Trust Proof Format\n"
        "\n"
        "```json\n"
        '{"did": "did:opena2a:agent:x", "transparencyLogIndex": 42}\n'
        "```\n"
        "\n"
        "### 4.6 Agent Trust eXtension (ATX)\n"
        "\n"
        "{note}\n"
        "\n"
        "### 4.5 Proof Retrieval\n"
        "\n"
        "```\n"
        "POST /api/v1/trust/verify\n"
        "Content-Type: application/json\n"
        "```\n"
        "\n"
        "## 11. IANA Considerations\n"
        "\n"
        "{iana}\n"
        "\n"
        "## 12. References\n"
    )
    NOTE = "Note: Section 4.2 shows `transparencyLogIndex` in its example payload."
    IANA = "- **Media Type:** none. A trust proof is `application/json`."

    def spec(self, note=NOTE, iana=IANA):
        return self.SPEC.replace("{note}", note).replace("{iana}", iana)

    def test_repository_spec_passes(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.example_claim_errors(spec), [])
        self.assertEqual(validate_examples.media_type_errors(spec), [])

    def test_repository_section_4_2_example_omits_scan_summary(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        example = validate_examples.section_example(spec, "4.2")
        self.assertIn("transparencyLogIndex", example)
        self.assertNotIn("scanSummary", example)

    def test_no_line_says_sigstore_enters_the_trust_score(self):
        """Section 4.3.1 counts a co-signature toward neither step 7 nor Section
        6, and Section 4.1 defines the score without it."""
        for name in ("ATP-SPEC.md", "README.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(name):
                self.assertEqual(
                    [line for line in text.splitlines()
                     if "Sigstore" in line and "trust score" in line.lower()],
                    [],
                )

    def test_member_the_example_shows_passes(self):
        self.assertEqual(validate_examples.example_claim_errors(self.spec()), [])

    def test_member_the_example_omits_fails(self):
        note = (
            "Note: Section 4.2 shows `scanSummary` and\n"
            "`transparencyLogIndex` in its example payload."
        )
        errors = validate_examples.example_claim_errors(self.spec(note=note))
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:9: "), errors[0])
        self.assertIn("`scanSummary`", errors[0])

    def test_section_without_json_example_fails(self):
        note = "Note: Section 4.5 shows `trustLevel` in its example."
        errors = validate_examples.example_claim_errors(self.spec(note=note))
        self.assertEqual(len(errors), 1)
        self.assertIn("Section 4.5 has no JSON object example", errors[0])

    def test_claim_ends_with_its_sentence(self):
        note = "Section 4.2 shows the base proof. Section 4.6 lists `scanSummary` in its example file."
        self.assertEqual(validate_examples.example_claim_errors(self.spec(note=note)), [])

    def test_dotted_name_in_a_code_span_is_checked(self):
        note = "Note: Section 4.2 shows `signatures.ed25519` in its example."
        errors = validate_examples.example_claim_errors(self.spec(note=note))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("`signatures.ed25519`", errors[0])

    def test_dot_that_does_not_end_the_sentence_keeps_the_claim(self):
        for note in (
            "Section 4.2 shows e.g. `notAMember` in its example.",
            "Section 4.2 shows `notAMember` (see Section 4.3) in its example.",
            "Section 4.2 shows `notAMember` and, as of v1.1, `did` in its example.",
            "Section 4.2 shows `did`, `transparencyLogIndex`, etc. and `notAMember` in its example.",
        ):
            with self.subTest(note=note):
                errors = validate_examples.example_claim_errors(self.spec(note=note))
                self.assertEqual(len(errors), 1, errors)
                self.assertTrue(errors[0].startswith("ATP-SPEC.md:9: "), errors[0])
                self.assertIn("`notAMember`", errors[0])

    def test_only_the_first_json_block_of_a_section_is_its_example(self):
        def section(*blocks):
            return "### 4.2 Trust Proof Format\n\n" + "".join(
                f"```json\n{block}\n```\n\n" for block in blocks
            )

        both = section('{"first": 1}', '{"second": 2}')
        self.assertEqual(validate_examples.section_example(both, "4.2"), {"first": 1})
        errors = validate_examples.example_claim_errors(
            both + "Section 4.2 shows `first` and `second` in its example.\n"
        )
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("`second`", errors[0])
        # A first block that is not JSON is not skipped for a later one, and
        # is not read together with it.
        for first, later in (
            ("", '{"second": 2}'),
            ("not JSON", '{"second": 2}'),
            ('{"first": 1,', '"second": 2}'),
        ):
            with self.subTest(first=first):
                self.assertIsNone(validate_examples.section_example(section(first, later), "4.2"))

    def test_label_that_heads_two_sections_keeps_the_example_of_the_first(self):
        with_example = "### 4.2 Trust Proof Format\n\n```json\n{\"first\": 1}\n```\n\n"
        without_example = "### 4.2 Trust Proof Format\n\nProse only.\n\n"
        for first, later, expected in (
            (with_example, "### 4.2 Again\n\n```json\n{\"second\": 2}\n```\n", {"first": 1}),
            (with_example, "### 4.2 Again\n\nProse only.\n", {"first": 1}),
            (without_example, "### 4.2 Again\n\n```json\n{\"second\": 2}\n```\n", None),
        ):
            with self.subTest(first=first, later=later):
                self.assertEqual(validate_examples.section_example(first + later, "4.2"), expected)

    def assert_time_grows_with_the_text(self, text_of):
        """example_claim_errors takes time in proportion to its text: on 16
        times the text it takes about 16 times as long, where a check that
        rescans its text takes up to 256 times as long. The bound is 64. The
        two runs are compared with each other, in CPU time of this process, so
        neither the speed of the machine nor other work on it decides the
        result. A pair over the bound is run again, up to three times, and the
        shortest time of each size is kept."""
        texts = (text_of(500), text_of(8000))
        tick = time.get_clock_info("process_time").resolution
        shortest = [float("inf"), float("inf")]
        for _ in range(3):
            for size, text in enumerate(texts):
                started = time.process_time()
                errors = validate_examples.example_claim_errors(text)
                shortest[size] = min(shortest[size], time.process_time() - started)
                self.assertEqual(errors, [])
            small, large = max(shortest[0], tick), shortest[1]
            if large < 64 * small:
                return
        self.fail(f"16 times the text took {large / small:.0f} times as long")

    def test_many_claims_read_the_document_once(self):
        # Reading the document once per claim took about 3.5 s for 10000
        # claims here and grew with the square of their number.
        claim = "Section 4.2 shows `did` in its example. "
        self.assert_time_grows_with_the_text(lambda claims: self.spec() + claim * claims + "\n")

    def test_repeated_claim_opening_is_scanned_in_linear_time(self):
        # The earlier pattern took about 8 s on 11000 openings and grew with
        # the square of their number.
        self.assert_time_grows_with_the_text(lambda openings: "Section 1.1 shows " * openings + "\n")

    def test_media_type_the_spec_carries_passes(self):
        self.assertEqual(validate_examples.media_type_errors(self.spec()), [])

    def test_media_type_nothing_carries_fails(self):
        iana = "- **Media Type:** `application/atp+json` — ATP trust proof format"
        errors = validate_examples.media_type_errors(self.spec(iana=iana))
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:20 "), errors[0])
        self.assertIn("application/atp+json", errors[0])

    def test_missing_iana_section_fails(self):
        errors = validate_examples.media_type_errors("## 12. References\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("not found", errors[0])

    def test_main_fails_on_claim_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "media_type_errors", return_value=["type unused"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("claims FAIL", out.getvalue())
        self.assertIn("type unused", out.getvalue())


class AgentCardPathTest(unittest.TestCase):
    def errors(self, text):
        return validate_examples.agent_card_path_errors("guide.md", text)

    def test_repository_documents_name_the_a2a_path(self):
        documents = validate_examples.agent_card_documents()
        for name in ("ATP-SPEC.md", "examples/a2a-integration.md"):
            with self.subTest(name):
                self.assertIn(ROOT / name, documents)
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertTrue(
                    "/.well-known/agent-card.json" in text,
                    f"{name} does not name /.well-known/agent-card.json",
                )
        for doc in documents:
            name = doc.relative_to(ROOT).as_posix()
            with self.subTest(name):
                text = doc.read_text(encoding="utf-8")
                self.assertEqual(validate_examples.agent_card_path_errors(name, text), [])

    def test_retired_path_fails_in_prose_and_in_code(self):
        text = (
            "Agent cards are served at `/.well-known/agent.json`.\n"
            "\n"
            "```bash\n"
            "curl -s https://weather.example.com/.well-known/agent.json | jq '.atp'\n"
            "```\n"
        )
        errors = self.errors(text)
        self.assertEqual(len(errors), 2)
        self.assertTrue(errors[0].startswith("guide.md:1 "), errors[0])
        self.assertTrue(errors[1].startswith("guide.md:4 "), errors[1])
        self.assertIn("/.well-known/agent-card.json", errors[0])

    def test_retired_path_ending_a_sentence_fails(self):
        self.assertEqual(len(self.errors("The card is at /.well-known/agent.json.\n")), 1)

    def test_a2a_path_and_other_well_known_names_pass(self):
        text = (
            "The card is at /.well-known/agent-card.json.\n"
            "\n"
            "```bash\n"
            "curl -s https://weather.example.com/.well-known/agent-card.json | jq '.atp'\n"
            "curl https://api.oa2a.org/.well-known/atp\n"
            "```\n"
        )
        self.assertEqual(self.errors(text), [])

    def test_main_fails_on_agent_card_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "agent_card_path_errors", return_value=["retired path named"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("card FAIL", out.getvalue())
        self.assertIn("retired path named", out.getvalue())


class RevocationIndexTest(unittest.TestCase):
    def schema(self):
        path = ROOT / "schemas" / "revocation-list-v1.schema.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_repository_schema_passes(self):
        self.assertEqual(validate_examples.revocation_index_errors(), [])

    def test_schema_requiring_the_index_fails(self):
        schema = self.schema()
        required = schema["properties"]["revocations"]["items"]["required"]
        required.append("transparencyLogIndex")
        errors = validate_examples.revocation_index_errors(schema)
        self.assertEqual(len(errors), 1)
        self.assertIn("without transparencyLogIndex is refused", errors[0])

    def test_schema_dropping_another_member_fails(self):
        schema = self.schema()
        required = schema["properties"]["revocations"]["items"]["required"]
        required.remove("revokedByKeyId")
        errors = validate_examples.revocation_index_errors(schema)
        self.assertEqual(len(errors), 1)
        self.assertIn("without revokedByKeyId is accepted", errors[0])

    def index_errors(self, edit):
        schema = self.schema()
        edit(schema["properties"]["revocations"]["items"]["properties"]["transparencyLogIndex"])
        return validate_examples.revocation_index_errors(schema)

    def test_schema_without_minimum_fails(self):
        errors = self.index_errors(lambda index: index.pop("minimum"))
        self.assertEqual(len(errors), 1)
        self.assertIn("transparencyLogIndex -1 is accepted", errors[0])

    def test_schema_with_number_type_fails(self):
        errors = self.index_errors(lambda index: index.update(type="number"))
        self.assertEqual(len(errors), 1)
        self.assertIn("transparencyLogIndex 1.5 is accepted", errors[0])

    def test_schema_with_minimum_one_fails(self):
        errors = self.index_errors(lambda index: index.update(minimum=1))
        self.assertEqual(len(errors), 1)
        self.assertIn("transparencyLogIndex 0 is refused", errors[0])

    def test_schema_with_maximum_below_a_large_index_fails(self):
        errors = self.index_errors(lambda index: index.update(maximum=1847299))
        self.assertEqual(len(errors), 1)
        self.assertIn("transparencyLogIndex 1847300 is refused", errors[0])

    def test_schema_widening_the_index_type_fails(self):
        for extra, probe in (
            ("string", "'1847300'"),
            ("null", "None"),
            ("boolean", "True"),
            ("array", "[]"),
            ("object", "{}"),
        ):
            with self.subTest(extra=extra):
                errors = self.index_errors(lambda index: index.update(type=["integer", extra]))
                self.assertEqual(len(errors), 1)
                self.assertIn(f"transparencyLogIndex {probe} is accepted", errors[0])

    def test_main_fails_on_index_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "revocation_index_errors", return_value=["probe refused"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("index FAIL", out.getvalue())
        self.assertIn("probe refused", out.getvalue())


# A specification with Sections 4.3 and 10.2 and a one-row threat model table;
# the row is on line 13.
THREAT_SPEC = (
    "## 4. Trust Proofs\n\n"
    "### 4.3 Signing\n\n"
    "## 10. Security Considerations\n\n"
    "### 10.1 Threat Model\n\n"
    "ATP assumes the following threats.\n\n"
    "| Threat | Defense | Conformance Level |\n"
    "|--------|---------|-------------------|\n"
    "{row}\n\n"
    "### 10.2 Trust Proof Validity\n"
)
ISSUE_ROW = "| Signing key compromise | Multi-key threshold signing | Level 1+ |"


class ThreatModelTest(unittest.TestCase):
    def errors(self, row, after=""):
        return validate_examples.threat_model_errors(THREAT_SPEC.format(row=row) + after)

    def test_repository_spec_passes(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.threat_model_errors(spec), [])

    def test_repository_spec_with_the_issue_row_fails(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        row = next(line for line in spec.splitlines() if line.startswith("| Signing key compromise |"))
        errors = validate_examples.threat_model_errors(spec.replace(row, ISSUE_ROW))
        self.assertEqual(len(errors), 1)
        self.assertIn("'Multi-key threshold signing', cites no section", errors[0])

    def test_defense_citing_no_section_fails_at_its_line(self):
        errors = self.errors(ISSUE_ROW)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:13:"), errors[0])

    def test_defense_citing_a_missing_section_fails(self):
        errors = self.errors("| Signing key compromise | Threshold signing (Section 4.7) | Level 1+ |")
        self.assertEqual(len(errors), 1)
        self.assertIn("cites Section 4.7, which is not a heading", errors[0])

    def test_defense_citing_existing_sections_passes(self):
        row = "| Signing key compromise | Revocation (Section 4.3) and validity (Section 10.2) | Level 1+ |"
        self.assertEqual(self.errors(row), [])

    def test_heading_inside_a_code_block_is_not_a_section(self):
        row = "| Signing key compromise | Threshold signing (Section 4.7) | Level 1+ |"
        errors = self.errors(row, after="\n```markdown\n### 4.7 Threshold Signing\n```\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("cites Section 4.7", errors[0])

    def test_section_without_a_table_fails(self):
        text = "### 10.1 Threat Model\n\nNo table.\n\n### 10.2 Trust Proof Validity\n\n| a | b |\n"
        errors = validate_examples.threat_model_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertIn("no threat rows", errors[0])

    def test_main_fails_on_threat_model_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "threat_model_errors", return_value=["row cites no section"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("threats FAIL", out.getvalue())
        self.assertIn("row cites no section", out.getvalue())


TRANSPORT_SPEC = (
    "### 7.1 Well-Known Endpoint\n\n"
    "A trust authority MUST serve a discovery document.\n\n"
    "{rules}\n\n"
    "#### 7.1.1 Issuer key set\n\n"
    "{claim}\n\n"
    "### 7.2 Batch Queries\n"
)
TRANSPORT_RULE = "A client MUST NOT send a request under an authority URL whose scheme is not `https`."
AGE_RULE = "A verifier MUST NOT use a copy whose age is more than 3600 seconds."
CITED_CLAIM = "Its authenticity rides on the transport Section 7.1 requires."
UNCITED_CLAIM = "Its authenticity rides on the transport."


class DiscoveryTransportTest(unittest.TestCase):
    def errors(self, rules=f"{TRANSPORT_RULE} {AGE_RULE}", claim=CITED_CLAIM):
        return validate_examples.discovery_transport_errors(
            TRANSPORT_SPEC.format(rules=rules, claim=claim)
        )

    def spec(self):
        return (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")

    def without_paragraph(self, lead):
        lines = self.spec().splitlines(keepends=True)
        begins = [i for i, line in enumerate(lines) if line.startswith(lead)]
        self.assertEqual(len(begins), 1, f"ATP-SPEC.md has no one paragraph starting {lead!r}")
        end = next((i for i in range(begins[0], len(lines)) if not lines[i].strip()), len(lines))
        return "".join(lines[:begins[0]] + lines[end + 1:])

    def test_repository_spec_passes(self):
        self.assertEqual(validate_examples.discovery_transport_errors(self.spec()), [])

    def test_repository_spec_with_its_earlier_claims_fails_at_their_lines(self):
        # Sections 7.1.1 and 8.1 said authenticity rides on the transport and named none.
        spec = self.spec().replace(
            "rides on the transport Section 7.1 requires", "rides on the transport"
        )
        lines = spec.splitlines()

        def starts(text):
            return next(n for n, line in enumerate(lines, start=1) if text in line)

        errors = validate_examples.discovery_transport_errors(spec)
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(
            errors[0].startswith(f"ATP-SPEC.md:{starts('The set protects against')}:"), errors[0]
        )
        self.assertTrue(
            errors[1].startswith(f"ATP-SPEC.md:{starts('The response body itself')}:"), errors[1]
        )

    def test_repository_spec_without_its_transport_paragraph_fails(self):
        errors = validate_examples.discovery_transport_errors(
            self.without_paragraph("The authority URL is an `https` URL.")
        )
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("no sentence that requires `https` with a MUST", errors[0])

    def test_repository_spec_without_its_maximum_age_paragraph_fails(self):
        errors = validate_examples.discovery_transport_errors(
            self.without_paragraph("A verifier MUST NOT use a copy of the discovery document")
        )
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("sets no maximum age", errors[0])

    def test_rules_and_a_cited_claim_pass(self):
        self.assertEqual(self.errors(), [])

    def test_uncited_claim_fails_at_its_line(self):
        errors = self.errors(claim=UNCITED_CLAIM)
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:9:"), errors[0])
        self.assertIn("without citing Section 7.1", errors[0])

    def test_claim_wrapped_across_lines_fails_at_the_line_it_starts_on(self):
        claim = "The document is not signed.\nIts authenticity rides on the\ntransport alone."
        errors = self.errors(claim=claim)
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:10:"), errors[0])

    def test_rests_on_the_transport_is_a_claim(self):
        errors = self.errors(claim="An entry without an index rests on the transport alone.")
        self.assertEqual(len(errors), 1, errors)

    def test_claim_citing_another_section_fails(self):
        for claim in (
            "Its authenticity rides on the transport Section 7.1.1 names.",
            "Its authenticity rides on the transport Section 7.10 names.",
            "Its authenticity rides on the transport (Section 8.1).",
        ):
            with self.subTest(claim=claim):
                errors = self.errors(claim=claim)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("without citing Section 7.1", errors[0])

    def test_claim_citing_section_7_1_passes(self):
        for claim in (
            "Its authenticity rides on the transport of Section 7.1.",
            "Its authenticity rests on the transport §7.1 requires.",
            "It rides on the transport Section 7.1 requires, as Section 7.1.1 says.",
        ):
            with self.subTest(claim=claim):
                self.assertEqual(self.errors(claim=claim), [])

    def test_https_without_a_must_names_no_transport(self):
        errors = self.errors(rules=f"The authority URL is an `https` URL. {AGE_RULE}")
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:1:"), errors[0])
        self.assertIn("names no transport", errors[0])

    def test_age_without_a_must_sets_no_maximum(self):
        rules = f"{TRANSPORT_RULE} A verifier SHOULD refetch a copy whose age is more than 3600 seconds."
        errors = self.errors(rules=rules)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("sets no maximum age", errors[0])

    def test_rules_in_a_subsection_do_not_count(self):
        errors = self.errors(rules="No rule here.", claim=f"{TRANSPORT_RULE} {AGE_RULE} {CITED_CLAIM}")
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(all(error.startswith("ATP-SPEC.md:1:") for error in errors), errors)

    def test_code_blocks_are_not_read(self):
        errors = self.errors(
            rules=f"```\n{TRANSPORT_RULE} {AGE_RULE}\n```", claim=f"```\n{UNCITED_CLAIM}\n```"
        )
        self.assertEqual(len(errors), 2, errors)
        self.assertFalse(any("without citing" in error for error in errors), errors)

    def test_section_ending_the_text_is_read(self):
        text = f"### 7.1 Well-Known Endpoint\n\n{TRANSPORT_RULE} {AGE_RULE}\n"
        self.assertEqual(validate_examples.discovery_transport_errors(text), [])

    def test_missing_heading_fails(self):
        errors = validate_examples.discovery_transport_errors("### 7.2 Batch Queries\n\nText.\n")
        self.assertEqual(errors, ["ATP-SPEC.md: heading '### 7.1 Well-Known Endpoint' not found"])

    def test_main_fails_on_discovery_transport_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "discovery_transport_errors", return_value=["names no transport"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("transport FAIL", out.getvalue())
        self.assertIn("names no transport", out.getvalue())


KEY_SET_HEADING = "#### 7.1.1 Issuer key set"


class IssuerKeySetTest(unittest.TestCase):
    """Section 7.1.1: the discovery schema admits the example's issuer key set
    and refuses one of another shape, issuer_key_set_errors() reports each
    rule the schema cannot express, main() reports a mapped discovery example
    that breaks one, and Sections 2.1, 4.4 and 10.1 name the set."""

    def setUp(self):
        self.spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.validator = Draft202012Validator(
            json.loads((ROOT / "schemas" / "discovery-v1.schema.json").read_text(encoding="utf-8"))
        )
        self.example = json.loads(validate_examples.extract_block(ROOT / "ATP-SPEC.md", KEY_SET_HEADING))
        self.key_ids = self.example["issuerKeySet"]["keyIds"]

    def edited(self, edit):
        document = copy.deepcopy(self.example)
        edit(document)
        return document

    def test_example_is_a_2_of_3_set_the_schema_and_the_rules_accept(self):
        self.assertEqual(self.example["issuerKeySet"]["threshold"], 2)
        self.assertEqual(len(self.key_ids), 3)
        self.assertTrue(self.validator.is_valid(self.example))
        self.assertEqual(validate_examples.issuer_key_set_errors(self.example), [])

    def test_discovery_without_a_set_passes(self):
        discovery = json.loads(
            validate_examples.extract_block(ROOT / "ATP-SPEC.md", "### 7.1 Well-Known Endpoint")
        )
        self.assertNotIn("issuerKeySet", discovery)
        self.assertEqual(validate_examples.issuer_key_set_errors(discovery), [])

    def test_threshold_equal_to_the_number_of_keys_passes(self):
        document = self.edited(lambda d: d["issuerKeySet"].update(threshold=3))
        self.assertEqual(validate_examples.issuer_key_set_errors(document), [])

    def test_schema_refuses_a_set_of_another_shape(self):
        def without(name):
            return lambda d: d["issuerKeySet"].pop(name)

        def setting(name, value):
            return lambda d: d["issuerKeySet"].update({name: value})

        cases = {
            "threshold 0": setting("threshold", 0),
            "threshold -1": setting("threshold", -1),
            "threshold 1.5": setting("threshold", 1.5),
            "threshold as a string": setting("threshold", "2"),
            "no threshold": without("threshold"),
            "no keyIds": without("keyIds"),
            "no keys": setting("keyIds", []),
            "keyIds as a string": setting("keyIds", self.key_ids[0]),
            "a keyId without a fragment": setting("keyIds", ["did:opena2a:authority:example.org"]),
            "a member beside threshold and keyIds": setting("m", 2),
            "a set that is a list": lambda d: d.update(issuerKeySet=[2, self.key_ids]),
        }
        for label, edit in cases.items():
            with self.subTest(label):
                self.assertFalse(self.validator.is_valid(self.edited(edit)))

    def test_rules_the_schema_cannot_express_fail(self):
        """Each document is valid against the discovery schema and breaks one
        Section 7.1.1 rule, which issuer_key_set_errors() names."""
        ml_dsa = {
            "keyId": "did:opena2a:authority:example.org#pqc-1",
            "algorithm": "ML-DSA-65",
            "publicKeyHex": "00ff",
            "status": "active",
            "validFrom": "2026-10-01T00:00:00Z",
        }

        def with_ml_dsa(d):
            d["publicKeys"].append(ml_dsa)
            d["issuerKeySet"]["keyIds"] = [self.key_ids[0], ml_dsa["keyId"]]

        def same_public_key(d):
            d["publicKeys"][1]["publicKeyHex"] = d["publicKeys"][0]["publicKeyHex"]

        absent = "did:opena2a:authority:example.org#key-4"
        cases = {
            "threshold above the keys": (
                lambda d: d["issuerKeySet"].update(threshold=4),
                "issuerKeySet threshold 4 is more than the 3 keys it lists",
            ),
            "threshold above one key": (
                lambda d: d["issuerKeySet"].update(keyIds=self.key_ids[:1]),
                "issuerKeySet threshold 2 is more than the 1 key it lists",
            ),
            "one key listed twice": (
                lambda d: d["issuerKeySet"].update(keyIds=[self.key_ids[0], self.key_ids[0]]),
                f"issuerKeySet lists {self.key_ids[0]} twice",
            ),
            "a key that is not in publicKeys": (
                lambda d: d["issuerKeySet"]["keyIds"].append(absent),
                f"issuerKeySet lists {absent}, which is not the keyId of a publicKeys entry",
            ),
            "an ML-DSA-65 key": (
                with_ml_dsa,
                f"issuerKeySet lists {ml_dsa['keyId']}, an ML-DSA-65 key; Section 7.1.1 lists Ed25519 keys",
            ),
            "two keys with the same publicKeyHex": (
                same_public_key,
                f"issuerKeySet lists {self.key_ids[1]} and {self.key_ids[0]}, which have the same publicKeyHex",
            ),
        }
        for label, (edit, error) in cases.items():
            with self.subTest(label):
                document = self.edited(edit)
                self.assertTrue(self.validator.is_valid(document))
                self.assertEqual(validate_examples.issuer_key_set_errors(document), [error])

    def test_main_reports_a_mapped_example_that_breaks_a_rule(self):
        self.assertEqual(self.spec.count('"threshold": 2,'), 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy(ROOT / "README.md", root / "README.md")
            (root / "ATP-SPEC.md").write_text(
                self.spec.replace('"threshold": 2,', '"threshold": 4,'), encoding="utf-8"
            )
            for directory in ("schemas", "registries", "examples"):
                shutil.copytree(ROOT / directory, root / directory)
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                code = validate_examples.main()
        lines = out.getvalue().splitlines()
        self.assertEqual(code, 1)
        failure = f"example FAIL   ATP-SPEC.md @ {KEY_SET_HEADING!r} vs schemas/discovery-v1.schema.json"
        self.assertEqual([line for line in lines if "FAIL" in line or "INVALID" in line], [failure], lines)
        self.assertEqual(
            lines[lines.index(failure) + 1], "    $: issuerKeySet threshold 4 is more than the 3 keys it lists"
        )
        self.assertIn("example OK     ATP-SPEC.md @ '### 7.1 Well-Known Endpoint'", lines)
        self.assertEqual(lines[-1], "1 failure(s)")

    def test_sections_2_1_4_4_and_10_1_name_the_set(self):
        lines = self.spec.splitlines()
        step_4 = next(line for line in lines if line.startswith("4. **Signature:**"))
        self.assertIn("issuer key set (Section 7.1.1)", step_4)
        count = next(line for line in lines if line.startswith("**Issuer key set count.**"))
        self.assertIn("at least `threshold` distinct", count)
        row = next(line for line in lines if line.startswith("| Signing key compromise |"))
        self.assertIn("m-of-n issuer key set (Section 7.1.1)", row)
        coverage = next(line for line in lines if line.startswith(validate_examples.COVERAGE_LIST))
        self.assertIn("issuer key set count (Section 7.1.1)", coverage)


class IssuerKeySetProofTest(unittest.TestCase):
    """The Section 4.4.2 proof and the Section 4.4 issuer key set count:
    key_set_count_errors() accepts the proof under the set of the Section
    7.1.1 example and refuses each edit that leaves fewer than `threshold`
    distinct keys of the set, key_set_proof_check() passes and fails on the
    edits it makes, and main() reports the check once."""

    HEADING = validate_examples.KEY_SET_PROOF_HEADING
    KEYSET = "ATP-SPEC.md Section 4.4.2 vs the Section 7.1.1 issuer key set"

    def setUp(self):
        self.spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.proof = validate_examples.key_set_proof_example()
        self.discovery = validate_examples.key_set_discovery_example()
        self.keys = validate_examples.discovery_keys(self.discovery)
        self.first, self.second = self.proof["signatures"]
        self.key_ids = self.discovery["issuerKeySet"]["keyIds"]

    def count(self, signatures=None, discovery=None, **members):
        proof = {**self.proof, **members}
        if signatures is not None:
            proof["signatures"] = signatures
        return validate_examples.key_set_count_errors(
            proof, self.discovery if discovery is None else discovery
        )

    def with_set(self, **members):
        discovery = copy.deepcopy(self.discovery)
        discovery["issuerKeySet"].update(members)
        return discovery

    @staticmethod
    def fewer(count, threshold=2):
        return (
            f"step 4: {count} key{'' if count == 1 else 's'} of the issuer key set signed the "
            f"proof, fewer than its threshold of {threshold}"
        )

    @staticmethod
    def changed(entry):
        value = bytearray(base64.b64decode(entry["value"]))
        value[0] ^= 1
        return {**entry, "value": base64.b64encode(bytes(value)).decode()}

    def test_repository_spec_passes(self):
        self.assertEqual(validate_examples.key_set_proof_check(), [])
        self.assertEqual(self.count(), [])
        self.assertEqual(validate_examples.two_authority_errors(self.proof, self.keys), [])

    def test_proof_is_signed_by_two_keys_of_the_2_of_3_set_of_its_issuer(self):
        self.assertEqual(self.proof["issuerDid"], self.discovery["authorityDid"])
        self.assertEqual(self.discovery["issuerKeySet"]["threshold"], 2)
        self.assertEqual(len(self.key_ids), 3)
        self.assertEqual([entry["keyId"] for entry in self.proof["signatures"]], self.key_ids[:2])
        self.assertEqual({entry["algorithm"] for entry in self.proof["signatures"]}, {"Ed25519"})
        self.assertLess(self.proof["trustLevel"], 3)

    def test_signatures_verify_under_the_keys_of_the_section_7_1_1_example(self):
        message = validate_examples.canonical_string(self.proof).encode("utf-8")
        self.assertEqual(
            message.decode("utf-8"),
            "did:opena2a:mcp_server:agent_conformance_test_001|2|0.743200|listed|"
            "2026-10-12T12:00:00Z|2026-10-13T06:00:00Z|did:opena2a:authority:example.org",
        )
        for entry, other in ((self.first, self.second), (self.second, self.first)):
            with self.subTest(keyId=entry["keyId"]):
                value = base64.b64decode(entry["value"])
                self.assertTrue(validate_examples.ed25519_verifies(self.keys[entry["keyId"]], message, value))
                self.assertFalse(validate_examples.ed25519_verifies(self.keys[other["keyId"]], message, value))

    def test_one_key_of_the_set_is_fewer_than_the_threshold(self):
        for entry in (self.first, self.second):
            with self.subTest(keyId=entry["keyId"]):
                self.assertEqual(self.count([entry]), [self.fewer(1)])

    def test_entries_with_the_same_key_id_count_as_one_key(self):
        for signatures in ([self.first, self.first], [self.second, self.second, self.second]):
            with self.subTest(entries=len(signatures)):
                self.assertEqual(self.count(signatures), [self.fewer(1)])

    def test_key_counts_when_any_entry_carrying_it_verifies(self):
        for signatures in (
            [self.first, self.changed(self.second), self.second],
            [self.changed(self.first), self.first, self.second],
        ):
            with self.subTest(signatures=[entry["value"][:8] for entry in signatures]):
                self.assertEqual(self.count(signatures), [])

    def test_entry_that_does_not_verify_counts_toward_no_key(self):
        for entry in (self.changed(self.second), {**self.second, "value": "not base64!"}):
            with self.subTest(value=entry["value"][:12]):
                self.assertEqual(self.count([self.first, entry]), [self.fewer(1)])

    def test_entry_whose_key_id_is_not_in_the_set_counts_toward_no_key(self):
        # The second entry's key is in publicKeys and verifies, but this set leaves it out.
        discovery = self.with_set(keyIds=[self.key_ids[0], self.key_ids[2]])
        self.assertEqual(validate_examples.issuer_key_set_errors(discovery), [])
        self.assertEqual(self.count(discovery=discovery), [self.fewer(1)])

    def test_entry_of_another_algorithm_counts_toward_no_key(self):
        sigstore = validate_examples.sigstore_example()["signatures"][1]
        for entry in (
            {**self.second, "algorithm": "ML-DSA-65"},
            {**self.second, "algorithm": "Sigstore"},
            {**validate_examples.ML_DSA_SIGNATURE, "keyId": self.second["keyId"]},
            {**sigstore, "keyId": self.second["keyId"]},
        ):
            with self.subTest(algorithm=entry["algorithm"], value="value" in entry):
                self.assertEqual(self.count([self.first, entry]), [self.fewer(1)])

    def test_threshold_decides_how_many_keys_meet_the_set(self):
        self.assertEqual(self.count([self.first], self.with_set(threshold=1)), [])
        self.assertEqual(
            self.count(discovery=self.with_set(threshold=3)),
            ["step 4: 2 keys of the issuer key set signed the proof, fewer than its threshold of 3"],
        )

    def test_no_key_signed_a_changed_proof(self):
        self.assertEqual(
            self.count(trustScore=0.7433),
            ["step 4: 0 keys of the issuer key set signed the proof, fewer than its threshold of 2"],
        )

    def test_set_that_breaks_a_rule_is_met_by_no_proof(self):
        broken = "step 4: no proof meets an issuer key set that breaks Section 7.1.1: "
        for members, rule in (
            ({"threshold": 4}, "issuerKeySet threshold 4 is more than the 3 keys it lists"),
            ({"keyIds": [self.key_ids[0], self.key_ids[0], self.key_ids[1]]},
             f"issuerKeySet lists {self.key_ids[0]} twice"),
        ):
            with self.subTest(members=members):
                self.assertEqual(self.count(discovery=self.with_set(**members)), [broken + rule])

    def test_discovery_without_a_set_is_met_by_every_proof(self):
        discovery = copy.deepcopy(self.discovery)
        del discovery["issuerKeySet"]
        for signatures in ([self.first], [self.changed(self.first)]):
            with self.subTest(signatures=signatures[0]["value"][:8]):
                self.assertEqual(self.count(signatures, discovery), [])

    def test_timestamp_that_is_not_rfc3339_is_one_error(self):
        errors = self.count(issuedAt="never")
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("no Section 4.3 canonical string: "), errors[0])

    def test_edits_break_the_count_and_no_other_rule(self):
        """The proof without its #key-2 entry, and with its #key-1 entry in
        place of that entry: Section 4.4.2's two rejected cases."""
        for signatures in ([self.first], [self.first, self.first]):
            with self.subTest(entries=len(signatures)):
                edit = {**self.proof, "signatures": signatures}
                self.assertEqual(validate_examples.two_authority_errors(edit, self.keys), [])
                self.assertEqual(self.count(signatures), [self.fewer(1)])

    def test_check_fails_when_an_edit_meets_the_set(self):
        with mock.patch.object(validate_examples, "key_set_count_errors", return_value=[]):
            errors = validate_examples.key_set_proof_check()
        self.assertEqual(
            errors,
            [
                "the example without its last entry does not break the count alone",
                "the example with its first entry in place of its last does not break the count alone",
            ],
        )

    def test_check_fails_a_proof_one_key_signed(self):
        with mock.patch.object(
            validate_examples, "key_set_proof_example", return_value={**self.proof, "signatures": [self.first]}
        ):
            self.assertEqual(validate_examples.key_set_proof_check(), [self.fewer(1)])

    def test_check_fails_a_proof_at_trust_level_3(self):
        # Another trustLevel changes the canonical string, so no signature is verified here.
        with mock.patch.object(
            validate_examples, "key_set_proof_example", return_value={**self.proof, "trustLevel": 3}
        ), mock.patch.object(validate_examples, "ed25519_verifies", return_value=True):
            self.assertEqual(validate_examples.key_set_proof_check(), [validate_examples.SINGLE_AUTHORITY])

    def test_check_fails_a_proof_of_another_authority(self):
        issuer = "did:opena2a:authority:opena2a.org"
        with mock.patch.object(
            validate_examples, "key_set_proof_example", return_value={**self.proof, "issuerDid": issuer}
        ):
            errors = validate_examples.key_set_proof_check()
        self.assertEqual(
            errors,
            [
                f"the example's issuerDid {issuer!r} is not the authorityDid "
                f"'did:opena2a:authority:example.org' of the {KEY_SET_HEADING!r} example"
            ],
        )

    def test_check_fails_when_the_section_7_1_1_example_declares_no_set(self):
        discovery = copy.deepcopy(self.discovery)
        del discovery["issuerKeySet"]
        with mock.patch.object(validate_examples, "key_set_discovery_example", return_value=discovery):
            errors = validate_examples.key_set_proof_check()
        self.assertEqual(errors, [f"the {KEY_SET_HEADING!r} example declares no issuerKeySet"])

    def test_sections_4_4_7_1_1_and_2_1_name_the_proof(self):
        lines = self.spec.splitlines()
        count = next(i for i, line in enumerate(lines) if line.startswith("**Issuer key set count.**"))
        paragraph = " ".join(lines[count:lines.index("", count)])
        self.assertIn("Section 4.4.2 is a proof that meets the set of the Section 7.1.1 example.", paragraph)
        self.assertIn("Section 4.4.2 is a proof that two of its keys signed.", self.spec)
        coverage = next(line for line in lines if line.startswith(validate_examples.COVERAGE_LIST))
        self.assertIn("the Section 4.4.2 proof and its two edits are the three cases", coverage)

    def with_block(self, heading, block):
        """ATP-SPEC.md with `block` in place of the ```json block under `heading`."""
        start = self.spec.index("```json\n", self.spec.index(f"\n{heading}\n")) + len("```json\n")
        end = self.spec.index("\n```\n", start)
        return self.spec[:start] + block + self.spec[end:]

    def main_with_spec(self, spec, unmapped=None):
        """Run main() in a copy of the repository whose ATP-SPEC.md is `spec`,
        without the examples map entry of the heading `unmapped` when one is
        given. Returns the exit code, the output lines and those of them that
        report a failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy(ROOT / "README.md", root / "README.md")
            (root / "ATP-SPEC.md").write_text(spec, encoding="utf-8")
            for directory in ("schemas", "registries", "examples"):
                shutil.copytree(ROOT / directory, root / directory)
            if unmapped is not None:
                map_path = root / "schemas" / "examples-map.json"
                entries = json.loads(map_path.read_text(encoding="utf-8"))
                kept = [entry for entry in entries if entry.get("heading") != unmapped]
                self.assertEqual(len(kept), len(entries) - 1)
                map_path.write_text(json.dumps(kept), encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                code = validate_examples.main()
        lines = out.getvalue().splitlines()
        return code, lines, [line for line in lines if "FAIL" in line or "INVALID" in line]

    def test_main_reports_the_check(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 0)
        self.assertIn(f"keyset OK      {self.KEYSET}\n", out.getvalue())
        self.assertIn(f"example OK     ATP-SPEC.md @ {self.HEADING!r}\n", out.getvalue())

    def test_main_fails_on_key_set_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "key_set_proof_check", return_value=["one key"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn(f"keyset FAIL    {self.KEYSET}\n    one key\n", out.getvalue())

    def test_main_fails_on_a_proof_one_key_signed(self):
        for signatures in ([self.first], [self.first, self.first]):
            with self.subTest(entries=len(signatures)):
                block = json.dumps({**self.proof, "signatures": signatures}, indent=2)
                code, lines, failed = self.main_with_spec(self.with_block(self.HEADING, block))
                self.assertEqual((code, failed), (1, [f"keyset FAIL    {self.KEYSET}"]), lines)
                self.assertIn(f"    {self.fewer(1)}", lines)
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_reports_an_example_it_cannot_read_once(self):
        """The examples map validates each block and reports it, and checks
        the Section 7.1.1 rules on that example; the check is not compared,
        not failed a second time."""
        proof_label = f"ATP-SPEC.md @ {self.HEADING!r}"
        set_label = f"ATP-SPEC.md @ {KEY_SET_HEADING!r}"
        proof_schema = f"example FAIL   {proof_label} vs schemas/trust-proof-v1.schema.json"
        for heading, block, failure, state in (
            (self.HEADING, json.dumps(self.proof, indent=2)[:-1], f"example INVALID JSON  {proof_label}: ",
             f"the {self.HEADING!r} example is not JSON"),
            (self.HEADING, "[]", proof_schema,
             f"the {self.HEADING!r} example is not a trust proof the schema accepts"),
            (self.HEADING, json.dumps({**self.proof, "trustLevel": 5}), proof_schema,
             f"the {self.HEADING!r} example is not a trust proof the schema accepts"),
            (KEY_SET_HEADING, "[]", f"example FAIL   {set_label} vs schemas/discovery-v1.schema.json",
             f"the {KEY_SET_HEADING!r} example is not a discovery document the schema accepts"),
            (KEY_SET_HEADING, json.dumps(self.with_set(threshold=4), indent=2),
             f"example FAIL   {set_label} vs schemas/discovery-v1.schema.json",
             f"the {KEY_SET_HEADING!r} example's issuerKeySet breaks a Section 7.1.1 rule"),
        ):
            with self.subTest(heading=heading, block=block[:20], state=state):
                code, lines, failed = self.main_with_spec(self.with_block(heading, block))
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith(failure), failed)
                self.assertIn(f"keyset SKIP    {self.KEYSET}: not compared, {state}", lines)
                self.assertEqual([line for line in lines if line.startswith("keyset OK")], [])
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_fails_the_check_on_an_unmapped_example_it_cannot_read(self):
        for heading, block, state in (
            (self.HEADING, "[]", f"the {self.HEADING!r} example is not a trust proof the schema accepts"),
            (KEY_SET_HEADING, json.dumps(self.with_set(threshold=4), indent=2),
             f"the {KEY_SET_HEADING!r} example's issuerKeySet breaks a Section 7.1.1 rule"),
        ):
            with self.subTest(heading=heading):
                code, lines, failed = self.main_with_spec(self.with_block(heading, block), unmapped=heading)
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"keyset FAIL    {self.KEYSET}"], lines)
                self.assertIn(f"    {state}", lines)
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_reports_a_heading_that_is_not_in_the_spec_once(self):
        not_found = f"ATP-SPEC.md: heading {self.HEADING!r} not found"
        self.assertEqual(self.spec.count(f"\n{self.HEADING}\n"), 1)
        renamed = self.spec.replace(f"\n{self.HEADING}\n", f"\n{self.HEADING} entry\n")
        code, lines, failed = self.main_with_spec(renamed)
        self.assertEqual((code, failed), (1, [f"example FAIL   {not_found}"]), lines)
        self.assertIn(f"keyset SKIP    {self.KEYSET}: not compared, {not_found}", lines)
        code, lines, failed = self.main_with_spec(renamed, unmapped=self.HEADING)
        self.assertEqual((code, failed), (1, [f"keyset FAIL    {self.KEYSET}"]), lines)
        self.assertIn(f"    {not_found}", lines)
        self.assertEqual(lines[-1], "1 failure(s)")


# A Section 4.3 with a table of served timestamps; {row} is on line 6.
SIGNING_SPEC = (
    "### 4.3 Signing\n\n"
    "| Served | In the canonical string |\n"
    "|---|---|\n"
    "| `2026-05-23T12:00:00Z` | `2026-05-23T12:00:00Z` |\n"
    "{row}\n\n"
    "### 4.4 Verification\n"
)
# The issuedAt a live proof was served with: nanoseconds, signed in whole seconds.
LIVE_ISSUED_AT = "2026-10-12T02:57:21.581346834Z"


class SignedTimestampTest(unittest.TestCase):
    def errors(self, row):
        return validate_examples.signed_timestamp_errors(SIGNING_SPEC.format(row=row))

    def test_repository_spec_passes(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.assertEqual(validate_examples.signed_timestamp_errors(spec), [])

    def test_live_proof_timestamp_is_signed_in_whole_seconds(self):
        self.assertEqual(validate_examples.signed_time(LIVE_ISSUED_AT), "2026-10-12T02:57:21Z")

    def test_fractional_seconds_are_dropped_not_rounded(self):
        self.assertEqual(validate_examples.signed_time("2026-10-12T02:57:21.999Z"), "2026-10-12T02:57:21Z")

    def test_offset_is_converted_to_utc(self):
        self.assertEqual(
            validate_examples.signed_time("2026-10-11T20:57:21.5-06:00"), "2026-10-12T02:57:21Z"
        )

    def test_signed_form_is_unchanged(self):
        self.assertEqual(validate_examples.signed_time("2026-05-23T12:00:00Z"), "2026-05-23T12:00:00Z")

    def test_timestamp_that_is_not_rfc3339_raises(self):
        for value in ("2026-10-12 02:57:21Z", "2026-10-12T02:57:21", "2026-13-12T02:57:21Z"):
            with self.subTest(value), self.assertRaises(ValueError):
                validate_examples.signed_time(value)

    def test_table_with_a_fractional_row_passes(self):
        self.assertEqual(self.errors(f"| `{LIVE_ISSUED_AT}` | `2026-10-12T02:57:21Z` |"), [])

    def test_row_signing_the_served_bytes_fails_at_its_line(self):
        errors = self.errors(f"| `{LIVE_ISSUED_AT}` | `{LIVE_ISSUED_AT}` |")
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("ATP-SPEC.md:6:"), errors[0])
        self.assertIn("is signed as '2026-10-12T02:57:21Z'", errors[0])

    def test_row_rounding_the_seconds_fails(self):
        errors = self.errors("| `2026-10-12T02:57:21.999Z` | `2026-10-12T02:57:22Z` |")
        self.assertEqual(len(errors), 1)
        self.assertIn("is signed as '2026-10-12T02:57:21Z'", errors[0])

    def test_row_keeping_the_offset_fails(self):
        errors = self.errors("| `2026-10-11T20:57:21.5-06:00` | `2026-10-11T20:57:21-06:00` |")
        self.assertEqual(len(errors), 1)
        self.assertIn("is signed as '2026-10-12T02:57:21Z'", errors[0])

    def test_row_serving_no_timestamp_fails(self):
        errors = self.errors("| `2026-10-12 02:57:21.5Z` | `2026-10-12T02:57:21Z` |")
        self.assertEqual(len(errors), 2)
        self.assertIn("is not an RFC 3339 timestamp", errors[0])
        self.assertIn("fractional seconds", errors[1])

    def test_table_without_a_fractional_row_fails(self):
        errors = self.errors("| `2026-05-24T06:00:00Z` | `2026-05-24T06:00:00Z` |")
        self.assertEqual(len(errors), 1)
        self.assertIn("no row shows a served timestamp with fractional seconds", errors[0])

    def test_section_without_a_table_fails(self):
        text = "### 4.3 Signing\n\nNo table.\n\n### 4.4 Verification\n\n| a | b |\n|---|---|\n| c | d |\n"
        errors = validate_examples.signed_timestamp_errors(text)
        self.assertEqual(len(errors), 1)
        self.assertIn("no timestamp rows", errors[0])

    def test_main_fails_on_signed_timestamp_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "signed_timestamp_errors", return_value=["row signs the served bytes"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("timestamp FAIL", out.getvalue())
        self.assertIn("row signs the served bytes", out.getvalue())


class SigstoreCoSignatureTest(unittest.TestCase):
    def schema(self):
        path = ROOT / "schemas" / "trust-proof-v1.schema.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def errors(self, definition, edit):
        schema = self.schema()
        edit(schema["$defs"][definition])
        return validate_examples.sigstore_cosignature_errors(schema)

    @staticmethod
    def log_entry(bundle):
        return bundle["properties"]["verificationMaterial"]["properties"]["tlogEntries"]

    def test_repository_schema_passes(self):
        self.assertEqual(validate_examples.sigstore_cosignature_errors(), [])

    def test_example_adds_a_bundle_to_the_authority_signature(self):
        signatures = validate_examples.sigstore_example()["signatures"]
        self.assertEqual([entry["algorithm"] for entry in signatures], ["Ed25519", "Sigstore"])
        self.assertIn("bundle", signatures[1])
        self.assertNotIn("value", signatures[1])

    def test_schema_with_key_signatures_only_fails(self):
        schema = self.schema()
        schema["properties"]["signatures"]["items"] = schema["$defs"]["keySignature"]
        errors = validate_examples.sigstore_cosignature_errors(schema)
        self.assertIn("the Section 4.3.1 co-signature entry is refused", errors)

    def test_schema_without_a_required_key_signature_fails(self):
        schema = self.schema()
        del schema["properties"]["signatures"]["contains"]
        errors = validate_examples.sigstore_cosignature_errors(schema)
        self.assertEqual(errors, [
            "a proof whose only signature is the Sigstore entry is accepted",
            "a proof whose only signatures are two Sigstore entries is accepted",
            "a proof whose only signature is an ML-DSA-65 entry is accepted",
        ])

    def test_schema_requiring_any_key_signature_fails(self):
        """Section 4.4 step 4 needs an Ed25519 entry; an ML-DSA-65 entry is a
        key signature too, and never stands alone."""
        schema = self.schema()
        schema["properties"]["signatures"]["contains"] = {"$ref": "#/$defs/keySignature"}
        errors = validate_examples.sigstore_cosignature_errors(schema)
        self.assertEqual(errors, ["a proof whose only signature is an ML-DSA-65 entry is accepted"])

    def test_two_entry_probe_holds_two_sigstore_entries(self):
        """A schema that refuses one Sigstore-only entry and accepts two fails
        the two-entry probe alone, so that probe holds two entries."""
        schema = self.schema()
        signatures = schema["properties"]["signatures"]
        del signatures["contains"]
        signatures["minItems"] = 2
        errors = validate_examples.sigstore_cosignature_errors(schema)
        self.assertEqual(errors, ["a proof whose only signatures are two Sigstore entries is accepted"])

    def test_open_entry_fails(self):
        errors = self.errors("sigstoreCoSignature", lambda entry: entry.pop("additionalProperties"))
        self.assertEqual(errors, ["a co-signature with a value beside its bundle is accepted"])

    def test_open_bundle_fails(self):
        errors = self.errors("sigstoreBundle", lambda bundle: bundle.pop("additionalProperties"))
        self.assertEqual(
            errors, ["a co-signature with a DSSE envelope beside its message signature is accepted"]
        )

    def test_key_signature_admitting_a_bundle_fails(self):
        def edit(entry):
            entry["required"].remove("value")
            entry["properties"]["bundle"] = {"type": "object"}

        errors = self.errors("keySignature", edit)
        self.assertEqual(errors, ["a co-signature with algorithm Ed25519 is accepted"])

    def test_any_bundle_media_type_fails(self):
        errors = self.errors(
            "sigstoreBundle", lambda bundle: bundle["properties"].update(mediaType={"type": "string"})
        )
        self.assertEqual(errors, ["a co-signature in a version 0.1 bundle is accepted"])

    def test_empty_log_fails(self):
        def edit(bundle):
            self.log_entry(bundle).pop("minItems")
            self.log_entry(bundle).pop("contains")

        self.assertIn("a co-signature with no log entry is accepted", self.errors("sigstoreBundle", edit))

    def test_log_without_a_required_hashedrekord_entry_fails(self):
        errors = self.errors("sigstoreBundle", lambda bundle: self.log_entry(bundle).pop("contains"))
        self.assertEqual(errors, [
            "a co-signature whose log entry has no inclusionProof is accepted",
            "a co-signature whose log entry is not hashedrekord is accepted",
            "a co-signature whose hashedrekord entry has no inclusionProof and whose other log "
            "entry is another kind is accepted",
        ])

    def test_log_entry_without_inclusion_proof_fails(self):
        errors = self.errors("hashedrekordEntry", lambda entry: entry["required"].remove("inclusionProof"))
        self.assertEqual(errors, [
            "a co-signature whose log entry has no inclusionProof is accepted",
            "a co-signature whose hashedrekord entry has no inclusionProof and whose other log "
            "entry is another kind is accepted",
        ])

    def test_schema_requiring_every_log_entry_to_be_a_hashedrekord_entry_fails(self):
        """Section 4.3.1 rule 2 needs one hashedrekord entry with an inclusion
        proof; a bundle may hold other entries beside it."""
        for label, edit in (
            ("hashedrekord kind", lambda entry: entry["properties"]["kindVersion"]["properties"]
             .update(kind={"const": "hashedrekord"})),
            ("inclusionProof", lambda entry: entry["required"].append("inclusionProof")),
        ):
            with self.subTest(label):
                self.assertEqual(self.errors("tlogEntry", edit), [
                    "a co-signature with a second log entry of another kind and no inclusionProof "
                    "is refused",
                ])

    def test_schema_requiring_integrated_time_fails(self):
        for definition in ("tlogEntry", "hashedrekordEntry"):
            with self.subTest(definition):
                errors = self.errors(definition, lambda entry: entry["required"].append("integratedTime"))
                self.assertEqual(
                    errors,
                    ["a co-signature from a Rekor v2 log, timed by an RFC 3161 timestamp is refused"],
                )

    def test_schema_requiring_log_index_fails(self):
        for definition in ("tlogEntry", "hashedrekordEntry"):
            with self.subTest(definition):
                errors = self.errors(definition, lambda entry: entry["required"].append("logIndex"))
                self.assertEqual(errors, ["a co-signature whose log entry has no logIndex is refused"])

    @staticmethod
    def errors_for_example(edit):
        """sigstore_cosignature_errors() on the Section 4.3.1 example with edit
        applied to its Sigstore entry."""
        example = validate_examples.sigstore_example()
        edit(example["signatures"][1])
        with mock.patch.object(validate_examples, "sigstore_example", return_value=example):
            return validate_examples.sigstore_cosignature_errors()

    UNEDITABLE = (f"the {validate_examples.SIGSTORE_HEADING!r} example has a Sigstore entry "
                  "without the members the probes edit")

    def test_refused_entry_the_probes_cannot_edit_is_unusable(self):
        """The examples map reports an example the schema refuses, so the
        co-signature check raises SourceUnusable, not a Python exception."""
        for label, edit in (
            ("bundle that is not an object", lambda entry: entry.update(bundle="x")),
            ("bundle without verificationMaterial", lambda entry: entry["bundle"].pop("verificationMaterial")),
            ("tlogEntries that is an object",
             lambda entry: entry["bundle"]["verificationMaterial"].update(tlogEntries={})),
            ("no log entry", lambda entry: entry["bundle"]["verificationMaterial"].update(tlogEntries=[])),
            ("messageSignature that is a list", lambda entry: entry["bundle"].update(messageSignature=[])),
        ):
            with self.subTest(label):
                with self.assertRaises(validate_examples.SourceUnusable) as raised:
                    self.errors_for_example(edit)
                self.assertEqual(str(raised.exception), self.UNEDITABLE)

    def test_admitted_entry_the_probes_cannot_edit_fails(self):
        """Nothing else reports an example the schema admits, so the check fails
        with one error instead of a Python exception or a silent skip."""
        log_entry = ("bundle", "verificationMaterial", "tlogEntries", 0)
        for name in ("inclusionPromise", "integratedTime", "logIndex"):
            with self.subTest(name):
                errors = self.errors_for_example(validate_examples.member(log_entry + (name,)))
                self.assertEqual(errors, [self.UNEDITABLE])

    def test_ed25519_signature_is_the_key_signature_restricted_to_ed25519(self):
        """The schema writes ed25519Signature out in full beside keySignature;
        apart from descriptions it is keySignature with algorithm fixed to Ed25519."""
        definitions = self.schema()["$defs"]

        def without_descriptions(value):
            if isinstance(value, dict):
                return {key: without_descriptions(item) for key, item in value.items() if key != "description"}
            if isinstance(value, list):
                return [without_descriptions(item) for item in value]
            return value

        expected = copy.deepcopy(definitions["keySignature"])
        expected["properties"]["algorithm"] = {"const": "Ed25519"}
        self.assertEqual(without_descriptions(definitions["ed25519Signature"]), without_descriptions(expected))

    def main_with_cosignature_example(self, block, mapped=True):
        """Run main() in a copy of the repository whose Section 4.3.1 example
        block is `block`, with or without its examples map entry. Returns the
        exit code, the output lines and those of them that report a failure."""
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        heading = validate_examples.SIGSTORE_HEADING
        start = spec.index("```json\n", spec.index(heading)) + len("```json\n")
        end = spec.index("\n```\n", start)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy(ROOT / "README.md", root / "README.md")
            (root / "ATP-SPEC.md").write_text(spec[:start] + block + spec[end:], encoding="utf-8")
            for directory in ("schemas", "registries", "examples"):
                shutil.copytree(ROOT / directory, root / directory)
            if not mapped:
                map_path = root / "schemas" / "examples-map.json"
                entries = json.loads(map_path.read_text(encoding="utf-8"))
                kept = [entry for entry in entries if entry.get("heading") != heading]
                self.assertEqual(len(kept), len(entries) - 1)
                map_path.write_text(json.dumps(kept), encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                code = validate_examples.main()
        lines = out.getvalue().splitlines()
        return code, lines, [line for line in lines if "FAIL" in line or "INVALID" in line]

    def test_main_reports_a_cosignature_example_it_cannot_read_once(self):
        """The examples map validates the block and reports it; the co-signature
        check is not compared, not failed a second time."""
        cosign = "cosign SKIP    schemas/trust-proof-v1.schema.json vs Section 4.3.1: not compared, "
        label = f"ATP-SPEC.md @ {validate_examples.SIGSTORE_HEADING!r}"
        example = validate_examples.sigstore_example()
        unbundled = copy.deepcopy(example)
        unbundled["signatures"][1]["bundle"] = "x"
        for state, block, failure in (
            ("is not JSON", json.dumps(example, indent=2)[:-1], f"example INVALID JSON  {label}: "),
            ("has no signatures list", "[]",
             f"example FAIL   {label} vs schemas/trust-proof-v1.schema.json"),
            ("has no signatures list", json.dumps({**example, "signatures": "FAKE"}),
             f"example FAIL   {label} vs schemas/trust-proof-v1.schema.json"),
            ("has a Sigstore entry without the members the probes edit", json.dumps(unbundled),
             f"example FAIL   {label} vs schemas/trust-proof-v1.schema.json"),
        ):
            with self.subTest(state=state, block=block[:20]):
                code, lines, failed = self.main_with_cosignature_example(block)
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith(failure), failed)
                self.assertIn(f"{cosign}the {validate_examples.SIGSTORE_HEADING!r} example {state}", lines)
                self.assertEqual([line for line in lines if line.startswith("cosign OK")], [])
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_fails_the_cosignature_check_on_an_unmapped_example_it_cannot_read(self):
        code, lines, failed = self.main_with_cosignature_example("[]", mapped=False)
        self.assertEqual(code, 1)
        self.assertEqual(failed, ["cosign FAIL    schemas/trust-proof-v1.schema.json vs Section 4.3.1"])
        self.assertIn(f"    the {validate_examples.SIGSTORE_HEADING!r} example has no signatures list", lines)
        self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_fails_on_cosignature_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "sigstore_cosignature_errors", return_value=["probe accepted"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("cosign FAIL", out.getvalue())
        self.assertIn("probe accepted", out.getvalue())


class VerifiableCredentialFormTest(unittest.TestCase):
    """Section 4.6: examples/atx-vc-example.json is the mapping table applied
    to examples/atx-example.json, and the schema refuses a form that leaves a
    member where the table moves it from."""

    REQUIRED = ["@context", "type", "issuer", "credentialSubject"]
    VC_SCHEMA = "schemas/atx-vc-v1.schema.json"

    def setUp(self):
        self.atx = json.loads((ROOT / "examples" / "atx-example.json").read_text(encoding="utf-8"))
        self.vc = json.loads((ROOT / "examples" / "atx-vc-example.json").read_text(encoding="utf-8"))
        self.rows = validate_examples.vc_form_rows()
        self.schema = json.loads((ROOT / self.VC_SCHEMA).read_text(encoding="utf-8"))
        self.validator = Draft202012Validator(
            self.schema, registry=validate_examples.local_registry()
        )

    def moved(self):
        """(ATX member, property) for each row that moves a member."""
        for row in self.rows:
            member, placed = row["ATX member"], row["Verifiable Credential property"]
            if member not in (validate_examples.NO_ATX_MEMBER, placed):
                yield member, placed

    def test_repository_example_passes(self):
        self.assertEqual(validate_examples.atx_vc_form_errors(self.vc), [])
        self.assertEqual(list(self.validator.iter_errors(self.vc)), [])

    def test_example_carries_the_properties_the_atx_example_lacks(self):
        self.assertEqual([name for name in self.REQUIRED if name in self.atx], [])
        self.assertEqual([name for name in self.REQUIRED if name not in self.vc], [])
        messages = [err.message for err in self.validator.iter_errors(self.atx)]
        for name in self.REQUIRED:
            self.assertIn(f"{name!r} is a required property", messages)

    @staticmethod
    def parent_of(vc, placed):
        """The object of `vc` that holds the property `placed`, and its name there."""
        *parents, name = placed.split(".")
        for parent in parents:
            vc = vc[parent]
        return vc, name

    def test_dropping_or_changing_what_a_row_places_fails(self):
        for row in self.rows:
            placed = row["Verifiable Credential property"]
            with self.subTest(placed):
                dropped = copy.deepcopy(self.vc)
                parent, name = self.parent_of(dropped, placed)
                del parent[name]
                self.assertEqual(
                    validate_examples.atx_vc_form_errors(dropped), [f"{placed} is missing"]
                )
                changed = copy.deepcopy(self.vc)
                parent, name = self.parent_of(changed, placed)
                parent[name] = "changed"
                errors = validate_examples.atx_vc_form_errors(changed)
                self.assertEqual(len(errors), 1)
                self.assertTrue(errors[0].startswith(f'{placed} is "changed"; '), errors[0])

    def test_member_left_at_its_atx_name_fails(self):
        for member, _ in self.moved():
            with self.subTest(member):
                left = dict(self.vc, **{member: self.atx[member]})
                self.assertEqual(
                    validate_examples.atx_vc_form_errors(left),
                    [f"{member} is not produced by the Section 4.6 table"],
                )
                self.assertFalse(self.validator.is_valid(left))

    def test_claim_the_table_does_not_name_fails(self):
        added = copy.deepcopy(self.vc)
        added["credentialSubject"]["admin"] = True
        self.assertEqual(
            validate_examples.atx_vc_form_errors(added),
            ["credentialSubject.admin is not produced by the Section 4.6 table"],
        )
        self.assertFalse(self.validator.is_valid(added))

    def test_schema_subject_claims_are_the_table_rows(self):
        placed = {
            row["Verifiable Credential property"].split(".", 1)[1]
            for row in self.rows
            if row["Verifiable Credential property"].startswith("credentialSubject.")
        }
        subject = self.schema["properties"]["credentialSubject"]
        self.assertEqual(set(subject["properties"]), placed)
        self.assertIs(subject["additionalProperties"], False)

    def test_atx_member_without_a_row_fails(self):
        rows = [row for row in self.rows if row["ATX member"] != "capabilities"]
        self.assertEqual(
            validate_examples.atx_vc_form_errors(self.vc, rows=rows),
            [
                "ATX member 'capabilities' of examples/atx-example.json has no row in the "
                "Section 4.6 table",
                "credentialSubject.capabilities is not produced by the Section 4.6 table",
            ],
        )

    def test_row_that_changes_a_value_fails(self):
        rows = [
            dict(row, Value="uppercased") if row["ATX member"] == "verdict" else row
            for row in self.rows
        ]
        errors = validate_examples.atx_vc_form_errors(self.vc, rows=rows)
        self.assertEqual(len(errors), 1)
        self.assertIn("'verdict' has Value 'uppercased'", errors[0])

    def test_every_section_4_6_schema_member_has_a_row(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8").split("\n")
        _, fields = validate_examples.table_after_marker(spec, "#### Schema")
        listed = {name.strip() for row in fields for name in row["Field"].split(",")}
        self.assertIn("declaredPurpose", listed)
        self.assertEqual(listed - {row["ATX member"] for row in self.rows}, set())

    def test_schema_requires_the_base_context_and_both_types(self):
        context = self.vc["@context"]
        for edit in (
            {"@context": ["https://www.w3.org/2018/credentials/v1", context[1]]},
            {"@context": context[:1]},
            {"@context": context[::-1]},
            {"@context": context[0]},
            {"type": ["AtxCredential"]},
            {"type": ["VerifiableCredential"]},
            {"type": "VerifiableCredential"},
        ):
            with self.subTest(edit=edit):
                self.assertFalse(self.validator.is_valid(dict(self.vc, **edit)))

    def test_schema_holds_base_members_to_the_trust_proof_shapes(self):
        for placed, value in (
            ("issuer", "not-a-did"),
            ("credentialSubject.id", "not-a-did"),
            ("credentialSubject.trustLevel", 5),
            ("credentialSubject.trustScore", 1.5),
            ("credentialSubject.verdict", "trusted"),
        ):
            with self.subTest(placed):
                edited = copy.deepcopy(self.vc)
                parent, name = self.parent_of(edited, placed)
                parent[name] = value
                self.assertFalse(self.validator.is_valid(edited))

    def test_schema_admits_a_property_the_mapping_does_not_produce(self):
        secured = dict(self.vc, proof={"type": "DataIntegrityProof"})
        self.assertTrue(self.validator.is_valid(secured))

    def test_schema_refuses_a_timestamp_that_is_not_a_date_time_stamp(self):
        for value in (
            "2026-05-19t14:00:00Z",
            "2026-05-19T14:00:00z",
            "2026-05-19 14:00:00Z",
            "2026-05-19T14:00:00",
            20260519,
        ):
            with self.subTest(value=value):
                self.assertFalse(self.validator.is_valid(dict(self.vc, validFrom=value)))
                self.assertFalse(self.validator.is_valid(dict(self.vc, validUntil=value)))
        offset = dict(self.vc, validFrom="2026-05-19T16:00:00+02:00")
        self.assertTrue(self.validator.is_valid(offset))

    def test_main_validates_the_example_file(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 0)
        self.assertIn("example OK     examples/atx-vc-example.json\n", out.getvalue())
        out = io.StringIO()
        with mock.patch.dict(
            validate_examples.SEMANTIC_CHECKS, {self.VC_SCHEMA: lambda vc: ["row broken"]}
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn(
            f"example FAIL   examples/atx-vc-example.json vs {self.VC_SCHEMA}\n", out.getvalue()
        )
        self.assertIn("row broken", out.getvalue())

    ATX_FAIL = "atx FAIL       README.md, example and schema vs Section 4.6"
    FORM_FAIL = f"example FAIL   examples/atx-vc-example.json vs {VC_SCHEMA}"

    def main_in_tree(self, examples):
        """Run main() in a copy of the repository whose examples directory
        holds only `examples` (file name to text, or to bytes for a file that
        is not UTF-8). Returns the exit code, the output lines and those of
        them that report a failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("README.md", "ATP-SPEC.md"):
                shutil.copy(ROOT / name, root / name)
            for directory in ("schemas", "registries"):
                shutil.copytree(ROOT / directory, root / directory)
            (root / "examples").mkdir()
            for name, text in examples.items():
                content = text if isinstance(text, bytes) else text.encode("utf-8")
                (root / "examples" / name).write_bytes(content)
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                code = validate_examples.main()
        lines = out.getvalue().splitlines()
        return code, lines, [line for line in lines if "FAIL" in line or "INVALID" in line]

    def test_main_reports_a_missing_form_example_as_one_failure(self):
        atx = (ROOT / "examples" / "atx-example.json").read_text(encoding="utf-8")
        code, lines, failed = self.main_in_tree({"atx-example.json": atx})
        self.assertEqual(code, 1)
        self.assertEqual(failed, [self.FORM_FAIL])
        at = lines.index(self.FORM_FAIL)
        self.assertEqual(
            lines[at + 1],
            "    examples/atx-vc-example.json: missing; schemas/examples-map.json maps it to "
            f"{self.VC_SCHEMA}",
        )
        self.assertFalse(lines[at + 2].startswith("    "), lines)

    def test_main_does_not_fail_the_form_for_an_atx_example_it_cannot_read(self):
        atx = (ROOT / "examples" / "atx-example.json").read_text(encoding="utf-8")
        vc = (ROOT / "examples" / "atx-vc-example.json").read_text(encoding="utf-8")
        for state, text in (
            ("is missing", None),
            ("is not UTF-8", b"\xe9" + atx.encode("utf-8")),
            ("is not JSON", atx.rstrip().rstrip("}")),
            ("is not a JSON object", "[]"),
        ):
            with self.subTest(state):
                examples = {"atx-vc-example.json": vc}
                if text is not None:
                    examples["atx-example.json"] = text
                code, lines, failed = self.main_in_tree(examples)
                self.assertEqual(code, 1)
                self.assertEqual(failed, [self.ATX_FAIL])
                self.assertIn(
                    "example SKIP   examples/atx-vc-example.json: not compared, "
                    f"examples/atx-example.json {state}",
                    lines,
                )
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_main_reports_two_missing_example_files_as_two_failures(self):
        code, lines, failed = self.main_in_tree({})
        self.assertEqual(code, 1)
        self.assertEqual(failed, [self.ATX_FAIL, self.FORM_FAIL])
        self.assertEqual(lines[-1], "2 failure(s)")

    def test_readme_claim_points_at_the_mapping(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        # The claim is in the Interoperability list, which docs/interoperability.md holds.
        interop = (ROOT / "docs" / "interoperability.md").read_text(encoding="utf-8")
        claims = [
            line
            for text in (readme, interop)
            for line in text.splitlines()
            if "vc-data-model-2.0" in line
        ]
        self.assertEqual(len(claims), 1)
        self.assertNotIn("structurally compatible", claims[0])
        self.assertIn("(../README.md#verifiable-credential-form)", claims[0])
        self.assertIn("\n### Verifiable Credential form\n", readme)
        self.assertIn("(./ATP-SPEC.md#verifiable-credential-form)", readme)
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.assertIn(f"\n{validate_examples.VC_FORM_HEADING}\n", spec)
        for path in ("examples/atx-vc-example.json", self.VC_SCHEMA):
            self.assertIn(f"(./{path})", readme)
            self.assertIn(f"(./{path})", spec)


CONFORMANCE = ROOT / "conformance"
HAS_JQ = shutil.which("jq") is not None
HAS_SCRIPT_TOOLS = HAS_JQ and all(shutil.which(tool) for tool in ("bash", "curl"))
LEVEL1 = [
    "Discovery endpoint returns JSON",
    "Discovery has authorityDid, version, endpoints",
    "Conformance level is 1-3",
    "DID resolution returns document",
    "DID Document has @context",
    "DID Document has verificationMethod",
    "Trust proof endpoint returns proof",
    "Trust proof has all required fields",
    "Trust proof has an Ed25519 authority signature",
    "Trust proof not expired",
    "Trust level is 0-4",
    "Trust score is 0.0-1.0",
    "Verify endpoint accepts proof",
    "Verification result is valid=true",
]
LEVEL2 = [
    "Transparency log endpoint returns data",
    "Log entries have structure",
    "Revocations endpoint returns data",
]
T1 = dict(zip(range(1, 15), LEVEL1))
T2 = dict(zip(range(1, 4), LEVEL2))
COSIGNED = validate_examples.sigstore_example()["signatures"]
SHARED_CURL_OPTIONS = ("--path-as-is", "--connect-timeout", "--max-time")
TRANSPORT_REFUSED = "the authority URL is neither https nor http to a loopback address literal (Section 7.1)"


def without_comment(line):
    """line up to a comment: a # that starts a word, outside quotes."""
    quote = None
    escaped = False
    for at, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            quote = None if char == quote else quote
        elif char in "'\"":
            quote = char
        elif char == "#" and (at == 0 or line[at - 1] in " \t;&|()"):
            return line[:at]
    return line


def curl_calls(text):
    """The text after each curl word of a shell script, read with continued
    lines joined, that is outside comments and the word list of a for loop."""
    calls = []
    for line in text.replace("\\\n", " ").splitlines():
        code = re.sub(r"(?:^|(?<=[;&|(]))[ \t]*for[ \t]+\w+[ \t]+in\b[^;]*", "", without_comment(line))
        calls += [code[word.end():] for word in re.finditer(r"(?<![\w.-])curl(?![\w.-])", code)]
    return calls


def missing_curl_options(call):
    """The shared options the text after a curl word does not pass."""
    options = call.split()
    missing = [option for option in SHARED_CURL_OPTIONS if option not in options]
    if not any(re.fullmatch(r"-[A-Za-z]*g[A-Za-z]*|--globoff", option) for option in options):
        missing.insert(0, "-g")
    return missing


def pop(*names):
    return lambda body: [body.pop(name) for name in names]


def put(**members):
    return lambda body: body.update(members)


def first(member, edit):
    return lambda body: edit(body[member][0])


def inside(member, edit):
    return lambda body: edit(body[member])


def with_log_entry(cosignature, kind, at=None):
    """A copy of cosignature whose bundle's log entry at index `at` is of kind
    `kind`, or, with no index, that has a second log entry of that kind."""
    edited = copy.deepcopy(cosignature)
    if at is None:
        validate_examples.log_entry_added(kind)(edited)
    else:
        path = validate_examples.MATERIAL + ("tlogEntries", at, "kindVersion", "kind")
        validate_examples.member(path, kind)(edited)
    return edited


def at_offset(hours_from_now, utc_offset_hours):
    """An RFC 3339 time hours_from_now away, written in a +/-utc_offset_hours zone."""
    zone = timezone(timedelta(hours=utc_offset_hours))
    return (datetime.now(zone) + timedelta(hours=hours_from_now)).replace(microsecond=0).isoformat()


@unittest.skipUnless(HAS_SCRIPT_TOOLS, "the conformance scripts need bash, curl and jq")
class ConformanceScriptTest(unittest.TestCase):
    """conformance/level2.sh (which runs level1.sh first) against the fixture
    authority: the spec's examples pass every test, and removing or corrupting
    one member fails exactly the tests that check it."""

    @classmethod
    def setUpClass(cls):
        cls.authority = fixture_authority.serve()

    @classmethod
    def tearDownClass(cls):
        cls.authority.shutdown()
        cls.authority.server_close()

    def run_scripts(self, url=None, env=None, **overrides):
        self.authority.overrides = overrides
        self.authority.requests.clear()
        run = subprocess.run(
            ["bash", str(CONFORMANCE / "level2.sh"), url or self.authority.url],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, **(env or {})},
        )
        failed = [
            name
            for name in LEVEL1 + LEVEL2
            if re.search(rf"^FAIL: {re.escape(name)}( \(|$)", run.stdout, re.M)
        ]
        return run, failed

    def probe(self, expected, **overrides):
        run, failed = self.run_scripts(**overrides)
        self.assertEqual(failed, expected, run.stdout)
        self.assertEqual(run.returncode, len(expected), run.stdout)
        return run

    def probes(self, cases):
        for label, expected, overrides in cases:
            with self.subTest(label):
                self.probe(expected, **overrides)

    def received(self, part):
        """The requests of the last run that contain part."""
        return [request for request in self.authority.requests if part in request]

    def test_spec_examples_pass_every_test(self):
        run = self.probe([])
        self.assertIn("=== Results: 14 passed, 0 failed ===", run.stdout)
        self.assertIn("=== Level 2 Results: 3 passed, 0 failed ===", run.stdout)

    def test_authority_from_the_issue_fails(self):
        def proof(body):
            pop("did", "trustLevel", "verdict", "issuedAt")(body)
            body["expiresAt"] = "never"

        run, failed = self.run_scripts(
            discovery=pop("authorityDid", "version"), proof=proof, revocations="<html></html>"
        )
        self.assertIn(T1[2], failed)
        self.assertIn(T2[3], failed)
        self.assertIn("(not met: authorityDid, version)", run.stdout)
        self.assertNotEqual(run.returncode, 0)

    def test_discovery_probes(self):
        self.probes([
            ("HTML body", LEVEL1, {"discovery": "<html><body>ATP</body></html>"}),
            ("no authorityDid", [T1[2]] + LEVEL1[3:], {"discovery": pop("authorityDid")}),
            ("no version", [T1[2]], {"discovery": pop("version")}),
            ("version 2.0", [T1[2]], {"discovery": put(version="2.0")}),
            ("empty endpoints", [T1[2]], {"discovery": put(endpoints={})}),
            ("empty endpoint string", [T1[2]],
             {"discovery": inside("endpoints", put(trustProof=""))}),
            ("no conformanceLevel", [T1[3]], {"discovery": pop("conformanceLevel")}),
            ("string conformanceLevel", [T1[3]], {"discovery": put(conformanceLevel="3")}),
            ("conformanceLevel 0", [T1[3]], {"discovery": put(conformanceLevel=0)}),
            ("conformanceLevel 4", [T1[3]], {"discovery": put(conformanceLevel=4)}),
        ])

    def test_trust_proof_endpoint_must_be_a_path(self):
        other = fixture_authority.serve()
        self.addCleanup(other.server_close)
        self.addCleanup(other.shutdown)
        userinfo = "@" + other.url.split("//", 1)[1] + "/api/v1/trust/proof"
        run = self.probe(LEVEL1[6:], discovery=inside("endpoints", put(trustProof=userinfo)))
        self.assertIn("(endpoints.trustProof does not start with /)", run.stdout)
        self.assertEqual(other.requests, [])

    def test_trust_proof_endpoint_without_a_leading_slash_fails_without_a_request(self):
        """Appended to an authority URL without a port or path, such as
        https://api.oa2a.org, a value that starts with "." extends the host
        name (https://api.oa2a.org.attacker.example/...), and one that starts
        with a letter runs into it. T1.7 sends neither request, and says why."""
        for label, value in (
            ("host suffix", ".attacker.example/api/v1/trust/proof"),
            ("no leading slash", "api/v1/trust/proof"),
        ):
            with self.subTest(label):
                run = self.probe(LEVEL1[6:], discovery=inside("endpoints", put(trustProof=value)))
                self.assertIn(
                    f"FAIL: {T1[7]} (endpoints.trustProof does not start with /)", run.stdout
                )
                self.assertEqual(self.received("/trust/pro"), [])

    def test_trust_proof_endpoint_reading(self):
        """T1.7 requests /api/v1/trust/proof when endpoints.trustProof is not a
        string, and reads a string with its NUL characters and trailing
        newlines removed, without a shell warning on stderr."""
        did = self.authority.examples["discovery"]["authorityDid"]
        for label, expected, value in (
            ("number", [T1[2]], 42),
            ("trailing newline", [], "/api/v1/trust/proof\n"),
            ("leading NUL character", [], "\x00/api/v1/trust/proof"),
            ("NUL character inside the path", [], "/api/v1/trust\x00/proof"),
        ):
            with self.subTest(label):
                run = self.probe(expected, discovery=inside("endpoints", put(trustProof=value)))
                self.assertEqual(self.received("?did="), [f"GET /api/v1/trust/proof?did={did}"])
                self.assertEqual(run.stderr, "")

    def test_trust_proof_endpoint_that_breaks_the_url_fails_without_a_request(self):
        """A "#" would end the path and drop the did parameter, and curl sends
        nothing for a URL that holds whitespace or a control character."""
        for label, value in (
            ("fragment", "/api/v1/trust/proof#frag"),
            ("space", "/api/v1/trust/pro of"),
            ("tab", "/api/v1/trust/proof\tx"),
            ("newline inside the path", "/api/v1/trust\n/proof"),
            ("control character", "/api/v1/trust/proof\x01"),
            ("DEL character", "/api/v1/trust/proof\x7f"),
        ):
            with self.subTest(label):
                run = self.probe(LEVEL1[6:], discovery=inside("endpoints", put(trustProof=value)))
                self.assertIn(
                    "(endpoints.trustProof holds #, whitespace or a control character)", run.stdout
                )
                self.assertEqual(self.received("/trust/pro"), [])

    def test_trust_proof_endpoint_with_a_query_gets_the_did_after_an_ampersand(self):
        did = self.authority.examples["discovery"]["authorityDid"]
        self.probe([], discovery=inside("endpoints", put(trustProof="/api/v1/trust/proof?v=1")))
        self.assertEqual(self.received("did="), [f"GET /api/v1/trust/proof?v=1&did={did}"])

    def test_dot_segments_are_sent_as_written(self):
        """curl does not remove . and .. segments: the declared path gets the
        request, and the tests fail when it is not served."""
        did = self.authority.examples["discovery"]["authorityDid"]
        self.probe(LEVEL1[6:],
                   discovery=inside("endpoints", put(trustProof="/x/../api/v1/trust/proof")))
        self.assertEqual(self.received("?did="), [f"GET /x/../api/v1/trust/proof?did={did}"])

        self.probe([T1[2], T1[8]], discovery=put(authorityDid=".."))
        self.assertEqual(self.received("/api/v1/did/"), ["GET /api/v1/did/.."])

        run, failed = self.run_scripts(url=self.authority.url + "/x/..")
        self.assertEqual(failed, LEVEL1 + LEVEL2, run.stdout)
        self.assertEqual(self.authority.requests, [
            "GET /x/../.well-known/atp",
            "GET /x/../api/v1/transparency/trust-proofs?limit=5",
            "GET /x/../api/v1/trust/revocations?since=2026-01-01T00:00:00Z",
        ])

    def test_authority_did_is_percent_encoded(self):
        """The DID goes into the T1.4 path and the T1.7 query percent-encoded
        except for ":" and "@", so a "#", "?", "/", "%" or space in it does not
        change the request, and the proof is still for the declared DID."""
        for did in ("did:opena2a:authority:opena2a.org#key-1",
                    "did:opena2a:agent@opena2a.org/a?b c%d"):
            with self.subTest(did):
                in_url = quote(did, safe=":@")
                self.probe([] if "#" in did else [T1[2], T1[8]], discovery=put(authorityDid=did))
                self.assertEqual(self.received("/api/v1/did/"), [f"GET /api/v1/did/{in_url}"])
                self.assertEqual(self.received("?did="),
                                 [f"GET /api/v1/trust/proof?did={in_url}"])

    def test_pattern_in_the_authority_host_or_port_is_not_a_valid_url(self):
        """With URL globbing off, curl rejects a brace list or bracket range in
        the host or port: no request is sent, and every test fails. The URLs
        are https ones: the Section 7.1 transport rule refuses an http URL
        whose host is not a loopback address literal before curl reads it."""
        port = self.authority.server_address[1]
        for url in (f"https://127.0.0.[1-1]:{port}", f"https://127.0.0.{{1}}:{port}",
                    f"https://127.0.0.1:{{{port}}}"):
            with self.subTest(url):
                run, failed = self.run_scripts(url=url)
                self.assertEqual(failed, LEVEL1 + LEVEL2, run.stdout)
                self.assertEqual(run.returncode, len(LEVEL1 + LEVEL2), run.stdout)
                self.assertEqual(self.authority.requests, [])
                for name in (T1[1], T2[1], T2[3]):
                    self.assertIn(f"FAIL: {name} (the authority URL is not a valid URL)",
                                  run.stdout)

    def test_transport_rule_allows_https_and_http_to_a_loopback_address_literal(self):
        allowed = [
            "https://api.oa2a.org", "HTTPS://api.oa2a.org", "http://127.0.0.1", "Http://127.0.0.1?x",
            "http://127.0.0.1:8080/atp", "http://127.255.255.254:8080", "http://[::1]:8080",
        ]
        refused = [
            "http://api.oa2a.org", "http://localhost:8080", "http://127.1", "http://127.0.0.01",
            "http://127.0.0.256", "http://128.0.0.1", "http://127.0.0.1.attacker.example",
            "http://127.0.0.1@attacker.example", "http://127.0.0.1:@attacker.example",
            "http://[::ffff:127.0.0.1]", "http://127.0.0.[1-1]", "api.oa2a.org", "ftp://127.0.0.1",
            " https://api.oa2a.org",
        ]
        script = '. "$1"; shift; for url; do transport_allowed "$url" && echo allowed || echo refused; done'
        run = subprocess.run(
            ["bash", "-c", script, "bash", str(CONFORMANCE / "lib.sh"), *allowed, *refused],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(
            list(zip(allowed + refused, run.stdout.split())),
            [(url, "allowed") for url in allowed] + [(url, "refused") for url in refused],
            run.stderr,
        )

    def test_authority_url_the_transport_rule_refuses_gets_no_request(self):
        """No request goes under an authority URL that is neither https nor
        http to a loopback address literal, and each test that would send one
        says why. curl reaches the fixture authority under each of these URLs
        when it requests them, so the authority's empty request list shows
        that none was sent."""
        port = self.authority.server_address[1]
        for url in (f"http://localhost:{port}", f"http://LOCALHOST:{port}", f"http://127.1:{port}",
                    f"http://127.0.0.01:{port}", f"127.0.0.1:{port}"):
            with self.subTest(url):
                run, failed = self.run_scripts(url=url)
                self.assertEqual(failed, LEVEL1 + LEVEL2, run.stdout)
                self.assertEqual(run.returncode, len(LEVEL1 + LEVEL2), run.stdout)
                self.assertEqual(self.authority.requests, [])
                for name in (T1[1], T2[1], T2[3]):
                    self.assertIn(f"FAIL: {name} ({TRANSPORT_REFUSED})", run.stdout)

    def test_http_authority_url_is_requested_without_a_proxy(self):
        """A request under an http authority URL goes to its loopback address,
        not to a proxy the environment names, which would request the URL
        from its own machine."""
        proxy = fixture_authority.serve()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        self.probe([], env={"http_proxy": proxy.url, "no_proxy": "", "NO_PROXY": ""})
        self.assertEqual(proxy.requests, [])
        self.assertTrue(self.authority.requests)

    def test_curlrc_is_not_read(self):
        """curl runs with -q, so a .curlrc, which could turn the certificate
        check off or turn following redirects on, changes no request. This one
        sends each request as PUT, which the fixture authority answers with
        HTTP 501, when curl reads it."""
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        (Path(home.name) / ".curlrc").write_text('request = "PUT"\n', encoding="utf-8")
        self.probe([], env={"CURL_HOME": home.name})

    def test_every_curl_call_starts_with_q(self):
        """curl reads -q only as the first option of a call."""
        for script in ("lib.sh", "level1.sh", "level2.sh"):
            for call in curl_calls((CONFORMANCE / script).read_text(encoding="utf-8")):
                with self.subTest(script=script, call=call):
                    self.assertEqual(call.split()[:1], ["-q"])

    def test_unanswered_request_fails_at_the_time_limit(self):
        """A server that accepts the connection and never answers holds each
        request for ATP_MAX_TIME seconds, and the failure names the limit."""
        silent = socket.socket()
        self.addCleanup(silent.close)
        silent.bind(("127.0.0.1", 0))
        silent.listen(8)
        start = time.monotonic()
        run, failed = self.run_scripts(url=f"http://127.0.0.1:{silent.getsockname()[1]}",
                                       env={"ATP_CONNECT_TIMEOUT": "5", "ATP_MAX_TIME": "1"})
        self.assertLess(time.monotonic() - start, 60)
        self.assertEqual(failed, LEVEL1 + LEVEL2, run.stdout)
        for name in (T1[1], T2[1], T2[3]):
            self.assertIn(
                f"FAIL: {name} (no answer within the time limit: 5 s to connect, 1 s in all)",
                run.stdout,
            )

    def test_bracketed_trust_proof_endpoint_is_one_request(self):
        """curl does not expand a pattern in endpoints.trustProof: the declared
        path gets one request, and T1.7 fails when it is not served."""
        did = self.authority.examples["discovery"]["authorityDid"]
        self.probe(LEVEL1[6:],
                   discovery=inside("endpoints", put(trustProof="/api/v1/trust/proo[e-f]")))
        self.assertEqual(self.received("?did="), [f"GET /api/v1/trust/proo[e-f]?did={did}"])

    def test_bracketed_authority_did_is_one_request(self):
        did = self.authority.examples["discovery"]["authorityDid"][:-1] + "[f-g]"
        in_url = did[:-5] + "%5Bf-g%5D"
        self.probe([T1[2], T1[8]], discovery=put(authorityDid=did))
        self.assertEqual(self.received("/api/v1/did/"), [f"GET /api/v1/did/{in_url}"])
        self.assertEqual(self.received("?did="), [f"GET /api/v1/trust/proof?did={in_url}"])

    def test_braces_in_the_authority_url_are_sent_as_written(self):
        run, failed = self.run_scripts(url=self.authority.url + "/{a,b}")
        self.assertEqual(failed, LEVEL1 + LEVEL2, run.stdout)
        self.assertEqual(self.authority.requests, [
            "GET /{a,b}/.well-known/atp",
            "GET /{a,b}/api/v1/transparency/trust-proofs?limit=5",
            "GET /{a,b}/api/v1/trust/revocations?since=2026-01-01T00:00:00Z",
        ])

    def test_every_curl_call_passes_the_shared_options(self):
        """Every curl call turns URL globbing off, sends dot segments as written
        and has both time limits."""
        calls = []
        for script in ("lib.sh", "level1.sh", "level2.sh"):
            calls += curl_calls((CONFORMANCE / script).read_text(encoding="utf-8"))
        self.assertTrue(calls)
        for call in calls:
            with self.subTest(call):
                self.assertEqual(missing_curl_options(call), [])

    def test_curl_calls_are_every_curl_word_outside_comments(self):
        """A call in any position of a command is read, and so is a call whose
        options continue on the next line; a comment and the for-loop word list
        of the tool check are not calls."""
        script = (
            'if curl -s "$BASE_URL" > /dev/null; then :; fi\n'
            "body=$(curl -g --max-time 1 \\\n  --url u)\n"
            "! curl -s a && { curl -s b; }\n"
            "printf '%s' x | /usr/bin/curl -s c\n"
            "# curl -s in a comment line\n"
            'echo "a #, b" # curl -s in a trailing comment\n'
            "for tool in curl jq; do :; done\n"
        )
        self.assertEqual(
            [call.split()[:2] for call in curl_calls(script)],
            [["-s", '"$BASE_URL"'], ["-g", "--max-time"], ["-s", "a"], ["-s", "b;"], ["-s", "c"]],
        )
        level1 = (CONFORMANCE / "level1.sh").read_text(encoding="utf-8")
        appended = curl_calls(level1 + 'if curl -s "$BASE_URL" > /dev/null; then :; fi\n')
        self.assertEqual(missing_curl_options(appended[-1]), ["-g", *SHARED_CURL_OPTIONS])

    def test_did_document_probes(self):
        self.probes([
            ("no @context", [T1[5]], {"did": pop("@context")}),
            ("false @context", [T1[5]], {"did": put(**{"@context": False})}),
            ("empty @context array", [T1[5]], {"did": put(**{"@context": []})}),
            ("empty @context string", [T1[5]], {"did": put(**{"@context": ""})}),
            ("object @context", [T1[5]], {"did": put(**{"@context": {}})}),
            ("string @context", [], {"did": put(**{"@context": "https://www.w3.org/ns/did/v1"})}),
            ("string verificationMethod", [T1[6]], {"did": put(verificationMethod="key-1")}),
            ("empty verificationMethod", [T1[6]], {"did": put(verificationMethod=[])}),
            ("not found", [T1[4], T1[5], T1[6]], {"did": 404}),
        ])

    def test_trust_proof_probes(self):
        self.probes([
            ("no did", [T1[7], T1[8]], {"proof": pop("did")}),
            ("another agent's did", [T1[7]], {"proof": put(did="did:opena2a:agent:other")}),
            ("no verdict", [T1[8]], {"proof": pop("verdict")}),
            ("unknown verdict", [T1[8]], {"proof": put(verdict="trusted")}),
            ("no issuedAt", [T1[8]], {"proof": pop("issuedAt")}),
            ("no issuerDid", [T1[8]], {"proof": pop("issuerDid")}),
            ("issuedAt offset +99:99", [T1[8]],
             {"proof": put(issuedAt="2026-01-01T00:00:00+99:99")}),
            ("issuedAt offset +24:00", [T1[8]],
             {"proof": put(issuedAt="2026-01-01T00:00:00+24:00")}),
            ("issuedAt followed by a newline", [T1[8]],
             {"proof": put(issuedAt="2026-01-01T00:00:00Z\n")}),
            ("issuedAt at hour 24", [T1[8]], {"proof": put(issuedAt="2026-01-01T24:00:00Z")}),
            ("issuedAt before 1900", [], {"proof": put(issuedAt="1899-12-31T00:00:00Z")}),
            ("no trustLevel", [T1[8], T1[11]], {"proof": pop("trustLevel")}),
            ("trustLevel 4.0", [], {"proof": put(trustLevel=4.0)}),
            ("fractional trustLevel", [T1[8], T1[11]], {"proof": put(trustLevel=2.5)}),
            ("string trustLevel", [T1[8], T1[11]], {"proof": put(trustLevel="3")}),
            ("trustLevel 5", [T1[8], T1[11]], {"proof": put(trustLevel=5)}),
            ("string trustScore", [T1[8], T1[12]], {"proof": put(trustScore="0.5")}),
            ("expiresAt never", [T1[8], T1[10]], {"proof": put(expiresAt="never")}),
            ("expiresAt February 30", [T1[8], T1[10]],
             {"proof": put(expiresAt="2099-02-30T00:00:00Z")}),
            ("unexpired expiresAt followed by a newline", [T1[8], T1[10]],
             {"proof": put(expiresAt=at_offset(1, 0) + "\n")}),
            ("expired, written at +05:00", [T1[10]], {"proof": put(expiresAt=at_offset(-1, 5))}),
            ("unexpired, written at -05:00", [], {"proof": put(expiresAt=at_offset(1, -5))}),
            ("string signatures", [T1[9]], {"proof": put(signatures="FAKE")}),
            ("no signatures", [T1[9]], {"proof": put(signatures=[])}),
            ("Sigstore co-signature", [], {"proof": put(signatures=COSIGNED)}),
            ("only a Sigstore co-signature", [T1[9]], {"proof": put(signatures=COSIGNED[1:])}),
            ("Ed25519 and ML-DSA-65 signatures", [],
             {"proof": put(signatures=[COSIGNED[0], validate_examples.ML_DSA_SIGNATURE])}),
            ("only an ML-DSA-65 signature", [T1[9]],
             {"proof": put(signatures=[validate_examples.ML_DSA_SIGNATURE])}),
            ("Sigstore bundle with a second log entry of another kind", [],
             {"proof": put(signatures=[COSIGNED[0], with_log_entry(COSIGNED[1], "dsse")])}),
            ("Sigstore bundle whose only log entry is another kind", [T1[9]],
             {"proof": put(signatures=[COSIGNED[0], with_log_entry(COSIGNED[1], "dsse", 0)])}),
            ("Sigstore entry without a bundle", [T1[9]],
             {"proof": put(signatures=[COSIGNED[0], {**COSIGNED[1], "bundle": "FAKE"}])}),
            ("no proof served", LEVEL1[6:], {"proof": 404}),
        ])

    def test_verify_probes(self):
        self.probes([
            ("server error", [T1[13], T1[14]], {"verify": 500}),
            ("string valid", [T1[14]], {"verify": put(valid="true")}),
        ])

    def test_transparency_log_probes(self):
        entry = self.authority.examples["log"]
        self.probes([
            ("bare array of entries", [], {"log": json.dumps([entry])}),
            ("HTML body", [T2[1], T2[2]], {"log": "<html></html>"}),
            ("no entries", [T2[2]], {"log": '{"entries": []}'}),
            ("string entry", [T2[2]], {"log": '{"entries": ["FAKE"]}'}),
            ("entry without timestamp", [T2[2]], {"log": first("entries", pop("timestamp"))}),
            ("timestamp at epoch second -1", [],
             {"log": first("entries", put(timestamp="1969-12-31T23:59:59Z"))}),
            ("entry without entryType", [T2[2]], {"log": first("entries", pop("entryType"))}),
            ("negative logIndex", [T2[2]], {"log": first("entries", put(logIndex=-1))}),
        ])

    def test_revocation_probes(self):
        self.probes([
            ("entry without transparencyLogIndex", [],
             {"revocations": first("revocations", pop("transparencyLogIndex"))}),
            ("no revocations", [], {"revocations": put(revocations=[])}),
            ("HTML body", [T2[3]], {"revocations": "<html>revocations</html>"}),
            ("empty object", [T2[3]], {"revocations": "{}"}),
            ("no nextSince", [T2[3]], {"revocations": pop("nextSince")}),
            ("free-text reason", [T2[3]],
             {"revocations": first("revocations", put(reason="key leaked"))}),
            ("malformed revokedAt", [T2[3]],
             {"revocations": first("revocations", put(revokedAt="2026-03-22 15:00"))}),
            ("extra top-level member", [T2[3]], {"revocations": put(unexpected=1)}),
        ])

    def test_body_with_two_json_values_fails(self):
        body = json.dumps(self.authority.examples["revocations"])
        run = self.probe([T2[3]], revocations=body + "\n" + body)
        self.assertIn("(more than one JSON value)", run.stdout)


@unittest.skipUnless(all(shutil.which(tool) for tool in ("bash", "curl", "dirname")),
                     "the conformance scripts need bash, curl and dirname")
class SetupErrorTest(unittest.TestCase):
    """A missing tool or schema stops both scripts with exit code 69, and a run
    without an authority URL with exit code 64, codes no count of failed tests
    reaches, before any test runs, with one error line."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def assert_setup_error(self, conformance, path, message, env=None):
        for script in ("level1.sh", "level2.sh"):
            with self.subTest(script):
                run = subprocess.run(
                    [shutil.which("bash"), str(conformance / script), "http://127.0.0.1:9"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env={"PATH": path, **(env or {})},
                )
                self.assertEqual(run.returncode, 69, run.stderr)
                self.assertIn(message, run.stderr)
                # level2.sh runs level1.sh, which must not print the error a second time.
                self.assertEqual(len(run.stderr.splitlines()), 1, run.stderr)
                self.assertEqual(run.stdout, "")

    def test_missing_jq_exits_69(self):
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        for tool in ("bash", "curl", "dirname"):
            (bin_dir / tool).symlink_to(shutil.which(tool))
        self.assert_setup_error(CONFORMANCE, str(bin_dir), "error: jq is required")

    @unittest.skipUnless(HAS_JQ, "needs jq")
    def test_missing_schema_exits_69(self):
        copied = self.dir / "conformance"
        shutil.copytree(CONFORMANCE, copied)
        self.assert_setup_error(copied, os.environ.get("PATH", ""), "schema.json not found")

    @unittest.skipUnless(HAS_JQ, "needs jq")
    def test_time_limit_that_is_not_a_number_exits_69(self):
        for name, value in (("ATP_CONNECT_TIMEOUT", "ten"), ("ATP_MAX_TIME", "-1")):
            with self.subTest(name):
                self.assert_setup_error(CONFORMANCE, os.environ.get("PATH", ""),
                                        f"error: {name} must be a number of seconds",
                                        env={name: value})

    @unittest.skipUnless(HAS_JQ, "needs jq")
    def test_time_limit_under_a_millisecond_exits_69(self):
        """curl counts a limit in whole milliseconds and reads 0 as no overall
        limit (--max-time) or as its own connect default (--connect-timeout)."""
        for name, value in (("ATP_MAX_TIME", "0"), ("ATP_MAX_TIME", "0.0004"),
                            ("ATP_CONNECT_TIMEOUT", "0.0"), ("ATP_CONNECT_TIMEOUT", "000")):
            with self.subTest(name=name, value=value):
                self.assert_setup_error(CONFORMANCE, os.environ.get("PATH", ""),
                                        f"error: {name} must be a number of seconds, at least 0.001",
                                        env={name: value})

    @unittest.skipUnless(HAS_JQ, "needs jq")
    def test_missing_authority_url_exits_64(self):
        """64 is EX_USAGE in sysexits.h; bash's own ${1:?} error exits 1, which
        reads as one failed test."""
        for script in ("level1.sh", "level2.sh"):
            for args in ((), ("",)):
                with self.subTest(script=script, args=args):
                    path = str(CONFORMANCE / script)
                    run = subprocess.run(
                        [shutil.which("bash"), path, *args],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        env={"PATH": os.environ.get("PATH", "")},
                    )
                    self.assertEqual(run.returncode, 64, run.stderr)
                    self.assertEqual(run.stderr, f"Usage: {path} <authority-url>\n")
                    self.assertEqual(run.stdout, "")

    @unittest.skipUnless(HAS_JQ, "needs jq")
    def test_time_limit_of_a_millisecond_or_more_runs_the_tests(self):
        for value in ("0.001", "0.05", "007", "1.0"):
            with self.subTest(value):
                run = subprocess.run(
                    [shutil.which("bash"), str(CONFORMANCE / "level1.sh"), "http://127.0.0.1:9"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env={"PATH": os.environ.get("PATH", ""), "ATP_MAX_TIME": value,
                         "ATP_CONNECT_TIMEOUT": value},
                )
                self.assertEqual(run.stderr, "")
                self.assertIn("=== Results: 0 passed, 14 failed ===", run.stdout)


class ReferenceAuthorityRunTest(unittest.TestCase):
    """The README says which conformance tests the reference authority passes
    and fails, as the run docs/reference-implementation.md records them,
    instead of naming a conformance level."""

    IDS = [f"T1.{n}" for n in range(1, 15)] + [f"T2.{n}" for n in range(1, 4)]

    @staticmethod
    def ranges(ids):
        """Test IDs in suite order written as ranges: 'T1.7 to T1.14 and T2.1 to T2.3'."""
        groups = []
        for test_id in ids:
            level, number = (int(part) for part in test_id[1:].split("."))
            if groups and groups[-1][0] == level and groups[-1][2] == number - 1:
                groups[-1][2] = number
            else:
                groups.append([level, number, number])
        names = [f"T{lv}.{a}" if a == b else f"T{lv}.{a} to T{lv}.{b}" for lv, a, b in groups]
        return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]

    def test_ranges(self):
        self.assertEqual(self.ranges(["T1.1", "T1.2", "T1.3"]), "T1.1 to T1.3")
        self.assertEqual(self.ranges(["T1.4", "T1.14", "T2.1", "T2.2"]),
                         "T1.4, T1.14 and T2.1 to T2.2")

    def test_readme_names_the_tests_the_recorded_run_passes_and_fails(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        section = readme.split("\n## Reference Implementation\n", 1)[1].split("\n## ", 1)[0]
        record = (ROOT / "docs" / "reference-implementation.md").read_text(encoding="utf-8")
        run = record.split("\n## Conformance run\n", 1)[1].split("\n## ", 1)[0]
        results = {}
        for test_id, name in zip(self.IDS, LEVEL1 + LEVEL2):
            if f"\nPASS: {name}\n" in run:
                results[test_id] = True
            elif f"\nFAIL: {name}" in run:
                results[test_id] = False
        self.assertEqual(list(results), self.IDS)
        self.assertIn(f"=== Results: {sum(results[i] for i in self.IDS[:14])} passed", run)
        passed = self.ranges([i for i in self.IDS if results[i]])
        failed = self.ranges([i for i in self.IDS if not results[i]])
        self.assertIn(f"({passed})", section)
        self.assertIn(f"({failed})", section)
        self.assertNotRegex(section, r"(?i)\bimplements ATP at\b|\blevel [1-3] conformance\b")
        self.assertIn("(docs/reference-implementation.md#conformance-run)", section)


class DiscoveryEndpointPathTest(unittest.TestCase):
    """Section 7.1 and the discovery schema define an endpoints value as a
    path, the form T1.7 appends to the authority URL, and the values of the
    Section 7.1 example are paths."""

    def test_section_7_1_and_the_schema_define_endpoint_values_as_paths(self):
        spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        section = spec.split("\n### 7.1 Well-Known Endpoint\n", 1)[1].split("\n### ", 1)[0]
        self.assertIn("Each `endpoints` value is a path", section)
        schema = json.loads((ROOT / "schemas" / "discovery-v1.schema.json").read_text(encoding="utf-8"))
        description = schema["properties"]["endpoints"]["description"]
        self.assertNotIn("URL map", description)
        self.assertIn("a path that starts with /", description)

    def test_section_7_1_example_endpoint_values_are_paths(self):
        example = json.loads(
            validate_examples.extract_block(ROOT / "ATP-SPEC.md", "### 7.1 Well-Known Endpoint")
        )
        self.assertTrue(example["endpoints"])
        for name, value in example["endpoints"].items():
            with self.subTest(name):
                self.assertRegex(value, r"\A/[^#\s\x00-\x1f\x7f]*\Z")


class FixtureAuthorityTest(unittest.TestCase):
    """fixture_authority.py serves examples it reads from ATP-SPEC.md. A
    specification without one of their headings, with an example that is not
    JSON, or that is not UTF-8, stops it with one error line that names the
    file and the heading or the decoding error, not a traceback. One that is
    missing stops it with one error line that names the file and not its path
    on disk. A port that is not a number from 0 to 65535, or that it cannot
    listen on, stops it with one error line that names the port. It reads the
    examples before it opens a socket."""

    def run_authority(self, spec: bytes | None = None, port: str = "0", place=None):
        """Run fixture_authority.py on a port (a free one unless given), in a
        copy of the scripts beside an ATP-SPEC.md that holds spec (the
        repository's unless given). When `place` is given it is called with
        the path of ATP-SPEC.md, and no specification is written there."""
        if spec is None:
            spec = (ROOT / "ATP-SPEC.md").read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(SCRIPTS, root / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            if place is None:
                (root / "ATP-SPEC.md").write_bytes(spec)
            else:
                place(root / "ATP-SPEC.md")
            return subprocess.run(
                [sys.executable, "-B", str(root / "scripts" / "fixture_authority.py"), port],
                capture_output=True,
                text=True,
                timeout=60,
            )

    def test_heading_that_is_not_in_the_spec_is_one_error_line(self):
        spec = (ROOT / "ATP-SPEC.md").read_bytes()
        for heading in fixture_authority.EXAMPLES.values():
            line = f"\n{heading}\n".encode("utf-8")
            self.assertEqual(spec.count(line), 1, heading)
            with self.subTest(heading=heading):
                run = self.run_authority(spec.replace(line, f"\n{heading}s\n".encode("utf-8")))
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual(run.stderr, f"error: ATP-SPEC.md: heading {heading!r} not found\n")
                self.assertEqual(run.stdout, "")

    def test_spec_that_is_not_utf8_is_one_error_line(self):
        run = self.run_authority(b"\xe9" + (ROOT / "ATP-SPEC.md").read_bytes())
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(len(run.stderr.splitlines()), 1, run.stderr)
        self.assertTrue(run.stderr.startswith("error: ATP-SPEC.md: not UTF-8: "), run.stderr)
        self.assertIn("can't decode byte 0xe9", run.stderr)
        self.assertEqual(run.stdout, "")

    def test_spec_that_is_missing_is_one_error_line(self):
        """A specification that is not there, or a directory in its place, is
        one line that names the file as the repository does."""
        for name, place in (("not there", lambda path: None), ("a directory", Path.mkdir)):
            with self.subTest(spec=name):
                run = self.run_authority(place=place)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual(run.stderr, "error: ATP-SPEC.md: missing\n")
                self.assertEqual(run.stdout, "")

    def test_example_that_is_not_json_is_one_error_line(self):
        spec = (ROOT / "ATP-SPEC.md").read_bytes()
        fence = b"```json\n"
        for heading in fixture_authority.EXAMPLES.values():
            # One line that is not JSON, after the fence that opens the example.
            at = spec.index(fence, spec.index(f"\n{heading}\n".encode("utf-8"))) + len(fence)
            with self.subTest(heading=heading):
                run = self.run_authority(spec[:at] + b"not json,\n" + spec[at:])
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual(len(run.stderr.splitlines()), 1, run.stderr)
                self.assertTrue(
                    run.stderr.startswith(
                        f"error: ATP-SPEC.md: the ```json block after {heading!r} is not JSON: "
                    ),
                    run.stderr,
                )
                self.assertEqual(run.stdout, "")

    def test_port_that_is_not_a_port_number_is_one_error_line(self):
        for port in ("--help", "-h", "http", "80.5", "", "-1", "65536", "9" * 5000):
            with self.subTest(port=port[:8]):
                run = self.run_authority(port=port)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual(
                    run.stderr,
                    f"error: port {port!r} is not a number from 0 to 65535; "
                    "run: python3 scripts/fixture_authority.py [port]\n",
                )
                self.assertEqual(run.stdout, "")

    def test_port_another_process_holds_is_one_error_line(self):
        with socket.socket() as holder:
            holder.bind(("127.0.0.1", 0))
            holder.listen()
            port = holder.getsockname()[1]
            run = self.run_authority(port=str(port))
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(run.stderr, f"error: port {port}: Address already in use\n")
        self.assertEqual(run.stdout, "")

    def test_spec_without_an_example_leaves_no_socket_open(self):
        """FixtureAuthority reads the examples before it opens a socket, so a
        specification without one of them leaves none open."""
        opened = []

        class Recorded(socket.socket):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                opened.append(self)

        def close_opened():
            for sock in opened:
                sock.close()

        self.addCleanup(close_opened)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(socket, "socket", Recorded):
            spec = Path(tmp) / "ATP-SPEC.md"
            spec.write_text("# A specification without an example\n", encoding="utf-8")
            with mock.patch.object(fixture_authority, "SPEC", spec):
                with self.assertRaises(fixture_authority.CannotServe) as raised:
                    fixture_authority.FixtureAuthority()
            self.assertEqual(
                str(raised.exception),
                f"ATP-SPEC.md: heading {fixture_authority.EXAMPLES['discovery']!r} not found",
            )
            self.assertEqual([sock for sock in opened if sock.fileno() != -1], [])
            # An authority that starts opens one, so the list above reads what is opened.
            authority = fixture_authority.FixtureAuthority()
            self.addCleanup(authority.server_close)
            self.assertEqual([sock.fileno() for sock in opened], [authority.fileno()])


# Written apart from the rfc3339 pattern in checks.jq (a full match, the fields
# bounded by number and the day by calendar), so the agreement tests can catch a
# mistake in either.
RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)
DATE_TIME = FormatChecker(formats=())


@DATE_TIME.checks("date-time")
def is_date_time(value):
    """RFC 3339 Section 5.6: a year from 0000 to 9999, a day of the month, an
    hour from 00 to 23, a minute and a second from 00 to 59 (no leap second, as
    in checks.jq) and a UTC offset from 00:00 to 23:59. datetime is not used for
    the date: it has no year 0000, and on Python 3.14 fromisoformat reads hour
    24 as midnight of the next day."""
    if not isinstance(value, str):
        return True
    match = RFC3339.fullmatch(value)
    if not match:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.group(1, 2, 3, 4, 5, 6))
    offset_hours, offset_minutes = match.group(7, 8)
    if offset_hours is not None and (int(offset_hours) > 23 or int(offset_minutes) > 59):
        return False
    return (
        1 <= month <= 12
        and 1 <= day <= calendar.monthrange(year, month)[1]
        and hour <= 23
        and minute <= 59
        and second <= 59
    )


@unittest.skipUnless(HAS_JQ, "checks.jq needs jq")
class SchemaCheckTest(unittest.TestCase):
    """checks.jq's schema_ok, which the scripts validate bodies with, agrees
    with a JSON Schema validator on the spec examples, on each edit that
    removes one of their members or replaces it with one of REPLACEMENTS, and
    on each example with one extra top-level member."""

    EXAMPLES = {
        "### 7.1 Well-Known Endpoint": "discovery-v1",
        KEY_SET_HEADING: "discovery-v1",
        "### 4.2 Trust Proof Format": "trust-proof-v1",
        "#### 4.3.1 Sigstore co-signature": "trust-proof-v1",
        "#### 4.4.1 Two-authority proof (Level 3)": "trust-proof-v1",
        "#### 4.4.2 Issuer key set proof": "trust-proof-v1",
        "### 8.1 Trust Proof Revocation": "revocation-list-v1",
    }
    REPLACEMENTS = (
        None, True, -1, 1.5, "x", [], {},
        "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00Z\n", "2099-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z", "1899-12-31T00:00:00Z",
    )
    TIMESTAMPS = {
        "2026-01-01T00:00:00Z": True,
        "2026-01-01t00:00:00.5z": True,
        "2026-01-01T00:00:00+23:59": True,
        "2026-01-01T00:00:00-00:00": True,
        "2026-01-01T00:00:00+99:99": False,
        "2026-01-01T00:00:00+24:00": False,
        "2026-01-01T00:00:00-00:60": False,
        "2026-01-01T00:00:00Z\n": False,
        "\n2026-01-01T00:00:00Z": False,
        "2099-02-30T00:00:00Z": False,
        # Hour 24, a minute or second of 60 and a day the month lacks are not RFC
        # 3339; a year before 1900, 1969-12-31T23:59:59Z (epoch second -1) and
        # year 0000 are, whatever the platform's mktime accepts.
        "2026-01-01T24:00:00Z": False,
        "2026-01-01T23:60:00Z": False,
        "2026-12-31T23:59:60Z": False,
        "1900-02-29T00:00:00Z": False,
        "2000-02-29T00:00:00Z": True,
        "1899-12-31T00:00:00Z": True,
        "1000-01-01T00:00:00+05:30": True,
        "1969-12-31T23:59:59Z": True,
        "0000-02-29T00:00:00Z": True,
        "9999-12-31T23:59:59Z": True,
    }
    # Epoch seconds that rfc3339 gives, worked out apart from it: by datetime
    # where it has the year, and from 0001-01-01 (-62135596800) for year 0000,
    # a leap year of 366 days.
    EPOCH_SECONDS = {
        "1970-01-01T00:00:00Z": 0,
        "1969-12-31T23:59:59Z": -1,
        "2026-10-12T02:57:21.999Z": 1791773841,
        "2026-10-11T20:57:21.5-06:00": 1791773841,
        "2026-01-01T00:30:00+01:00": 1767223800,
        "1899-12-31T23:00:00-01:00": -2208988800,
        "1600-02-29T12:00:00Z": None,
        "0001-01-01T00:00:00Z": -62135596800,
        "0000-01-01T00:00:00Z": -62135596800 - 366 * 86400,
        "9999-12-31T23:59:59Z": None,
    }
    SUPPORTED = {
        "type", "const", "enum", "anyOf", "pattern", "minLength", "format", "minimum",
        "maximum", "minItems", "items", "contains", "minProperties", "required", "properties",
        "additionalProperties", "$ref",
    }
    ANNOTATIONS = {"$schema", "$id", "title", "description", "$defs"}

    def schema(self, name):
        return json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))

    @staticmethod
    def members(node, path=()):
        if isinstance(node, dict):
            for key, value in node.items():
                yield path + (key,)
                yield from SchemaCheckTest.members(value, path + (key,))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                yield from SchemaCheckTest.members(item, path + (index,))

    def edits(self, body):
        yield body
        yield dict(body, unexpected=1)
        for path in list(self.members(body)):
            for replacement in (...,) + self.REPLACEMENTS:
                edited = copy.deepcopy(body)
                parent = edited
                for step in path[:-1]:
                    parent = parent[step]
                if replacement is ...:
                    del parent[path[-1]]
                else:
                    parent[path[-1]] = replacement
                yield edited

    def keywords(self, schema):
        yield from schema
        for key in ("properties", "$defs"):
            for sub in schema.get(key, {}).values():
                yield from self.keywords(sub)
        for sub in schema.get("anyOf", []):
            yield from self.keywords(sub)
        for key in ("items", "additionalProperties", "contains"):
            if isinstance(schema.get(key), dict):
                yield from self.keywords(schema[key])

    def test_rfc3339_bounds_the_offset_and_rejects_a_trailing_newline(self):
        timestamps = list(self.TIMESTAMPS)
        run = subprocess.run(
            ["jq", "-c", "-L", str(CONFORMANCE), 'include "checks"; map(rfc3339 != null)'],
            input=json.dumps(timestamps),
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        expected = list(self.TIMESTAMPS.values())
        self.assertEqual(dict(zip(timestamps, json.loads(run.stdout))), self.TIMESTAMPS)
        self.assertEqual([is_date_time(value) for value in timestamps], expected)

    def test_rfc3339_counts_epoch_seconds_without_mktime(self):
        """T1.10 compares the seconds rfc3339 gives with now. They are counted
        in checks.jq, so a year mktime refuses on a platform still gets them."""
        expected = {
            value: int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
            if seconds is None else seconds
            for value, seconds in self.EPOCH_SECONDS.items()
        }
        run = subprocess.run(
            ["jq", "-c", "-L", str(CONFORMANCE), 'include "checks"; map(rfc3339)'],
            input=json.dumps(list(expected)),
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(dict(zip(expected, json.loads(run.stdout))), expected)

    def test_schemas_use_only_keywords_checks_jq_implements(self):
        for name in self.EXAMPLES.values():
            with self.subTest(name):
                unknown = set(self.keywords(self.schema(name))) - self.SUPPORTED - self.ANNOTATIONS
                self.assertEqual(unknown, set())

    def test_no_keyword_sits_beside_a_ref(self):
        """schema_ok follows a $ref and reads nothing beside it, so a schema that
        narrows the target of a $ref writes the narrowed schema out in full."""
        for name in sorted(set(self.EXAMPLES.values())):
            with self.subTest(name):
                schema = self.schema(name)
                beside = []
                for path in self.members(schema):
                    if path[-1] != "$ref":
                        continue
                    node = schema
                    for step in path[:-1]:
                        node = node[step]
                    beside += [path[:-1] + (key,) for key in node
                               if key != "$ref" and key not in self.ANNOTATIONS]
                self.assertEqual(beside, [])

    def test_schema_ok_agrees_with_a_json_schema_validator(self):
        cases = []
        for heading, name in self.EXAMPLES.items():
            schema = self.schema(name)
            example = json.loads(validate_examples.extract_block(ROOT / "ATP-SPEC.md", heading))
            cases += [(name, schema, body) for body in self.edits(example)]
        run = subprocess.run(
            ["jq", "-c", "-L", str(CONFORMANCE),
             'include "checks"; map(.schema as $s | .body | schema_ok($s; $s))'],
            input=json.dumps([{"schema": schema, "body": body} for _, schema, body in cases]),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        verdicts = json.loads(run.stdout)
        expected = [
            Draft202012Validator(schema, format_checker=DATE_TIME).is_valid(body)
            for _, schema, body in cases
        ]
        disagreements = [
            (name, body, verdict)
            for (name, _, body), verdict, want in zip(cases, verdicts, expected)
            if verdict != want
        ]
        self.assertEqual(disagreements, [])
        self.assertEqual(len(verdicts), len(cases))
        self.assertTrue(any(expected) and not all(expected))


class GenRegistriesTest(unittest.TestCase):
    TABLE = (
        "<!-- opena2a-definition: revocation-reasons -->\n"
        "| Reason | Since |\n"
        "|--------|-------|\n"
        "| `manual` | 1.1.0 |\n"
        "| **unspecified** | 1.1.0 |\n"
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["gen_registries.py", *args]), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(err):
            code = gen_registries.main()
        return code, out.getvalue(), err.getvalue()

    def generate_from(self, spec_text):
        spec = self.dir / "ATP-SPEC.md"
        spec.write_text(spec_text, encoding="utf-8")
        tables = {"revocation-reasons": gen_registries.TABLES["revocation-reasons"]}
        with mock.patch.object(gen_registries, "SPEC", spec), mock.patch.object(
            gen_registries, "TABLES", tables
        ):
            return gen_registries.generate()

    def test_repository_registries_match_the_spec(self):
        code, out, err = self.run_main("--check")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("registries match the specification tables", out)

    def test_table_cells_lose_backticks_and_bold(self):
        data = self.generate_from("# Spec\n\n" + self.TABLE)["revocation-reasons"]
        self.assertEqual(data["columns"], ["Reason", "Since"])
        self.assertEqual(
            data["rows"],
            [{"Reason": "manual", "Since": "1.1.0"}, {"Reason": "unspecified", "Since": "1.1.0"}],
        )

    def test_duplicate_unique_value_fails(self):
        with self.assertRaisesRegex(SystemExit, r"duplicate Reason values \['manual'\]"):
            self.generate_from(self.TABLE + "| manual | 1.2.0 |\n")

    def test_missing_marker_fails(self):
        with self.assertRaisesRegex(SystemExit, "marker not found"):
            self.generate_from("# Spec\n\n| Reason | Since |\n")

    def test_heading_before_table_fails(self):
        text = self.TABLE.replace("\n", "\n## Next section\n\n", 1)
        with self.assertRaisesRegex(SystemExit, "no table before the next heading"):
            self.generate_from(text)

    def test_check_fails_on_stale_and_missing_files(self):
        registries = self.dir / "registries"
        with mock.patch.object(gen_registries, "ROOT", self.dir), mock.patch.object(
            gen_registries, "REGISTRIES", registries
        ):
            code, out, _ = self.run_main()
            self.assertEqual(code, 0)
            self.assertEqual(len(out.splitlines()), len(gen_registries.TABLES))
            self.assertEqual(self.run_main("--check")[0], 0)
            (registries / "trust-levels.json").write_text("{}\n", encoding="utf-8")
            (registries / "revocation-reasons.json").unlink()
            code, _, err = self.run_main("--check")
        self.assertEqual(code, 1)
        self.assertIn("registries/trust-levels.json", err)
        self.assertIn("registries/revocation-reasons.json", err)
        self.assertNotIn("transparency-entry-types", err)

    def test_check_reports_a_file_that_is_not_utf8_in_one_line(self):
        registries = self.dir / "registries"
        name = "registries/revocation-reasons.json"
        with mock.patch.object(gen_registries, "ROOT", self.dir), mock.patch.object(
            gen_registries, "REGISTRIES", registries
        ):
            self.assertEqual(self.run_main()[0], 0)
            generated = (self.dir / name).read_bytes()
            for where in ("first", "last"):
                (self.dir / name).write_bytes(
                    b"\xe9" + generated if where == "first" else generated + b"\xe9"
                )
                with self.subTest(byte=where):
                    code, out, err = self.run_main("--check")
                    self.assertEqual(code, 1)
                    self.assertEqual(
                        err, f"stale registries (run scripts/gen_registries.py): {name} (not UTF-8)\n"
                    )
                    self.assertEqual(out, "")

    def test_spec_that_is_missing_or_not_utf8_is_one_line(self):
        """In either mode, a specification that is not there, a directory in
        its place, or one that is not UTF-8 is one line that names ATP-SPEC.md
        and not its path on disk, and no registry is written."""
        spec = (ROOT / "ATP-SPEC.md").read_bytes()
        cases = (
            ("not there", lambda path: None, "error: ATP-SPEC.md: missing\n"),
            ("a directory", Path.mkdir, "error: ATP-SPEC.md: missing\n"),
            ("not UTF-8", lambda path: path.write_bytes(spec + b"\xe9"), None),
        )
        for name, place, expected in cases:
            for mode in (["--check"], []):
                with self.subTest(spec=name, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    shutil.copytree(
                        SCRIPTS, root / "scripts", ignore=shutil.ignore_patterns("__pycache__")
                    )
                    place(root / "ATP-SPEC.md")
                    run = subprocess.run(
                        [sys.executable, "-B", str(root / "scripts" / "gen_registries.py"), *mode],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(run.returncode, 1, run.stderr)
                    self.assertEqual(run.stdout, "")
                    if expected is None:
                        self.assertTrue(
                            run.stderr.startswith("error: ATP-SPEC.md: not UTF-8: "), run.stderr
                        )
                        self.assertIn("can't decode byte 0xe9", run.stderr)
                        self.assertEqual(len(run.stderr.splitlines()), 1, run.stderr)
                    else:
                        self.assertEqual(run.stderr, expected)
                    self.assertNotIn(tmp, run.stderr)
                    self.assertFalse((root / "registries").exists())


class GuideBlocksTest(unittest.TestCase):
    """check_guides.py runs the blocks of the integration guides and of
    ATP-SPEC.md Appendix B.1 and B.2 against recorded responses; each test
    below puts back one defect the examples used to carry, or could, and
    expects the check to fail on it."""

    @classmethod
    def setUpClass(cls):
        cls.texts = check_guides.guide_texts()

    def edited(self, guide, old, new):
        self.assertIn(old, self.texts[guide])
        return {**self.texts, guide: self.texts[guide].replace(old, new, 1)}

    def failing_cases(self, texts, block):
        errors = check_guides.run(texts, select=lambda case: case.block == block)
        return [
            case.name
            for case in check_guides.CASES
            if any(error.startswith(case.name + ":") for error in errors)
        ]

    def test_repository_guides_pass(self):
        self.assertEqual(check_guides.run(), [])

    def test_gate_reading_the_top_level_fails(self):
        texts = self.edited("ci", "jq -ce '.proof | objects'", "jq -ce '. | objects'")
        failing = self.failing_cases(texts, check_guides.GATE)
        self.assertIn("gate: level 2 at threshold 2 passes", failing)

    def test_gate_without_expiry_check_fails(self):
        texts = self.edited("ci", "fromdateiso8601 > now", "fromdateiso8601 > 0")
        self.assertEqual(
            self.failing_cases(texts, check_guides.GATE), ["gate: expired proof refuses"]
        )

    def test_gate_without_revocation_check_fails(self):
        texts = self.edited("ci", '  true) refuse "revoked" ;;', "  true) ;;")
        self.assertEqual(
            self.failing_cases(texts, check_guides.GATE), ["gate: revoked agent refuses"]
        )

    def test_gate_refusing_only_level_0_as_blocked_fails(self):
        texts = self.edited(
            "ci",
            'if [ "$LEVEL" -eq 0 ] || [ "$VERDICT" = blocked ]; then refuse',
            'if [ "$LEVEL" -eq 0 ]; then refuse',
        )
        self.assertEqual(
            self.failing_cases(texts, check_guides.GATE), ["gate: level 3 blocked proof refuses"]
        )

    def test_batch_loop_in_a_pipeline_subshell_fails(self):
        texts = self.edited(
            "ci", "while read -r DID; do", "jq -r '.[]' \"$AGENTS_FILE\" | while read -r DID; do"
        )
        texts["ci"] = texts["ci"].replace("done < <(jq -r '.[]' \"$AGENTS_FILE\")", "done", 1)
        failing = self.failing_cases(texts, check_guides.BATCH)
        self.assertIn("batch: blocked and missing agents fail", failing)

    def test_quick_check_reading_the_top_level_fails(self):
        texts = self.edited("mcp", "jq '.proof | {", "jq '{")
        errors = check_guides.run(texts, select=lambda case: case.block == check_guides.QUICK)
        self.assertEqual(len(errors), 1)
        self.assertIn('"trustLevel": null', errors[0])

    def test_python_check_reading_the_top_level_fails(self):
        texts = self.edited("mcp", 'proof = resp.json().get("proof") or {}', "proof = resp.json()")
        failing = self.failing_cases(texts, check_guides.MCP_PY)
        self.assertIn("mcp python: listed server connects", failing)

    def test_a2a_following_the_cards_verify_at_fails(self):
        texts = self.edited(
            "a2a",
            "        verify_url,\n        json=proof,",
            '        atp.get("verifyAt", verify_url),\n        json=proof,',
        )
        failing = self.failing_cases(texts, check_guides.A2A_PY)
        self.assertEqual(failing, ["a2a python: the card's verifyAt is not followed"])

    def test_a2a_without_the_did_check_fails(self):
        for block, old, never, sample in (
            (check_guides.A2A_PY,
             '    if not atp.get("did") or proof.get("did") != atp["did"]:\n',
             "    if False:\n", "a2a python"),
            (check_guides.A2A_TS,
             "  if (!card.atp.did || proof.did !== card.atp.did) {\n",
             "  if (false) {\n", "a2a typescript"),
        ):
            with self.subTest(sample):
                texts = self.edited("a2a", old, never)
                self.assertEqual(self.failing_cases(texts, block), [
                    f"{sample}: a proof about another DID is not trusted",
                    f"{sample}: a card without atp.did is not trusted",
                ])

    def test_a2a_typescript_without_expiry_check_fails(self):
        texts = self.edited(
            "a2a", "  if (!(Date.parse(proof.expiresAt) > Date.now())) {", "  if (false) {"
        )
        self.assertEqual(
            self.failing_cases(texts, check_guides.A2A_TS),
            ["a2a typescript: expired proof is not trusted"],
        )

    def test_refresh_storing_the_envelope_fails(self):
        texts = self.edited(
            "a2a",
            'update_agent_card_proof(resp.json()["proof"])',
            "update_agent_card_proof(resp.json())",
        )
        failing = self.failing_cases(texts, check_guides.REFRESH)
        self.assertEqual(failing, ["a2a refresh: the stored proof is what verify accepts"])

    def test_spec_example_importing_an_atp_library_fails(self):
        texts = self.edited("spec", "import requests\n", "import requests\nimport atp\n")
        failing = self.failing_cases(texts, check_guides.SPEC_PEER)
        self.assertEqual(
            failing,
            [case.name for case in check_guides.CASES if case.block == check_guides.SPEC_PEER],
        )

    def test_spec_example_without_the_did_check_fails(self):
        texts = self.edited("spec", 'proof.get("did") != did or ', "")
        failing = self.failing_cases(texts, check_guides.SPEC_PEER)
        self.assertEqual(failing, ["spec b.1: proof about another DID is rejected"])

    def test_spec_example_reading_the_envelope_fails(self):
        texts = self.edited("spec", "(await resp.json()).proof ?? {}", "await resp.json()")
        failing = self.failing_cases(texts, check_guides.SPEC_MCP)
        self.assertIn("spec b.2: listed server connects", failing)

    def test_spec_b2_without_the_did_check_fails(self):
        texts = self.edited("spec", "if (proof.did !== did || !(", "if (!(")
        self.assertEqual(
            self.failing_cases(texts, check_guides.SPEC_MCP),
            ["spec b.2: proof about another DID is refused"],
        )

    def test_a_call_that_follows_redirects_fails(self):
        """Each requests and fetch call of the A2A and MCP guides and of Appendix
        B.1 and B.2 refuses a redirect (Section 7.1). Without allow_redirects=False
        or redirect: "error" the call follows one, as both libraries do by
        default, and the case that redirects that call to http fails."""
        for guide, old, new, block, case in (
            ("spec", "        allow_redirects=False,  # Section 7.1: a redirect's 3xx fails the check below\n",
             "", check_guides.SPEC_PEER, "spec b.1: a redirect of the proof request is not followed"),
            ("spec", "json=proof, timeout=10, allow_redirects=False", "json=proof, timeout=10",
             check_guides.SPEC_PEER, "spec b.1: a redirect of the verify request is not followed"),
            ("spec", '    { redirect: "error" }\n', "",
             check_guides.SPEC_MCP, "spec b.2: a redirect of the proof request is not followed"),
            ("spec", '    body: JSON.stringify(proof),\n    redirect: "error",\n',
             "    body: JSON.stringify(proof),\n",
             check_guides.SPEC_MCP, "spec b.2: a redirect of the verify request is not followed"),
            ("a2a", "requests.get(agent_card_url, timeout=10, allow_redirects=False)",
             "requests.get(agent_card_url, timeout=10)",
             check_guides.A2A_PY, "a2a python: a redirect of the card request is not followed"),
            ("a2a", "        timeout=10,\n        allow_redirects=False,\n    )\n    if check.is_redirect:",
             "        timeout=10,\n    )\n    if check.is_redirect:",
             check_guides.A2A_PY, "a2a python: a redirect of the verify request is not followed"),
            ("a2a", "        timeout=30,\n        allow_redirects=False,\n", "        timeout=30,\n",
             check_guides.DELEGATE, "a2a python: delegate_task does not follow a redirect"),
            ("a2a", 'fetch(agentCardUrl, { redirect: "error" })', "fetch(agentCardUrl)",
             check_guides.A2A_TS, "a2a typescript: a redirect of the card request is not followed"),
            ("a2a", '    body: JSON.stringify(proof),\n    redirect: "error",\n',
             "    body: JSON.stringify(proof),\n",
             check_guides.A2A_TS, "a2a typescript: a redirect of the verify request is not followed"),
            ("a2a", "                timeout=10,\n                allow_redirects=False,\n",
             "                timeout=10,\n",
             check_guides.REFRESH, "a2a refresh: a redirect is not followed"),
            ("mcp", "        timeout=10,\n        allow_redirects=False,\n", "        timeout=10,\n",
             check_guides.MCP_PY, "mcp python: a redirect is not followed"),
            ("mcp", 'fetch(url, { redirect: "error" })', "fetch(url)",
             check_guides.MCP_TS, "mcp typescript: a redirect is not followed"),
            ("mcp", "        timeout=15,\n        allow_redirects=False,\n", "        timeout=15,\n",
             check_guides.MCP_BATCH, "mcp batch: a redirect is not followed"),
        ):
            with self.subTest(case):
                texts = self.edited(guide, old, new)
                self.assertEqual(self.failing_cases(texts, block), [case])

    def test_a_request_to_a_url_that_is_not_https_fails_its_case(self):
        """A block that sends a request to an http URL fails its case even when
        it handles the refused connection and prints what the case expects."""
        block = (
            "import requests\n\n"
            "try:\n"
            "    requests.get('http://api.oa2a.org/.well-known/atp', timeout=10)\n"
            "except requests.ConnectionError:\n"
            "    print('handled')\n"
        )
        texts = {**self.texts, "mcp": self.texts["mcp"] + f"\n## Extra\n\n```python\n{block}```\n"}
        case = check_guides.Case("extra: handled", ("mcp", "## Extra", 0), 0, ("handled",))
        with mock.patch.object(check_guides, "CASES", [case]):
            errors = check_guides.run(texts, select=lambda case: True)
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(
            errors[0].startswith("extra: handled: sent GET http://api.oa2a.org/.well-known/atp, "),
            errors[0],
        )

    def test_batch_guides_state_the_recorded_refusal(self):
        self.assertEqual(check_guides.batch_note_errors(self.texts), [])
        self.assertIn("batchRejection", check_guides.RECORDED)
        for guide, heading, _ in check_guides.BATCH_SECTIONS:
            with self.subTest(guide):
                self.assertIn(check_guides.BATCH_REFUSAL,
                              check_guides.section_prose(self.texts[guide], heading))

    def test_batch_guide_without_the_note_fails(self):
        for guide, heading, _ in check_guides.BATCH_SECTIONS:
            with self.subTest(guide):
                prose = check_guides.section_prose(self.texts[guide], heading)
                note = next(p for p in prose.split("\n\n") if check_guides.BATCH_REFUSAL in p)
                texts = self.edited(guide, note + "\n", "")
                errors = check_guides.batch_note_errors(texts)
                self.assertEqual(len(errors), 1, errors)
                self.assertTrue(errors[0].startswith(check_guides.GUIDES[guide].name + ":"),
                                errors[0])

    def test_note_without_a_recorded_refusal_fails(self):
        recorded = {k: v for k, v in check_guides.RECORDED.items() if k != "batchRejection"}
        errors = check_guides.batch_note_errors(self.texts, recorded)
        self.assertEqual(len(errors), len(check_guides.BATCH_SECTIONS), errors)
        for error in errors:
            self.assertIn("no recorded response", error)

    def test_section_prose_leaves_out_code_blocks_and_later_sections(self):
        text = (
            "## Batch\n\nFirst paragraph.\n\n```bash\necho HTTP 400\n```\n\n"
            "Last paragraph.\n\n### Detail\n\nStill here.\n\n## Next\n\nNot here.\n"
        )
        prose = check_guides.section_prose(text, "## Batch")
        self.assertIn("First paragraph.", prose)
        self.assertIn("Still here.", prose)
        self.assertNotIn("HTTP 400", prose)
        self.assertNotIn("Not here.", prose)
        self.assertEqual(check_guides.section_prose(text, "## Missing"), "")

    def test_docstring_says_whether_a_workflow_runs_the_check(self):
        """No workflow names check_guides.py yet, so its docstring says so
        instead of saying a drifting example fails the build."""
        workflows = "".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        )
        in_ci = "check_guides.py" in workflows
        self.assertEqual("fails the build" in check_guides.__doc__, in_ci)
        self.assertEqual(
            "No workflow in .github/workflows runs it" in check_guides.__doc__, not in_ci
        )

    def test_spec_examples_are_appendix_b1_and_b2(self):
        examples = self.texts["spec"]
        self.assertTrue(examples.startswith("### B.1 "))
        self.assertIn("\n### B.2 ", examples)
        self.assertNotIn("### B.3 ", examples)
        self.assertEqual(check_guides.spec_examples("# No appendix\n"), "")

    def test_block_no_case_runs_fails(self):
        texts = {**self.texts, "ci": self.texts["ci"] + "\n## Extra\n\n```bash\necho extra\n```\n"}
        errors = check_guides.unchecked_blocks(texts)
        self.assertEqual(len(errors), 1)
        self.assertIn("'## Extra' is run by no case", errors[0])

    def test_stub_refuses_hosts_other_than_the_authority_and_served_cards(self):
        proof_url = "https://api.oa2a.org/api/v1/trust/proof?did=x"
        self.assertIsNone(check_guides.answer({}, "GET", "https://verifier.example.net/v", ""))
        self.assertIsNone(check_guides.answer({"unreachable": True}, "GET", proof_url, ""))

    def test_stub_answers_a_redirected_url_with_a_301_to_the_same_url_under_http(self):
        scenario = {"redirect": [check_guides.PROOF_URL]}
        url = check_guides.PROOF_URL + "?did=x"
        self.assertEqual(check_guides.answer(scenario, "GET", url, ""), (301, ""))
        self.assertEqual(
            check_guides.location(scenario, url), "http://api.oa2a.org/api/v1/trust/proof?did=x"
        )
        self.assertIsNone(check_guides.location(scenario, check_guides.VERIFY_URL))
        self.assertIsNone(check_guides.location({}, url))
        self.assertIsNone(check_guides.answer(scenario, "GET", check_guides.location(scenario, url), ""))

    def test_exchange_follows_a_redirect_as_requests_and_fetch_do_by_default(self):
        """Followed, a POST answered 301 goes to the Location as a GET, which the
        stub refuses and the request log records; not followed, the 301 is the
        answer."""
        with tempfile.TemporaryDirectory() as tmp:
            scenario = Path(tmp) / ".scenario.json"
            scenario.write_text(json.dumps({"redirect": [check_guides.VERIFY_URL]}), encoding="utf-8")
            plain = "http://api.oa2a.org/api/v1/trust/verify"
            with mock.patch.dict(os.environ, {check_guides.SCENARIO_ENV: str(scenario)}):
                followed = check_guides.exchange("POST", check_guides.VERIFY_URL, "{}", follow=True)
                kept = check_guides.exchange("POST", check_guides.VERIFY_URL, "{}", follow=False)
            self.assertEqual(followed, (None, plain))
            self.assertEqual(kept, ((301, "", plain), check_guides.VERIFY_URL))
            self.assertEqual(check_guides.requests_not_https(Path(tmp)), [f"GET {plain}"])

    def test_stub_answers_a_since_timestamp_on_advisories_with_the_recorded_400(self):
        status, body = check_guides.answer(
            {}, "GET", "https://api.oa2a.org/api/v1/trust/advisories?since=2026-10-11T00:00:00Z", ""
        )
        self.assertEqual(status, 400)
        self.assertIn("YYYY-MM-DD", body)


# The marker test derives the unit test suites and packages from the tree: a
# unit test suite is a test*.py module (unittest's default discovery pattern)
# or a *.test.ts module (the TypeScript client's), and a package is a manifest
# that pip or npm builds one from.
PACKAGE_MANIFESTS = ("pyproject.toml", "setup.py", "package.json")
# How the marker names a unit test suite: "<path>, <what it tests> (run: <command>)".
SUITE_CLAUSE = re.compile(r"([\w./-]+), [^();]+ \(run: ([^()]+)\)")


def is_test_module(path):
    name = Path(path).name
    return (name.startswith("test") and name.endswith(".py")) or name.endswith(".test.ts")


def tree_files(root, wanted):
    """The paths, relative to root, of the files under it whose name `wanted`
    accepts, outside hidden directories, node_modules, build directories and
    virtual environments (a directory holding pyvenv.cfg)."""
    found = []
    for directory, subdirs, names in os.walk(root):
        here = Path(directory)
        subdirs[:] = [
            name
            for name in subdirs
            if not name.startswith(".")
            and name not in ("node_modules", "build")
            and not (here / name / "pyvenv.cfg").exists()
        ]
        found += [(here / name).relative_to(root).as_posix() for name in names if wanted(name)]
    return sorted(found)


def unit_test_suites(root):
    return tree_files(root, is_test_module)


def package_manifests(root):
    return tree_files(root, lambda name: name in PACKAGE_MANIFESTS)


def marker_errors(marker, root):
    """What the marker gets wrong about the tree under root: a unit test suite
    it does not name with the command that runs it, a suite it names that is
    not in the tree, and a package manifest it does not name."""
    named = [path for path, _ in SUITE_CLAUSE.findall(marker) if is_test_module(path)]
    suites = unit_test_suites(root)
    errors = [
        f"the marker does not name the unit test suite {path} with the command that runs it"
        for path in suites
        if path not in named
    ]
    errors += [
        f"the marker names the unit test suite {path}, which is not in the tree"
        for path in named
        if path not in suites
    ]
    errors += [
        f"the marker does not name the package manifest {path}"
        for path in package_manifests(root)
        if not re.search(rf"(?<![\w./-]){re.escape(path)}(?!\.?[\w/-])", marker)
    ]
    return errors


class TestSuiteMarkerTest(unittest.TestCase):
    # Names the unit test suite a/test_a.py and the package manifest b/pyproject.toml.
    NAMED = (
        "The unit test suite is a/test_a.py, the unit tests for a (run: python3 a/test_a.py); "
        "the package is b (b/pyproject.toml)."
    )

    def setUp(self):
        self.marker = (ROOT / ".pre-push-review-not-required").read_text(encoding="utf-8")

    def tree(self, *paths):
        """A temporary directory holding an empty file at each path."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for path in paths:
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).touch()
        return root

    def test_marker_names_every_unit_test_suite_and_package(self):
        title = (ROOT / "conformance" / "README.md").read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("Test Suite", title)
        self.assertNotIn("The only test suite", self.marker)
        self.assertIn(Path(__file__).resolve().relative_to(ROOT).as_posix(), unit_test_suites(ROOT))
        self.assertTrue(package_manifests(ROOT))
        self.assertEqual(marker_errors(self.marker, ROOT), [])

    def test_marker_installs_and_tests_the_clients_as_their_readme_does(self):
        blocks = check_guides.parse_blocks((ROOT / "clients" / "README.md").read_text(encoding="utf-8"))
        commands = dict(SUITE_CLAUSE.findall(self.marker))
        # The first block under each client's heading builds or installs it, and
        # the blocks under "## Tests" run the clients' tests in the same order.
        for index, (heading, suite) in enumerate(
            [
                ("## Python", "clients/python/tests/test_atp_client.py"),
                ("## TypeScript", "clients/typescript/test/atp-client.test.ts"),
            ]
        ):
            with self.subTest(client=heading):
                install = " && ".join(blocks[(heading, 0)].body.splitlines())
                tests = " && ".join(blocks[("## Tests", index)].body.splitlines())
                self.assertIn(f"(run: {install})", self.marker)
                self.assertEqual(commands.get(suite), tests)

    def test_marker_naming_the_tree_passes(self):
        self.assertEqual(marker_errors(self.NAMED, self.tree("a/test_a.py", "b/pyproject.toml")), [])

    def test_typescript_test_module_is_a_unit_test_suite(self):
        root = self.tree(
            "a/test_a.py", "b/pyproject.toml", "c/test/c.test.ts", "c/dist/test/c.test.js", "c/dist/test/c.test.d.ts"
        )
        self.assertEqual(unit_test_suites(root), ["a/test_a.py", "c/test/c.test.ts"])
        self.assertEqual(
            marker_errors(self.NAMED, root),
            ["the marker does not name the unit test suite c/test/c.test.ts with the command that runs it"],
        )
        named = self.NAMED + " The other is c/test/c.test.ts, the unit tests for c (run: cd c && npm test)."
        self.assertEqual(marker_errors(named, root), [])

    def test_suite_or_package_the_marker_does_not_name_fails(self):
        root = self.tree(
            "a/test_a.py", "b/pyproject.toml", "b/tests/test_b.py", "c/package.json", "pyproject.toml"
        )
        self.assertEqual(
            marker_errors(self.NAMED, root),
            [
                "the marker does not name the unit test suite b/tests/test_b.py with the command that runs it",
                "the marker does not name the package manifest c/package.json",
                "the marker does not name the package manifest pyproject.toml",
            ],
        )

    def test_manifest_is_named_only_by_its_whole_path(self):
        root = self.tree("b/pyproject.toml")
        self.assertEqual(marker_errors("The package manifest is b/pyproject.toml.", root), [])
        for marker in (
            "The package manifest is x/b/pyproject.toml.",
            "The package manifest is b/pyproject.toml.bak.",
        ):
            with self.subTest(marker=marker):
                self.assertEqual(
                    marker_errors(marker, root),
                    ["the marker does not name the package manifest b/pyproject.toml"],
                )

    def test_suite_named_without_its_command_fails(self):
        marker = self.NAMED.replace(" (run: python3 a/test_a.py)", "")
        self.assertEqual(
            marker_errors(marker, self.tree("a/test_a.py", "b/pyproject.toml")),
            ["the marker does not name the unit test suite a/test_a.py with the command that runs it"],
        )

    def test_suite_the_tree_does_not_hold_fails(self):
        self.assertEqual(
            marker_errors(self.NAMED, self.tree("b/pyproject.toml")),
            ["the marker names the unit test suite a/test_a.py, which is not in the tree"],
        )

    def test_hidden_build_node_modules_and_virtual_environment_files_are_not_derived(self):
        root = self.tree(
            ".venv/lib/test_a.py",
            "env/pyvenv.cfg",
            "env/lib/test_b.py",
            "b/build/lib/test_c.py",
            "c/node_modules/d/package.json",
        )
        self.assertEqual(unit_test_suites(root), [])
        self.assertEqual(package_manifests(root), [])

    def test_marker_run_command_runs_this_file(self):
        this = Path(__file__).resolve().relative_to(ROOT).as_posix()
        self.assertIn(f"(run: python3 {this})", self.marker)

    def test_marker_names_the_conformance_test_suite(self):
        scripts = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "conformance").glob("level*.sh"))
        self.assertTrue(scripts)
        self.assertEqual(sorted(re.findall(r"conformance/[\w.-]+\.sh", self.marker)), scripts)
        clause = f"the conformance test suite ({', '.join(scripts)}) tests a running authority"
        self.assertIn(clause, self.marker)

    def test_every_check_script_has_unit_tests(self):
        source = Path(__file__).read_text(encoding="utf-8")
        for script in sorted(SCRIPTS.glob("*.py")):
            if script.name == Path(__file__).name:
                continue
            with self.subTest(script=script.name):
                imported = re.search(rf"(?m)^import {script.stem}\b", source)
                called = re.search(rf"\b{script.stem}\.\w+\(", source)
                self.assertTrue(imported and called, f"no unit test calls {script.name}")

    def test_marker_names_no_undescribed_gate(self):
        self.assertNotRegex(self.marker, r"\d+-phase")


class AtxStatusTest(unittest.TestCase):
    def files(self):
        return {
            "spec": (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8"),
            "readme": (ROOT / "README.md").read_text(encoding="utf-8"),
            "example": (ROOT / "examples" / "atx-example.json").read_text(encoding="utf-8"),
            "schema": (ROOT / "schemas" / "trust-proof-v1.schema.json").read_text(encoding="utf-8"),
        }

    def readme_row(self, readme, field):
        return next(line for line in readme.splitlines() if line.startswith(f"| {field} |"))

    def test_repository_files_pass(self):
        self.assertEqual(validate_examples.atx_status_errors(**self.files()), [])

    def test_readme_lists_every_section_4_6_field(self):
        readme = self.files()["readme"]
        for field in ["capabilities", "buildAttestation", "behavioralProfile", "scanSummary", "declaredPurpose"]:
            with self.subTest(field=field):
                self.assertIn("ATX v1.1", self.readme_row(readme, field))

    def test_status_cells_name_no_release_version(self):
        # The README restates each Section 4.6 status, so a release version in a
        # status cell is a version in the README; the cells say what is signed and where.
        files = self.files()
        for name, text, heading in (
            ("ATP-SPEC.md", files["spec"], validate_examples.SPEC_ATX_HEADING),
            ("README.md", files["readme"], validate_examples.README_ATX_HEADING),
        ):
            rows = validate_examples.status_table(text, heading)
            self.assertTrue(rows, name)
            for field, (number, status) in rows.items():
                with self.subTest(file=name, line=number):
                    self.assertIsNone(validate_examples.VERSION.search(status), f"{field}: {status!r}")

    def test_proposed_readme_status_fails(self):
        files = self.files()
        row = self.readme_row(files["readme"], "capabilities")
        files["readme"] = files["readme"].replace(
            row, "| capabilities | Proposed (v1.1) | Declared capability set. |"
        )
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 2, errors)
        self.assertIn("capabilities is 'Proposed (v1.1)'", errors[0])
        self.assertRegex(errors[1], r"^README\.md:\d+: labels a field \"Proposed\" v1\.1")

    def test_readme_without_declared_purpose_row_fails(self):
        files = self.files()
        row = self.readme_row(files["readme"], "declaredPurpose")
        files["readme"] = files["readme"].replace(row + "\n", "")
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("the ATX table has no declaredPurpose row", errors[0])

    def test_readme_row_section_4_6_does_not_list_fails(self):
        files = self.files()
        row = self.readme_row(files["readme"], "declaredPurpose")
        files["readme"] = files["readme"].replace(row, row + "\n| slsaLevel | ATX v1.1 | Build level. |")
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("the ATX table lists slsaLevel, which Section 4.6 does not", errors[0])

    def test_example_without_a_v1_1_field_fails(self):
        files = self.files()
        example = json.loads(files["example"])
        del example["declaredPurpose"]
        files["example"] = json.dumps(example, indent=2)
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("examples/atx-example.json: no declaredPurpose member", errors[0])

    def test_proposed_example_comment_fails(self):
        files = self.files()
        example = json.loads(files["example"])
        example["$comment"] = "Proposed v1.1 fields are shown for shape only."
        files["example"] = json.dumps(example, indent=2)
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertRegex(errors[0], r"^examples/atx-example\.json:2: labels a field \"Proposed\"")

    def test_proposed_schema_description_fails(self):
        files = self.files()
        schema = json.loads(files["schema"])
        schema["properties"]["scanSummary"]["description"] = "Proposed v1.1 (section 4.6)."
        files["schema"] = json.dumps(schema, indent=2)
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 2, errors)
        self.assertIn("scanSummary is described as 'Proposed v1.1 (section 4.6).'", errors[0])
        self.assertRegex(errors[1], r"^schemas/trust-proof-v1\.schema\.json:\d+: labels a field \"Proposed\"")

    def test_spec_without_the_table_fails(self):
        files = self.files()
        files["spec"] = files["spec"].replace(validate_examples.SPEC_ATX_HEADING, "### 4.6 ATX")
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("no schema table", errors[0])

    def test_spec_table_without_a_v1_1_row_fails(self):
        files = self.files()
        files["spec"] = files["spec"].replace("| ATX v1.1 (", "| Draft (")
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(errors, ["ATP-SPEC.md: the Section 4.6 schema table has no ATX v1.1 row"])

    def test_readme_without_the_atx_table_fails(self):
        files = self.files()
        files["readme"] = files["readme"].replace(validate_examples.README_ATX_HEADING, "## ATX")
        errors = validate_examples.atx_status_errors(**files)
        fields = validate_examples.status_table(files["spec"], validate_examples.SPEC_ATX_HEADING)
        self.assertEqual(len(errors), 1 + len(fields), errors)
        self.assertEqual(errors[0], f"README.md: no ATX table under {validate_examples.README_ATX_HEADING!r}")
        for field, error in zip(fields, errors[1:]):
            self.assertIn(f"the ATX table has no {field} row", error)

    def test_example_that_is_not_json_is_one_error(self):
        files = self.files()
        files["example"] = files["example"].rstrip().rstrip("}")
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("examples/atx-example.json: not JSON: "), errors[0])

    def test_example_that_is_not_utf8_is_one_error(self):
        files = self.files()
        for example in (
            b"\xe9" + files["example"].encode("utf-8"),
            files["example"].encode("utf-8") + b"\xe9",
        ):
            with self.subTest(example=example[:1] + example[-1:]):
                errors = validate_examples.atx_status_errors(**{**files, "example": example})
                self.assertEqual(len(errors), 1, errors)
                self.assertTrue(
                    errors[0].startswith("examples/atx-example.json: not UTF-8: "), errors[0]
                )
                self.assertIn("can't decode byte 0xe9", errors[0])

    def test_example_given_as_utf8_bytes_passes(self):
        files = self.files()
        files["example"] = files["example"].encode("utf-8")
        self.assertEqual(validate_examples.atx_status_errors(**files), [])

    def test_example_that_is_json_but_not_an_object_is_one_error_per_v1_1_field(self):
        files = self.files()
        fields = [
            field
            for field, (_, status) in validate_examples.status_table(
                files["spec"], validate_examples.SPEC_ATX_HEADING
            ).items()
            if status.startswith(validate_examples.ATX_V11_STATUS)
        ]
        self.assertTrue(fields)
        # An array or string naming every field is still an example with no members.
        for example in ("[]", json.dumps(fields), json.dumps(" ".join(fields))):
            with self.subTest(example=example):
                files["example"] = example
                errors = validate_examples.atx_status_errors(**files)
                self.assertEqual(len(errors), len(fields), errors)
                for field, error in zip(fields, errors):
                    self.assertTrue(
                        error.startswith(f"examples/atx-example.json: no {field} member;"), error
                    )

    def test_missing_example_is_one_error(self):
        files = self.files()
        files["example"] = None
        errors = validate_examples.atx_status_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("examples/atx-example.json: missing;"), errors[0])

    def test_main_reports_a_missing_example_as_one_atx_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("README.md", "ATP-SPEC.md"):
                shutil.copy(ROOT / name, root / name)
            for directory in ("schemas", "registries"):
                shutil.copytree(ROOT / directory, root / directory)
            # The ATX example is the one mapped example file the tree lacks.
            (root / "examples").mkdir()
            shutil.copy(ROOT / "examples" / "atx-vc-example.json", root / "examples")
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                self.assertEqual(validate_examples.main(), 1)
        lines = out.getvalue().splitlines()
        self.assertEqual([line for line in lines if "FAIL" in line or "INVALID" in line],
                         ["atx FAIL       README.md, example and schema vs Section 4.6"])
        failed = lines.index("atx FAIL       README.md, example and schema vs Section 4.6")
        self.assertTrue(lines[failed + 1].startswith("    examples/atx-example.json: missing;"), lines)
        self.assertFalse(lines[failed + 2].startswith("    "), lines)

    def test_retired_status_matches_each_spacing(self):
        for text in ("Proposed (v1.1)", "Proposed v1.1", "proposed( v1.1", "PROPOSED ( v1.1", "Proposed(v1.1)"):
            with self.subTest(text=text):
                self.assertTrue(validate_examples.RETIRED_STATUS.search(text))
        for text in ("Proposed v1.10", "Proposed (v1.2)", "Proposed ((v1.1)", "unproposed v1.1"):
            with self.subTest(text=text):
                self.assertFalse(validate_examples.RETIRED_STATUS.search(text))

    def test_long_whitespace_run_after_proposed_is_scanned_in_linear_time(self):
        # The earlier pattern took about 7 s on this line and grew with the
        # square of the run's length.
        files = self.files()
        files["readme"] += "\nproposed" + " " * 50000 + "v1.2\n"
        started = time.perf_counter()
        self.assertEqual(validate_examples.atx_status_errors(**files), [])
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_changelog_quotes_the_section_4_6_status_in_full(self):
        statuses = {
            status
            for _, status in validate_examples.status_table(
                self.files()["spec"], validate_examples.SPEC_ATX_HEADING
            ).values()
        }
        changelog = " ".join((ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split())
        quoted = re.findall(r'"(ATX v1\.1 \([^"]*\))"', changelog)
        self.assertTrue(quoted)
        for status in quoted:
            with self.subTest(status=status):
                self.assertIn(status, statuses)

    def test_main_fails_on_atx_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "atx_status_errors", return_value=["status differs"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("atx FAIL", out.getvalue())
        self.assertIn("status differs", out.getvalue())


class FixtureCoverageTest(unittest.TestCase):
    PRE_FIX_ROW = "| `revocation-list-valid.json` | 2 | §8.1 revocation response (structural) | ACCEPT |"

    def files(self):
        return {
            "spec": (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8"),
            "readme": (ROOT / "README.md").read_text(encoding="utf-8"),
            "schema": (ROOT / "schemas" / "revocation-list-v1.schema.json").read_text(encoding="utf-8"),
        }

    def test_repository_files_pass(self):
        self.assertEqual(validate_examples.fixture_coverage_errors(**self.files()), [])

    def test_coverage_list_names_the_section_4_4_rejections_no_fixture_has(self):
        """No fixture carries a proof signed by a revoked key (step 3) or one
        whose only Ed25519 entry is a key of another DID (step 4)."""
        coverage = next(
            line for line in self.files()["spec"].splitlines()
            if line.startswith(validate_examples.COVERAGE_LIST)
        )
        self.assertIn("§4.4 step 3 rejection of a proof signed by a revoked authority key", coverage)
        self.assertIn(
            "§4.4 step 4 rejection of a proof whose only Ed25519 entry is signed by a key of a DID "
            "other than its `issuerDid`",
            coverage,
        )

    def test_readme_citing_fixture_without_8_1_1_fails(self):
        # (appended paragraph, offset of the offending sentence's first line
        # from the paragraph's last line). A later sentence naming Section
        # 8.1.1 does not excuse an earlier one, and an offending sentence that
        # starts on a later line is reported at that line.
        cases = {
            "8.1.1 in the next sentence": (
                "\nThe conformance suite pins the Section 8.1 body\n"
                "(`fixtures/revocation-list-valid.json`) and the malformed-timestamp rejection. Its\n"
                "free-text reason predates the Section 8.1.1 codes.\n",
                2,
            ),
            "offending sentence on a later line": (
                "\nNo fixture pins the Section 8.1.1 reason codes\n"
                "yet. The conformance suite pins\n"
                "`fixtures/revocation-list-valid.json` as well.\n",
                1,
            ),
        }
        for label, (paragraph, back) in cases.items():
            with self.subTest(label):
                files = self.files()
                files["readme"] += paragraph
                line = len(files["readme"].splitlines()) - back
                errors = validate_examples.fixture_coverage_errors(**files)
                self.assertEqual(len(errors), 1, errors)
                self.assertTrue(errors[0].startswith(f"README.md:{line}: cites revocation-list-valid"), errors[0])

    def test_spec_table_row_without_8_1_1_fails(self):
        files = self.files()
        row = next(
            line for line in files["spec"].splitlines() if line.startswith("| `revocation-list-valid.json` |")
        )
        files["spec"] = files["spec"].replace(row, self.PRE_FIX_ROW)
        errors = validate_examples.fixture_coverage_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertRegex(errors[0], r"^ATP-SPEC\.md:\d+: cites revocation-list-valid")

    def test_coverage_list_deferring_to_the_suite_fails(self):
        files = self.files()
        files["spec"] = files["spec"].replace(
            "this list is authoritative, and the suite's `notCovered` list can lag it",
            "the suite's `notCovered` list is authoritative",
        )
        errors = validate_examples.fixture_coverage_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("does not say 'this list is authoritative'", errors[0])

    def test_spec_without_coverage_list_fails(self):
        files = self.files()
        files["spec"] = files["spec"].replace(validate_examples.COVERAGE_LIST, "Uncovered")
        errors = validate_examples.fixture_coverage_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("no 'Not yet covered by fixtures' list", errors[0])

    def test_schema_description_calling_fixture_ground_truth_fails(self):
        files = self.files()
        schema = json.loads(files["schema"])
        schema["description"] = (
            "Structural schema for the section 8.1 revocation response, derived from that section's "
            "pinned body with the atp-conformance revocation-list-valid fixture as ground truth. "
            "`reason` is a section 8.1.1 code, never free text."
        )
        files["schema"] = json.dumps(schema, indent=2)
        errors = validate_examples.fixture_coverage_errors(**files)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("the description cites revocation-list-valid without section 8.1.1", errors[0])

    def test_code_block_may_cite_fixture(self):
        files = self.files()
        files["readme"] += "\n```bash\nls fixtures/revocation-list-valid.json\n```\n"
        self.assertEqual(validate_examples.fixture_coverage_errors(**files), [])

    def test_main_fails_on_fixture_coverage_errors(self):
        out = io.StringIO()
        with mock.patch.object(
            validate_examples, "fixture_coverage_errors", return_value=["coverage differs"]
        ), contextlib.redirect_stdout(out):
            self.assertEqual(validate_examples.main(), 1)
        self.assertIn("fixtures FAIL", out.getvalue())
        self.assertIn("coverage differs", out.getvalue())


class InputFileTest(unittest.TestCase):
    """A schema file, the examples map, ATP-SPEC.md or README.md that cannot
    be used (missing, not UTF-8, not JSON, not the expected shape, for the map
    without an entry or, for a schema, not valid under the metaschema) is one
    failure line, and main() returns without running any check. Each of those
    checks reads one or more of these files; none reads all of them. A map
    entry whose schema, file, heading or ```json block is not there is one
    failure line in the count main() ends with. A Markdown file in examples/,
    the ATX example or the revocation reason registry that is not UTF-8 is one
    failure, in the same count, of the check that reads it, as is a reason
    registry that is not JSON or is JSON of another shape than the generated
    one, a link in examples/ whose name ends in .md and whose target is not
    there, and a revocation schema with no object schema for an entry's
    reason. A directory in examples/ whose name ends in .md, or in schemas/
    whose name ends in .schema.json, is not read; a link in schemas/ whose
    target is not there is one failure line."""

    NOT_RUN = "the checks that read these files did not run"
    MAP = "schemas/examples-map.json"

    def run_main(self, damage):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("README.md", "ATP-SPEC.md"):
                shutil.copy(ROOT / name, root / name)
            for directory in ("schemas", "registries", "examples"):
                shutil.copytree(ROOT / directory, root / directory)
            damage(root)
            out = io.StringIO()
            with mock.patch.object(validate_examples, "ROOT", root), contextlib.redirect_stdout(out):
                code = validate_examples.main()
        lines = out.getvalue().splitlines()
        return code, lines, [line for line in lines if "FAIL" in line or "INVALID" in line]

    def test_copied_repository_passes(self):
        code, lines, failed = self.run_main(lambda root: None)
        self.assertEqual((code, failed), (0, []), lines)
        self.assertNotIn(self.NOT_RUN, lines[-1])

    def test_schema_that_is_not_json_is_one_failure_line(self):
        for name in ("discovery-v1", "revocation-list-v1", "trust-proof-v1"):
            path = f"schemas/{name}.schema.json"
            with self.subTest(path=path):
                code, lines, failed = self.run_main(
                    lambda root, path=path: (root / path).write_text("{", encoding="utf-8")
                )
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith(f"schema INVALID {path}: not JSON: "), failed[0])
                self.assertEqual([line for line in lines if line.startswith(f"schema OK      {path}")], [])
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_schema_that_is_not_utf8_is_one_failure_line(self):
        path = "schemas/discovery-v1.schema.json"

        def damage(root):
            (root / path).write_bytes(b"\xe9" + (root / path).read_bytes())

        code, lines, failed = self.run_main(damage)
        self.assertEqual(code, 1)
        self.assertEqual(len(failed), 1, lines)
        self.assertTrue(failed[0].startswith(f"schema INVALID {path}: not JSON: "), failed[0])
        self.assertIn("utf-8", failed[0])
        self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_schema_that_is_not_a_valid_object_schema_is_one_failure_line(self):
        cases = (
            ("discovery-v1", "[]", "not a JSON object"),
            ("revocation-list-v1", "true", "not a JSON object"),
            ("consistency-proof-v1", '{"type": 7}', "7 is not valid under any of the given schemas"),
            ("trust-proof-v1", '{"properties": []}', "[] is not of type 'object'"),
        )
        for name, content, reason in cases:
            path = f"schemas/{name}.schema.json"
            with self.subTest(path=path):
                code, lines, failed = self.run_main(
                    lambda root, path=path, content=content: (root / path).write_text(content, encoding="utf-8")
                )
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"schema INVALID {path}: {reason}"], lines)
                self.assertEqual([line for line in lines if line.startswith(f"schema OK      {path}")], [])
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_missing_schema_read_by_name_is_one_failure_line(self):
        for path in validate_examples.SCHEMAS_READ_BY_NAME:
            with self.subTest(path=path):
                code, lines, failed = self.run_main(lambda root, path=path: (root / path).unlink())
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"schema FAIL    {path}: missing"], lines)
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_directory_in_schemas_named_as_a_schema_is_not_read(self):
        """A directory whose name ends in .schema.json is not a schema. One in
        place of a schema read by name is that schema missing, once."""
        registered = []

        def damage(root):
            (root / "schemas" / "notes.schema.json").mkdir()
            with mock.patch.object(validate_examples, "ROOT", root):
                registered.extend(validate_examples.local_registry())

        code, lines, failed = self.run_main(damage)
        self.assertEqual((code, failed), (0, []), lines)
        self.assertEqual([line for line in lines if "notes.schema.json" in line], [])
        self.assertIn(
            json.loads((ROOT / "schemas" / "revocation-list-v1.schema.json").read_text())["$id"],
            registered,
        )
        for path in validate_examples.SCHEMAS_READ_BY_NAME:
            with self.subTest(path=path):

                def replace(root, path=path):
                    (root / path).unlink()
                    (root / path).mkdir()

                code, lines, failed = self.run_main(replace)
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"schema FAIL    {path}: missing"], lines)
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_link_in_schemas_whose_target_is_missing_is_one_failure_line(self):
        """The link is listed with the schemas and is one line that names it,
        not a traceback with its path on disk; a schema read by name is not
        also reported missing."""
        for path in ("schemas/notes.schema.json", *validate_examples.SCHEMAS_READ_BY_NAME):
            with self.subTest(path=path):

                def damage(root, path=path):
                    (root / path).unlink(missing_ok=True)
                    (root / path).symlink_to("missing.schema.json")

                code, lines, failed = self.run_main(damage)
                self.assertEqual(code, 1)
                self.assertEqual(
                    failed,
                    [f"schema INVALID {path}: cannot be read: No such file or directory"],
                    lines,
                )
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_link_in_schemas_whose_target_is_missing_is_not_in_the_registry(self):
        """listed_files() lists the link so main() can report it; local_registry()
        is built from the schemas that are there, without the link and without
        a traceback."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "schemas", root / "schemas")
            with mock.patch.object(validate_examples, "ROOT", root):
                expected = sorted(validate_examples.local_registry())
                link = root / "schemas" / "zz.schema.json"
                link.symlink_to("missing.schema.json")
                self.assertIn(link, validate_examples.listed_files(root / "schemas", "*.schema.json"))
                registered = sorted(validate_examples.local_registry())
        self.assertEqual(registered, expected)
        self.assertIn(
            json.loads((ROOT / "schemas" / "revocation-list-v1.schema.json").read_text())["$id"],
            registered,
        )

    def test_examples_map_that_is_not_a_list_of_entries_is_one_failure_line(self):
        for content, reason in (
            ("{", "not JSON: "),
            ('{"file": "ATP-SPEC.md"}', "not a list of objects"),
            ('[{"file": "ATP-SPEC.md", "heading": "### 4.2 Trust Proof Format"}]', "not a list of objects"),
            ('[{"file": "ATP-SPEC.md", "heading": 7, "schema": "schemas/trust-proof-v1.schema.json"}]',
             "not a list of objects"),
            ('[{"file": "ATP-SPEC.md", "heading": null, "schema": "schemas/trust-proof-v1.schema.json"}]',
             "not a list of objects"),
        ):
            with self.subTest(content=content):
                code, lines, failed = self.run_main(
                    lambda root, content=content: (root / "schemas" / "examples-map.json").write_text(
                        content, encoding="utf-8"
                    )
                )
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(
                    failed[0].startswith(f"map INVALID    schemas/examples-map.json: {reason}"), failed[0]
                )
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_missing_examples_map_is_one_failure_line(self):
        def removed(root):
            (root / self.MAP).unlink()

        def a_directory(root):
            removed(root)
            (root / self.MAP).mkdir()

        for damage in (removed, a_directory):
            with self.subTest(damage=damage.__name__):
                code, lines, failed = self.run_main(damage)
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"map FAIL       {self.MAP}: missing"], lines)
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_examples_map_without_an_entry_is_one_failure_line(self):
        self.assertTrue(validate_examples.is_entry_list([]))
        code, lines, failed = self.run_main(
            lambda root: (root / self.MAP).write_text("[]", encoding="utf-8")
        )
        self.assertEqual(code, 1)
        self.assertEqual(failed, [f"map INVALID    {self.MAP}: lists no example"], lines)
        self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_examples_map_that_is_not_utf8_is_one_failure_line(self):
        def damage(root):
            (root / self.MAP).write_bytes(b"\xe9" + (root / self.MAP).read_bytes())

        code, lines, failed = self.run_main(damage)
        self.assertEqual(code, 1)
        self.assertEqual(len(failed), 1, lines)
        self.assertTrue(failed[0].startswith(f"map INVALID    {self.MAP}: not JSON: "), failed[0])
        self.assertIn("utf-8", failed[0])
        self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def edit_map(self, edit):
        """A damage that passes the map's entries to `edit` and writes them back."""
        def damage(root):
            entries = json.loads((root / self.MAP).read_text(encoding="utf-8"))
            edit(root, entries)
            (root / self.MAP).write_text(json.dumps(entries), encoding="utf-8")

        return damage

    def test_map_heading_that_is_not_in_its_file_is_one_failure(self):
        mapped = len(json.loads((ROOT / self.MAP).read_text(encoding="utf-8")))

        def edit(root, entries):
            entries[0]["heading"] = "### 99.9 Nowhere"

        code, lines, failed = self.run_main(self.edit_map(edit))
        self.assertEqual(code, 1)
        # The line names the file as the map does, not by its path on disk.
        self.assertEqual(
            failed, ["example FAIL   ATP-SPEC.md: heading '### 99.9 Nowhere' not found"], lines
        )
        # The other entries are validated, and the run ends with its count.
        self.assertEqual(len([line for line in lines if line.startswith("example OK ")]), mapped - 1)
        self.assertEqual(lines[-1], "1 failure(s)")

    def test_map_heading_without_a_closed_json_block_is_one_failure(self):
        schema = "schemas/discovery-v1.schema.json"
        for content, reason in (
            ("## A\n\nProse.\n\n## B\n\n```json\n{}\n```\n",
             "no ```json block between '## A' and the next heading"),
            ("## A\n\nProse.\n", "no ```json block after '## A'"),
            ("## A\n\n```json\n{\n", "unterminated ```json block after '## A'"),
        ):
            def edit(root, entries, content=content):
                (root / "NOTES.md").write_text(content, encoding="utf-8")
                entries.insert(0, {"file": "NOTES.md", "heading": "## A", "schema": schema})

            with self.subTest(reason=reason):
                code, lines, failed = self.run_main(self.edit_map(edit))
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"example FAIL   NOTES.md: {reason}"], lines)
                self.assertIn("example OK     examples/atx-vc-example.json", lines)
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_mapped_file_that_is_not_utf8_is_one_failure(self):
        """A map entry whose file is not UTF-8 and is read by no other check,
        with or without a heading, is one counted failure line, as a heading
        that is not in its file is."""
        def json_file(root):
            path = root / "examples" / "atx-vc-example.json"
            path.write_bytes(b"\xe9" + path.read_bytes())

        def markdown_file(root, entries):
            # The heading and its block are there; the byte after them is not UTF-8.
            (root / "NOTES.md").write_bytes(b"## A\n\n```json\n{}\n```\n\xe9\n")
            entries.insert(0, {"file": "NOTES.md", "heading": "## A",
                               "schema": "schemas/discovery-v1.schema.json"})

        for name, damage in (
            ("examples/atx-vc-example.json", json_file),
            ("NOTES.md", self.edit_map(markdown_file)),
        ):
            with self.subTest(name=name):
                code, lines, failed = self.run_main(damage)
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith(f"example FAIL   {name}: not UTF-8: "), failed[0])
                self.assertIn("can't decode byte 0xe9", failed[0])
                self.assertIn("example OK     ATP-SPEC.md @ '### 4.2 Trust Proof Format'", lines)
                self.assertEqual(lines[-1], "1 failure(s)")

    CARD_FAIL = "card FAIL      ATP-SPEC.md, README.md, examples/*.md vs the A2A agent card path"
    ATX_FAIL = "atx FAIL       README.md, example and schema vs Section 4.6"
    REASONS_FAIL = "reasons FAIL   schemas/revocation-list-v1.schema.json vs Section 8.1.1"
    REASONS = "registries/revocation-reasons.json"

    def assert_one_failure_naming(self, damage, failure, detail):
        """main() counts one failure, the check `failure` names, and the one
        line under it starts with `detail`. The mapped examples still pass."""
        code, lines, failed = self.run_main(damage)
        self.assertEqual(code, 1)
        self.assertEqual(failed, [failure], lines)
        at = lines.index(failure)
        self.assertTrue(lines[at + 1].startswith(f"    {detail}"), lines[at + 1])
        self.assertFalse(lines[at + 2].startswith("    "), lines)
        self.assertIn("example OK     ATP-SPEC.md @ '### 4.2 Trust Proof Format'", lines)
        self.assertEqual(lines[-1], "1 failure(s)")
        return lines

    def test_file_one_check_reads_that_is_not_utf8_is_one_failure(self):
        """A Markdown file in examples/, the ATX example and the revocation
        reason registry are not entries of the examples map; the A2A agent
        card check, the ATX check and the revocation reason check read them.
        One that is not UTF-8 is one failure of its check, with a line under
        it that names the file, and the other checks run."""
        guides = sorted(path.name for path in (ROOT / "examples").glob("*.md"))
        self.assertIn("a2a-integration.md", guides)
        cases = [(f"examples/{guide}", self.CARD_FAIL) for guide in guides]
        cases += [("examples/atx-example.json", self.ATX_FAIL), (self.REASONS, self.REASONS_FAIL)]
        for name, failure in cases:
            for where in ("first", "last"):
                def damage(root, name=name, where=where):
                    content = (root / name).read_bytes()
                    (root / name).write_bytes(
                        b"\xe9" + content if where == "first" else content + b"\xe9"
                    )

                with self.subTest(name=name, byte=where):
                    lines = self.assert_one_failure_naming(damage, failure, f"{name}: not UTF-8: ")
                    self.assertIn("can't decode byte 0xe9", lines[lines.index(failure) + 1])

    def test_revocation_reason_registry_that_is_not_json_is_one_failure(self):
        self.assert_one_failure_naming(
            lambda root: (root / self.REASONS).write_text("{", encoding="utf-8"),
            self.REASONS_FAIL,
            f"{self.REASONS}: not JSON: ",
        )

    def test_revocation_reason_registry_of_another_shape_is_one_failure(self):
        """The registry is JSON, and not an object whose `rows` is a list of
        objects that each have a string `Reason`, as gen_registries.py writes."""
        for content in (
            "{}",
            "[]",
            "null",
            '"rows"',
            '{"rows": null}',
            '{"rows": {}}',
            '{"rows": [{}]}',
            '{"rows": ["manual"]}',
            '{"rows": [{"Reason": 7}]}',
            '{"rows": [{"Reason": "manual"}, {"Since": "1.1.0"}]}',
        ):
            with self.subTest(content=content):
                lines = self.assert_one_failure_naming(
                    lambda root, content=content: (root / self.REASONS).write_text(
                        content, encoding="utf-8"
                    ),
                    self.REASONS_FAIL,
                    f"{self.REASONS}: not an object whose rows each have a string Reason ",
                )
                self.assertTrue(
                    lines[lines.index(self.REASONS_FAIL) + 1].endswith("(run scripts/gen_registries.py)")
                )

    def test_directory_in_examples_named_as_a_markdown_file_is_not_read(self):
        listed = []

        def damage(root):
            (root / "examples" / "notes.md").mkdir()
            with mock.patch.object(validate_examples, "ROOT", root):
                listed.extend(
                    path.relative_to(root).as_posix()
                    for path in validate_examples.agent_card_documents()
                )

        code, lines, failed = self.run_main(damage)
        self.assertNotIn("examples/notes.md", listed)
        self.assertIn("examples/a2a-integration.md", listed)
        self.assertEqual((code, failed), (0, []), lines)
        self.assertIn(
            "card OK        ATP-SPEC.md, README.md, examples/*.md vs the A2A agent card path", lines
        )

    def test_link_in_examples_whose_target_is_missing_is_one_failure(self):
        """A link whose name ends in .md and whose target is not there is one
        failure of the A2A agent card check that names it, and not its path
        on disk."""
        lines = self.assert_one_failure_naming(
            lambda root: (root / "examples" / "zz.md").symlink_to("missing.md"),
            self.CARD_FAIL,
            "examples/zz.md: cannot be read: No such file or directory",
        )
        self.assertEqual([line for line in lines if "missing.md" in line], [])

    REASON_SCHEMA = "schemas/revocation-list-v1.schema.json"
    REASON_SCHEMA_PATH = "properties.revocations.items.properties.reason"

    def test_revocation_schema_of_another_shape_is_one_failure_of_the_reason_check(self):
        """A valid schema with no object schema for an entry's reason, at
        properties.revocations.items.properties.reason, is one line under the
        reason check that names the schema file. The index check reads the
        same schema and fails on its own terms where the shape admits what
        Section 8.1 refuses."""
        schema = json.loads((ROOT / self.REASON_SCHEMA).read_text(encoding="utf-8"))
        reason_true = copy.deepcopy(schema)
        reason_true["properties"]["revocations"]["items"]["properties"]["reason"] = True
        items_true = copy.deepcopy(schema)
        items_true["properties"]["revocations"]["items"] = True
        no_revocations = copy.deepcopy(schema)
        del no_revocations["properties"]["revocations"]
        for name, content in (
            ("an object schema", {"type": "object"}),
            ("reason is true", reason_true),
            ("items is true", items_true),
            ("no revocations member", no_revocations),
        ):
            with self.subTest(schema=name):
                code, lines, failed = self.run_main(
                    lambda root, content=content: (root / self.REASON_SCHEMA).write_text(
                        json.dumps(content), encoding="utf-8"
                    )
                )
                self.assertEqual(code, 1)
                self.assertIn(self.REASONS_FAIL, failed, lines)
                at = lines.index(self.REASONS_FAIL)
                self.assertEqual(
                    lines[at + 1],
                    f"    {self.REASON_SCHEMA}: no object schema at {self.REASON_SCHEMA_PATH}, "
                    "an entry's reason",
                )
                self.assertFalse(lines[at + 2].startswith("    "), lines)
                self.assertIn("example OK     ATP-SPEC.md @ '### 4.2 Trust Proof Format'", lines)
                if content is reason_true:
                    # Entries keep their required members, so only the reason check fails.
                    self.assertEqual(failed, [self.REASONS_FAIL], lines)

    def test_revocation_reason_with_a_boolean_branch_is_compared(self):
        """A `false` branch before the enum and an enum value that is not a
        string are compared with the Section 8.1.1 table, not a traceback."""
        schema = json.loads((ROOT / self.REASON_SCHEMA).read_text(encoding="utf-8"))
        schema["properties"]["revocations"]["items"]["properties"]["reason"] = {
            "anyOf": [False, {"enum": ["manual", 1]}]
        }
        code, lines, failed = self.run_main(
            lambda root: (root / self.REASON_SCHEMA).write_text(json.dumps(schema), encoding="utf-8")
        )
        self.assertEqual(code, 1)
        self.assertIn(self.REASONS_FAIL, failed, lines)
        self.assertIn("    private-use reason 'x-private_use' is refused", lines)
        self.assertTrue(
            any(line.startswith("    schema codes [1, 'manual'] differ from the Section 8.1.1 table ")
                for line in lines),
            lines,
        )

    def test_section_4_3_1_heading_that_is_not_in_the_spec_is_one_failure(self):
        """The examples map reports the heading, so the co-signature check is not
        compared; when the map does not list it, the co-signature check fails on it."""
        heading = validate_examples.SIGSTORE_HEADING
        not_found = f"ATP-SPEC.md: heading {heading!r} not found"

        def renamed(root, entries):
            spec = (root / "ATP-SPEC.md").read_text(encoding="utf-8")
            self.assertEqual(spec.count(f"\n{heading}\n"), 1)
            (root / "ATP-SPEC.md").write_text(
                spec.replace(f"\n{heading}\n", f"\n{heading} entry\n"), encoding="utf-8"
            )

        def renamed_and_unmapped(root, entries):
            renamed(root, entries)
            kept = [entry for entry in entries if entry.get("heading") != heading]
            self.assertEqual(len(kept), len(entries) - 1)
            entries[:] = kept

        cosign = "schemas/trust-proof-v1.schema.json vs Section 4.3.1"
        for edit, failure, reported in (
            (renamed, f"example FAIL   {not_found}", f"cosign SKIP    {cosign}: not compared, {not_found}"),
            (renamed_and_unmapped, f"cosign FAIL    {cosign}", f"    {not_found}"),
        ):
            with self.subTest(edit=edit.__name__):
                code, lines, failed = self.run_main(self.edit_map(edit))
                self.assertEqual(code, 1)
                self.assertEqual(failed, [failure], lines)
                self.assertIn(reported, lines)
                self.assertEqual([line for line in lines if line.startswith("cosign OK")], [])
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_map_entry_naming_a_file_that_is_not_there_is_one_failure(self):
        for member, value in (("schema", "schemas/absent-v1.schema.json"), ("file", "ABSENT.md")):
            def damage(root, member=member, value=value):
                path = root / "schemas" / "examples-map.json"
                entries = json.loads(path.read_text(encoding="utf-8"))
                entries[0][member] = value
                path.write_text(json.dumps(entries), encoding="utf-8")

            with self.subTest(member=member):
                code, lines, failed = self.run_main(damage)
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith("example FAIL   "), failed[0])
                self.assertTrue(failed[0].endswith(f": {value} not found"), failed[0])
                self.assertEqual(lines[-1], "1 failure(s)")

    def test_map_entry_may_leave_out_its_heading(self):
        schema = "schemas/trust-proof-v1.schema.json"
        self.assertTrue(validate_examples.is_entry_list([{"file": "examples/a.json", "schema": schema}]))
        for heading in (7, None, ["### 4.2 Trust Proof Format"]):
            with self.subTest(heading=heading):
                self.assertFalse(
                    validate_examples.is_entry_list(
                        [{"file": "ATP-SPEC.md", "heading": heading, "schema": schema}]
                    )
                )

    def test_entry_without_a_heading_naming_a_schema_that_is_not_there_is_one_failure(self):
        def damage(root):
            path = root / "schemas" / "examples-map.json"
            entries = json.loads(path.read_text(encoding="utf-8"))
            entries.append({"file": "examples/absent.json", "schema": "schemas/absent-v1.schema.json"})
            path.write_text(json.dumps(entries), encoding="utf-8")

        code, lines, failed = self.run_main(damage)
        self.assertEqual(code, 1)
        self.assertEqual(
            failed, ["example FAIL   examples/absent.json: schemas/absent-v1.schema.json not found"], lines
        )
        self.assertEqual(lines[-1], "1 failure(s)")

    def test_missing_document_is_one_failure_line(self):
        for name in ("README.md", "ATP-SPEC.md"):
            with self.subTest(name=name):
                code, lines, failed = self.run_main(lambda root, name=name: (root / name).unlink())
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"document FAIL  {name}: missing"], lines)
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_document_that_is_a_directory_is_missing(self):
        def damage(root):
            (root / "README.md").unlink()
            (root / "README.md").mkdir()

        code, lines, failed = self.run_main(damage)
        self.assertEqual(code, 1)
        self.assertEqual(failed, ["document FAIL  README.md: missing"], lines)
        self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_document_that_is_not_utf8_is_one_failure_line(self):
        for name in ("README.md", "ATP-SPEC.md"):
            def damage(root, name=name):
                (root / name).write_bytes(b"\xe9" + (root / name).read_bytes())

            with self.subTest(name=name):
                code, lines, failed = self.run_main(damage)
                self.assertEqual(code, 1)
                self.assertEqual(len(failed), 1, lines)
                self.assertTrue(failed[0].startswith(f"document FAIL  {name}: not UTF-8: "), failed[0])
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_unusable_files_and_an_invalid_schema_are_counted_together(self):
        def damage(root):
            (root / "README.md").unlink()
            (root / "schemas" / "discovery-v1.schema.json").write_text("{", encoding="utf-8")
            (root / "schemas" / "trust-proof-v1.schema.json").write_text('{"type": 7}', encoding="utf-8")

        code, lines, failed = self.run_main(damage)
        self.assertEqual(code, 1)
        self.assertEqual(len(failed), 3, lines)
        self.assertEqual(lines[-1], f"3 failure(s); {self.NOT_RUN}")


class LegacyPathMilestoneTest(unittest.TestCase):
    """No vX.Y.Z-final release the specification names, such as the one at
    which Section 7.1 ends the consumer fallback to the legacy discovery path,
    is earlier than the version in the specification's header, and the
    changelog entry names the same releases and describes the rule as Section
    7.1 states it."""

    FINAL = re.compile(r"\bv(\d+)\.(\d+)\.(\d+)-final\b")
    ENTRY = "- §7.1 legacy-path migration rule:"

    def setUp(self):
        self.spec = (ROOT / "ATP-SPEC.md").read_text(encoding="utf-8")
        self.rule = next(
            line for line in self.spec.splitlines() if line.startswith("**Legacy path migration.**")
        )
        lines = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith(self.ENTRY))
        entry = [lines[start]]
        for line in lines[start + 1:]:
            if not line.startswith("  "):
                break
            entry.append(line.strip())
        self.entry = " ".join(entry)

    def test_spec_names_no_final_release_behind_its_header_version(self):
        header = validate_examples.SPEC_VERSION.search(self.spec).group(1)
        series = tuple(int(part) for part in header.split("-")[0].split("."))
        for release in self.FINAL.findall(self.spec):
            with self.subTest(release=".".join(release)):
                self.assertGreaterEqual(tuple(int(part) for part in release), series)

    def test_changelog_entry_states_the_rule_as_section_7_1_does(self):
        self.assertIn("optional alias", self.rule)
        self.assertIn("optional alias", self.entry)
        self.assertNotIn("must gain", self.entry)
        self.assertEqual(self.FINAL.findall(self.entry), self.FINAL.findall(self.rule))


if __name__ == "__main__":
    unittest.main()
