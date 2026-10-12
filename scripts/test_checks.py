#!/usr/bin/env python3
"""Regression tests for check_license.py, the README, reference implementation,
specification claim, revocation schema, Sigstore co-signature, threat model,
signed timestamp, ATX status, fixture coverage, A2A agent card path and
Verifiable Credential form checks in validate_examples.py, check_guides.py, the
conformance scripts (run against fixture_authority.py; needs bash, curl and
jq), the registry generation and --check mode of gen_registries.py, and the
test-suite sentences of the .pre-push-review-not-required marker. Run:
python3 scripts/test_checks.py
"""
import contextlib
import copy
import io
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

    def test_repeated_claim_opening_is_scanned_in_linear_time(self):
        # The earlier pattern took about 8 s on this line and grew with the
        # square of its length.
        line = "Section 1.1 shows " * 11000 + "\n"
        started = time.perf_counter()
        self.assertEqual(validate_examples.example_claim_errors(line), [])
        self.assertLess(time.perf_counter() - started, 1.0)

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

    def test_open_entry_fails(self):
        errors = self.errors("sigstoreCoSignature", lambda entry: entry.pop("additionalProperties"))
        self.assertEqual(errors, ["a co-signature with a value beside its bundle is accepted"])

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
        errors = self.errors("sigstoreBundle", lambda bundle: self.log_entry(bundle).pop("minItems"))
        self.assertEqual(errors, ["a co-signature with no log entry is accepted"])

    def test_log_entry_without_inclusion_proof_fails(self):
        errors = self.errors(
            "sigstoreBundle",
            lambda bundle: self.log_entry(bundle)["items"]["required"].remove("inclusionProof"),
        )
        self.assertEqual(errors, ["a co-signature whose log entry has no inclusionProof is accepted"])

    def test_schema_requiring_integrated_time_fails(self):
        errors = self.errors(
            "sigstoreBundle",
            lambda bundle: self.log_entry(bundle)["items"]["required"].append("integratedTime"),
        )
        self.assertEqual(
            errors, ["a co-signature from a Rekor v2 log, timed by an RFC 3161 timestamp is refused"]
        )

    def test_schema_requiring_log_index_fails(self):
        errors = self.errors(
            "sigstoreBundle",
            lambda bundle: self.log_entry(bundle)["items"]["required"].append("logIndex"),
        )
        self.assertEqual(errors, ["a co-signature whose log entry has no logIndex is refused"])

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
        holds only `examples` (file name to text). Returns the exit code, the
        output lines and those of them that report a failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("README.md", "ATP-SPEC.md"):
                shutil.copy(ROOT / name, root / name)
            for directory in ("schemas", "registries"):
                shutil.copytree(ROOT / directory, root / directory)
            (root / "examples").mkdir()
            for name, text in examples.items():
                (root / "examples" / name).write_text(text, encoding="utf-8")
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

    def test_main_reports_two_missing_example_files_as_two_failures(self):
        code, lines, failed = self.main_in_tree({})
        self.assertEqual(code, 1)
        self.assertEqual(failed, [self.ATX_FAIL, self.FORM_FAIL])
        self.assertEqual(lines[-1], "2 failure(s)")

    def test_readme_claim_points_at_the_mapping(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        claims = [line for line in readme.splitlines() if "vc-data-model-2.0" in line]
        self.assertEqual(len(claims), 1)
        self.assertNotIn("structurally compatible", claims[0])
        self.assertIn("(#verifiable-credential-form)", claims[0])
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
    "Trust proof has at least one signature",
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


def pop(*names):
    return lambda body: [body.pop(name) for name in names]


def put(**members):
    return lambda body: body.update(members)


def first(member, edit):
    return lambda body: edit(body[member][0])


def inside(member, edit):
    return lambda body: edit(body[member])


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
        the host or port: no request is sent, and every test fails."""
        port = self.authority.server_address[1]
        for url in (f"http://127.0.0.[1-1]:{port}", f"http://127.0.0.{{1}}:{port}",
                    f"http://127.0.0.1:{{{port}}}"):
            with self.subTest(url):
                run, failed = self.run_scripts(url=url)
                self.assertEqual(failed, LEVEL1 + LEVEL2, run.stdout)
                self.assertEqual(run.returncode, len(LEVEL1 + LEVEL2), run.stdout)
                self.assertEqual(self.authority.requests, [])
                for name in (T1[1], T2[1], T2[3]):
                    self.assertIn(f"FAIL: {name} (the authority URL is not a valid URL)",
                                  run.stdout)

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
            text = (CONFORMANCE / script).read_text(encoding="utf-8")
            calls += re.findall(r"(?:^[ \t]*|\$\(|[;&|][ \t]*)curl[ \t]+([^\n]*)", text, re.M)
        self.assertTrue(calls)
        for call in calls:
            with self.subTest(call):
                options = call.split()
                self.assertTrue(
                    any(re.fullmatch(r"-[A-Za-z]*g[A-Za-z]*|--globoff", option)
                        for option in options)
                )
                for option in ("--path-as-is", "--connect-timeout", "--max-time"):
                    self.assertIn(option, options)

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
    """A missing tool or schema stops both scripts with exit code 69, which no
    count of failed tests reaches, before any test runs."""

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


# Written apart from the rfc3339 pattern in checks.jq (a full match, and the UTC
# offset bounded by number), so the agreement tests can catch a mistake in either.
RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)
DATE_TIME = FormatChecker(formats=())


@DATE_TIME.checks("date-time")
def is_date_time(value):
    if not isinstance(value, str):
        return True
    match = RFC3339.fullmatch(value)
    if not match:
        return False
    offset_hours, offset_minutes = match.group(2, 3)
    if offset_hours is not None and (int(offset_hours) > 23 or int(offset_minutes) > 59):
        return False
    try:
        datetime.fromisoformat(value[:10] + "T" + value[11:19])
    except ValueError:
        return False
    return True


@unittest.skipUnless(HAS_JQ, "checks.jq needs jq")
class SchemaCheckTest(unittest.TestCase):
    """checks.jq's schema_ok, which the scripts validate bodies with, agrees
    with a JSON Schema validator on the spec examples, on each edit that
    removes one of their members or replaces it with one of REPLACEMENTS, and
    on each example with one extra top-level member."""

    EXAMPLES = {
        "### 7.1 Well-Known Endpoint": "discovery-v1",
        "### 4.2 Trust Proof Format": "trust-proof-v1",
        "#### 4.3.1 Sigstore co-signature": "trust-proof-v1",
        "### 8.1 Trust Proof Revocation": "revocation-list-v1",
    }
    REPLACEMENTS = (
        None, True, -1, 1.5, "x", [], {},
        "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00Z\n", "2099-02-30T00:00:00Z",
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
    }
    SUPPORTED = {
        "type", "const", "enum", "anyOf", "pattern", "minLength", "format", "minimum",
        "maximum", "minItems", "items", "minProperties", "required", "properties",
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
        for key in ("items", "additionalProperties"):
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

    def test_schemas_use_only_keywords_checks_jq_implements(self):
        for name in self.EXAMPLES.values():
            with self.subTest(name):
                unknown = set(self.keywords(self.schema(name))) - self.SUPPORTED - self.ANNOTATIONS
                self.assertEqual(unknown, set())

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

    def test_stub_answers_a_since_timestamp_on_advisories_with_the_recorded_400(self):
        status, body = check_guides.answer(
            {}, "GET", "https://api.oa2a.org/api/v1/trust/advisories?since=2026-10-11T00:00:00Z", ""
        )
        self.assertEqual(status, 400)
        self.assertIn("YYYY-MM-DD", body)


class TestSuiteMarkerTest(unittest.TestCase):
    def setUp(self):
        self.marker = (ROOT / ".pre-push-review-not-required").read_text(encoding="utf-8")

    def test_marker_names_the_only_unit_test_suite(self):
        title = (ROOT / "conformance" / "README.md").read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("Test Suite", title)
        self.assertNotIn("The only test suite", self.marker)
        self.assertIn("The only unit test suite is scripts/test_checks.py", self.marker)

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
    """A file every check reads that is missing or not JSON is one failure
    line, and main() returns without running the checks that read it."""

    NOT_RUN = "the checks that read these files did not run"

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
                self.assertEqual(lines[-1], f"1 failure(s); {self.NOT_RUN}")

    def test_missing_document_is_one_failure_line(self):
        for name in ("README.md", "ATP-SPEC.md"):
            with self.subTest(name=name):
                code, lines, failed = self.run_main(lambda root, name=name: (root / name).unlink())
                self.assertEqual(code, 1)
                self.assertEqual(failed, [f"document FAIL  {name}: missing"], lines)
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
    """Section 7.1 ends the consumer fallback to the legacy discovery path at a
    release of the series the specification's header is on, and the changelog
    describes the rule as Section 7.1 states it."""

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
