#!/usr/bin/env python3
"""Regression tests for check_license.py, the README, reference implementation,
specification claim, revocation schema, ATX status and fixture coverage checks
in validate_examples.py, the conformance scripts (run against
fixture_authority.py; needs bash, curl and jq), the registry generation and
--check mode of gen_registries.py, and the test-suite sentences of the
.pre-push-review-not-required marker. Run: python3 scripts/test_checks.py
"""
import contextlib
import copy
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

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
        longer = "See https://github.com/opena2a-org/opena2a-registry-web.\n"
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


CONFORMANCE = ROOT / "conformance"
HAS_JQ = shutil.which("jq") is not None
HAS_SCRIPT_TOOLS = HAS_JQ and all(shutil.which(tool) for tool in ("bash", "curl"))
LEVEL1 = [
    "Discovery endpoint returns JSON",
    "Discovery has authorityDid, version, endpoints",
    "Conformance level >= 1",
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


def pop(*names):
    return lambda body: [body.pop(name) for name in names]


def put(**members):
    return lambda body: body.update(members)


def first(member, edit):
    return lambda body: edit(body[member][0])


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

    def run_scripts(self, **overrides):
        self.authority.overrides = overrides
        run = subprocess.run(
            ["bash", str(CONFORMANCE / "level2.sh"), self.authority.url],
            capture_output=True,
            text=True,
            timeout=120,
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
            ("no conformanceLevel", [T1[3]], {"discovery": pop("conformanceLevel")}),
            ("string conformanceLevel", [T1[3]], {"discovery": put(conformanceLevel="3")}),
        ])

    def test_did_document_probes(self):
        self.probes([
            ("no @context", [T1[5]], {"did": pop("@context")}),
            ("string verificationMethod", [T1[6]], {"did": put(verificationMethod="key-1")}),
            ("not found", [T1[4], T1[5], T1[6]], {"did": 404}),
        ])

    def test_trust_proof_probes(self):
        self.probes([
            ("no did", [T1[7], T1[8]], {"proof": pop("did")}),
            ("another agent's did", [T1[7]], {"proof": put(did="did:opena2a:agent:other")}),
            ("no verdict", [T1[8]], {"proof": pop("verdict")}),
            ("unknown verdict", [T1[8]], {"proof": put(verdict="trusted")}),
            ("no issuedAt", [T1[8]], {"proof": pop("issuedAt")}),
            ("no trustLevel", [T1[8], T1[11]], {"proof": pop("trustLevel")}),
            ("fractional trustLevel", [T1[8], T1[11]], {"proof": put(trustLevel=2.5)}),
            ("string trustLevel", [T1[8], T1[11]], {"proof": put(trustLevel="3")}),
            ("trustLevel 5", [T1[8], T1[11]], {"proof": put(trustLevel=5)}),
            ("string trustScore", [T1[8], T1[12]], {"proof": put(trustScore="0.5")}),
            ("expiresAt never", [T1[8], T1[10]], {"proof": put(expiresAt="never")}),
            ("expired, written at +05:00", [T1[10]], {"proof": put(expiresAt=at_offset(-1, 5))}),
            ("unexpired, written at -05:00", [], {"proof": put(expiresAt=at_offset(1, -5))}),
            ("string signatures", [T1[9]], {"proof": put(signatures="FAKE")}),
            ("no signatures", [T1[9]], {"proof": put(signatures=[])}),
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
        ])


RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$")
DATE_TIME = FormatChecker(formats=())


@DATE_TIME.checks("date-time")
def is_date_time(value):
    if not isinstance(value, str):
        return True
    if not RFC3339.match(value):
        return False
    try:
        datetime.fromisoformat(value[:10] + "T" + value[11:19])
    except ValueError:
        return False
    return True


@unittest.skipUnless(HAS_JQ, "checks.jq needs jq")
class SchemaCheckTest(unittest.TestCase):
    """checks.jq's schema_ok, which the scripts validate bodies with, agrees
    with a JSON Schema validator on the spec examples and on every edit that
    removes or replaces one of their members."""

    EXAMPLES = {
        "### 7.1 Well-Known Endpoint": "discovery-v1",
        "### 4.2 Trust Proof Format": "trust-proof-v1",
        "### 8.1 Trust Proof Revocation": "revocation-list-v1",
    }
    REPLACEMENTS = (None, True, -1, 1.5, "x", [], {})
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
        files = self.files()
        files["readme"] += (
            "\nThe conformance suite pins the Section 8.1 body\n"
            "(`fixtures/revocation-list-valid.json`) and the malformed-timestamp rejection.\n"
        )
        line = len(files["readme"].splitlines()) - 1
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


if __name__ == "__main__":
    unittest.main()
