"""Tests for atp_client.

Every conformance fixture in clients/fixtures must get the verdict and reject
category its expected block pins. The other tests sign proofs, tree heads and
trees with keys generated here and check each Section 4.4 step, the RFC 9162
proof algorithms and the client's requests against a local server.

Run from clients/python, with the package installed:
    python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import pathlib
import threading
import unittest
import urllib.parse
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

import atp_client as atp

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "fixtures"
AUTHORITY = "did:opena2a:authority:authority.example"
AGENT = "did:opena2a:agent:example-agent"
CLOCK = "2026-05-24T00:00:00Z"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def run_fixture(document: dict) -> atp.VerifyResult:
    state = document["verifierState"]
    keys, trusted = state["publicKeys"], state["trustedIssuers"]
    kind = document["fixtureType"]
    if kind == "trustProof":
        return atp.verify_trust_proof(document["trustProof"], keys, trusted, now=state["clockRfc3339"])
    if kind == "discovery":
        return atp.verify_discovery(document["discoveryResponse"], trusted)
    if kind == "sth":
        return atp.verify_signed_tree_head(document["signedTreeHead"], keys)
    if kind == "inclusionProof":
        return atp.verify_inclusion_proof(document["inclusionProof"], keys)
    if kind == "consistencyProof":
        return atp.verify_consistency_proof(document["consistencyProof"], keys)
    if kind == "revocationList":
        return atp.verify_revocation_list(document["revocationList"])
    raise AssertionError(f"unknown fixtureType {kind}")


class Signer:
    """A key generated for one test, with the Section 7.1 entry naming it."""

    def __init__(self, key_id: str = AUTHORITY + "#key-1", algorithm: str = "Ed25519") -> None:
        self.key_id = key_id
        self.algorithm = algorithm
        self.private = Ed25519PrivateKey.generate() if algorithm == "Ed25519" else MLDSA65PrivateKey.generate()

    def key(self, **members: str) -> dict:
        public = self.private.public_key().public_bytes_raw().hex()
        return {"keyId": self.key_id, "algorithm": self.algorithm, "publicKeyHex": public, **members}

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private.sign(message)).decode()

    def entry(self, message: bytes) -> dict:
        return {"keyId": self.key_id, "algorithm": self.algorithm, "value": self.sign(message)}


def signed_proof(*signers: Signer, canonical: str | None = None, **members) -> dict:
    """A trust proof about AGENT from AUTHORITY, with members replacing the
    defaults, signed by signers over its canonical string (or canonical)."""
    proof = {
        "did": AGENT,
        "trustLevel": 3,
        "trustScore": 0.5,
        "verdict": "passed",
        "issuedAt": "2026-05-23T12:00:00Z",
        "expiresAt": "2026-05-24T06:00:00Z",
        "issuerDid": AUTHORITY,
        "signatures": [],
        **members,
    }
    message = (canonical or atp.canonical_string(proof)).encode()
    proof["signatures"] = [signer.entry(message) for signer in signers]
    return proof


def flip_first_byte(text: str) -> str:
    raw = bytearray(base64.b64decode(text))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


class FixtureTests(unittest.TestCase):
    def test_fixture_bytes_match_the_suite_pins(self):
        lines = (FIXTURES / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()
        pins = dict(reversed(line.split("  fixtures/")) for line in lines)
        self.assertEqual(len(pins), 14)
        self.assertEqual(sorted(pins), sorted(path.name for path in FIXTURES.glob("*.json")))
        for name, digest in pins.items():
            with self.subTest(name):
                self.assertEqual(hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(), digest)

    def test_each_fixture_gets_its_pinned_verdict(self):
        paths = sorted(FIXTURES.glob("*.json"))
        self.assertEqual(len(paths), 14)
        for path in paths:
            document = json.loads(path.read_text(encoding="utf-8"))
            expected = document["expected"]
            with self.subTest(path.name):
                result = run_fixture(document)
                self.assertEqual(result.valid, expected["verifyResult"] == "ACCEPT", result)
                self.assertEqual(result.category, expected.get("rejectCategory"), result)
                self.assertIn(expected.get("reasonContains", ""), result.reason)

    def test_fixture_proofs_verify_under_the_discovery_fixture_keys(self):
        discovery = fixture("discovery-valid")["discoveryResponse"]
        client = atp.AtpClient("https://authority.example", discovery=discovery)
        for name in ("trust-proof-baseline", "trust-proof-hybrid"):
            proof = fixture(name)["trustProof"]
            with self.subTest(name):
                result = atp.verify_trust_proof(proof, discovery["publicKeys"], discovery["authorityDid"], now=CLOCK)
                self.assertTrue(result.valid, result)
                self.assertTrue(client.verify(proof, now=CLOCK).valid)

    def test_a_tampered_ml_dsa_signature_on_the_hybrid_fixture_is_rejected(self):
        document = fixture("trust-proof-hybrid")
        entry = document["trustProof"]["signatures"][1]
        self.assertEqual(entry["algorithm"], "ML-DSA-65")
        entry["value"] = flip_first_byte(entry["value"])
        result = run_fixture(document)
        self.assertEqual(result.category, "SIGNATURE_INVALID")
        self.assertIn("ML-DSA-65 signature", result.reason)


class CanonicalStringTests(unittest.TestCase):
    def test_baseline_fixture(self):
        self.assertEqual(
            atp.canonical_string(fixture("trust-proof-baseline")["trustProof"]),
            "did:opena2a:mcp_server:agent_conformance_test_001|3|0.825000|passed"
            "|2026-05-23T12:00:00Z|2026-05-24T06:00:00Z|did:opena2a:authority:opena2a.org",
        )

    def test_served_timestamps_reduce_to_whole_utc_seconds(self):
        # The table in Section 4.3.
        rows = {
            "2026-05-23T12:00:00Z": "2026-05-23T12:00:00Z",
            "2026-10-12T02:57:21.581346834Z": "2026-10-12T02:57:21Z",
            "2026-10-12T02:57:21.999Z": "2026-10-12T02:57:21Z",
            "2026-10-11T20:57:21.5-06:00": "2026-10-12T02:57:21Z",
        }
        base = fixture("trust-proof-baseline")["trustProof"]
        for served, signed in rows.items():
            with self.subTest(served):
                self.assertEqual(atp.canonical_string({**base, "issuedAt": served}).split("|")[4], signed)

    def test_trust_score_is_six_places_with_a_tie_to_even(self):
        base = fixture("trust-proof-baseline")["trustProof"]
        for score, written in ((0.0078125, "0.007812"), (0.0234375, "0.023438"), (1, "1.000000"), (0.825, "0.825000")):
            with self.subTest(score):
                self.assertEqual(atp.canonical_string({**base, "trustScore": score}).split("|")[2], written)

    def test_trust_level_with_a_zero_fraction_is_written_as_an_integer(self):
        base = fixture("trust-proof-baseline")["trustProof"]
        self.assertEqual(atp.canonical_string({**base, "trustLevel": 4.0}).split("|")[1], "4")

    def test_an_unreadable_proof_raises(self):
        with self.assertRaises(ValueError):
            atp.canonical_string({"did": AGENT})


class TrustProofTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer()
        self.keys = [self.signer.key(status="active")]

    def verify(self, proof, keys=None, trusted=AUTHORITY, now=CLOCK):
        return atp.verify_trust_proof(proof, self.keys if keys is None else keys, trusted, now=now)

    def assertRejected(self, result, category, reason=""):
        self.assertFalse(result.valid, result)
        self.assertEqual(result.category, category, result)
        self.assertIn(reason, result.reason)

    def test_a_proof_signed_by_a_trusted_key_verifies(self):
        self.assertEqual(self.verify(signed_proof(self.signer)), atp.VerifyResult(True))

    def test_step_1_a_proof_is_expired_at_its_expiry_instant(self):
        proof = signed_proof(self.signer)
        self.assertRejected(self.verify(proof, now="2026-05-24T06:00:00Z"), "EXPIRED", "expired")
        self.assertTrue(self.verify(proof, now="2026-05-24T05:59:59.999999Z").valid)
        self.assertTrue(self.verify(proof, now=datetime.fromisoformat("2026-05-24T05:59:00+00:00")).valid)

    def test_step_2_an_issuer_outside_the_trusted_set_is_rejected(self):
        result = self.verify(signed_proof(self.signer), trusted=["did:opena2a:authority:other.example"])
        self.assertRejected(result, "UNTRUSTED_ISSUER", AUTHORITY)

    def test_step_3_a_key_id_that_resolves_to_no_usable_key_is_rejected(self):
        proof = signed_proof(self.signer)
        cases = {
            "unknown keyId": [Signer(AUTHORITY + "#key-2").key()],
            "revoked key": [self.signer.key(status="revoked")],
            "key of another algorithm": [{**self.signer.key(), "algorithm": "ML-DSA-65"}],
            "key that is not 32 bytes": [{**self.signer.key(), "publicKeyHex": "ab" * 31}],
        }
        for label, keys in cases.items():
            with self.subTest(label):
                self.assertRejected(self.verify(proof, keys=keys), "SIGNATURE_INVALID", "does not resolve")

    def test_step_4_a_signature_over_other_bytes_is_rejected(self):
        proof = signed_proof(self.signer)
        proof["trustLevel"] = 4
        self.assertRejected(self.verify(proof), "SIGNATURE_INVALID", "did not verify")

    def test_step_4_needs_an_ed25519_signature_by_a_key_of_the_issuer(self):
        other = Signer("did:opena2a:authority:other.example#key-1")
        result = self.verify(signed_proof(other), keys=[other.key()])
        self.assertRejected(result, "SIGNATURE_INVALID", f"no Ed25519 signature by a key of {AUTHORITY}")

    def test_step_4_a_hybrid_proof_needs_both_signatures_to_verify(self):
        pqc = Signer(AUTHORITY + "#key-1-pqc", "ML-DSA-65")
        keys = [self.signer.key(), pqc.key()]
        proof = signed_proof(self.signer, pqc)
        self.assertTrue(self.verify(proof, keys=keys).valid)
        proof["signatures"][1]["value"] = flip_first_byte(proof["signatures"][1]["value"])
        self.assertRejected(self.verify(proof, keys=keys), "SIGNATURE_INVALID", "ML-DSA-65 signature")
        self.assertRejected(self.verify(signed_proof(pqc), keys=keys), "SIGNATURE_INVALID", "no Ed25519 signature")

    def test_step_4_a_sigstore_co_signature_is_rejected(self):
        proof = signed_proof(self.signer)
        proof["signatures"].append({"keyId": "https://ci.example/workflow", "algorithm": "Sigstore", "bundle": {}})
        self.assertRejected(self.verify(proof), "SIGNATURE_INVALID", "Sigstore")

    def test_step_5_semantic_rules(self):
        cases = {
            "trustLevel": {"trustLevel": 5},
            "trustScore": {"trustScore": 1.5},
            "verdict": {"verdict": "approved"},
            "issuedAt is not before": {"issuedAt": "2026-05-24T06:00:00Z"},
            "longer than 24 hours": {"issuedAt": "2026-05-23T05:59:59Z"},
        }
        for reason, members in cases.items():
            with self.subTest(reason):
                self.assertRejected(self.verify(signed_proof(self.signer, **members)), "SEMANTIC_INVALID", reason)

    def test_step_5_the_window_is_compared_to_the_microsecond(self):
        exactly = signed_proof(self.signer, issuedAt="2026-05-23T06:00:00Z", expiresAt="2026-05-24T06:00:00Z")
        self.assertTrue(self.verify(exactly).valid)
        # The canonical string drops the fraction, so the signature still
        # verifies; the served expiresAt is 24 hours and 1 microsecond after.
        longer = signed_proof(self.signer, issuedAt="2026-05-23T06:00:00Z", expiresAt="2026-05-24T06:00:00.000001Z")
        self.assertRejected(self.verify(longer), "SEMANTIC_INVALID", "longer than 24 hours")

    def test_served_fractions_and_offsets_verify_against_the_whole_second_string(self):
        canonical = f"{AGENT}|3|0.500000|passed|2026-10-12T02:57:21Z|2026-10-12T20:57:21Z|{AUTHORITY}"
        proof = signed_proof(
            self.signer,
            canonical=canonical,
            issuedAt="2026-10-11T20:57:21.5-06:00",
            expiresAt="2026-10-12T20:57:21.581346834Z",
        )
        self.assertTrue(self.verify(proof, now="2026-10-12T12:00:00Z").valid)

    def test_members_that_cannot_be_read_are_parse_errors(self):
        cases = {
            "trustLevel as a string": {"trustLevel": "3"},
            "trustLevel as true": {"trustLevel": True},
            "trustScore as null": {"trustScore": None},
            "lower-case t": {"issuedAt": "2026-05-23t12:00:00Z"},
            "a space for T": {"issuedAt": "2026-05-23 12:00:00Z"},
            "no zone": {"issuedAt": "2026-05-23T12:00:00"},
            "February 30": {"issuedAt": "2026-02-30T12:00:00Z"},
            "second 60": {"issuedAt": "2026-05-23T12:00:60Z"},
            "hour 24": {"expiresAt": "2026-05-24T24:00:00Z"},
            "offset hour 24": {"expiresAt": "2026-05-24T06:00:00+24:00"},
            "year 0": {"issuedAt": "0000-05-23T12:00:00Z"},
            "negative log index": {"transparencyLogIndex": -1},
        }
        for label, members in cases.items():
            with self.subTest(label):
                proof = {**signed_proof(self.signer), **members}
                self.assertEqual(self.verify(proof).category, "PARSE_ERROR")
        self.assertEqual(self.verify({**signed_proof(self.signer), "signatures": []}).category, "PARSE_ERROR")
        self.assertEqual(self.verify([]).category, "PARSE_ERROR")

    def test_a_clock_that_cannot_be_read_raises(self):
        proof = signed_proof(self.signer)
        for now in ("yesterday", datetime(2026, 5, 24)):
            with self.subTest(repr(now)), self.assertRaises(ValueError):
                self.verify(proof, now=now)


class Tree:
    """A log of leaves hashed as RFC 6962 Section 2.1 defines, with PATH and
    PROOF built from its recursive definitions."""

    def __init__(self, size: int) -> None:
        self.leaves = [hashlib.sha256(b"\x00" + f"entry {i}".encode()).digest() for i in range(size)]

    @staticmethod
    def split(n: int) -> int:
        k = 1
        while k * 2 < n:
            k *= 2
        return k

    def root(self, leaves=None) -> bytes:
        leaves = self.leaves if leaves is None else leaves
        if len(leaves) == 1:
            return leaves[0]
        k = self.split(len(leaves))
        return hashlib.sha256(b"\x01" + self.root(leaves[:k]) + self.root(leaves[k:])).digest()

    def path(self, m: int, leaves=None) -> list[bytes]:
        leaves = self.leaves if leaves is None else leaves
        if len(leaves) == 1:
            return []
        k = self.split(len(leaves))
        if m < k:
            return self.path(m, leaves[:k]) + [self.root(leaves[k:])]
        return self.path(m - k, leaves[k:]) + [self.root(leaves[:k])]

    def proof(self, m: int, leaves=None, whole: bool = True) -> list[bytes]:
        leaves = self.leaves if leaves is None else leaves
        if m == len(leaves):
            return [] if whole else [self.root(leaves)]
        k = self.split(len(leaves))
        if m <= k:
            return self.proof(m, leaves[:k], whole) + [self.root(leaves[k:])]
        return self.proof(m - k, leaves[k:], False) + [self.root(leaves[:k])]


def wire(digest: bytes) -> str:
    return "SHA256:" + digest.hex()


def altered(wire_hash: str) -> str:
    raw = bytearray(bytes.fromhex(wire_hash[len("SHA256:"):]))
    raw[0] ^= 0xFF
    return wire(bytes(raw))


class TransparencyTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer()
        self.keys = [self.signer.key()]

    def head(self, tree: Tree) -> dict:
        root = tree.root()
        return {
            "treeSize": len(tree.leaves),
            "timestamp": "2026-05-23T00:00:00Z",
            "rootHash": wire(root),
            "signedBy": self.signer.key_id,
            "signature": self.signer.sign(root),
        }

    def test_an_inclusion_proof_for_every_leaf_of_trees_up_to_17_leaves(self):
        for size in range(1, 18):
            tree = Tree(size)
            head = self.head(tree)
            for index in range(size):
                path = [wire(node) for node in tree.path(index)]
                proof = {"logIndex": index, "leafHash": wire(tree.leaves[index]), "auditPath": path, "signedTreeHead": head}
                with self.subTest(size=size, index=index):
                    self.assertTrue(atp.verify_inclusion_proof(proof, self.keys).valid)
                    for position in range(len(path)):
                        changed = path[:position] + [altered(path[position])] + path[position + 1 :]
                        result = atp.verify_inclusion_proof({**proof, "auditPath": changed}, self.keys)
                        self.assertEqual(result.category, "PROOF_INVALID")
                    extended = {**proof, "auditPath": path + [wire(bytes(32))]}
                    self.assertEqual(atp.verify_inclusion_proof(extended, self.keys).category, "PROOF_INVALID")

    def test_a_consistency_proof_between_every_pair_of_sizes_up_to_17(self):
        for second in range(2, 18):
            later = Tree(second)
            for first in range(1, second):
                earlier = Tree(first)
                path = [wire(node) for node in later.proof(first)]
                proof = {
                    "fromSize": first,
                    "toSize": second,
                    "consistencyPath": path,
                    "fromSignedTreeHead": self.head(earlier),
                    "toSignedTreeHead": self.head(later),
                }
                with self.subTest(first=first, second=second):
                    self.assertTrue(atp.verify_consistency_proof(proof, self.keys).valid)
                    for position in range(len(path)):
                        changed = path[:position] + [altered(path[position])] + path[position + 1 :]
                        result = atp.verify_consistency_proof({**proof, "consistencyPath": changed}, self.keys)
                        self.assertEqual(result.category, "PROOF_INVALID")

    def test_a_tree_head_the_keys_do_not_sign_is_rejected(self):
        head = self.head(Tree(8))
        self.assertEqual(atp.verify_signed_tree_head(head, [Signer().key()]).category, "SIGNATURE_INVALID")
        self.assertEqual(atp.verify_signed_tree_head({**head, "signedBy": AUTHORITY + "#key-9"}, self.keys).category, "SIGNATURE_INVALID")
        self.assertEqual(atp.verify_signed_tree_head({**head, "rootHash": wire(bytes(32))}, self.keys).category, "SIGNATURE_INVALID")

    def test_members_outside_their_form_are_parse_errors(self):
        tree = Tree(4)
        head = self.head(tree)
        proof = {"logIndex": 4, "leafHash": wire(tree.leaves[0]), "auditPath": [], "signedTreeHead": head}
        self.assertEqual(atp.verify_inclusion_proof(proof, self.keys).category, "PARSE_ERROR")
        self.assertEqual(atp.verify_signed_tree_head({**head, "rootHash": head["rootHash"].upper()}, self.keys).category, "PARSE_ERROR")
        consistency = {
            "fromSize": 4,
            "toSize": 4,
            "consistencyPath": [],
            "fromSignedTreeHead": head,
            "toSignedTreeHead": head,
        }
        self.assertEqual(atp.verify_consistency_proof(consistency, self.keys).category, "PARSE_ERROR")


class RevocationTests(unittest.TestCase):
    ENTRY = {
        "agentDid": "did:opena2a:mcp_server:compromised-package",
        "revokedAt": "2026-03-22T15:00:00Z",
        "reason": "security_incident",
        "revokedByKeyId": AUTHORITY + "#key-1",
    }

    def check(self, *entries, next_since="2026-03-22T15:00:00Z"):
        return atp.verify_revocation_list({"revocations": list(entries), "nextSince": next_since})

    def test_entries_section_8_1_tells_a_client_to_apply_are_accepted(self):
        self.assertTrue(self.check().valid)
        self.assertTrue(self.check(self.ENTRY).valid, "an entry without transparencyLogIndex")
        self.assertTrue(self.check({**self.ENTRY, "reason": "x-operator_flag"}).valid)
        self.assertTrue(self.check({**self.ENTRY, "reason": "Supply chain compromise detected"}).valid)
        self.assertTrue(self.check({**self.ENTRY, "revokedAt": "2026-03-22T09:00:00-06:00"}).valid)

    def test_a_malformed_member_rejects_the_whole_response(self):
        reason_missing = {key: value for key, value in self.ENTRY.items() if key != "reason"}
        self.assertEqual(self.check(self.ENTRY, reason_missing).category, "PARSE_ERROR")
        self.assertEqual(self.check(self.ENTRY, next_since="2026-03-22").category, "PARSE_ERROR")
        self.assertEqual(self.check({**self.ENTRY, "transparencyLogIndex": "7"}).category, "PARSE_ERROR")
        self.assertEqual(atp.verify_revocation_list({"nextSince": "2026-03-22T15:00:00Z"}).category, "PARSE_ERROR")


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.document = fixture("discovery-valid")["discoveryResponse"]

    def test_a_key_without_publickeyhex_is_named(self):
        key = {k: v for k, v in self.document["publicKeys"][0].items() if k != "publicKeyHex"}
        result = atp.verify_discovery({**self.document, "publicKeys": [key]})
        self.assertEqual(result.category, "PARSE_ERROR")
        self.assertIn("publicKeys[0].publicKeyHex", result.reason)

    def test_other_malformed_documents(self):
        cases = {
            "version": {"version": "2.0"},
            "conformanceLevel": {"conformanceLevel": 4},
            "endpoints": {"endpoints": {}},
            "publicKeys": {"publicKeys": []},
        }
        for reason, members in cases.items():
            with self.subTest(reason):
                result = atp.verify_discovery({**self.document, **members})
                self.assertEqual(result.category, "PARSE_ERROR")
                self.assertIn(reason, result.reason)

    def test_an_authority_outside_the_trusted_set_is_rejected(self):
        result = atp.verify_discovery(self.document, ["did:opena2a:authority:partner.example"])
        self.assertEqual(result.category, "UNTRUSTED_ISSUER")


class Authority(http.server.BaseHTTPRequestHandler):
    """Answers each path from the server's routes: a (status, body) pair, or
    (status, None, headers) for an answer without a body."""

    def do_GET(self):
        self.server.requests.append(self.path)
        route = self.server.routes.get(urllib.parse.urlsplit(self.path).path, (404, {"error": "not found"}))
        status, body, headers = (route + ({},))[:3]
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        payload = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Authority)
        self.server.routes, self.server.requests = {}, []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.client = atp.AtpClient(f"http://127.0.0.1:{self.server.server_address[1]}/", timeout=5)
        self.signer = Signer()
        self.discovery = {
            "authorityDid": AUTHORITY,
            "version": "1.0",
            "endpoints": {"trustProof": "/api/v1/trust/proof"},
            "publicKeys": [self.signer.key(status="active", validFrom="2026-01-01T00:00:00Z")],
        }

    def test_get_trust_proof_unwraps_the_proof_and_verify_checks_it_offline(self):
        proof = signed_proof(self.signer, did="did:opena2a:mcp_server:@scope/server name")
        self.server.routes = {
            "/.well-known/atp": (200, self.discovery),
            "/api/v1/trust/proof": (200, {"algorithm": "ed25519", "proof": proof}),
        }
        self.assertEqual(self.client.get_trust_proof(proof["did"]), proof)
        sent = self.server.requests[-1]
        self.assertIn("did=did%3Aopena2a%3Amcp_server%3A%40scope%2Fserver%20name", sent)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(sent).query)["did"], [proof["did"]])
        self.assertTrue(self.client.verify(proof, now=CLOCK).valid)
        self.assertEqual(self.server.requests.count("/.well-known/atp"), 1)
        self.assertTrue(self.client.verify(proof, now=CLOCK).valid)
        self.assertEqual(self.server.requests.count("/.well-known/atp"), 1, "the discovery document is kept")

    def test_get_trust_proof_reads_a_proof_served_at_the_top_level(self):
        proof = signed_proof(self.signer)
        self.server.routes = {"/api/v1/trust/proof": (200, proof)}
        self.assertEqual(self.client.get_trust_proof(AGENT), proof)

    def test_a_proof_about_another_did_raises(self):
        self.server.routes = {"/api/v1/trust/proof": (200, {"proof": signed_proof(self.signer)})}
        with self.assertRaisesRegex(atp.AtpError, "did not answer with a trust proof"):
            self.client.get_trust_proof("did:opena2a:agent:another-agent")

    def test_discovery_falls_back_to_the_legacy_path_on_404(self):
        self.server.routes = {"/.well-known/opena2a": (200, self.discovery)}
        self.assertEqual(self.client.get_discovery(), self.discovery)
        self.assertEqual(self.server.requests, ["/.well-known/atp", "/.well-known/opena2a"])

    def test_error_answers_raise_with_their_status(self):
        self.server.routes = {"/.well-known/atp": (500, {"error": "unavailable"}), "/api/v1/trust/proof": (200, b"<html>")}
        with self.assertRaises(atp.AtpError) as raised:
            self.client.get_discovery()
        self.assertEqual(raised.exception.status, 500)
        with self.assertRaisesRegex(atp.AtpError, "did not answer with JSON"):
            self.client.get_trust_proof(AGENT)
        self.server.routes = {}
        with self.assertRaises(atp.AtpError) as raised:
            self.client.get_trust_proof(AGENT)
        self.assertEqual(raised.exception.status, 404)

    def test_a_redirect_is_not_followed(self):
        self.server.routes = {"/.well-known/atp": (302, None, {"Location": "/elsewhere"}), "/elsewhere": (200, self.discovery)}
        with self.assertRaisesRegex(atp.AtpError, "redirects are not followed"):
            self.client.get_discovery()
        self.assertNotIn("/elsewhere", self.server.requests)

    def test_verify_names_a_discovery_document_it_cannot_use(self):
        key = {"keyId": AUTHORITY + "#key-v1", "version": 1, "algorithm": "Ed25519", "publicKey": "c2hvcnQ="}
        self.server.routes = {"/.well-known/atp": (200, {**self.discovery, "publicKeys": [key]})}
        result = self.client.verify(signed_proof(self.signer), now=CLOCK)
        self.assertEqual(result.category, "PARSE_ERROR")
        self.assertIn("discovery document: publicKeys[0].publicKeyHex", result.reason)

    def test_a_base_url_that_is_not_http_raises(self):
        for url in ("ftp://authority.example", "authority.example", "https://authority.example/?a=1"):
            with self.subTest(url), self.assertRaises(ValueError):
                atp.AtpClient(url)


if __name__ == "__main__":
    unittest.main()
