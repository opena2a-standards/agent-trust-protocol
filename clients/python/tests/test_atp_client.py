"""Tests for atp_client.

Every conformance fixture in clients/fixtures must get the verdict and reject
category its expected block pins. The other tests sign proofs, tree heads and
trees with keys generated here and check each Section 4.4 step, the RFC 9162
proof algorithms and the client's requests against a local server. Step 7 is
also checked on the Section 4.4.1 proof of ATP-SPEC.md, with the keys of its
table.

Run from clients/python, with the package installed:
    python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import ipaddress
import json
import math
import os
import pathlib
import ssl
import tempfile
import threading
import time
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import atp_client as atp

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "fixtures"
SPEC = pathlib.Path(__file__).resolve().parents[3] / "ATP-SPEC.md"
AUTHORITY = "did:opena2a:authority:authority.example"
COSIGNER = "did:opena2a:authority:cosigner.example"
AGENT = "did:opena2a:agent:example-agent"
CLOCK = "2026-05-24T00:00:00Z"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def two_authority_proof() -> tuple[dict, list[dict]]:
    """The Section 4.4.1 proof of ATP-SPEC.md, and the rows of its key table
    as Section 7.1 publicKeys entries, in table order."""
    text = SPEC.read_text(encoding="utf-8")
    section = text[text.index("\n#### 4.4.1 Two-authority proof (Level 3)\n") :]
    section = section[: section.index("\n### ")]
    keys = []
    for line in section.splitlines():
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) == 3 and cells[1].startswith("did:"):
            keys.append({"keyId": cells[1], "algorithm": "Ed25519", "publicKeyHex": cells[2]})
    start = section.index("```json\n") + len("```json\n")
    return json.loads(section[start : section.index("\n```", start)]), keys


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

    def test_a_member_that_utf8_cannot_encode_is_a_parse_error(self):
        # json.loads reads the escape \ud800 as a lone surrogate, for which
        # str.encode("utf-8") raises.
        served = json.loads('"did:opena2a:agent:x\\ud800"')
        self.assertRaises(UnicodeEncodeError, served.encode, "utf-8")
        signed = signed_proof(self.signer)
        cases = {"did": served, "verdict": "passed\udc00", "issuerDid": AUTHORITY + "\ud800"}
        for name, value in cases.items():
            with self.subTest(name):
                reason = f"{name} holds a lone surrogate, which UTF-8 cannot encode"
                self.assertEqual(self.verify({**signed, name: value}), atp.VerifyResult(False, "PARSE_ERROR", reason))
                with self.assertRaisesRegex(ValueError, reason):
                    atp.canonical_string({**signed, name: value})
        discovery = {
            "authorityDid": AUTHORITY,
            "version": "1.0",
            "endpoints": {"trustProof": "/api/v1/trust/proof"},
            "publicKeys": [self.signer.key(status="active", validFrom="2026-01-01T00:00:00Z")],
        }
        client = atp.AtpClient("https://authority.example", discovery=discovery)
        self.assertRejected(client.verify({**signed, "did": served}, now=CLOCK), "PARSE_ERROR", "did holds a lone surrogate")

    def test_a_clock_that_cannot_be_read_raises(self):
        proof = signed_proof(self.signer)
        for now in ("yesterday", datetime(2026, 5, 24)):
            with self.subTest(repr(now)), self.assertRaises(ValueError):
                self.verify(proof, now=now)


class SecondAuthorityTests(unittest.TestCase):
    """Section 4.4 step 7, which verify_trust_proof applies when it is given
    second_authorities: a proof at trust level 3 or 4 needs an Ed25519
    signature by a second authority the verifier knows, one that shares no
    public key with the issuer."""

    NONE_SIGNED = "no Ed25519 signature by a second authority verified (step 7)"
    SHARES = f"{COSIGNER} shares a public key with {AUTHORITY}"

    def setUp(self):
        self.issuer = Signer()
        self.cosigner = Signer(COSIGNER + "#key-1")
        self.keys = [self.issuer.key(status="active")]
        self.second = {COSIGNER: [self.cosigner.key(status="active")]}

    def verify(self, proof, keys=None, second=None, now=CLOCK):
        return atp.verify_trust_proof(
            proof,
            self.keys if keys is None else keys,
            AUTHORITY,
            now=now,
            second_authorities=self.second if second is None else second,
        )

    def assertRejected(self, result, category, reason):
        self.assertFalse(result.valid, result)
        self.assertEqual(result.category, category, result)
        self.assertIn(reason, result.reason)

    def test_a_proof_a_second_authority_co_signs_verifies_at_levels_3_and_4(self):
        for level in (3, 4):
            with self.subTest(level=level):
                proof = signed_proof(self.issuer, self.cosigner, trustLevel=level)
                self.assertEqual(self.verify(proof), atp.VerifyResult(True))

    def test_a_proof_the_issuer_alone_signs_fails_step_7_at_levels_3_and_4_only(self):
        for level in (0, 1, 2):
            with self.subTest(level=level):
                self.assertTrue(self.verify(signed_proof(self.issuer, trustLevel=level)).valid)
        for level in (3, 4):
            with self.subTest(level=level):
                result = self.verify(signed_proof(self.issuer, trustLevel=level))
                self.assertRejected(result, "SIGNATURE_INVALID", self.NONE_SIGNED)
                self.assertIn(f"trustLevel {level} needs one", result.reason)

    def test_without_second_authorities_step_7_is_not_checked(self):
        self.assertTrue(atp.verify_trust_proof(signed_proof(self.issuer), self.keys, AUTHORITY, now=CLOCK).valid)
        keys = self.keys + self.second[COSIGNER]
        cosigned = signed_proof(self.issuer, self.cosigner)
        self.assertTrue(atp.verify_trust_proof(cosigned, keys, AUTHORITY, now=CLOCK).valid)

    def test_a_signer_outside_second_authorities_is_not_a_second_authority(self):
        # Its key is among keys, as the issuer's discovery document could list
        # it; step 7 counts only an authority the verifier names itself.
        other = Signer("did:opena2a:authority:other.example#key-1")
        result = self.verify(signed_proof(self.issuer, other), keys=self.keys + [other.key()])
        self.assertRejected(result, "SIGNATURE_INVALID", self.NONE_SIGNED)
        keys = self.keys + self.second[COSIGNER]
        result = self.verify(signed_proof(self.issuer, self.cosigner), keys=keys, second={})
        self.assertRejected(result, "SIGNATURE_INVALID", self.NONE_SIGNED)

    def test_the_issuer_is_one_authority_however_many_entries_or_keys_it_signs_with(self):
        second_key = Signer(AUTHORITY + "#key-2")
        cases = {
            "its entry twice": (signed_proof(self.issuer, self.issuer), self.keys, self.second),
            "a second key of its own": (
                signed_proof(self.issuer, second_key),
                self.keys + [second_key.key()],
                self.second,
            ),
            "named in second_authorities": (signed_proof(self.issuer, self.issuer), self.keys, {AUTHORITY: self.keys}),
        }
        for label, (proof, keys, second) in cases.items():
            with self.subTest(label):
                self.assertRejected(self.verify(proof, keys=keys, second=second), "SIGNATURE_INVALID", self.NONE_SIGNED)

    def test_an_authority_that_shares_a_key_with_the_issuer_is_not_distinct(self):
        proof = signed_proof(self.issuer, self.cosigner)
        issuer_key, cosigner_key = self.issuer.key(), self.cosigner.key()
        as_cosigner = {**issuer_key, "keyId": COSIGNER + "#key-2"}
        cases = {
            "the co-signer's key is also a key of the issuer": (
                self.keys + [{**cosigner_key, "keyId": AUTHORITY + "#key-2"}],
                self.second,
            ),
            "the issuer's key is also a key of the co-signer": (
                self.keys,
                {COSIGNER: self.second[COSIGNER] + [as_cosigner]},
            ),
            "the same key in upper-case hex": (
                self.keys,
                {COSIGNER: self.second[COSIGNER] + [{**as_cosigner, "publicKeyHex": as_cosigner["publicKeyHex"].upper()}]},
            ),
            "the same key revoked": (
                self.keys,
                {COSIGNER: self.second[COSIGNER] + [{**as_cosigner, "status": "revoked"}]},
            ),
        }
        for label, (keys, second) in cases.items():
            with self.subTest(label):
                result = self.verify(proof, keys=keys, second=second)
                self.assertRejected(result, "SIGNATURE_INVALID", f"no second authority distinct from {AUTHORITY} signed (step 7)")
                self.assertIn(self.SHARES, result.reason)
        # One key under two DIDs: the issuer's key signs as the co-signer too.
        same = Signer(COSIGNER + "#key-1")
        same.private = self.issuer.private
        result = self.verify(signed_proof(self.issuer, same), second={COSIGNER: [same.key()]})
        self.assertRejected(result, "SIGNATURE_INVALID", self.SHARES)

    def test_a_second_authority_signature_resolves_among_its_own_keys_alone(self):
        # The issuer lists, under the co-signer's keyId, a key it holds itself.
        forged = Signer(COSIGNER + "#key-1")
        result = self.verify(signed_proof(self.issuer, forged), keys=self.keys + [forged.key()])
        self.assertRejected(result, "SIGNATURE_INVALID", f"signature of {COSIGNER}#key-1 did not verify")
        unlisted = Signer(COSIGNER + "#key-2")
        result = self.verify(signed_proof(self.issuer, unlisted), keys=self.keys + [unlisted.key()])
        self.assertRejected(result, "SIGNATURE_INVALID", f"keyId {COSIGNER}#key-2 does not resolve")

    def test_only_an_ed25519_signature_of_the_second_authority_counts(self):
        issuer_pqc = Signer(AUTHORITY + "#key-1-pqc", "ML-DSA-65")
        result = self.verify(signed_proof(self.issuer, issuer_pqc), keys=self.keys + [issuer_pqc.key()])
        self.assertRejected(result, "SIGNATURE_INVALID", self.NONE_SIGNED)
        cosigner_pqc = Signer(COSIGNER + "#key-1-pqc", "ML-DSA-65")
        second = {COSIGNER: [self.cosigner.key(), cosigner_pqc.key()]}
        result = self.verify(signed_proof(self.issuer, cosigner_pqc), second=second)
        self.assertRejected(result, "SIGNATURE_INVALID", self.NONE_SIGNED)
        self.assertTrue(self.verify(signed_proof(self.issuer, self.cosigner, cosigner_pqc), second=second).valid)

    def test_a_second_authority_entry_is_held_to_steps_3_and_4(self):
        proof = signed_proof(self.issuer, self.cosigner)
        proof["signatures"][1]["value"] = flip_first_byte(proof["signatures"][1]["value"])
        self.assertRejected(self.verify(proof), "SIGNATURE_INVALID", "did not verify")
        revoked = {COSIGNER: [self.cosigner.key(status="revoked")]}
        result = self.verify(signed_proof(self.issuer, self.cosigner), second=revoked)
        self.assertRejected(result, "SIGNATURE_INVALID", "does not resolve")

    def test_atp_client_verify_checks_against_one_authority(self):
        key = self.issuer.key(status="active", validFrom="2026-01-01T00:00:00Z")
        discovery = {"authorityDid": AUTHORITY, "version": "1.0", "endpoints": {"trustProof": "/t"}, "publicKeys": [key]}
        client = atp.AtpClient("https://authority.example", discovery=discovery)
        self.assertTrue(client.verify(signed_proof(self.issuer), now=CLOCK).valid)
        result = client.verify(signed_proof(self.issuer, self.cosigner), now=CLOCK)
        self.assertRejected(result, "SIGNATURE_INVALID", f"keyId {COSIGNER}#key-1 does not resolve")

    def test_steps_1_to_5_come_before_step_7(self):
        self.assertRejected(self.verify(signed_proof(self.issuer), now="2026-05-24T06:00:00Z"), "EXPIRED", "expired")
        longer = signed_proof(self.issuer, issuedAt="2026-05-23T05:59:59Z")
        self.assertRejected(self.verify(longer), "SEMANTIC_INVALID", "longer than 24 hours")

    def test_the_section_4_4_1_proof_passes_step_7_under_the_keys_of_its_table(self):
        proof, (issuer_key, cosigner_key) = two_authority_proof()
        issuer = proof["issuerDid"]
        second = {cosigner_key["keyId"].partition("#")[0]: [cosigner_key]}
        result = atp.verify_trust_proof(proof, [issuer_key], issuer, now=CLOCK, second_authorities=second)
        self.assertEqual(result, atp.VerifyResult(True))
        # Without the co-signer's entry it is the baseline fixture's proof, which
        # the suite pins ACCEPT for a verifier that does not apply step 7.
        alone = {**proof, "signatures": proof["signatures"][:1]}
        self.assertEqual(alone, fixture("trust-proof-baseline")["trustProof"])
        self.assertTrue(atp.verify_trust_proof(alone, [issuer_key], issuer, now=CLOCK).valid)
        result = atp.verify_trust_proof(alone, [issuer_key], issuer, now=CLOCK, second_authorities=second)
        self.assertRejected(result, "SIGNATURE_INVALID", self.NONE_SIGNED)


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

    def test_a_key_algorithm_that_is_an_array_or_an_object_is_refused(self):
        reason = "publicKeys[0].algorithm is not Ed25519 or ML-DSA-65"
        for algorithm in ([], {}, ["Ed25519"], {"name": "Ed25519"}):
            with self.subTest(algorithm=algorithm):
                key = {**self.document["publicKeys"][0], "algorithm": algorithm}
                document = {**self.document, "publicKeys": [key]}
                self.assertEqual(atp.verify_discovery(document), atp.VerifyResult(False, "PARSE_ERROR", reason))
                client = atp.AtpClient("https://authority.example", discovery=document)
                self.assertEqual(client.verify({}), atp.VerifyResult(False, "PARSE_ERROR", f"discovery document: {reason}"))

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

    def check(self, value, name="trustProof"):
        """verify_discovery on the document with endpoints[name] set to value."""
        endpoints = {**self.document["endpoints"], name: value}
        return atp.verify_discovery({**self.document, "endpoints": endpoints})

    def assert_refused(self, value, reason):
        result = self.check(value)
        self.assertFalse(result.valid)
        self.assertEqual(result.category, "PARSE_ERROR")
        self.assertEqual(result.reason, f"endpoints.trustProof {reason}")

    def test_an_endpoint_value_without_a_leading_slash_is_refused(self):
        # Section 7.1: appended to https://api.oa2a.org, the first runs into
        # the host name, the second extends it and the third replaces it.
        for value in ("api/v1/trust/proof", ".attacker.example/x", "@attacker.example/x", ""):
            with self.subTest(value=value):
                self.assert_refused(value, "does not start with /")

    def test_an_endpoint_value_with_a_fragment_is_refused(self):
        self.assert_refused("/a#b", "holds #, whitespace or a control character")

    def test_an_endpoint_value_with_whitespace_is_refused(self):
        for value in ("/a b", "/a\tb", "/a\nb", "/a b", "/a　b"):
            with self.subTest(value=value):
                self.assert_refused(value, "holds #, whitespace or a control character")

    def test_an_endpoint_value_with_a_control_character_is_refused(self):
        for value in ("/a\x00b", "/a\x01b", "/a\x7fb", "/a\x9fb"):
            with self.subTest(value=value):
                self.assert_refused(value, "holds #, whitespace or a control character")

    def test_an_endpoint_value_that_is_not_a_string_is_refused(self):
        for value in (42, None, ["/api/v1/trust/proof"]):
            with self.subTest(value=value):
                self.assert_refused(value, "is not a string")

    def test_the_reason_names_the_endpoint_member(self):
        result = self.check("api/v1/trust/revocations", name="revocations")
        self.assertEqual(result.reason, "endpoints.revocations does not start with /")

    def test_endpoint_values_that_are_paths_are_accepted(self):
        for value in ("/", "/api/v1/trust/proof?v=1", "/api/v1/did/{did}", "/a%20b"):
            with self.subTest(value=value):
                self.assertTrue(self.check(value).valid)

    def test_an_authority_outside_the_trusted_set_is_rejected(self):
        result = atp.verify_discovery(self.document, ["did:opena2a:authority:partner.example"])
        self.assertEqual(result.category, "UNTRUSTED_ISSUER")

    def test_a_document_that_declares_an_issuer_key_set_is_refused(self):
        # The client does not count an issuer key set (Section 7.1.1), so it
        # refuses one that meets the rules as well as one that breaks them.
        key_id = self.document["publicKeys"][0]["keyId"]
        cases = {
            "a 1-of-1 set": {"threshold": 1, "keyIds": [key_id]},
            "a threshold above the number of keys": {"threshold": 5, "keyIds": [key_id]},
            "a keyId listed twice": {"threshold": 1, "keyIds": [key_id, key_id]},
            "null": None,
        }
        for label, key_set in cases.items():
            with self.subTest(label):
                result = atp.verify_discovery({**self.document, "issuerKeySet": key_set})
                self.assertEqual(result.category, "SIGNATURE_INVALID")
                self.assertIn("issuerKeySet", result.reason)


class ReasonTextTests(unittest.TestCase):
    """A reason shows text it takes from the input unchanged when that text is
    printable ASCII without a space, a quote or a backslash, and in JSON
    string form otherwise; an endpoints member name that is not an identifier
    is written endpoints["name"]. The tests check the reason given for text
    that holds control characters, and for other text, and that each reason
    is printable ASCII."""

    # A line feed, a carriage return, an escape, DEL, NEL (a C1 control) and
    # the Unicode line separator.
    CONTROLS = "\n\r\x1b\x7f\x85 "
    NOT_A_VERDICT = "is not one of passed, warning, blocked, listed, verified, unknown"

    def setUp(self):
        self.document = fixture("discovery-valid")["discoveryResponse"]
        self.issuer = "did:opena2a:authority:a" + self.CONTROLS + "b"
        self.signer = Signer(self.issuer + "#key-1")

    def assertReason(self, result, category, reason):
        self.assertFalse(result.valid, result)
        self.assertEqual(result.category, category, result)
        self.assertEqual(result.reason, reason)
        self.assertTrue(result.reason.isascii() and result.reason.isprintable(), ascii(result.reason))

    def test_an_endpoints_member_named_with_a_line_feed_is_escaped(self):
        document = {**self.document, "endpoints": {"x\ny": "z"}}
        self.assertReason(atp.verify_discovery(document), "PARSE_ERROR", 'endpoints["x\\ny"] does not start with /')
        client = atp.AtpClient("https://authority.example", discovery=document)
        result = client.verify(signed_proof(Signer()), now=CLOCK)
        self.assertReason(result, "PARSE_ERROR", 'discovery document: endpoints["x\\ny"] does not start with /')

    def test_an_endpoints_member_name_that_is_not_an_identifier_is_in_json_string_form(self):
        name = "x" + self.CONTROLS
        cases = {
            (name, 42): f"endpoints[{json.dumps(name)}] is not a string",
            (name, "z"): f"endpoints[{json.dumps(name)}] does not start with /",
            (name, "/a#b"): f"endpoints[{json.dumps(name)}] holds #, whitespace or a control character",
            ("trust-proof", "z"): 'endpoints["trust-proof"] does not start with /',
            ("", "z"): 'endpoints[""] does not start with /',
        }
        for (key, value), reason in cases.items():
            with self.subTest(reason):
                result = atp.verify_discovery({**self.document, "endpoints": {key: value}})
                self.assertReason(result, "PARSE_ERROR", reason)

    def test_an_authority_did_with_control_characters_is_in_json_string_form(self):
        result = atp.verify_discovery({**self.document, "authorityDid": self.issuer}, AUTHORITY)
        self.assertReason(result, "UNTRUSTED_ISSUER", f"authorityDid {json.dumps(self.issuer)} is not a trusted issuer")

    def test_an_issuer_did_with_control_characters_is_in_json_string_form(self):
        shown = json.dumps(self.issuer)
        proof = signed_proof(self.signer, issuerDid=self.issuer)
        result = atp.verify_trust_proof(proof, [self.signer.key()], AUTHORITY, now=CLOCK)
        self.assertReason(result, "UNTRUSTED_ISSUER", f"issuerDid {shown} is not a trusted issuer")
        other = Signer("did:opena2a:authority:other.example#key-1")
        proof = signed_proof(other, issuerDid=self.issuer)
        result = atp.verify_trust_proof(proof, [other.key()], self.issuer, now=CLOCK)
        self.assertReason(result, "SIGNATURE_INVALID", f"no Ed25519 signature by a key of {shown} verified")

    def test_a_signature_algorithm_and_key_id_with_control_characters_are_in_json_string_form(self):
        proof = signed_proof(Signer())
        algorithm = "Ed25519" + self.CONTROLS
        proof["signatures"][0]["algorithm"] = algorithm
        result = atp.verify_trust_proof(proof, [Signer().key()], AUTHORITY, now=CLOCK)
        reason = f"signatures[0] has algorithm {json.dumps(algorithm)}, not Ed25519 or ML-DSA-65"
        self.assertReason(result, "SIGNATURE_INVALID", reason)
        signer = Signer(AUTHORITY + "#key-" + self.CONTROLS)
        shown = json.dumps(signer.key_id)
        result = atp.verify_trust_proof(signed_proof(signer), [Signer().key()], AUTHORITY, now=CLOCK)
        reason = f"signatures[0] keyId {shown} does not resolve to a non-revoked Ed25519 key"
        self.assertReason(result, "SIGNATURE_INVALID", reason)
        proof = signed_proof(signer)
        proof["signatures"][0]["value"] = flip_first_byte(proof["signatures"][0]["value"])
        result = atp.verify_trust_proof(proof, [signer.key()], AUTHORITY, now=CLOCK)
        self.assertReason(result, "SIGNATURE_INVALID", f"the Ed25519 signature of {shown} did not verify")

    def test_a_verdict_is_unchanged_only_without_a_space_a_quote_a_backslash_or_a_control_character(self):
        signer = Signer()
        cases = {
            "approved": f"verdict approved {self.NOT_A_VERDICT}",
            "passed" + self.CONTROLS: f"verdict {json.dumps('passed' + self.CONTROLS)} {self.NOT_A_VERDICT}",
            "not passed": f'verdict "not passed" {self.NOT_A_VERDICT}',
            'say "passed"': f'verdict "say \\"passed\\"" {self.NOT_A_VERDICT}',
            # A line feed, and a backslash followed by n, give two reasons.
            "a\nb": f'verdict "a\\nb" {self.NOT_A_VERDICT}',
            "a\\nb": f'verdict "a\\\\nb" {self.NOT_A_VERDICT}',
        }
        for verdict, reason in cases.items():
            with self.subTest(verdict=verdict):
                proof = signed_proof(signer, verdict=verdict)
                result = atp.verify_trust_proof(proof, [signer.key()], AUTHORITY, now=CLOCK)
                self.assertReason(result, "SEMANTIC_INVALID", reason)

    def test_dids_with_control_characters_at_step_7_are_in_json_string_form(self):
        issuer = json.dumps(self.issuer)
        second = {COSIGNER: [Signer(COSIGNER + "#key-1").key()]}
        proof = signed_proof(self.signer, issuerDid=self.issuer)
        result = atp.verify_trust_proof(proof, [self.signer.key()], self.issuer, now=CLOCK, second_authorities=second)
        reason = (
            "no Ed25519 signature by a second authority verified (step 7): trustLevel 3 needs one by an "
            f"authority of second_authorities other than {issuer}"
        )
        self.assertReason(result, "SIGNATURE_INVALID", reason)
        # A second authority whose key is the issuer's.
        cosigner = "did:opena2a:authority:c" + self.CONTROLS + "d"
        same = Signer(cosigner + "#key-1")
        same.private = self.signer.private
        proof = signed_proof(self.signer, same, issuerDid=self.issuer)
        second = {cosigner: [same.key()]}
        result = atp.verify_trust_proof(proof, [self.signer.key()], self.issuer, now=CLOCK, second_authorities=second)
        reason = (
            f"no second authority distinct from {issuer} signed (step 7): "
            f"{json.dumps(cosigner)} shares a public key with {issuer}"
        )
        self.assertReason(result, "SIGNATURE_INVALID", reason)

    def test_a_tree_head_signed_by_with_control_characters_is_in_json_string_form(self):
        signed_by = AUTHORITY + "#key-" + self.CONTROLS
        head = {
            "treeSize": 1,
            "timestamp": "2026-05-23T00:00:00Z",
            "rootHash": wire(bytes(32)),
            "signedBy": signed_by,
            "signature": Signer().sign(bytes(32)),
        }
        result = atp.verify_signed_tree_head(head, [Signer().key()])
        reason = f"signedTreeHead.signedBy {json.dumps(signed_by)} does not resolve to a non-revoked Ed25519 key"
        self.assertReason(result, "SIGNATURE_INVALID", reason)


class Authority(http.server.BaseHTTPRequestHandler):
    """Answers each path from the server's routes: a (status, body) pair, or
    (status, body, headers). A body of None is an answer without a body, and
    headers is a dict or a list of (name, value) pairs."""

    def do_GET(self):
        self.server.requests.append(self.path)
        route = self.server.routes.get(urllib.parse.urlsplit(self.path).path, (404, {"error": "not found"}))
        status, body, headers = (route + ({},))[:3]
        self.send_response(status)
        for name, value in headers.items() if isinstance(headers, dict) else headers:
            self.send_header(name, value)
        payload = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except ConnectionError:
            pass  # the client stopped reading, as it does past MAX_RESPONSE_BYTES

    def log_message(self, *args):
        pass


class Drip(http.server.BaseHTTPRequestHandler):
    """Answers 200 one byte at a time, 0.1 seconds apart, from the status
    line on, or from the body on when server.phase is "body". Sets
    server.closed when a write fails because the client closed the
    connection."""

    def do_GET(self):
        body = json.dumps({"pad": "x" * 1000}).encode()
        head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)
        if self.server.phase == "body":
            self.wfile.write(head)
            head = b""
        try:
            for byte in head + body:
                self.wfile.write(bytes([byte]))
                time.sleep(0.1)
        except OSError:
            self.server.closed.set()

    def log_message(self, *args):
        pass


def tls_context(directory: pathlib.Path) -> ssl.SSLContext:
    """A TLS server context with a certificate for 127.0.0.1, signed by a CA
    generated here, whose certificate is written to directory / "ca.pem"."""
    now = datetime.now(timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "atp-client test CA")])

    def certificate(subject: x509.Name, public_key, *extensions) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
        )
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical=critical)
        return builder.sign(ca_key, hashes.SHA256())

    ca = certificate(
        ca_name,
        ca_key.public_key(),
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),  # keyCertSign, cRLSign
        (x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False),
    )
    leaf = certificate(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]),
        key.public_key(),
        (x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False),
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False),
    )
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    chain = directory / "server.pem"
    chain.write_bytes(
        leaf.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain)
    return context


def serve(
    test: unittest.TestCase, handler: type, context: ssl.SSLContext | None = None
) -> http.server.ThreadingHTTPServer:
    """A server on 127.0.0.1 that answers with handler until test ends, over
    TLS with context when one is given."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.routes, server.requests = {}, []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return server


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.server = serve(self, Authority)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.client = atp.AtpClient(self.url + "/", timeout=5)
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

    def test_verify_refuses_a_proof_of_an_authority_that_declares_an_issuer_key_set(self):
        signers = [self.signer, Signer(AUTHORITY + "#key-2"), Signer(AUTHORITY + "#key-3")]
        keys = [signer.key(status="active", validFrom="2026-01-01T00:00:00Z") for signer in signers]
        cases = {
            "one key of a 2-of-3 set": ({"threshold": 2, "keyIds": [s.key_id for s in signers]}, signers[:1]),
            "two keys of a 2-of-3 set": ({"threshold": 2, "keyIds": [s.key_id for s in signers]}, signers[:2]),
            "a set that breaks Section 7.1.1": ({"threshold": 5, "keyIds": [self.signer.key_id]}, signers[:1]),
        }
        for label, (key_set, signed_by) in cases.items():
            with self.subTest(label):
                client = atp.AtpClient(
                    "https://authority.example",
                    discovery={**self.discovery, "publicKeys": keys, "issuerKeySet": key_set},
                )
                result = client.verify(signed_proof(*signed_by), now=CLOCK)
                self.assertEqual(result.category, "SIGNATURE_INVALID")
                self.assertIn("discovery document: issuerKeySet", result.reason)

    def test_a_base_url_that_is_not_http_raises(self):
        for url in ("ftp://authority.example", "authority.example", "https://authority.example/?a=1"):
            with self.subTest(url), self.assertRaises(ValueError):
                atp.AtpClient(url)

    def test_an_http_base_url_needs_a_loopback_address_literal(self):
        # Section 7.1: an https authority URL, or an http one whose host is in
        # 127.0.0.0/8 or is ::1; the name localhost is not an address literal.
        for url in ("http://127.0.0.1:8080", "http://127.255.0.9/", "http://[::1]:8080", "https://authority.example"):
            with self.subTest(url):
                self.assertEqual(atp.AtpClient(url).base_url, url.rstrip("/"))
        refused = (
            "http://authority.example",
            "http://localhost:8080",
            "http://0.0.0.0",
            "http://128.0.0.1",
            "http://127.1",
            "http://[::2]",
            "http://[::ffff:127.0.0.1]",
        )
        for url in refused:
            with self.subTest(url), self.assertRaisesRegex(ValueError, r"Section 7\.1"):
                atp.AtpClient(url)

    def test_a_request_under_an_http_url_does_not_go_through_a_proxy(self):
        proxy = serve(self, Authority)
        proxy.routes = {"/.well-known/atp": (200, {**self.discovery, "authorityDid": "did:opena2a:authority:proxy"})}
        self.server.routes = {"/.well-known/atp": (200, self.discovery)}
        address = f"http://127.0.0.1:{proxy.server_address[1]}"
        with mock.patch.dict(os.environ, {"http_proxy": address, "HTTP_PROXY": address}):
            for name in ("no_proxy", "NO_PROXY"):
                os.environ.pop(name, None)
            self.assertEqual(self.client.get_discovery(), self.discovery)
        self.assertEqual(proxy.requests, [])

    def test_an_answer_body_longer_than_max_response_bytes_raises(self):
        document = json.dumps(self.discovery).encode()
        self.server.routes = {"/.well-known/atp": (200, document + b" " * (atp.MAX_RESPONSE_BYTES - len(document)))}
        self.assertEqual(self.client.get_discovery(), self.discovery)
        for path, size in (
            ("/.well-known/atp", 20 * 1024 * 1024),
            ("/.well-known/atp", atp.MAX_RESPONSE_BYTES + 1),
            ("/api/v1/trust/proof", atp.MAX_RESPONSE_BYTES + 1),
        ):
            with self.subTest(path=path, size=size):
                self.server.routes = {path: (200, b" " * (size - 2) + b"{}")}
                client = atp.AtpClient(self.url)
                fetch = client.get_discovery if path == "/.well-known/atp" else lambda: client.get_trust_proof(AGENT)
                with self.assertRaisesRegex(atp.AtpError, rf"GET {path}\S* answered with a body longer than 1048576 bytes"):
                    fetch()

    def tls(self, handler: type) -> tuple[http.server.ThreadingHTTPServer, dict[str, str]]:
        """A server that answers with handler over TLS, and the environment
        under which a client created trusts its certificate."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        server = serve(self, handler, tls_context(pathlib.Path(directory.name)))
        return server, {"SSL_CERT_FILE": os.path.join(directory.name, "ca.pem")}

    def test_an_https_authority_is_reached_and_its_certificate_verified(self):
        server, trust = self.tls(Authority)
        server.routes = {"/.well-known/atp": (200, self.discovery)}
        url = f"https://127.0.0.1:{server.server_address[1]}"
        with mock.patch.dict(os.environ, trust):
            client = atp.AtpClient(url)
        self.assertEqual(client.get_discovery(), self.discovery)
        with self.assertRaisesRegex(atp.AtpError, "CERTIFICATE_VERIFY_FAILED"):
            atp.AtpClient(url).get_discovery()

    def test_a_request_that_has_not_finished_within_the_timeout_raises(self):
        # Each byte arrives well within the timeout, so only a deadline on the
        # whole request ends it; the client then closes the connection.
        for scheme, phase in (("http", "headers"), ("http", "body"), ("https", "body")):
            with self.subTest(scheme=scheme, phase=phase):
                server, trust = self.tls(Drip) if scheme == "https" else (serve(self, Drip), {})
                server.phase, server.closed = phase, threading.Event()
                with mock.patch.dict(os.environ, trust):
                    client = atp.AtpClient(f"{scheme}://127.0.0.1:{server.server_address[1]}", timeout=1)
                started = time.monotonic()
                with self.assertRaisesRegex(atp.AtpError, "did not finish within the 1-second timeout"):
                    client.get_discovery()
                self.assertLess(time.monotonic() - started, 3)
                self.assertTrue(server.closed.wait(5), "the client did not close the connection")

    def test_a_removed_key_stops_verifying_once_the_copy_is_older_than_refresh_after(self):
        # Section 8.2 step 2: the authority removes a revoked key from its
        # discovery document, and the client requests the document again.
        client = atp.AtpClient(self.url, refresh_after=0.05)
        proof = signed_proof(self.signer)
        self.server.routes = {"/.well-known/atp": (200, self.discovery)}
        self.assertTrue(client.verify(proof, now=CLOCK).valid)
        other = Signer(AUTHORITY + "#key-2").key(status="active", validFrom="2026-01-01T00:00:00Z")
        self.server.routes = {"/.well-known/atp": (200, {**self.discovery, "publicKeys": [other]})}
        time.sleep(0.1)
        result = client.verify(proof, now=CLOCK)
        self.assertEqual(result.category, "SIGNATURE_INVALID")
        self.assertIn("does not resolve", result.reason)
        self.assertEqual(self.server.requests.count("/.well-known/atp"), 2)

    def test_the_age_header_counts_toward_the_age_of_the_copy(self):
        proof = signed_proof(self.signer)
        for age, requests in (("290", 1), ("301", 2)):
            with self.subTest(age=age):
                self.server.routes, self.server.requests = {"/.well-known/atp": (200, self.discovery, {"Age": age})}, []
                client = atp.AtpClient(self.url)
                self.assertTrue(client.verify(proof, now=CLOCK).valid)
                self.assertTrue(client.verify(proof, now=CLOCK).valid)
                self.assertEqual(self.server.requests.count("/.well-known/atp"), requests)

    def test_a_copy_more_than_3600_seconds_old_on_arrival_raises(self):
        proof = signed_proof(self.signer)
        self.server.routes = {"/.well-known/atp": (200, self.discovery, {"Age": "3600"})}
        self.assertTrue(atp.AtpClient(self.url).verify(proof, now=CLOCK).valid)
        for age in ("3601", "0003601", "9" * 5000):
            with self.subTest(age=age[:8]):
                self.server.routes = {"/.well-known/atp": (200, self.discovery, {"Age": age})}
                with self.assertRaisesRegex(atp.AtpError, "more than the Section 7.1 maximum age of 3600 seconds"):
                    atp.AtpClient(self.url).verify(proof, now=CLOCK)

    def test_an_age_header_that_is_not_one_number_of_seconds_raises(self):
        for headers in ({"Age": "soon"}, {"Age": "-1"}, {"Age": "1.5"}, {"Age": ""}, [("Age", "1"), ("Age", "2")]):
            with self.subTest(headers=headers):
                self.server.routes = {"/.well-known/atp": (200, self.discovery, headers)}
                with self.assertRaisesRegex(atp.AtpError, "Age header is not one number of seconds"):
                    atp.AtpClient(self.url).get_discovery()

    def test_a_failed_request_for_a_new_copy_raises_instead_of_verifying(self):
        client = atp.AtpClient(self.url, refresh_after=0.05)
        proof = signed_proof(self.signer)
        self.server.routes = {"/.well-known/atp": (200, self.discovery)}
        self.assertTrue(client.verify(proof, now=CLOCK).valid)
        self.server.routes = {"/.well-known/atp": (503, {"error": "unavailable"})}
        time.sleep(0.1)
        with self.assertRaises(atp.AtpError) as raised:
            client.verify(proof, now=CLOCK)
        self.assertEqual(raised.exception.status, 503)
        self.server.routes = {"/.well-known/atp": (200, self.discovery)}
        self.assertTrue(client.verify(proof, now=CLOCK).valid)

    def test_a_stored_copy_is_used_until_its_age_is_more_than_refresh_after(self):
        proof = signed_proof(self.signer)
        stored = atp.AtpClient(self.url, discovery=self.discovery, discovery_age=290)
        self.assertTrue(stored.verify(proof, now=CLOCK).valid)
        self.assertEqual(self.server.requests, [])
        self.server.routes = {"/.well-known/atp": (503, {"error": "unavailable"})}
        stale = atp.AtpClient(self.url, discovery=self.discovery, discovery_age=3601)
        with self.assertRaises(atp.AtpError):
            stale.verify(proof, now=CLOCK)
        self.assertEqual(self.server.requests, ["/.well-known/atp"])

    def test_timeout_refresh_after_and_discovery_age_are_checked(self):
        cases = {
            "timeout": (0, -1, math.inf, math.nan, "10", None, True),
            "refresh_after": (-1, 3601, math.nan, "300"),
            "discovery_age": (-1, math.inf, math.nan, None),
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, name):
                    atp.AtpClient("https://authority.example", **{name: value})
        self.assertEqual(atp.AtpClient("https://authority.example", refresh_after=3600).refresh_after, 3600)


if __name__ == "__main__":
    unittest.main()
