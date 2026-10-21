"""Client for the Agent Trust Protocol (ATP-SPEC.md in this repository).

AtpClient fetches a trust authority's discovery document (Section 7.1) and its
trust proofs (Section 4.5). The verify functions make no network call: they
check a trust proof (Section 4.4 steps 1 to 5, except the issuer key set count
of step 4), a discovery document (Section 7.1), a signed tree head (Section
5.6), an inclusion proof (Section 5.4), a consistency proof (Section 5.5) and a
revocation response (Section 8.1). Each returns a VerifyResult; a rejected
input carries one of CATEGORIES and a reason that names the member or the step
that failed. The client does not count an issuer key set (Section 7.1.1), so
verify_discovery, and AtpClient.verify with it, refuse a discovery document
that declares one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
except ImportError:  # cryptography releases before 47 have no ML-DSA
    MLDSA65PublicKey = None

__all__ = [
    "CATEGORIES",
    "VERDICTS",
    "AtpClient",
    "AtpError",
    "VerifyResult",
    "canonical_string",
    "verify_consistency_proof",
    "verify_discovery",
    "verify_inclusion_proof",
    "verify_revocation_list",
    "verify_signed_tree_head",
    "verify_trust_proof",
]

CATEGORIES = (
    "PARSE_ERROR",
    "EXPIRED",
    "UNTRUSTED_ISSUER",
    "SIGNATURE_INVALID",
    "SEMANTIC_INVALID",
    "PROOF_INVALID",
)
VERDICTS = ("passed", "warning", "blocked", "listed", "verified", "unknown")
KEY_SIZES = {"Ed25519": 32, "ML-DSA-65": 1952}
KEY_STATUSES = ("active", "retired", "revoked")
MAX_VALIDITY_MICROSECONDS = 24 * 3600 * 1_000_000  # Section 10.2

_EPOCH = datetime(1970, 1, 1)
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))"
)
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_WIRE_HASH = re.compile(r"SHA256:([0-9a-f]{64})")
# What Section 7.1 bars from an endpoints value: "#", whitespace (str.isspace)
# and control characters (Unicode category Cc, U+0000 to U+001F and U+007F to U+009F).
_NOT_IN_ENDPOINT = re.compile(r"[#\s\x00-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class VerifyResult:
    """valid is True when every check passed. Otherwise category is one of
    CATEGORIES and reason says which member or step failed."""

    valid: bool
    category: str | None = None
    reason: str = ""


class AtpError(Exception):
    """A request to the authority failed, or its answer was not what was asked
    for. status is the HTTP status when the authority answered with one."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class _Reject(Exception):
    def __init__(self, category: str, reason: str) -> None:
        super().__init__(reason)
        self.category = category
        self.reason = reason


def _outcome(check: Callable[[], None]) -> VerifyResult:
    """Runs check, which raises _Reject at the first failure. Any other
    exception (a bad clock, for one) is the caller's error and propagates."""
    try:
        check()
    except _Reject as rejection:
        return VerifyResult(False, rejection.category, rejection.reason)
    return VerifyResult(True)


# Wire values


def _instant(value: Any, name: str) -> int:
    """value, an RFC 3339 date-time with an upper-case T and Z, as whole
    microseconds since 1970-01-01T00:00:00Z. Digits of a fraction after the
    sixth are dropped. A date that does not exist, an hour above 23, a second
    of 60 and a UTC time outside the years 1 to 9999 are refused."""
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _Reject("PARSE_ERROR", f"{name} is not an RFC 3339 date-time")
    offset = timedelta(0)
    if match.group(8):
        offset_hour, offset_minute = int(match.group(9)), int(match.group(10))
        if offset_hour > 23 or offset_minute > 59:
            raise _Reject("PARSE_ERROR", f"{name} has a UTC offset out of range")
        offset = timedelta(hours=offset_hour, minutes=offset_minute)
        if match.group(8) == "-":
            offset = -offset
    try:
        moment = datetime(*(int(group) for group in match.group(1, 2, 3, 4, 5, 6))) - offset
    except (ValueError, OverflowError):
        raise _Reject("PARSE_ERROR", f"{name} is not a valid date-time in the years 1 to 9999") from None
    fraction = int((match.group(7) or "")[:6].ljust(6, "0"))
    return (moment - _EPOCH) // timedelta(microseconds=1) + fraction


def _canonical_time(instant: int) -> str:
    """Section 4.3: the instant in UTC to the whole second, its fraction
    dropped, written YYYY-MM-DDTHH:MM:SSZ."""
    moment = _EPOCH + timedelta(seconds=instant // 1_000_000)
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}Z"
    )


def _clock(now: datetime | str | None) -> int:
    if now is None:
        now = datetime.now(timezone.utc)
    if isinstance(now, str):
        try:
            return _instant(now, "now")
        except _Reject as rejection:
            raise ValueError(rejection.reason) from None
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime or an RFC 3339 string")
    return (now.astimezone(timezone.utc).replace(tzinfo=None) - _EPOCH) // timedelta(microseconds=1)


def _integer(value: Any, name: str, minimum: int | None = None) -> int:
    """A JSON integer. As in JSON Schema, a number with a zero fraction (4.0)
    is the integer it equals; true and false are not integers."""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if type(value) is not int or (minimum is not None and value < minimum):
        bound = "" if minimum is None else f" of at least {minimum}"
        raise _Reject("PARSE_ERROR", f"{name} is missing or not an integer{bound}")
    return value


def _base64(value: Any, name: str, category: str) -> bytes:
    if not isinstance(value, str) or not value or _BASE64.fullmatch(value) is None:
        raise _Reject(category, f"{name} is not base64")
    return base64.b64decode(value)


def _wire_hash(value: Any, name: str) -> bytes:
    match = _WIRE_HASH.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise _Reject("PARSE_ERROR", f"{name} is not SHA256: and 64 lowercase hex digits")
    return bytes.fromhex(match.group(1))


def _hash_list(value: Any, name: str) -> list[bytes]:
    if not isinstance(value, list):
        raise _Reject("PARSE_ERROR", f"{name} is missing or not an array")
    return [_wire_hash(item, f"{name}[{index}]") for index, item in enumerate(value)]


def _trusted(trusted_issuers: str | Iterable[str]) -> set[str]:
    return {trusted_issuers} if isinstance(trusted_issuers, str) else set(trusted_issuers)


# Keys and signatures


def _key_bytes(keys: list[Any], key_id: str, algorithm: str) -> bytes | None:
    """Section 4.4 step 3: the raw public key keyId resolves to among keys (an
    entry with that keyId and algorithm, a hex key of the algorithm's size and
    a status other than revoked), or None."""
    for entry in keys:
        if (
            isinstance(entry, dict)
            and entry.get("keyId") == key_id
            and entry.get("algorithm") == algorithm
            and entry.get("status") != "revoked"
        ):
            raw = entry.get("publicKeyHex")
            if isinstance(raw, str) and len(raw) == 2 * KEY_SIZES[algorithm] and _HEX.fullmatch(raw):
                return bytes.fromhex(raw)
    return None


def _signature_valid(algorithm: str, public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        if algorithm == "Ed25519":
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        elif MLDSA65PublicKey is None:
            raise UnsupportedAlgorithm("ML-DSA-65")
        else:
            MLDSA65PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    except UnsupportedAlgorithm:
        raise _Reject(
            "SIGNATURE_INVALID",
            "this installation cannot verify ML-DSA-65 signatures: "
            "it needs cryptography 48 or later with OpenSSL 3.5 or later",
        ) from None
    return True


# Trust proofs (Sections 4.3 and 4.4)


@dataclass(frozen=True)
class _Proof:
    """The seven members of a trust proof that the canonical string covers."""

    did: str
    level: int
    score: float
    verdict: str
    issued: int
    expires: int
    issuer: str

    def canonical(self) -> str:
        # %.6f rounds the exact binary value, a tie to even, as Go and C do.
        return "|".join(
            (
                self.did,
                str(self.level),
                f"{self.score:.6f}",
                self.verdict,
                _canonical_time(self.issued),
                _canonical_time(self.expires),
                self.issuer,
            )
        )


def _parse_proof(proof: Any) -> _Proof:
    if not isinstance(proof, dict):
        raise _Reject("PARSE_ERROR", "the trust proof is not a JSON object")
    for name in ("did", "verdict", "issuerDid"):
        if not isinstance(proof.get(name), str):
            raise _Reject("PARSE_ERROR", f"{name} is missing or not a string")
    level = _integer(proof.get("trustLevel"), "trustLevel")
    score = proof.get("trustScore")
    if type(score) not in (int, float):
        raise _Reject("PARSE_ERROR", "trustScore is missing or not a number")
    try:
        score = float(score)
    except OverflowError:
        score = math.inf
    if not math.isfinite(score):
        raise _Reject("PARSE_ERROR", "trustScore is not a finite number")
    issued = _instant(proof.get("issuedAt"), "issuedAt")
    expires = _instant(proof.get("expiresAt"), "expiresAt")
    return _Proof(proof["did"], level, score, proof["verdict"], issued, expires, proof["issuerDid"])


def _signature_entries(proof: dict[str, Any]) -> list[dict[str, Any]]:
    signatures = proof.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise _Reject("PARSE_ERROR", "signatures is missing or empty")
    for index, entry in enumerate(signatures):
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("keyId"), str)
            and isinstance(entry.get("algorithm"), str)
        ):
            raise _Reject("PARSE_ERROR", f"signatures[{index}] has no keyId and algorithm strings")
    return signatures


def canonical_string(proof: dict[str, Any]) -> str:
    """The Section 4.3 canonical string of a trust proof: the bytes, encoded
    as UTF-8, that its signatures cover. Reads did, trustLevel, trustScore,
    verdict, issuedAt, expiresAt and issuerDid, and raises ValueError when one
    of them cannot be read."""
    try:
        return _parse_proof(proof).canonical()
    except _Reject as rejection:
        raise ValueError(rejection.reason) from None


def verify_trust_proof(
    proof: Any,
    keys: Iterable[Any],
    trusted_issuers: str | Iterable[str],
    *,
    now: datetime | str | None = None,
) -> VerifyResult:
    """Section 4.4 steps 1 to 5, offline, in order: expiry, issuer, key lookup,
    signatures, semantic validation. keys are Section 7.1 publicKeys entries
    (keyId, algorithm, publicKeyHex, optional status) and trusted_issuers the
    issuer DIDs the verifier trusts; now (default: the current time) is the
    clock for step 1. Step 6, the transparency log, is verify_inclusion_proof;
    step 7, co-signing by a second authority at conformance Level 3, is not
    checked. A Sigstore co-signature (Section 4.3.1) is not verified, so step 4
    rejects a proof that carries one. The issuer key set count of step 4
    (Section 7.1.1) is not applied: pass only the keys of an authority whose
    discovery document carries no issuerKeySet, which verify_discovery
    checks. Raises ValueError for a now that is not a timezone-aware datetime
    or an RFC 3339 string."""
    clock = _clock(now)
    return _outcome(lambda: _check_trust_proof(proof, list(keys), _trusted(trusted_issuers), clock))


def _check_trust_proof(proof: Any, keys: list[Any], trusted: set[str], clock: int) -> None:
    parsed = _parse_proof(proof)
    signatures = _signature_entries(proof)
    if proof.get("transparencyLogIndex") is not None:
        _integer(proof["transparencyLogIndex"], "transparencyLogIndex", minimum=0)

    if parsed.expires <= clock:
        raise _Reject("EXPIRED", f"the trust proof expired at {proof['expiresAt']}")

    if parsed.issuer not in trusted:
        raise _Reject("UNTRUSTED_ISSUER", f"issuerDid {parsed.issuer} is not a trusted issuer")

    resolved = []
    for index, entry in enumerate(signatures):
        algorithm = entry["algorithm"]
        if algorithm == "Sigstore":
            raise _Reject(
                "SIGNATURE_INVALID",
                f"signatures[{index}] is a Sigstore co-signature (Section 4.3.1), which this client does not verify",
            )
        if algorithm not in KEY_SIZES:
            raise _Reject("SIGNATURE_INVALID", f"signatures[{index}] has algorithm {algorithm}, not Ed25519 or ML-DSA-65")
        public = _key_bytes(keys, entry["keyId"], algorithm)
        if public is None:
            raise _Reject(
                "SIGNATURE_INVALID",
                f"signatures[{index}] keyId {entry['keyId']} does not resolve to a non-revoked {algorithm} key",
            )
        resolved.append((index, entry, public))

    message = parsed.canonical().encode("utf-8")
    issuer_signed = False
    for index, entry, public in resolved:
        signature = _base64(entry.get("value"), f"signatures[{index}].value", "SIGNATURE_INVALID")
        if not _signature_valid(entry["algorithm"], public, signature, message):
            raise _Reject("SIGNATURE_INVALID", f"the {entry['algorithm']} signature of {entry['keyId']} did not verify")
        key_did, _, fragment = entry["keyId"].partition("#")
        if entry["algorithm"] == "Ed25519" and fragment and key_did == parsed.issuer:
            issuer_signed = True
    if not issuer_signed:
        raise _Reject("SIGNATURE_INVALID", f"no Ed25519 signature by a key of {parsed.issuer} verified")

    if not 0 <= parsed.level <= 4:
        raise _Reject("SEMANTIC_INVALID", f"trustLevel {parsed.level} is outside 0 to 4")
    if not 0.0 <= parsed.score <= 1.0:
        raise _Reject("SEMANTIC_INVALID", f"trustScore {parsed.score} is outside 0.0 to 1.0")
    if parsed.verdict not in VERDICTS:
        raise _Reject("SEMANTIC_INVALID", f"verdict {parsed.verdict} is not one of {', '.join(VERDICTS)}")
    if parsed.issued >= parsed.expires:
        raise _Reject("SEMANTIC_INVALID", "issuedAt is not before expiresAt")
    if parsed.expires - parsed.issued > MAX_VALIDITY_MICROSECONDS:
        raise _Reject("SEMANTIC_INVALID", "the validity window from issuedAt to expiresAt is longer than 24 hours")


# Discovery (Section 7.1)


def verify_discovery(discovery: Any, trusted_issuers: str | Iterable[str] | None = None) -> VerifyResult:
    """Section 7.1: the members a verifier reads from a discovery document,
    each endpoints value a path that starts with "/" and holds no "#",
    whitespace or control character, and each publicKeys entry a hex key of
    its algorithm's size. With trusted_issuers, authorityDid must be one of
    them. A document that carries issuerKeySet is refused with
    SIGNATURE_INVALID: this client does not count an issuer key set (Section
    7.1.1), which Section 4.4 step 4 requires."""
    trusted = None if trusted_issuers is None else _trusted(trusted_issuers)
    return _outcome(lambda: _check_discovery(discovery, trusted))


def _check_discovery(discovery: Any, trusted: set[str] | None) -> None:
    if not isinstance(discovery, dict):
        raise _Reject("PARSE_ERROR", "the discovery document is not a JSON object")
    authority = discovery.get("authorityDid")
    if not isinstance(authority, str) or not authority.startswith("did:"):
        raise _Reject("PARSE_ERROR", "authorityDid is missing or not a DID")
    if discovery.get("version") != "1.0":
        raise _Reject("PARSE_ERROR", "version is not 1.0")
    if discovery.get("conformanceLevel") is not None:
        if _integer(discovery["conformanceLevel"], "conformanceLevel") not in (1, 2, 3):
            raise _Reject("PARSE_ERROR", "conformanceLevel is not 1, 2 or 3")
    endpoints = discovery.get("endpoints")
    if not isinstance(endpoints, dict) or not endpoints:
        raise _Reject("PARSE_ERROR", "endpoints is missing, empty or not a JSON object")
    for name, path in endpoints.items():
        # A client appends the value to the authority URL (Section 7.1).
        if not isinstance(path, str):
            raise _Reject("PARSE_ERROR", f"endpoints.{name} is not a string")
        if not path.startswith("/"):
            raise _Reject("PARSE_ERROR", f"endpoints.{name} does not start with /")
        if _NOT_IN_ENDPOINT.search(path):
            raise _Reject("PARSE_ERROR", f"endpoints.{name} holds #, whitespace or a control character")
    keys = discovery.get("publicKeys")
    if not isinstance(keys, list) or not keys:
        raise _Reject("PARSE_ERROR", "publicKeys is missing or empty")
    for index, key in enumerate(keys):
        name = f"publicKeys[{index}]"
        if not isinstance(key, dict):
            raise _Reject("PARSE_ERROR", f"{name} is not a JSON object")
        key_id = key.get("keyId")
        if not isinstance(key_id, str) or not key_id.startswith("did:") or "#" not in key_id:
            raise _Reject("PARSE_ERROR", f"{name}.keyId is not a DID with a fragment")
        algorithm = key.get("algorithm")
        if algorithm not in KEY_SIZES:
            raise _Reject("PARSE_ERROR", f"{name}.algorithm is not Ed25519 or ML-DSA-65")
        raw = key.get("publicKeyHex")
        if not isinstance(raw, str) or len(raw) != 2 * KEY_SIZES[algorithm] or not _HEX.fullmatch(raw):
            raise _Reject("PARSE_ERROR", f"{name}.publicKeyHex is not a {KEY_SIZES[algorithm]}-byte key in hex")
        if key.get("status") not in KEY_STATUSES:
            raise _Reject("PARSE_ERROR", f"{name}.status is not active, retired or revoked")
        _instant(key.get("validFrom"), f"{name}.validFrom")
    if trusted is not None and authority not in trusted:
        raise _Reject("UNTRUSTED_ISSUER", f"authorityDid {authority} is not a trusted issuer")
    # Section 4.4 step 4 requires a proof to meet a declared set, and no proof
    # meets a set that breaks Section 7.1.1; not counting sets, the client
    # refuses every one, whatever it holds.
    if "issuerKeySet" in discovery:
        raise _Reject(
            "SIGNATURE_INVALID",
            "issuerKeySet: this client does not count an issuer key set (Section 7.1.1), "
            "so it verifies no proof of an authority that declares one",
        )


# Transparency log (Sections 5.4 to 5.6, RFC 9162 Section 2.1)


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _inclusion_root(index: int, size: int, leaf: bytes, path: list[bytes]) -> bytes | None:
    """RFC 9162 Section 2.1.3.2: the root path leads to from leaf at index in
    a tree of size, or None when the path does not fit that tree."""
    if index >= size:
        return None
    fn, sn, root = index, size - 1, leaf
    for sibling in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            root = _node(sibling, root)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            root = _node(root, sibling)
        fn >>= 1
        sn >>= 1
    return root if sn == 0 else None


def _consistency_roots(first: int, second: int, path: list[bytes], first_root: bytes) -> tuple[bytes, bytes] | None:
    """RFC 9162 Section 2.1.4.2: the two roots path leads to for trees of first
    and second leaves, 0 < first < second, or None when it fits neither."""
    if not path:
        return None
    if first & (first - 1) == 0:
        path = [first_root, *path]
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    first_hash = second_hash = path[0]
    for node in path[1:]:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            first_hash = _node(node, first_hash)
            second_hash = _node(node, second_hash)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            second_hash = _node(second_hash, node)
        fn >>= 1
        sn >>= 1
    return (first_hash, second_hash) if sn == 0 else None


def _tree_head(sth: Any, name: str) -> tuple[int, bytes, str, Any]:
    """The members of a Section 5.6 tree head: (treeSize, root bytes,
    signedBy, signature as served)."""
    if not isinstance(sth, dict):
        raise _Reject("PARSE_ERROR", f"{name} is missing or not a JSON object")
    size = _integer(sth.get("treeSize"), f"{name}.treeSize", minimum=0)
    _instant(sth.get("timestamp"), f"{name}.timestamp")
    root = _wire_hash(sth.get("rootHash"), f"{name}.rootHash")
    signed_by = sth.get("signedBy")
    if not isinstance(signed_by, str):
        raise _Reject("PARSE_ERROR", f"{name}.signedBy is missing or not a string")
    return size, root, signed_by, sth.get("signature")


def _check_tree_head(name: str, root: bytes, signed_by: str, signature: Any, keys: list[Any]) -> None:
    """Section 5.6: an Ed25519 signature over the 32 bytes of rootHash by the
    key signedBy resolves to."""
    public = _key_bytes(keys, signed_by, "Ed25519")
    if public is None:
        raise _Reject("SIGNATURE_INVALID", f"{name}.signedBy {signed_by} does not resolve to a non-revoked Ed25519 key")
    if not _signature_valid("Ed25519", public, _base64(signature, f"{name}.signature", "SIGNATURE_INVALID"), root):
        raise _Reject("SIGNATURE_INVALID", f"the {name} signature did not verify")


def verify_signed_tree_head(sth: Any, keys: Iterable[Any]) -> VerifyResult:
    """Section 5.6: the tree head's members and its signature under keys."""
    keys = list(keys)
    return _outcome(lambda: _check_signed_tree_head(sth, keys))


def _check_signed_tree_head(sth: Any, keys: list[Any]) -> None:
    _, root, signed_by, signature = _tree_head(sth, "signedTreeHead")
    _check_tree_head("signedTreeHead", root, signed_by, signature, keys)


def verify_inclusion_proof(proof: Any, keys: Iterable[Any]) -> VerifyResult:
    """Section 5.4: the signed tree head verifies (step 1), then the root
    recomputed from leafHash along auditPath is its rootHash (step 2)."""
    keys = list(keys)
    return _outcome(lambda: _check_inclusion_proof(proof, keys))


def _check_inclusion_proof(proof: Any, keys: list[Any]) -> None:
    if not isinstance(proof, dict):
        raise _Reject("PARSE_ERROR", "the inclusion proof is not a JSON object")
    index = _integer(proof.get("logIndex"), "logIndex", minimum=0)
    leaf = _wire_hash(proof.get("leafHash"), "leafHash")
    path = _hash_list(proof.get("auditPath"), "auditPath")
    size, root, signed_by, signature = _tree_head(proof.get("signedTreeHead"), "signedTreeHead")
    _check_tree_head("signedTreeHead", root, signed_by, signature, keys)
    if index >= size:
        raise _Reject("PARSE_ERROR", f"logIndex {index} is not below signedTreeHead.treeSize {size}")
    if _inclusion_root(index, size, leaf, path) != root:
        raise _Reject(
            "PROOF_INVALID", "the root recomputed from leafHash along auditPath is not signedTreeHead.rootHash"
        )


def verify_consistency_proof(proof: Any, keys: Iterable[Any]) -> VerifyResult:
    """Section 5.5: both signed tree heads verify (step 1), then
    consistencyPath leads to both of their roots (step 2)."""
    keys = list(keys)
    return _outcome(lambda: _check_consistency_proof(proof, keys))


def _check_consistency_proof(proof: Any, keys: list[Any]) -> None:
    if not isinstance(proof, dict):
        raise _Reject("PARSE_ERROR", "the consistency proof is not a JSON object")
    first = _integer(proof.get("fromSize"), "fromSize", minimum=1)
    second = _integer(proof.get("toSize"), "toSize", minimum=1)
    path = _hash_list(proof.get("consistencyPath"), "consistencyPath")
    names = ("fromSignedTreeHead", "toSignedTreeHead")
    heads = [_tree_head(proof.get(name), name) for name in names]
    if (first, second) != (heads[0][0], heads[1][0]):
        raise _Reject("PARSE_ERROR", "fromSize and toSize are not the treeSize of the two tree heads")
    if first >= second:
        raise _Reject("PARSE_ERROR", f"fromSize {first} is not below toSize {second}")
    for name, (_, root, signed_by, signature) in zip(names, heads):
        _check_tree_head(name, root, signed_by, signature, keys)
    if _consistency_roots(first, second, path, heads[0][1]) != (heads[0][1], heads[1][1]):
        raise _Reject(
            "PROOF_INVALID",
            "consistencyPath does not lead to fromSignedTreeHead.rootHash and toSignedTreeHead.rootHash",
        )


# Revocation (Section 8.1)


def verify_revocation_list(body: Any) -> VerifyResult:
    """Section 8.1: the members of a revocation response. A malformed
    timestamp rejects the whole response; an entry without a
    transparencyLogIndex, or with a reason this client does not recognise,
    does not. The response is unsigned, so nothing here is a signature check."""
    return _outcome(lambda: _check_revocation_list(body))


def _check_revocation_list(body: Any) -> None:
    if not isinstance(body, dict):
        raise _Reject("PARSE_ERROR", "the revocation response is not a JSON object")
    revocations = body.get("revocations")
    if not isinstance(revocations, list):
        raise _Reject("PARSE_ERROR", "revocations is missing or not an array")
    _instant(body.get("nextSince"), "nextSince")
    for index, entry in enumerate(revocations):
        name = f"revocations[{index}]"
        if not isinstance(entry, dict):
            raise _Reject("PARSE_ERROR", f"{name} is not a JSON object")
        agent = entry.get("agentDid")
        if not isinstance(agent, str) or not agent.startswith("did:"):
            raise _Reject("PARSE_ERROR", f"{name}.agentDid is missing or not a DID")
        _instant(entry.get("revokedAt"), f"{name}.revokedAt")
        if "reason" not in entry:
            raise _Reject("PARSE_ERROR", f"{name}.reason is missing")
        key_id = entry.get("revokedByKeyId")
        if not isinstance(key_id, str) or "#" not in key_id:
            raise _Reject("PARSE_ERROR", f"{name}.revokedByKeyId is missing or has no fragment")
        if entry.get("transparencyLogIndex") is not None:
            _integer(entry["transparencyLogIndex"], f"{name}.transparencyLogIndex", minimum=0)


# Network


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _no_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


class AtpClient:
    """A client of one trust authority, named by its base URL.

    get_trust_proof and get_discovery send requests; verify checks a proof
    offline against the authority's discovery document, which is fetched once
    and kept. Pass discovery to verify against a stored copy instead."""

    def __init__(self, base_url: str, *, discovery: dict[str, Any] | None = None, timeout: float = 10.0) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.query or parts.fragment:
            raise ValueError("base_url must be an http or https URL without a query or fragment")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._discovery = discovery

    def get_discovery(self) -> dict[str, Any]:
        """The Section 7.1 discovery document from /.well-known/atp, or from
        the legacy /.well-known/opena2a when the first answers 404."""
        if self._discovery is None:
            try:
                document = self._get("/.well-known/atp")
            except AtpError as error:
                if error.status != 404:
                    raise
                document = self._get("/.well-known/opena2a")
            if not isinstance(document, dict):
                raise AtpError("the discovery document is not a JSON object")
            self._discovery = document
        return self._discovery

    def get_trust_proof(self, did: str) -> dict[str, Any]:
        """The current trust proof for did (Section 4.5). A proof the authority
        wraps under "proof" is unwrapped; a proof about another DID raises."""
        body = self._get("/api/v1/trust/proof?did=" + urllib.parse.quote(did, safe=""))
        proof = body.get("proof", body) if isinstance(body, dict) else None
        if not isinstance(proof, dict) or proof.get("did") != did:
            raise AtpError(f"the authority did not answer with a trust proof for {did}")
        return proof

    def verify(self, proof: Any, *, now: datetime | str | None = None) -> VerifyResult:
        """verify_trust_proof against this authority: its discovery document's
        publicKeys, and its authorityDid as the one trusted issuer. A discovery
        document that verify_discovery refuses, one that declares an issuer
        key set among them, rejects the proof with that category."""
        discovery = self.get_discovery()
        checked = verify_discovery(discovery)
        if not checked.valid:
            return VerifyResult(False, checked.category, f"discovery document: {checked.reason}")
        return verify_trust_proof(proof, discovery["publicKeys"], discovery["authorityDid"], now=now)

    def _get(self, path: str) -> Any:
        request = urllib.request.Request(self.base_url + path, headers={"Accept": "application/json"})
        try:
            with _OPENER.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            error.close()
            note = "; redirects are not followed" if 300 <= error.code < 400 else ""
            raise AtpError(f"GET {path} answered HTTP {error.code}{note}", error.code) from None
        except (urllib.error.URLError, OSError) as error:
            raise AtpError(f"GET {path} failed: {getattr(error, 'reason', error)}") from None
        try:
            return json.loads(raw, parse_constant=_no_constant)
        except ValueError:
            raise AtpError(f"GET {path} did not answer with JSON") from None
