# ATP clients

A Python client for the [Agent Trust Protocol](../ATP-SPEC.md): it fetches a trust proof from an
authority and verifies it offline, with the issuer keys of the authority's discovery document.
It is not published to a package index; install it from a checkout of this repository.

## Python

The package declares Python 3.10 or later (its tests were run on 3.14) and `cryptography` 48
or later, which pip installs. ML-DSA-65 signatures need a `cryptography` built with OpenSSL 3.5
or later, as its wheels are.

```bash
pip install ./clients/python
```

```python
from atp_client import AtpClient

client = AtpClient("https://authority.example")  # the authority this verifier trusts
proof = client.get_trust_proof("did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem")
result = client.verify(proof)  # no request beyond the discovery document, fetched once
if not result.valid:
    raise SystemExit(f"{result.category}: {result.reason}")
```

`AtpClient` sends two kinds of request: `get_discovery()` reads `/.well-known/atp` (and
`/.well-known/opena2a` when the first answers 404), and `get_trust_proof(did)` reads
`/api/v1/trust/proof?did=...`, takes the proof from under `proof` when the authority wraps
it, and raises `AtpError` for a proof about another DID. Redirects are not followed. To verify
against a stored discovery document, with no request at all, pass it in:
`AtpClient(url, discovery=document)`.

The verify functions make no request:

| Function | Checks | Section |
|---|---|---|
| `verify_trust_proof(proof, keys, trusted_issuers, now=None)` | Steps 1 to 5 in order, without the issuer key set count of step 4: expiry, issuer, key lookup by `keyId`, every signature over the canonical string (Ed25519 and ML-DSA-65), at least one Ed25519 signature by a key of `issuerDid`, then trust level, score, verdict and the 24-hour window | 4.3, 4.4 |
| `verify_discovery(document, trusted_issuers=None)` | The members a verifier reads, each `endpoints` value a path that starts with `/` and holds no `#`, whitespace or control character, and each key's size for its algorithm; a document that carries `issuerKeySet` is refused | 7.1, 7.1.1 |
| `verify_signed_tree_head(sth, keys)` | The Ed25519 signature over the 32 root-hash bytes | 5.6 |
| `verify_inclusion_proof(proof, keys)` | The tree head, then the RFC 9162 Section 2.1.3.2 root | 5.4 |
| `verify_consistency_proof(proof, keys)` | Both tree heads, then the RFC 9162 Section 2.1.4.2 roots | 5.5 |
| `verify_revocation_list(body)` | Required members and RFC 3339 timestamps; an unrecognised `reason` is accepted | 8.1 |

Each returns a `VerifyResult`: `valid`, and for a rejection a `category` (`PARSE_ERROR`,
`EXPIRED`, `UNTRUSTED_ISSUER`, `SIGNATURE_INVALID`, `SEMANTIC_INVALID` or `PROOF_INVALID`) and
a `reason` naming the member or step. `canonical_string(proof)` returns the Section 4.3 string.

Not checked: Section 4.4 step 7 (a second authority's signature on levels 3 and 4, conformance
Level 3); Sigstore co-signatures (Section 4.3.1), so a proof carrying one is rejected as
step 4 requires of a verifier that does not implement that section; and the issuer key set
count of step 4 (Section 7.1.1). Since the specification forbids ignoring a set,
`verify_discovery` refuses a discovery document that carries `issuerKeySet` with
`SIGNATURE_INVALID`, so `AtpClient.verify` verifies no proof of an authority that declares one.
`verify_trust_proof` receives keys without the set: pass it only the keys of an authority whose
discovery document has no `issuerKeySet`. `verify_inclusion_proof` checks the proof it is
given; tying its `leafHash` to a trust proof (Section 5.2) is the caller's.

## Tests

[`fixtures/`](fixtures/) holds byte copies of the 14 fixtures of
[atp-conformance](https://github.com/opena2a-standards/atp-conformance) at commit
`24187d4538b4c32263e293d21ae29834792a3888`, with its `MANIFEST.sha256`. The tests check each
copy against that manifest, then check that every fixture gets the verdict and reject
category it pins. The other tests sign proofs, tree heads and trees with keys they generate,
and run the client against a local server on 127.0.0.1.

```bash
cd clients/python
pip install .
python -m unittest discover -s tests
```

To take a new fixture set, copy `fixtures/*.json` and `MANIFEST.sha256` from that repository
and update the commit above.
