# ATP clients

Two clients for the [Agent Trust Protocol](../ATP-SPEC.md), one in Python and one in
TypeScript: each fetches a trust proof from an authority and verifies it offline, with the
issuer keys of the authority's discovery document. Neither is published to a package index;
install one from a checkout of this repository.

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
result = client.verify(proof)  # no request beyond the discovery document, requested again after 300 seconds
if not result.valid:
    raise SystemExit(f"{result.category}: {result.reason}")
```

`AtpClient` sends two kinds of request: `get_discovery()` reads `/.well-known/atp` (and
`/.well-known/opena2a` when the first answers 404), and `get_trust_proof(did)` reads
`/api/v1/trust/proof?did=...`, takes the proof from under `proof` when the authority wraps
it, and raises `AtpError` for a proof about another DID. Redirects are not followed. The base
URL is an `https` URL, as Section 7.1 requires, or an `http` URL whose host is a loopback
address literal, an IPv4 address in `127.0.0.0/8` or the IPv6 address `::1`; otherwise the
constructor raises `ValueError`, for `http://localhost` too. The constructor also raises
`ValueError` for a base URL that holds a `?` or `#`, even with nothing after it, since the
client appends each request's path to the base URL. A request under an `http` URL is sent
directly, not through a proxy. A request that has not finished within `timeout` seconds (10
when absent) raises `AtpError`, also when the authority keeps sending a byte at a time, and
so does an answer body longer than `MAX_RESPONSE_BYTES`, 1,048,576 bytes.

The client keeps the discovery document it receives and requests it again once its copy is
more than `refresh_after` seconds old: 300 when absent, the Section 8.1 polling interval, and
at most 3600. The age of a copy is the time since the client received it plus the answer's
`Age` header. A key the authority removes (Section 8.2) stops verifying once a copy without
it arrives. When the client needs a new copy and cannot get one, `verify` raises `AtpError`
instead of returning a result: the request failed, or the copy arrived more than 3600
seconds old (`MAX_DISCOVERY_AGE`, the Section 7.1 maximum age) or with an `Age` that is not a
number of seconds. To start from a stored copy, pass it with its age in seconds:
`AtpClient(url, discovery=document, discovery_age=age)` requests no discovery document until
that copy is more than `refresh_after` seconds old.

The verify functions make no request:

| Function | Checks | Section |
|---|---|---|
| `verify_trust_proof(proof, keys, trusted_issuers, now=None, second_authorities=None)` | Steps 1 to 5 in order, without the issuer key set count of step 4: expiry, issuer, key lookup by `keyId`, every signature over the canonical string (Ed25519 and ML-DSA-65), at least one Ed25519 signature by a key of `issuerDid`, then trust level, score, verdict and the 24-hour window; then step 7 when `second_authorities` is given | 4.3, 4.4 |
| `verify_discovery(document, trusted_issuers=None)` | The members a verifier reads, each `endpoints` value a path that starts with `/` and holds no `#`, whitespace or control character, and each key's size for its algorithm; a document that carries `issuerKeySet` is refused | 7.1, 7.1.1 |
| `verify_signed_tree_head(sth, keys)` | The Ed25519 signature over the 32 root-hash bytes | 5.6 |
| `verify_inclusion_proof(proof, keys)` | The tree head, then the RFC 9162 Section 2.1.3.2 root | 5.4 |
| `verify_consistency_proof(proof, keys)` | Both tree heads, then the RFC 9162 Section 2.1.4.2 roots | 5.5 |
| `verify_revocation_list(body)` | Required members and RFC 3339 timestamps; an unrecognised `reason` is accepted | 8.1 |

Each returns a `VerifyResult`: `valid`, and for a rejection a `category` (`PARSE_ERROR`,
`EXPIRED`, `UNTRUSTED_ISSUER`, `SIGNATURE_INVALID`, `SEMANTIC_INVALID` or `PROOF_INVALID`) and
a `reason` naming the member or step. `canonical_string(proof)` returns the Section 4.3 string.
Text the reason takes from the input, such as a DID, a `keyId` or a `verdict`, is unchanged
when it is printable ASCII without a space, a quote or a backslash, and in JSON string form
otherwise, so a control character in it is escaped. An `endpoints` member name is written
`endpoints.name` when it is an identifier (ASCII letters, digits and `_`, not starting with a
digit) and `endpoints["name"]` otherwise: for `"endpoints": {"x\ny": "z"}` the reason is
`endpoints["x\ny"] does not start with /`.
A `did`, `verdict` or `issuerDid` that holds a lone surrogate, which `json.loads` reads from
an escape such as `\ud800`, has no UTF-8 encoding to sign: `verify_trust_proof` rejects it
with `PARSE_ERROR` and `canonical_string` raises `ValueError`.

Not checked: Sigstore co-signatures (Section 4.3.1), so a proof carrying one is rejected as
step 4 requires of a verifier that does not implement that section; and the issuer key set
count of step 4 (Section 7.1.1). Since the specification forbids ignoring a set,
`verify_discovery` refuses a discovery document that carries `issuerKeySet` with
`SIGNATURE_INVALID`, so `AtpClient.verify` verifies no proof of an authority that declares one.
`verify_trust_proof` receives keys without the set: pass it only the keys of an authority whose
discovery document has no `issuerKeySet`. `verify_inclusion_proof` checks the proof it is
given; tying its `leafHash` to a trust proof (Section 5.2) is the caller's.

### Two authorities (conformance Level 3)

Section 4.4 step 7 requires a proof at trust level 3 or 4 to carry an Ed25519 signature by a
second trust authority, one the verifier knows from its own configuration. `verify_trust_proof`
applies it when it is given `second_authorities`, which maps the DID of each such authority to
that authority's `publicKeys` entries:

```python
from atp_client import AtpClient, verify_discovery, verify_trust_proof

issuer = AtpClient("https://authority.example").get_discovery()
cosigner = AtpClient("https://cosigner.example").get_discovery()  # a second authority this verifier knows
for document in (issuer, cosigner):
    checked = verify_discovery(document)
    if not checked.valid:
        raise SystemExit(f"{checked.category}: {checked.reason}")
result = verify_trust_proof(
    proof,
    issuer["publicKeys"],
    issuer["authorityDid"],
    second_authorities={cosigner["authorityDid"]: cosigner["publicKeys"]},
)
```

A signature whose `keyId` names one of those DIDs resolves only among that authority's
entries, so a key the issuer's discovery document lists under that `keyId` does not verify it.
A proof at trust level 3 or 4 is rejected with `SIGNATURE_INVALID` unless an Ed25519 signature
verified under a key of one of those authorities, and that authority shares no public key with
the entries of `keys` whose `keyId` names `issuerDid`. Without `second_authorities`, step 7 is
not checked: the fixtures pin their verdicts for such a verifier, and the baseline fixture, a
proof one authority signs at trust level 3, is pinned ACCEPT and fails step 7.
`AtpClient.verify` checks a proof against one authority's discovery document, so it does not
apply step 7, and it rejects a proof carrying a signature whose key that document does not
list (step 3).

## TypeScript

The package, `@opena2a/atp-client`, declares Node.js 22 or later (its tests were run on
22.23.3, 24.13.1 and 26.12.0) and has no runtime dependencies: it uses the `crypto` module
and `fetch` of Node.js. ML-DSA-65 signatures need a Node.js whose `crypto` module has
ML-DSA-65 keys, as 26.12.0 has.
`npm ci` installs the build's two dev dependencies, `typescript` and `@types/node`, at the
versions `package-lock.json` pins:

```bash
cd clients/typescript
npm ci
npm run build
```

Then, from the project that uses it, run `npm install <path to clients/typescript>`.

```typescript
import { AtpClient } from "@opena2a/atp-client";

const client = new AtpClient("https://authority.example"); // the authority this verifier trusts
const proof = await client.getTrustProof("did:opena2a:mcp_server:@modelcontextprotocol/server-filesystem");
const result = await client.verify(proof); // no request beyond the discovery document, requested again after 300 seconds
if (!result.valid) throw new Error(`${result.category}: ${result.reason}`);
```

It has the Python client's functions, named in camelCase, and sends the same two kinds of
request. `getDiscovery()`, `getTrustProof(did)` and `verify(proof, { now })` return promises;
`verifyTrustProof(proof, keys, trustedIssuers, { now })`, `verifyDiscovery(document,
trustedIssuers)`, `verifySignedTreeHead(sth, keys)`, `verifyInclusionProof(proof, keys)`,
`verifyConsistencyProof(proof, keys)` and `verifyRevocationList(body)` make the checks of the
table above except the two named below, leave unchecked what the Python client leaves
unchecked and return a `VerifyResult` whose `category` is `null` for a valid input. `now` is
a `Date` or an RFC 3339 string. Where the Python client raises `ValueError`, this one throws
a `TypeError`: the constructor throws one for a base URL that holds a `?` or `#`, even with
nothing after it, and `getTrustProof` throws one for a `did` that holds a lone surrogate,
before it sends a request. An `AtpError` carries `status`, `null` when the authority gave no
HTTP status.

The base URL is an `https` URL, or an `http` URL whose host is a loopback address literal,
an IPv4 address in `127.0.0.0/8` written as four decimal numbers or the IPv6 address `::1`;
otherwise the constructor throws a `TypeError`, for `http://localhost` and `http://127.1`
too. An answer body longer than `MAX_RESPONSE_BYTES`, 1,048,576 bytes, rejects with
`AtpError`. The client keeps the discovery document it receives and requests it again once
its copy is more than `refreshAfterMs` milliseconds old: 300000 when absent, the Section 8.1
polling interval, and at most 3600000 (`MAX_DISCOVERY_AGE_MS`). The age of a copy is the
time since the client received it plus the answer's `Age` header. When the client needs a new
copy and cannot get one, `verify` rejects with `AtpError` instead of returning a result: the
request failed, or the copy arrived more than 3600 seconds old or with an `Age` that is not
a number of seconds. `new AtpClient(url, { discovery, discoveryAgeMs, refreshAfterMs,
timeoutMs })` takes a stored copy, its age (0 when absent), the age past which the client
requests the document again, and a request timeout (10000 when absent), each in
milliseconds, where the Python client counts seconds.

Text a reason takes from the input follows the Python client's rule in both clients: it is
unchanged when it is printable ASCII without a space, a quote or a backslash, and otherwise
in JSON string form, with each character outside printable ASCII escaped as `json.dumps`
escapes it. For a proof whose `issuerDid`, `did:example:a`, a line feed and `b`, is not a
trusted issuer, both clients give the reason
`issuerDid "did:example:a\nb" is not a trusted issuer`. `verifyDiscovery` puts no
`endpoints` member name in a reason, so the `endpoints["name"]` form has no counterpart here.

Not checked by this client, though the Python client checks them: Section 4.4 step 7, since
`verifyTrustProof` has no counterpart of `second_authorities` and so never applies it; and
the Section 7.1 form of an `endpoints` value, since `verifyDiscovery` accepts any non-empty
string there, where `verify_discovery` requires a path that starts with `/` and holds no
`#`, whitespace or control character.

## Tests

[`fixtures/`](fixtures/) holds byte copies of the 14 fixtures of
[atp-conformance](https://github.com/opena2a-standards/atp-conformance) at commit
`24187d4538b4c32263e293d21ae29834792a3888`, with its `MANIFEST.sha256`. The tests of each
client check each copy against that manifest, then check that every fixture gets the verdict
and reject category it pins. The other tests sign proofs, tree heads and trees with keys they
generate, and run the client against a local server on 127.0.0.1. One reads the Section 4.4.1
proof and its key table from `ATP-SPEC.md`: the proof verifies with the co-signer's key in
`second_authorities`, and fails step 7 without the co-signer's entry.

```bash
cd clients/python
pip install .
python -m unittest discover -s tests
```

```bash
cd clients/typescript
npm ci
npm test
```

`npm test` builds `src/` and `test/` into `dist/` and runs `dist/test/atp-client.test.js`
with the Node.js test runner. On a Node.js that cannot generate ML-DSA-65 keys, as 22.23.3
cannot, it skips the one test that generates them and prints why; the fixture tests still
verify the hybrid fixture's ML-DSA-65 signature there.

To take a new fixture set, copy `fixtures/*.json` and `MANIFEST.sha256` from that repository
and update the commit above.
