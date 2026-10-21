/**
 * Tests for @opena2a/atp-client.
 *
 * Every conformance fixture in clients/fixtures must get the verdict and
 * reject category its expected block pins. The other tests sign proofs, tree
 * heads and trees with keys generated here and check each Section 4.4 step,
 * the RFC 9162 proof algorithms and the client's requests against a local
 * server on 127.0.0.1.
 *
 * Run from clients/typescript, after npm ci: npm test (it builds src/ and
 * test/ into dist/ first).
 */

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, it } from "node:test";

import * as atp from "../src/index.js";

// The compiled tests run from dist/test/, three directories below clients/.
const FIXTURES = new URL("../../../fixtures/", import.meta.url);
const AUTHORITY = "did:opena2a:authority:authority.example";
const AGENT = "did:opena2a:agent:example-agent";
const CLOCK = "2026-05-24T00:00:00Z";
const ACCEPTED: atp.VerifyResult = { valid: true, category: null, reason: "" };

type Algorithm = "Ed25519" | "ML-DSA-65";
type Members = Record<string, unknown>;

interface Fixture {
  readonly fixtureType: string;
  readonly verifierState: {
    readonly clockRfc3339: string;
    readonly trustedIssuers: string[];
    readonly publicKeys: unknown[];
  };
  readonly expected: { readonly verifyResult: string; readonly rejectCategory?: string; readonly reasonContains?: string };
  readonly [member: string]: unknown;
}

function fixture(name: string): Fixture {
  return JSON.parse(readFileSync(new URL(`${name}.json`, FIXTURES), "utf8")) as Fixture;
}

function fixtureNames(): string[] {
  return readdirSync(FIXTURES)
    .filter((name) => name.endsWith(".json"))
    .sort();
}

function runFixture(document: Fixture): atp.VerifyResult {
  const state = document.verifierState;
  switch (document.fixtureType) {
    case "trustProof":
      return atp.verifyTrustProof(document["trustProof"], state.publicKeys, state.trustedIssuers, {
        now: state.clockRfc3339,
      });
    case "discovery":
      return atp.verifyDiscovery(document["discoveryResponse"], state.trustedIssuers);
    case "sth":
      return atp.verifySignedTreeHead(document["signedTreeHead"], state.publicKeys);
    case "inclusionProof":
      return atp.verifyInclusionProof(document["inclusionProof"], state.publicKeys);
    case "consistencyProof":
      return atp.verifyConsistencyProof(document["consistencyProof"], state.publicKeys);
    case "revocationList":
      return atp.verifyRevocationList(document["revocationList"]);
  }
  throw new Error(`unknown fixtureType ${document.fixtureType}`);
}

// The @types/node release for Node.js 22 lists no "ml-dsa-65" key type.
const generate = generateKeyPairSync as (type: string) => { publicKey: KeyObject; privateKey: KeyObject };

/**
 * Why a test that generates ML-DSA-65 keys is skipped, or false where this
 * Node.js generates them. Node.js 22.23.3 verifies ML-DSA-65 signatures, so
 * the fixture tests run there, but refuses to generate the keys.
 */
const NO_ML_DSA_KEYS = ((): string | false => {
  try {
    generate("ml-dsa-65");
    return false;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return `Node.js ${process.version} cannot generate ML-DSA-65 keys: ${detail}`;
  }
})();

/** A key generated for one test, with the Section 7.1 entry naming it. */
class Signer {
  readonly keyId: string;
  readonly algorithm: Algorithm;
  readonly publicKeyHex: string;
  readonly #privateKey: KeyObject;

  constructor(keyId = `${AUTHORITY}#key-1`, algorithm: Algorithm = "Ed25519") {
    const pair = generate(algorithm === "Ed25519" ? "ed25519" : "ml-dsa-65");
    const jwk = pair.publicKey.export({ format: "jwk" }) as { x?: unknown; pub?: unknown };
    const encoded = algorithm === "Ed25519" ? jwk.x : jwk.pub;
    assert.equal(typeof encoded, "string");
    this.keyId = keyId;
    this.algorithm = algorithm;
    this.publicKeyHex = Buffer.from(encoded as string, "base64url").toString("hex");
    this.#privateKey = pair.privateKey;
  }

  key(members: Members = {}): Members {
    return { keyId: this.keyId, algorithm: this.algorithm, publicKeyHex: this.publicKeyHex, ...members };
  }

  sign(message: Buffer): string {
    return sign(null, message, this.#privateKey).toString("base64");
  }

  entry(message: Buffer): Members {
    return { keyId: this.keyId, algorithm: this.algorithm, value: this.sign(message) };
  }
}

/**
 * A trust proof about AGENT from AUTHORITY, with members replacing the
 * defaults, signed by signers over its canonical string (or canonical).
 */
function signedProof(signers: Signer[], members: Members = {}, canonical?: string): Members {
  const proof: Members = {
    did: AGENT,
    trustLevel: 3,
    trustScore: 0.5,
    verdict: "passed",
    issuedAt: "2026-05-23T12:00:00Z",
    expiresAt: "2026-05-24T06:00:00Z",
    issuerDid: AUTHORITY,
    signatures: [],
    ...members,
  };
  const message = Buffer.from(canonical ?? atp.canonicalString(proof), "utf8");
  proof["signatures"] = signers.map((signer) => signer.entry(message));
  return proof;
}

function signatures(proof: Members): Members[] {
  return proof["signatures"] as Members[];
}

function flipFirstByte(text: string): string {
  const raw = Buffer.from(text, "base64");
  raw[0] = (raw[0] ?? 0) ^ 0xff;
  return raw.toString("base64");
}

function assertRejected(result: atp.VerifyResult, category: atp.RejectCategory, reason = ""): void {
  assert.equal(result.valid, false, JSON.stringify(result));
  assert.equal(result.category, category, JSON.stringify(result));
  assert.ok(result.reason.includes(reason), `${JSON.stringify(result)} does not name ${reason}`);
}

describe("conformance fixtures", () => {
  it("each fixture's bytes match the suite's manifest", () => {
    const lines = readFileSync(new URL("MANIFEST.sha256", FIXTURES), "ascii").trim().split("\n");
    const pins = new Map(
      lines.map((line) => {
        const [digest, path] = line.split("  fixtures/");
        return [path, digest] as const;
      }),
    );
    assert.equal(pins.size, 14);
    assert.deepEqual([...pins.keys()].sort(), fixtureNames());
    for (const [name, digest] of pins) {
      const actual = createHash("sha256")
        .update(readFileSync(new URL(name ?? "", FIXTURES)))
        .digest("hex");
      assert.equal(actual, digest, name);
    }
  });

  it("each fixture gets its pinned verdict", () => {
    const names = fixtureNames();
    assert.equal(names.length, 14);
    for (const name of names) {
      const document = fixture(name.replace(/\.json$/, ""));
      const expected = document.expected;
      const result = runFixture(document);
      const label = `${name}: ${JSON.stringify(result)}`;
      assert.equal(result.valid, expected.verifyResult === "ACCEPT", label);
      assert.equal(result.category, expected.rejectCategory ?? null, label);
      assert.ok(result.reason.includes(expected.reasonContains ?? ""), label);
    }
  });

  it("the fixture proofs verify under the discovery fixture's keys", async () => {
    const discovery = fixture("discovery-valid")["discoveryResponse"] as Members;
    const client = new atp.AtpClient("https://authority.example", { discovery });
    for (const name of ["trust-proof-baseline", "trust-proof-hybrid"]) {
      const proof = fixture(name)["trustProof"];
      const keys = discovery["publicKeys"] as unknown[];
      const result = atp.verifyTrustProof(proof, keys, discovery["authorityDid"] as string, { now: CLOCK });
      assert.deepEqual(result, ACCEPTED, name);
      assert.deepEqual(await client.verify(proof, { now: CLOCK }), ACCEPTED, name);
    }
  });

  it("a tampered ML-DSA-65 signature on the hybrid fixture is rejected", () => {
    const document = fixture("trust-proof-hybrid");
    const entry = signatures(document["trustProof"] as Members)[1] as Members;
    assert.equal(entry["algorithm"], "ML-DSA-65");
    entry["value"] = flipFirstByte(entry["value"] as string);
    assertRejected(runFixture(document), "SIGNATURE_INVALID", "ML-DSA-65 signature");
  });
});

describe("canonicalString", () => {
  const base = (): Members => fixture("trust-proof-baseline")["trustProof"] as Members;
  const member = (members: Members, index: number): string | undefined =>
    atp.canonicalString({ ...base(), ...members }).split("|")[index];

  it("writes the baseline fixture's string", () => {
    assert.equal(
      atp.canonicalString(base()),
      "did:opena2a:mcp_server:agent_conformance_test_001|3|0.825000|passed" +
        "|2026-05-23T12:00:00Z|2026-05-24T06:00:00Z|did:opena2a:authority:opena2a.org",
    );
  });

  it("reduces served timestamps to whole UTC seconds", () => {
    // The table in Section 4.3, and an instant before 1970 with a fraction.
    const rows: [string, string][] = [
      ["2026-05-23T12:00:00Z", "2026-05-23T12:00:00Z"],
      ["2026-10-12T02:57:21.581346834Z", "2026-10-12T02:57:21Z"],
      ["2026-10-12T02:57:21.999Z", "2026-10-12T02:57:21Z"],
      ["2026-10-11T20:57:21.5-06:00", "2026-10-12T02:57:21Z"],
      ["1969-12-31T23:59:59.5Z", "1969-12-31T23:59:59Z"],
    ];
    for (const [served, signed] of rows) assert.equal(member({ issuedAt: served }, 4), signed, served);
  });

  it("writes trustScore to six places with a tie to even", () => {
    const rows: [number, string][] = [
      [0.0078125, "0.007812"],
      [0.0234375, "0.023438"],
      [1, "1.000000"],
      [0.825, "0.825000"],
    ];
    for (const [score, written] of rows) assert.equal(member({ trustScore: score }, 2), written, String(score));
  });

  it("writes a number from its exact binary value, as %.6f and Python's str(int) do", () => {
    assert.equal(member({ trustScore: -0 }, 2), "-0.000000");
    assert.equal(member({ trustScore: 1e21 }, 2), "1000000000000000000000.000000");
    assert.equal(member({ trustLevel: 1e21 }, 1), "1000000000000000000000");
  });

  it("writes a trustLevel with a zero fraction as an integer", () => {
    assert.equal(member(JSON.parse('{"trustLevel": 4.0}') as Members, 1), "4");
  });

  it("throws for a proof it cannot read", () => {
    assert.throws(() => atp.canonicalString({ did: AGENT }), TypeError);
    assert.throws(() => atp.canonicalString([]), TypeError);
  });
});

describe("verifyTrustProof", () => {
  let signer: Signer;
  let keys: Members[];

  beforeEach(() => {
    signer = new Signer();
    keys = [signer.key({ status: "active" })];
  });

  const verify = (
    proof: unknown,
    options: { keys?: unknown[]; trusted?: string | string[]; now?: Date | string } = {},
  ): atp.VerifyResult => atp.verifyTrustProof(proof, options.keys ?? keys, options.trusted ?? AUTHORITY, { now: options.now ?? CLOCK });

  it("accepts a proof signed by a trusted key", () => {
    assert.deepEqual(verify(signedProof([signer])), ACCEPTED);
  });

  it("step 1: a proof is expired at its expiry instant", () => {
    const proof = signedProof([signer]);
    assertRejected(verify(proof, { now: "2026-05-24T06:00:00Z" }), "EXPIRED", "expired");
    assert.deepEqual(verify(proof, { now: "2026-05-24T05:59:59.999999Z" }), ACCEPTED);
    assert.deepEqual(verify(proof, { now: new Date("2026-05-24T05:59:00Z") }), ACCEPTED);
  });

  it("step 2: an issuer outside the trusted set is rejected", () => {
    const result = verify(signedProof([signer]), { trusted: ["did:opena2a:authority:other.example"] });
    assertRejected(result, "UNTRUSTED_ISSUER", AUTHORITY);
  });

  it("step 3: a keyId that resolves to no usable key is rejected", () => {
    const proof = signedProof([signer]);
    const cases: [string, unknown[]][] = [
      ["unknown keyId", [new Signer(`${AUTHORITY}#key-2`).key()]],
      ["revoked key", [signer.key({ status: "revoked" })]],
      ["key of another algorithm", [signer.key({ algorithm: "ML-DSA-65" })]],
      ["key that is not 32 bytes", [signer.key({ publicKeyHex: "ab".repeat(31) })]],
    ];
    for (const [label, caseKeys] of cases) {
      const result = verify(proof, { keys: caseKeys });
      assert.equal(result.category, "SIGNATURE_INVALID", label);
      assert.ok(result.reason.includes("does not resolve"), label);
    }
  });

  it("step 4: a signature over other bytes is rejected", () => {
    const proof = signedProof([signer]);
    proof["trustLevel"] = 4;
    assertRejected(verify(proof), "SIGNATURE_INVALID", "did not verify");
  });

  it("step 4: needs an Ed25519 signature by a key of the issuer", () => {
    const other = new Signer("did:opena2a:authority:other.example#key-1");
    const result = verify(signedProof([other]), { keys: [other.key()] });
    assertRejected(result, "SIGNATURE_INVALID", `no Ed25519 signature by a key of ${AUTHORITY}`);
  });

  it("step 4: a hybrid proof needs both signatures to verify", { skip: NO_ML_DSA_KEYS }, () => {
    const pqc = new Signer(`${AUTHORITY}#key-1-pqc`, "ML-DSA-65");
    const hybridKeys = [signer.key(), pqc.key()];
    const proof = signedProof([signer, pqc]);
    assert.deepEqual(verify(proof, { keys: hybridKeys }), ACCEPTED);
    const entry = signatures(proof)[1] as Members;
    entry["value"] = flipFirstByte(entry["value"] as string);
    assertRejected(verify(proof, { keys: hybridKeys }), "SIGNATURE_INVALID", "ML-DSA-65 signature");
    assertRejected(verify(signedProof([pqc]), { keys: hybridKeys }), "SIGNATURE_INVALID", "no Ed25519 signature");
  });

  it("step 4: a Sigstore co-signature is rejected", () => {
    const proof = signedProof([signer]);
    signatures(proof).push({ keyId: "https://ci.example/workflow", algorithm: "Sigstore", bundle: {} });
    assertRejected(verify(proof), "SIGNATURE_INVALID", "Sigstore");
  });

  it("step 5: semantic rules", () => {
    const cases: [string, Members][] = [
      ["trustLevel", { trustLevel: 5 }],
      ["trustScore", { trustScore: 1.5 }],
      ["verdict", { verdict: "approved" }],
      ["issuedAt is not before", { issuedAt: "2026-05-24T06:00:00Z" }],
      ["longer than 24 hours", { issuedAt: "2026-05-23T05:59:59Z" }],
    ];
    for (const [reason, members] of cases) {
      assertRejected(verify(signedProof([signer], members)), "SEMANTIC_INVALID", reason);
    }
  });

  it("step 5: the window is compared to the microsecond", () => {
    const exactly = signedProof([signer], { issuedAt: "2026-05-23T06:00:00Z", expiresAt: "2026-05-24T06:00:00Z" });
    assert.deepEqual(verify(exactly), ACCEPTED);
    // The canonical string drops the fraction, so the signature still
    // verifies; the served expiresAt is 24 hours and 1 microsecond after.
    const longer = signedProof([signer], { issuedAt: "2026-05-23T06:00:00Z", expiresAt: "2026-05-24T06:00:00.000001Z" });
    assertRejected(verify(longer), "SEMANTIC_INVALID", "longer than 24 hours");
  });

  it("verifies served fractions and offsets against the whole-second string", () => {
    const canonical = `${AGENT}|3|0.500000|passed|2026-10-12T02:57:21Z|2026-10-12T20:57:21Z|${AUTHORITY}`;
    const proof = signedProof(
      [signer],
      { issuedAt: "2026-10-11T20:57:21.5-06:00", expiresAt: "2026-10-12T20:57:21.581346834Z" },
      canonical,
    );
    assert.deepEqual(verify(proof, { now: "2026-10-12T12:00:00Z" }), ACCEPTED);
  });

  it("rejects members it cannot read as parse errors", () => {
    const cases: [string, Members][] = [
      ["trustLevel as a string", { trustLevel: "3" }],
      ["trustLevel as true", { trustLevel: true }],
      ["trustScore as null", { trustScore: null }],
      ["lower-case t", { issuedAt: "2026-05-23t12:00:00Z" }],
      ["a space for T", { issuedAt: "2026-05-23 12:00:00Z" }],
      ["no zone", { issuedAt: "2026-05-23T12:00:00" }],
      ["February 30", { issuedAt: "2026-02-30T12:00:00Z" }],
      ["second 60", { issuedAt: "2026-05-23T12:00:60Z" }],
      ["hour 24", { expiresAt: "2026-05-24T24:00:00Z" }],
      ["offset hour 24", { expiresAt: "2026-05-24T06:00:00+24:00" }],
      ["year 0", { issuedAt: "0000-05-23T12:00:00Z" }],
      ["negative log index", { transparencyLogIndex: -1 }],
    ];
    for (const [label, members] of cases) {
      assert.equal(verify({ ...signedProof([signer]), ...members }).category, "PARSE_ERROR", label);
    }
    assert.equal(verify({ ...signedProof([signer]), signatures: [] }).category, "PARSE_ERROR");
    assert.equal(verify([]).category, "PARSE_ERROR");
  });

  it("refuses a lone surrogate, which UTF-8 cannot encode", () => {
    // Buffer.from writes a lone surrogate as U+FFFD, so without the check a
    // proof signed for the DID "x�" would verify for the DID "x\uD800".
    const signed = signedProof([signer], { did: "did:opena2a:agent:x�" });
    const served = { ...signed, did: "did:opena2a:agent:x\uD800" };
    assert.deepEqual(Buffer.from(served.did, "utf8"), Buffer.from(signed["did"] as string, "utf8"));
    assert.deepEqual(verify(signed), ACCEPTED);
    assertRejected(verify(served), "PARSE_ERROR", "did holds a lone surrogate");
    const cases: [string, string][] = [
      ["verdict", "passed\uDC00"],
      ["issuerDid", `${AUTHORITY}\uD800`],
    ];
    for (const [name, value] of cases) {
      assertRejected(verify({ ...signed, [name]: value }), "PARSE_ERROR", `${name} holds a lone surrogate`);
    }
  });

  it("throws for a clock it cannot read", () => {
    const proof = signedProof([signer]);
    for (const now of ["yesterday", new Date(Number.NaN), 0 as unknown as string]) {
      assert.throws(() => verify(proof, { now }), TypeError, String(now));
    }
  });
});

/**
 * A log of leaves hashed as RFC 6962 Section 2.1 defines, with PATH and
 * PROOF built from its recursive definitions.
 */
class Tree {
  readonly leaves: Buffer[];

  constructor(size: number) {
    this.leaves = Array.from({ length: size }, (_, index) =>
      createHash("sha256").update(Buffer.from([0])).update(`entry ${index}`).digest(),
    );
  }

  static split(n: number): number {
    let k = 1;
    while (k * 2 < n) k *= 2;
    return k;
  }

  root(leaves: readonly Buffer[] = this.leaves): Buffer {
    if (leaves.length === 1) return leaves[0] as Buffer;
    const k = Tree.split(leaves.length);
    return node(this.root(leaves.slice(0, k)), this.root(leaves.slice(k)));
  }

  path(m: number, leaves: readonly Buffer[] = this.leaves): Buffer[] {
    if (leaves.length === 1) return [];
    const k = Tree.split(leaves.length);
    if (m < k) return [...this.path(m, leaves.slice(0, k)), this.root(leaves.slice(k))];
    return [...this.path(m - k, leaves.slice(k)), this.root(leaves.slice(0, k))];
  }

  proof(m: number, leaves: readonly Buffer[] = this.leaves, whole = true): Buffer[] {
    if (m === leaves.length) return whole ? [] : [this.root(leaves)];
    const k = Tree.split(leaves.length);
    if (m <= k) return [...this.proof(m, leaves.slice(0, k), whole), this.root(leaves.slice(k))];
    return [...this.proof(m - k, leaves.slice(k), false), this.root(leaves.slice(0, k))];
  }
}

function node(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256").update(Buffer.from([1])).update(left).update(right).digest();
}

function wire(digest: Buffer): string {
  return `SHA256:${digest.toString("hex")}`;
}

function altered(wireHash: string): string {
  const raw = Buffer.from(wireHash.slice("SHA256:".length), "hex");
  raw[0] = (raw[0] ?? 0) ^ 0xff;
  return wire(raw);
}

function replaced(path: readonly string[], position: number): string[] {
  return path.map((hash, index) => (index === position ? altered(hash) : hash));
}

describe("transparency log proofs", () => {
  let signer: Signer;
  let keys: Members[];

  beforeEach(() => {
    signer = new Signer();
    keys = [signer.key()];
  });

  const head = (size: number | bigint, root: Buffer): Members => ({
    treeSize: Number(size),
    timestamp: "2026-05-23T00:00:00Z",
    rootHash: wire(root),
    signedBy: signer.keyId,
    signature: signer.sign(root),
  });

  it("verifies an inclusion proof for every leaf of trees up to 17 leaves", () => {
    for (let size = 1; size <= 17; size += 1) {
      const tree = new Tree(size);
      const signedHead = head(size, tree.root());
      for (let index = 0; index < size; index += 1) {
        const path = tree.path(index).map(wire);
        const proof = { logIndex: index, leafHash: wire(tree.leaves[index] as Buffer), auditPath: path, signedTreeHead: signedHead };
        const label = `size ${size}, index ${index}`;
        assert.deepEqual(atp.verifyInclusionProof(proof, keys), ACCEPTED, label);
        for (let position = 0; position < path.length; position += 1) {
          const result = atp.verifyInclusionProof({ ...proof, auditPath: replaced(path, position) }, keys);
          assert.equal(result.category, "PROOF_INVALID", label);
        }
        const extended = { ...proof, auditPath: [...path, wire(Buffer.alloc(32))] };
        assert.equal(atp.verifyInclusionProof(extended, keys).category, "PROOF_INVALID", label);
      }
    }
  });

  it("verifies a consistency proof between every pair of sizes up to 17", () => {
    for (let second = 2; second <= 17; second += 1) {
      const later = new Tree(second);
      for (let first = 1; first < second; first += 1) {
        const earlier = new Tree(first);
        const path = later.proof(first).map(wire);
        const proof = {
          fromSize: first,
          toSize: second,
          consistencyPath: path,
          fromSignedTreeHead: head(first, earlier.root()),
          toSignedTreeHead: head(second, later.root()),
        };
        const label = `from ${first} to ${second}`;
        assert.deepEqual(atp.verifyConsistencyProof(proof, keys), ACCEPTED, label);
        for (let position = 0; position < path.length; position += 1) {
          const result = atp.verifyConsistencyProof({ ...proof, consistencyPath: replaced(path, position) }, keys);
          assert.equal(result.category, "PROOF_INVALID", label);
        }
      }
    }
  });

  it("verifies proofs of a log larger than 2 ** 32 entries", () => {
    // In a tree of 2 ** 33 equal leaves the subtrees of one height share a
    // root, so the audit path of every leaf is that root at each height.
    const levels: Buffer[] = [createHash("sha256").update(Buffer.from([0])).update("entry").digest()];
    for (let height = 1; height <= 33; height += 1) {
      const below = levels[height - 1] as Buffer;
      levels.push(node(below, below));
    }
    const size = 2n ** 33n;
    const proof = {
      logIndex: Number(2n ** 32n + 5n),
      leafHash: wire(levels[0] as Buffer),
      auditPath: levels.slice(0, 33).map(wire),
      signedTreeHead: head(size, levels[33] as Buffer),
    };
    assert.deepEqual(atp.verifyInclusionProof(proof, keys), ACCEPTED);
    assert.equal(atp.verifyInclusionProof({ ...proof, auditPath: levels.slice(0, 32).map(wire) }, keys).category, "PROOF_INVALID");
    const consistency = {
      fromSize: Number(2n ** 32n),
      toSize: Number(size),
      consistencyPath: [wire(levels[32] as Buffer)],
      fromSignedTreeHead: head(2n ** 32n, levels[32] as Buffer),
      toSignedTreeHead: head(size, levels[33] as Buffer),
    };
    assert.deepEqual(atp.verifyConsistencyProof(consistency, keys), ACCEPTED);
    const tampered = { ...consistency, consistencyPath: [altered(wire(levels[32] as Buffer))] };
    assert.equal(atp.verifyConsistencyProof(tampered, keys).category, "PROOF_INVALID");
  });

  it("rejects a tree head the keys do not sign", () => {
    const tree = new Tree(8);
    const signedHead = head(8, tree.root());
    assert.equal(atp.verifySignedTreeHead(signedHead, [new Signer().key()]).category, "SIGNATURE_INVALID");
    const otherKey = { ...signedHead, signedBy: `${AUTHORITY}#key-9` };
    assert.equal(atp.verifySignedTreeHead(otherKey, keys).category, "SIGNATURE_INVALID");
    const otherRoot = { ...signedHead, rootHash: wire(Buffer.alloc(32)) };
    assert.equal(atp.verifySignedTreeHead(otherRoot, keys).category, "SIGNATURE_INVALID");
  });

  it("rejects members outside their form as parse errors", () => {
    const tree = new Tree(4);
    const signedHead = head(4, tree.root());
    const proof = { logIndex: 4, leafHash: wire(tree.leaves[0] as Buffer), auditPath: [], signedTreeHead: signedHead };
    assert.equal(atp.verifyInclusionProof(proof, keys).category, "PARSE_ERROR");
    const upperCase = { ...signedHead, rootHash: (signedHead["rootHash"] as string).toUpperCase() };
    assert.equal(atp.verifySignedTreeHead(upperCase, keys).category, "PARSE_ERROR");
    const consistency = {
      fromSize: 4,
      toSize: 4,
      consistencyPath: [],
      fromSignedTreeHead: signedHead,
      toSignedTreeHead: signedHead,
    };
    assert.equal(atp.verifyConsistencyProof(consistency, keys).category, "PARSE_ERROR");
  });
});

describe("verifyRevocationList", () => {
  const ENTRY: Members = {
    agentDid: "did:opena2a:mcp_server:compromised-package",
    revokedAt: "2026-03-22T15:00:00Z",
    reason: "security_incident",
    revokedByKeyId: `${AUTHORITY}#key-1`,
  };
  const check = (entries: Members[], nextSince = "2026-03-22T15:00:00Z"): atp.VerifyResult =>
    atp.verifyRevocationList({ revocations: entries, nextSince });

  it("accepts the entries Section 8.1 tells a client to apply", () => {
    assert.deepEqual(check([]), ACCEPTED);
    assert.deepEqual(check([ENTRY]), ACCEPTED, "an entry without transparencyLogIndex");
    assert.deepEqual(check([{ ...ENTRY, reason: "x-operator_flag" }]), ACCEPTED);
    assert.deepEqual(check([{ ...ENTRY, reason: "Supply chain compromise detected" }]), ACCEPTED);
    assert.deepEqual(check([{ ...ENTRY, revokedAt: "2026-03-22T09:00:00-06:00" }]), ACCEPTED);
  });

  it("rejects the whole response for one malformed member", () => {
    const { reason: _reason, ...reasonMissing } = ENTRY;
    assert.equal(check([ENTRY, reasonMissing]).category, "PARSE_ERROR");
    assert.equal(check([ENTRY], "2026-03-22").category, "PARSE_ERROR");
    assert.equal(check([{ ...ENTRY, transparencyLogIndex: "7" }]).category, "PARSE_ERROR");
    assert.equal(atp.verifyRevocationList({ nextSince: "2026-03-22T15:00:00Z" }).category, "PARSE_ERROR");
  });
});

describe("verifyDiscovery", () => {
  const document = (): Members => fixture("discovery-valid")["discoveryResponse"] as Members;
  const firstKey = (): Members => (document()["publicKeys"] as Members[])[0] as Members;

  it("names a key without publicKeyHex", () => {
    const { publicKeyHex: _publicKeyHex, ...key } = firstKey();
    const result = atp.verifyDiscovery({ ...document(), publicKeys: [key] });
    assertRejected(result, "PARSE_ERROR", "publicKeys[0].publicKeyHex");
  });

  it("rejects other malformed documents", () => {
    const cases: [string, Members][] = [
      ["version", { version: "2.0" }],
      ["conformanceLevel", { conformanceLevel: 4 }],
      ["endpoints", { endpoints: {} }],
      ["publicKeys", { publicKeys: [] }],
    ];
    for (const [reason, members] of cases) {
      assertRejected(atp.verifyDiscovery({ ...document(), ...members }), "PARSE_ERROR", reason);
    }
  });

  it("rejects an authority outside the trusted set", () => {
    const result = atp.verifyDiscovery(document(), ["did:opena2a:authority:partner.example"]);
    assert.equal(result.category, "UNTRUSTED_ISSUER");
  });

  it("refuses a document that declares an issuer key set", () => {
    // The client does not count an issuer key set (Section 7.1.1), so it
    // refuses one that meets the rules as well as one that breaks them.
    const keyId = firstKey()["keyId"];
    const cases: [string, unknown][] = [
      ["a 1-of-1 set", { threshold: 1, keyIds: [keyId] }],
      ["a threshold above the number of keys", { threshold: 5, keyIds: [keyId] }],
      ["a keyId listed twice", { threshold: 1, keyIds: [keyId, keyId] }],
      ["null", null],
    ];
    for (const [label, keySet] of cases) {
      const result = atp.verifyDiscovery({ ...document(), issuerKeySet: keySet });
      assert.equal(result.category, "SIGNATURE_INVALID", label);
      assert.ok(result.reason.includes("issuerKeySet"), label);
    }
  });
});

/** An answer of the local authority: a status, a JSON value or raw bytes, and headers. */
interface Route {
  readonly status: number;
  readonly body?: unknown;
  readonly headers?: Record<string, string>;
}

/** An HTTP server on 127.0.0.1 that answers each path from its routes and records the requests. */
class Authority {
  readonly requests: string[] = [];
  routes = new Map<string, Route>();
  readonly #server: Server = createServer((request, response) => this.#answer(request, response));

  #answer(request: IncomingMessage, response: ServerResponse): void {
    const path = request.url ?? "";
    this.requests.push(path);
    const route = this.routes.get(new URL(path, "http://127.0.0.1").pathname) ?? {
      status: 404,
      body: { error: "not found" },
    };
    const body = route.body;
    const payload =
      body === undefined ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
    response.writeHead(route.status, { ...route.headers, "Content-Length": String(payload.length) });
    response.end(payload);
  }

  start(): Promise<string> {
    return new Promise((resolve) => {
      this.#server.listen(0, "127.0.0.1", () => {
        resolve(`http://127.0.0.1:${(this.#server.address() as AddressInfo).port}/`);
      });
    });
  }

  stop(): Promise<void> {
    this.#server.closeAllConnections();
    return new Promise((resolve) => this.#server.close(() => resolve()));
  }
}

describe("AtpClient", () => {
  let authority: Authority;
  let client: atp.AtpClient;
  let signer: Signer;
  let discovery: Members;

  beforeEach(async () => {
    authority = new Authority();
    client = new atp.AtpClient(await authority.start(), { timeoutMs: 5000 });
    signer = new Signer();
    discovery = {
      authorityDid: AUTHORITY,
      version: "1.0",
      endpoints: { trustProof: "/api/v1/trust/proof" },
      publicKeys: [signer.key({ status: "active", validFrom: "2026-01-01T00:00:00Z" })],
    };
  });

  afterEach(() => authority.stop());

  const count = (path: string): number => authority.requests.filter((sent) => sent === path).length;

  it("getTrustProof unwraps the proof, and verify checks it offline", async () => {
    const proof = signedProof([signer], { did: "did:opena2a:mcp_server:@scope/server name" });
    authority.routes = new Map<string, Route>([
      ["/.well-known/atp", { status: 200, body: discovery }],
      ["/api/v1/trust/proof", { status: 200, body: { algorithm: "ed25519", proof } }],
    ]);
    assert.deepEqual(await client.getTrustProof(proof["did"] as string), proof);
    const sent = authority.requests.at(-1) ?? "";
    assert.ok(sent.includes("did=did%3Aopena2a%3Amcp_server%3A%40scope%2Fserver%20name"), sent);
    assert.equal(new URL(sent, "http://127.0.0.1").searchParams.get("did"), proof["did"]);
    assert.deepEqual(await client.verify(proof, { now: CLOCK }), ACCEPTED);
    assert.equal(count("/.well-known/atp"), 1);
    assert.deepEqual(await client.verify(proof, { now: CLOCK }), ACCEPTED);
    assert.equal(count("/.well-known/atp"), 1, "the discovery document is kept");
  });

  it("fetches the discovery document once for concurrent calls, and again after a failure", async () => {
    authority.routes = new Map<string, Route>([["/.well-known/atp", { status: 500, body: { error: "unavailable" } }]]);
    await assert.rejects(client.getDiscovery(), atp.AtpError);
    authority.routes = new Map<string, Route>([["/.well-known/atp", { status: 200, body: discovery }]]);
    const proof = signedProof([signer]);
    const results = await Promise.all([client.verify(proof, { now: CLOCK }), client.verify(proof, { now: CLOCK })]);
    assert.deepEqual(results, [ACCEPTED, ACCEPTED]);
    assert.equal(count("/.well-known/atp"), 2, "one failed request, then one for both calls");
  });

  it("getTrustProof reads a proof served at the top level", async () => {
    const proof = signedProof([signer]);
    authority.routes = new Map<string, Route>([["/api/v1/trust/proof", { status: 200, body: proof }]]);
    assert.deepEqual(await client.getTrustProof(AGENT), proof);
  });

  it("throws for a proof about another DID", async () => {
    authority.routes = new Map<string, Route>([["/api/v1/trust/proof", { status: 200, body: { proof: signedProof([signer]) } }]]);
    await assert.rejects(client.getTrustProof("did:opena2a:agent:another-agent"), {
      name: "AtpError",
      message: /did not answer with a trust proof/,
    });
  });

  it("getTrustProof throws a TypeError for a did that UTF-8 cannot encode, before any request", async () => {
    for (const did of [`${AGENT}\uD800`, `${AGENT}\uDC00x`]) {
      await assert.rejects(client.getTrustProof(did), {
        name: "TypeError",
        message: "did holds a lone surrogate, which UTF-8 cannot encode",
      });
    }
    assert.deepEqual(authority.requests, []);
    // A surrogate pair is one character, which UTF-8 encodes, so its request is sent.
    await assert.rejects(
      client.getTrustProof(`${AGENT}\u{1F600}`),
      (error: unknown) => error instanceof atp.AtpError && error.status === 404,
    );
    assert.deepEqual(authority.requests, ["/api/v1/trust/proof?did=did%3Aopena2a%3Aagent%3Aexample-agent%F0%9F%98%80"]);
  });

  it("falls back to the legacy discovery path on 404", async () => {
    authority.routes = new Map<string, Route>([["/.well-known/opena2a", { status: 200, body: discovery }]]);
    assert.deepEqual(await client.getDiscovery(), discovery);
    assert.deepEqual(authority.requests, ["/.well-known/atp", "/.well-known/opena2a"]);
  });

  it("throws for error answers, with their status", async () => {
    authority.routes = new Map<string, Route>([
      ["/.well-known/atp", { status: 500, body: { error: "unavailable" } }],
      ["/api/v1/trust/proof", { status: 200, body: Buffer.from("<html>") }],
    ]);
    await assert.rejects(client.getDiscovery(), (error: unknown) => error instanceof atp.AtpError && error.status === 500);
    await assert.rejects(client.getTrustProof(AGENT), { name: "AtpError", message: /did not answer with JSON/ });
    authority.routes = new Map();
    await assert.rejects(client.getTrustProof(AGENT), (error: unknown) => error instanceof atp.AtpError && error.status === 404);
  });

  it("does not follow a redirect", async () => {
    authority.routes = new Map<string, Route>([
      ["/.well-known/atp", { status: 302, headers: { Location: "/elsewhere" } }],
      ["/elsewhere", { status: 200, body: discovery }],
    ]);
    await assert.rejects(client.getDiscovery(), { name: "AtpError", message: /redirects are not followed/ });
    assert.ok(!authority.requests.includes("/elsewhere"));
  });

  it("verify names a discovery document it cannot use", async () => {
    const key = { keyId: `${AUTHORITY}#key-v1`, version: 1, algorithm: "Ed25519", publicKey: "c2hvcnQ=" };
    authority.routes = new Map<string, Route>([["/.well-known/atp", { status: 200, body: { ...discovery, publicKeys: [key] } }]]);
    const result = await client.verify(signedProof([signer]), { now: CLOCK });
    assertRejected(result, "PARSE_ERROR", "discovery document: publicKeys[0].publicKeyHex");
  });

  it("verify refuses a proof of an authority that declares an issuer key set", async () => {
    const signers = [signer, new Signer(`${AUTHORITY}#key-2`), new Signer(`${AUTHORITY}#key-3`)];
    const keys = signers.map((each) => each.key({ status: "active", validFrom: "2026-01-01T00:00:00Z" }));
    const keyIds = signers.map((each) => each.keyId);
    const cases: [string, Members, Signer[]][] = [
      ["one key of a 2-of-3 set", { threshold: 2, keyIds }, signers.slice(0, 1)],
      ["two keys of a 2-of-3 set", { threshold: 2, keyIds }, signers.slice(0, 2)],
      ["a set that breaks Section 7.1.1", { threshold: 5, keyIds: [signer.keyId] }, signers.slice(0, 1)],
    ];
    for (const [label, keySet, signedBy] of cases) {
      const local = new atp.AtpClient("https://authority.example", {
        discovery: { ...discovery, publicKeys: keys, issuerKeySet: keySet },
      });
      const result = await local.verify(signedProof(signedBy), { now: CLOCK });
      assert.equal(result.category, "SIGNATURE_INVALID", label);
      assert.ok(result.reason.includes("discovery document: issuerKeySet"), label);
    }
  });

  it("throws for a base URL that is not http or https", () => {
    for (const url of ["ftp://authority.example", "authority.example", "https://authority.example/?a=1"]) {
      assert.throws(() => new atp.AtpClient(url), TypeError, url);
    }
  });
});
