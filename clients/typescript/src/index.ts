/**
 * Client for the Agent Trust Protocol (ATP-SPEC.md in this repository).
 *
 * AtpClient fetches a trust authority's discovery document (Section 7.1) and
 * its trust proofs (Section 4.5). The verify functions make no network call:
 * they check a trust proof (Section 4.4 steps 1 to 5, except the issuer key set
 * count of step 4), a discovery document (Section 7.1), a signed tree head
 * (Section 5.6), an inclusion proof (Section 5.4), a consistency proof (Section
 * 5.5) and a revocation response (Section 8.1). Each returns a VerifyResult; a
 * rejected input carries one of CATEGORIES and a reason that names the member
 * or the step that failed. The client does not count an issuer key set
 * (Section 7.1.1), so verifyDiscovery, and AtpClient.verify with it, refuse a
 * discovery document that declares one. Its functions are those of the Python
 * client in clients/python, named in camelCase.
 */

import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";

export const CATEGORIES = [
  "PARSE_ERROR",
  "EXPIRED",
  "UNTRUSTED_ISSUER",
  "SIGNATURE_INVALID",
  "SEMANTIC_INVALID",
  "PROOF_INVALID",
] as const;
export const VERDICTS = ["passed", "warning", "blocked", "listed", "verified", "unknown"] as const;

/** One of CATEGORIES. */
export type RejectCategory = (typeof CATEGORIES)[number];

/** A JSON object, as JSON.parse returns one. */
export type JsonObject = { [member: string]: unknown };

/**
 * valid is true when every check passed. Otherwise category is one of
 * CATEGORIES and reason says which member or step failed.
 */
export interface VerifyResult {
  readonly valid: boolean;
  readonly category: RejectCategory | null;
  readonly reason: string;
}

/** now is the clock of Section 4.4 step 1: a Date or an RFC 3339 string, the current time when absent. */
export interface VerifyOptions {
  readonly now?: Date | string | undefined;
}

export interface AtpClientOptions {
  /** A stored discovery document to verify against, so verify sends no request. */
  readonly discovery?: JsonObject | undefined;
  /** How long a request may take, in milliseconds (default 10000). */
  readonly timeoutMs?: number | undefined;
}

/**
 * A request to the authority failed, or its answer was not what was asked
 * for. status is the HTTP status when the authority answered with one.
 */
export class AtpError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "AtpError";
    this.status = status;
  }
}

class Reject extends Error {
  readonly category: RejectCategory;
  readonly reason: string;

  constructor(category: RejectCategory, reason: string) {
    super(reason);
    this.category = category;
    this.reason = reason;
  }
}

type Algorithm = "Ed25519" | "ML-DSA-65";

const KEY_SIZES: Readonly<Record<Algorithm, number>> = { Ed25519: 32, "ML-DSA-65": 1952 };
// The DER SubjectPublicKeyInfo bytes before a raw public key, which name the
// algorithm by OID: 1.3.101.112 for Ed25519, 2.16.840.1.101.3.4.3.18 for ML-DSA-65.
const SPKI_PREFIXES: Readonly<Record<Algorithm, Buffer>> = {
  Ed25519: Buffer.from("302a300506032b6570032100", "hex"),
  "ML-DSA-65": Buffer.from("308207b2300b0609608648016503040312038207a100", "hex"),
};
const KEY_STATUSES: readonly unknown[] = ["active", "retired", "revoked"];
const MICROSECONDS = 1_000_000n;
const MAX_VALIDITY_MICROSECONDS = 24n * 3600n * MICROSECONDS; // Section 10.2

const RFC3339 =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$/;
const HEX = /^(?:[0-9a-fA-F]{2})+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const WIRE_HASH = /^SHA256:([0-9a-f]{64})$/;

function isAlgorithm(value: unknown): value is Algorithm {
  return value === "Ed25519" || value === "ML-DSA-65";
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The member name of object, or undefined when object has no member of its own by that name. */
function member(object: JsonObject, name: string): unknown {
  return Object.hasOwn(object, name) ? object[name] : undefined;
}

function result(valid: boolean, category: RejectCategory | null, reason: string): VerifyResult {
  return Object.freeze({ valid, category, reason });
}

/**
 * Runs check, which throws Reject at the first failure. Any other error is
 * not a rejection of the input, and propagates.
 */
function outcome(check: () => void): VerifyResult {
  try {
    check();
  } catch (error) {
    if (error instanceof Reject) return result(false, error.category, error.reason);
    throw error;
  }
  return result(true, null, "");
}

// Wire values

/** The days from 1970-01-01 to a date of the proleptic Gregorian calendar. */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yearOfEra = y - era * 400;
  const dayOfYear = Math.floor((153 * ((month + 9) % 12) + 2) / 5) + day - 1; // counted from March 1
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z, in seconds since 1970-01-01T00:00:00Z.
const FIRST_SECOND = daysFromCivil(1, 1, 1) * 86_400;
const LAST_SECOND = daysFromCivil(9999, 12, 31) * 86_400 + 86_399;

/**
 * value, an RFC 3339 date-time with an upper-case T and Z, as whole
 * microseconds since 1970-01-01T00:00:00Z. Digits of a fraction after the
 * sixth are dropped. A date that does not exist, an hour above 23, a second
 * of 60 and a UTC time outside the years 1 to 9999 are refused.
 */
function instant(value: unknown, name: string): bigint {
  const match = typeof value === "string" ? RFC3339.exec(value) : null;
  if (match === null) throw new Reject("PARSE_ERROR", `${name} is not an RFC 3339 date-time`);
  const field = (group: number): number => Number(match[group]);
  let offset = 0;
  if (match[8] !== undefined) {
    if (field(9) > 23 || field(10) > 59) throw new Reject("PARSE_ERROR", `${name} has a UTC offset out of range`);
    offset = (match[8] === "-" ? -1 : 1) * (field(9) * 3600 + field(10) * 60);
  }
  const year = field(1);
  const month = field(2);
  const day = field(3);
  const hour = field(4);
  const minute = field(5);
  const second = field(6);
  const seconds = daysFromCivil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    seconds < FIRST_SECOND ||
    seconds > LAST_SECOND
  ) {
    throw new Reject("PARSE_ERROR", `${name} is not a valid date-time in the years 1 to 9999`);
  }
  const fraction = BigInt((match[7] ?? "").slice(0, 6).padEnd(6, "0"));
  return BigInt(seconds) * MICROSECONDS + fraction;
}

/**
 * Section 4.3: the instant in UTC to the whole second, its fraction dropped,
 * written YYYY-MM-DDTHH:MM:SSZ.
 */
function canonicalTime(instant: bigint): string {
  // BigInt division truncates toward zero, so an instant before 1970 with a
  // fraction is moved down to its whole second here.
  const seconds = instant / MICROSECONDS - (instant % MICROSECONDS < 0n ? 1n : 0n);
  const moment = new Date(Number(seconds) * 1000);
  const two = (value: number): string => String(value).padStart(2, "0");
  return (
    `${String(moment.getUTCFullYear()).padStart(4, "0")}-${two(moment.getUTCMonth() + 1)}-${two(moment.getUTCDate())}` +
    `T${two(moment.getUTCHours())}:${two(moment.getUTCMinutes())}:${two(moment.getUTCSeconds())}Z`
  );
}

function clock(now: Date | string | undefined): bigint {
  if (now === undefined) return BigInt(Date.now()) * 1000n;
  if (typeof now === "string") {
    try {
      return instant(now, "now");
    } catch (error) {
      if (error instanceof Reject) throw new TypeError(error.reason);
      throw error;
    }
  }
  if (now instanceof Date && !Number.isNaN(now.getTime())) return BigInt(now.getTime()) * 1000n;
  throw new TypeError("now must be a valid Date or an RFC 3339 string");
}

/** A JSON integer: a number with no fraction, so 4.0 is the integer 4; true and false are not integers. */
function integer(value: unknown, name: string, minimum?: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || (minimum !== undefined && value < minimum)) {
    const bound = minimum === undefined ? "" : ` of at least ${minimum}`;
    throw new Reject("PARSE_ERROR", `${name} is missing or not an integer${bound}`);
  }
  return value;
}

/** The decimal digits of an integer, with no exponent: String(1e21) is "1e+21". */
function digits(value: number): string {
  return BigInt(value).toString();
}

function base64(value: unknown, name: string, category: RejectCategory): Buffer {
  if (typeof value !== "string" || value === "" || !BASE64.test(value)) {
    throw new Reject(category, `${name} is not base64`);
  }
  return Buffer.from(value, "base64");
}

function wireHash(value: unknown, name: string): Buffer {
  const match = typeof value === "string" ? WIRE_HASH.exec(value) : null;
  if (match === null) throw new Reject("PARSE_ERROR", `${name} is not SHA256: and 64 lowercase hex digits`);
  return Buffer.from(match[1] ?? "", "hex");
}

function hashList(value: unknown, name: string): Buffer[] {
  if (!Array.isArray(value)) throw new Reject("PARSE_ERROR", `${name} is missing or not an array`);
  return Array.from(value, (item: unknown, index) => wireHash(item, `${name}[${index}]`));
}

function trustedSet(trustedIssuers: string | Iterable<string>): Set<string> {
  return typeof trustedIssuers === "string" ? new Set([trustedIssuers]) : new Set(trustedIssuers);
}

// Keys and signatures

/**
 * Section 4.4 step 3: the raw public key keyId resolves to among keys (an
 * entry with that keyId and algorithm, a hex key of the algorithm's size and
 * a status other than revoked), or null.
 */
function keyBytes(keys: readonly unknown[], keyId: string, algorithm: Algorithm): Buffer | null {
  for (const entry of keys) {
    if (
      isObject(entry) &&
      member(entry, "keyId") === keyId &&
      member(entry, "algorithm") === algorithm &&
      member(entry, "status") !== "revoked"
    ) {
      const raw = member(entry, "publicKeyHex");
      if (typeof raw === "string" && raw.length === 2 * KEY_SIZES[algorithm] && HEX.test(raw)) {
        return Buffer.from(raw, "hex");
      }
    }
  }
  return null;
}

function signatureValid(algorithm: Algorithm, raw: Buffer, signature: Buffer, message: Buffer): boolean {
  let key: KeyObject;
  try {
    key = createPublicKey({ key: Buffer.concat([SPKI_PREFIXES[algorithm], raw]), format: "der", type: "spki" });
  } catch {
    // For a Node.js without ML-DSA-65 keys: a key its crypto module cannot
    // read is reported as such, not as a signature that did not verify.
    throw new Reject(
      "SIGNATURE_INVALID",
      `this installation cannot verify ${algorithm} signatures: its Node.js crypto module could not read the key`,
    );
  }
  try {
    return verifySignature(null, message, key, signature);
  } catch {
    return false;
  }
}

// Trust proofs (Sections 4.3 and 4.4)

/** The seven members of a trust proof that the canonical string covers. */
interface Proof {
  readonly did: string;
  readonly level: number;
  readonly score: number;
  readonly verdict: string;
  readonly issued: bigint;
  readonly expires: bigint;
  readonly issuer: string;
}

interface SignatureEntry {
  readonly keyId: string;
  readonly algorithm: string;
  readonly value: unknown;
}

/**
 * score as C's and Python's %.6f write it: its exact binary value rounded to
 * six places, a tie to even. toFixed(6) rounds a tie up, so it writes
 * 0.0078125 as 0.007813 where %.6f writes 0.007812.
 */
function sixPlaces(score: number): string {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, score);
  const bits = view.getBigUint64(0);
  const biased = Number((bits >> 52n) & 0x7ffn);
  const fraction = bits & ((1n << 52n) - 1n);
  // score is finite, and its magnitude is significand * 2 ** exponent exactly.
  const significand = biased === 0 ? fraction : fraction | (1n << 52n);
  const exponent = Math.max(biased, 1) - 1075;
  let millionths: bigint;
  if (exponent >= 0) {
    millionths = (significand << BigInt(exponent)) * 1_000_000n;
  } else {
    const numerator = significand * 1_000_000n;
    const denominator = 1n << BigInt(-exponent);
    millionths = numerator / denominator;
    const twiceRemainder = (numerator % denominator) * 2n;
    if (twiceRemainder > denominator || (twiceRemainder === denominator && millionths % 2n === 1n)) {
      millionths += 1n;
    }
  }
  const written = millionths.toString().padStart(7, "0");
  return `${bits >> 63n === 1n ? "-" : ""}${written.slice(0, -6)}.${written.slice(-6)}`;
}

function canonical(proof: Proof): string {
  return [
    proof.did,
    digits(proof.level),
    sixPlaces(proof.score),
    proof.verdict,
    canonicalTime(proof.issued),
    canonicalTime(proof.expires),
    proof.issuer,
  ].join("|");
}

function proofObject(proof: unknown): JsonObject {
  if (!isObject(proof)) throw new Reject("PARSE_ERROR", "the trust proof is not a JSON object");
  return proof;
}

/**
 * A string member that enters the canonical string. UTF-8 cannot encode a
 * lone surrogate, which Buffer.from would write as U+FFFD, so the string
 * "\uD800" and the string "�" would share one signature.
 */
function text(object: JsonObject, name: string): string {
  const value = member(object, name);
  if (typeof value !== "string") throw new Reject("PARSE_ERROR", `${name} is missing or not a string`);
  if (!value.isWellFormed()) throw new Reject("PARSE_ERROR", `${name} holds a lone surrogate, which UTF-8 cannot encode`);
  return value;
}

function parseProof(proof: JsonObject): Proof {
  const did = text(proof, "did");
  const verdict = text(proof, "verdict");
  const issuer = text(proof, "issuerDid");
  const level = integer(member(proof, "trustLevel"), "trustLevel");
  const score = member(proof, "trustScore");
  if (typeof score !== "number") throw new Reject("PARSE_ERROR", "trustScore is missing or not a number");
  if (!Number.isFinite(score)) throw new Reject("PARSE_ERROR", "trustScore is not a finite number");
  const issued = instant(member(proof, "issuedAt"), "issuedAt");
  const expires = instant(member(proof, "expiresAt"), "expiresAt");
  return { did, level, score, verdict, issued, expires, issuer };
}

function signatureEntries(proof: JsonObject): SignatureEntry[] {
  const signatures = member(proof, "signatures");
  if (!Array.isArray(signatures) || signatures.length === 0) {
    throw new Reject("PARSE_ERROR", "signatures is missing or empty");
  }
  return Array.from(signatures, (entry: unknown, index) => {
    const keyId = isObject(entry) ? member(entry, "keyId") : undefined;
    const algorithm = isObject(entry) ? member(entry, "algorithm") : undefined;
    if (!isObject(entry) || typeof keyId !== "string" || typeof algorithm !== "string") {
      throw new Reject("PARSE_ERROR", `signatures[${index}] has no keyId and algorithm strings`);
    }
    return { keyId, algorithm, value: member(entry, "value") };
  });
}

/**
 * The Section 4.3 canonical string of a trust proof: the bytes, encoded as
 * UTF-8, that its signatures cover. Reads did, trustLevel, trustScore,
 * verdict, issuedAt, expiresAt and issuerDid, and throws a TypeError when one
 * of them cannot be read.
 */
export function canonicalString(proof: unknown): string {
  try {
    return canonical(parseProof(proofObject(proof)));
  } catch (error) {
    if (error instanceof Reject) throw new TypeError(error.reason);
    throw error;
  }
}

/**
 * Section 4.4 steps 1 to 5, offline, in order: expiry, issuer, key lookup,
 * signatures, semantic validation. keys are Section 7.1 publicKeys entries
 * (keyId, algorithm, publicKeyHex, optional status) and trustedIssuers the
 * issuer DIDs the verifier trusts; options.now (default: the current time) is
 * the clock for step 1. Step 6, the transparency log, is verifyInclusionProof;
 * step 7, co-signing by a second authority at conformance Level 3, is not
 * checked. A Sigstore co-signature (Section 4.3.1) is not verified, so step 4
 * rejects a proof that carries one. The issuer key set count of step 4
 * (Section 7.1.1) is not applied: pass only the keys of an authority whose
 * discovery document carries no issuerKeySet, which verifyDiscovery checks.
 * Throws a TypeError for a now that is not a valid Date or an RFC 3339 string.
 */
export function verifyTrustProof(
  proof: unknown,
  keys: Iterable<unknown>,
  trustedIssuers: string | Iterable<string>,
  options: VerifyOptions = {},
): VerifyResult {
  const now = clock(options.now);
  const keyList = Array.from(keys);
  const trusted = trustedSet(trustedIssuers);
  return outcome(() => checkTrustProof(proof, keyList, trusted, now));
}

function checkTrustProof(proof: unknown, keys: readonly unknown[], trusted: ReadonlySet<string>, now: bigint): void {
  const object = proofObject(proof);
  const parsed = parseProof(object);
  const signatures = signatureEntries(object);
  const logIndex = member(object, "transparencyLogIndex");
  if (logIndex !== undefined && logIndex !== null) integer(logIndex, "transparencyLogIndex", 0);

  if (parsed.expires <= now) {
    throw new Reject("EXPIRED", `the trust proof expired at ${String(member(object, "expiresAt"))}`);
  }

  if (!trusted.has(parsed.issuer)) {
    throw new Reject("UNTRUSTED_ISSUER", `issuerDid ${parsed.issuer} is not a trusted issuer`);
  }

  const resolved: { index: number; entry: SignatureEntry; algorithm: Algorithm; raw: Buffer }[] = [];
  for (const [index, entry] of signatures.entries()) {
    const algorithm = entry.algorithm;
    if (algorithm === "Sigstore") {
      throw new Reject(
        "SIGNATURE_INVALID",
        `signatures[${index}] is a Sigstore co-signature (Section 4.3.1), which this client does not verify`,
      );
    }
    if (!isAlgorithm(algorithm)) {
      throw new Reject("SIGNATURE_INVALID", `signatures[${index}] has algorithm ${algorithm}, not Ed25519 or ML-DSA-65`);
    }
    const raw = keyBytes(keys, entry.keyId, algorithm);
    if (raw === null) {
      throw new Reject(
        "SIGNATURE_INVALID",
        `signatures[${index}] keyId ${entry.keyId} does not resolve to a non-revoked ${algorithm} key`,
      );
    }
    resolved.push({ index, entry, algorithm, raw });
  }

  const message = Buffer.from(canonical(parsed), "utf8");
  let issuerSigned = false;
  for (const { index, entry, algorithm, raw } of resolved) {
    const signature = base64(entry.value, `signatures[${index}].value`, "SIGNATURE_INVALID");
    if (!signatureValid(algorithm, raw, signature, message)) {
      throw new Reject("SIGNATURE_INVALID", `the ${algorithm} signature of ${entry.keyId} did not verify`);
    }
    const hash = entry.keyId.indexOf("#");
    const fragment = hash >= 0 && hash < entry.keyId.length - 1;
    if (algorithm === "Ed25519" && fragment && entry.keyId.slice(0, hash) === parsed.issuer) issuerSigned = true;
  }
  if (!issuerSigned) {
    throw new Reject("SIGNATURE_INVALID", `no Ed25519 signature by a key of ${parsed.issuer} verified`);
  }

  if (parsed.level < 0 || parsed.level > 4) {
    throw new Reject("SEMANTIC_INVALID", `trustLevel ${digits(parsed.level)} is outside 0 to 4`);
  }
  if (!(parsed.score >= 0 && parsed.score <= 1)) {
    throw new Reject("SEMANTIC_INVALID", `trustScore ${parsed.score} is outside 0.0 to 1.0`);
  }
  if (!(VERDICTS as readonly string[]).includes(parsed.verdict)) {
    throw new Reject("SEMANTIC_INVALID", `verdict ${parsed.verdict} is not one of ${VERDICTS.join(", ")}`);
  }
  if (parsed.issued >= parsed.expires) {
    throw new Reject("SEMANTIC_INVALID", "issuedAt is not before expiresAt");
  }
  if (parsed.expires - parsed.issued > MAX_VALIDITY_MICROSECONDS) {
    throw new Reject("SEMANTIC_INVALID", "the validity window from issuedAt to expiresAt is longer than 24 hours");
  }
}

// Discovery (Section 7.1)

/**
 * Section 7.1: the members a verifier reads from a discovery document, each
 * publicKeys entry a hex key of its algorithm's size. With trustedIssuers,
 * authorityDid must be one of them. A document that carries issuerKeySet is
 * refused with SIGNATURE_INVALID: this client does not count an issuer key
 * set (Section 7.1.1), which Section 4.4 step 4 requires.
 */
export function verifyDiscovery(discovery: unknown, trustedIssuers?: string | Iterable<string>): VerifyResult {
  const trusted = trustedIssuers === undefined ? null : trustedSet(trustedIssuers);
  return outcome(() => checkDiscovery(discovery, trusted));
}

function checkDiscovery(discovery: unknown, trusted: ReadonlySet<string> | null): void {
  if (!isObject(discovery)) throw new Reject("PARSE_ERROR", "the discovery document is not a JSON object");
  const authority = member(discovery, "authorityDid");
  if (typeof authority !== "string" || !authority.startsWith("did:")) {
    throw new Reject("PARSE_ERROR", "authorityDid is missing or not a DID");
  }
  if (member(discovery, "version") !== "1.0") throw new Reject("PARSE_ERROR", "version is not 1.0");
  const level = member(discovery, "conformanceLevel");
  if (level !== undefined && level !== null && ![1, 2, 3].includes(integer(level, "conformanceLevel"))) {
    throw new Reject("PARSE_ERROR", "conformanceLevel is not 1, 2 or 3");
  }
  const endpoints = member(discovery, "endpoints");
  if (
    !isObject(endpoints) ||
    Object.keys(endpoints).length === 0 ||
    !Object.values(endpoints).every((value) => typeof value === "string" && value !== "")
  ) {
    throw new Reject("PARSE_ERROR", "endpoints is not an object of non-empty strings");
  }
  const keys = member(discovery, "publicKeys");
  if (!Array.isArray(keys) || keys.length === 0) throw new Reject("PARSE_ERROR", "publicKeys is missing or empty");
  for (const [index, key] of (keys as unknown[]).entries()) {
    const name = `publicKeys[${index}]`;
    if (!isObject(key)) throw new Reject("PARSE_ERROR", `${name} is not a JSON object`);
    const keyId = member(key, "keyId");
    if (typeof keyId !== "string" || !keyId.startsWith("did:") || !keyId.includes("#")) {
      throw new Reject("PARSE_ERROR", `${name}.keyId is not a DID with a fragment`);
    }
    const algorithm = member(key, "algorithm");
    if (!isAlgorithm(algorithm)) throw new Reject("PARSE_ERROR", `${name}.algorithm is not Ed25519 or ML-DSA-65`);
    const raw = member(key, "publicKeyHex");
    if (typeof raw !== "string" || raw.length !== 2 * KEY_SIZES[algorithm] || !HEX.test(raw)) {
      throw new Reject("PARSE_ERROR", `${name}.publicKeyHex is not a ${KEY_SIZES[algorithm]}-byte key in hex`);
    }
    if (!KEY_STATUSES.includes(member(key, "status"))) {
      throw new Reject("PARSE_ERROR", `${name}.status is not active, retired or revoked`);
    }
    instant(member(key, "validFrom"), `${name}.validFrom`);
  }
  if (trusted !== null && !trusted.has(authority)) {
    throw new Reject("UNTRUSTED_ISSUER", `authorityDid ${authority} is not a trusted issuer`);
  }
  // Section 4.4 step 4 requires a proof to meet a declared set, and no proof
  // meets a set that breaks Section 7.1.1; not counting sets, the client
  // refuses every one, whatever it holds.
  if (Object.hasOwn(discovery, "issuerKeySet")) {
    throw new Reject(
      "SIGNATURE_INVALID",
      "issuerKeySet: this client does not count an issuer key set (Section 7.1.1), " +
        "so it verifies no proof of an authority that declares one",
    );
  }
}

// Transparency log (Sections 5.4 to 5.6, RFC 9162 Section 2.1)

const NODE_PREFIX = Buffer.from([0x01]);

function node(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256").update(NODE_PREFIX).update(left).update(right).digest();
}

// The two algorithms below count with BigInt: the bitwise operators of
// numbers work on 32 bits, and a log can hold more than 2 ** 32 entries.

/**
 * RFC 9162 Section 2.1.3.2: the root path leads to from leaf at index in a
 * tree of size, or null when the path does not fit that tree.
 */
function inclusionRoot(index: bigint, size: bigint, leaf: Buffer, path: readonly Buffer[]): Buffer | null {
  if (index >= size) return null;
  let fn = index;
  let sn = size - 1n;
  let root = leaf;
  for (const sibling of path) {
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      root = node(sibling, root);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      root = node(root, sibling);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n ? root : null;
}

/**
 * RFC 9162 Section 2.1.4.2: the two roots path leads to for trees of first
 * and second leaves, 0 < first < second, or null when it fits neither.
 */
function consistencyRoots(
  first: bigint,
  second: bigint,
  path: readonly Buffer[],
  firstRoot: Buffer,
): [Buffer, Buffer] | null {
  const nodes = (first & (first - 1n)) === 0n ? [firstRoot, ...path] : [...path];
  const start = nodes[0];
  if (path.length === 0 || start === undefined) return null;
  let fn = first - 1n;
  let sn = second - 1n;
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let firstHash = start;
  let secondHash = start;
  for (const hash of nodes.slice(1)) {
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      firstHash = node(hash, firstHash);
      secondHash = node(hash, secondHash);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      secondHash = node(secondHash, hash);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n ? [firstHash, secondHash] : null;
}

/** The members of a Section 5.6 tree head, with its signature as served. */
interface TreeHead {
  readonly size: bigint;
  readonly root: Buffer;
  readonly signedBy: string;
  readonly signature: unknown;
}

function treeHead(sth: unknown, name: string): TreeHead {
  if (!isObject(sth)) throw new Reject("PARSE_ERROR", `${name} is missing or not a JSON object`);
  const size = BigInt(integer(member(sth, "treeSize"), `${name}.treeSize`, 0));
  instant(member(sth, "timestamp"), `${name}.timestamp`);
  const root = wireHash(member(sth, "rootHash"), `${name}.rootHash`);
  const signedBy = member(sth, "signedBy");
  if (typeof signedBy !== "string") throw new Reject("PARSE_ERROR", `${name}.signedBy is missing or not a string`);
  return { size, root, signedBy, signature: member(sth, "signature") };
}

/**
 * Section 5.6: an Ed25519 signature over the 32 bytes of rootHash by the key
 * signedBy resolves to.
 */
function checkTreeHead(name: string, head: TreeHead, keys: readonly unknown[]): void {
  const raw = keyBytes(keys, head.signedBy, "Ed25519");
  if (raw === null) {
    throw new Reject("SIGNATURE_INVALID", `${name}.signedBy ${head.signedBy} does not resolve to a non-revoked Ed25519 key`);
  }
  const signature = base64(head.signature, `${name}.signature`, "SIGNATURE_INVALID");
  if (!signatureValid("Ed25519", raw, signature, head.root)) {
    throw new Reject("SIGNATURE_INVALID", `the ${name} signature did not verify`);
  }
}

/** Section 5.6: the tree head's members and its signature under keys. */
export function verifySignedTreeHead(sth: unknown, keys: Iterable<unknown>): VerifyResult {
  const keyList = Array.from(keys);
  return outcome(() => checkTreeHead("signedTreeHead", treeHead(sth, "signedTreeHead"), keyList));
}

/**
 * Section 5.4: the signed tree head verifies (step 1), then the root
 * recomputed from leafHash along auditPath is its rootHash (step 2).
 */
export function verifyInclusionProof(proof: unknown, keys: Iterable<unknown>): VerifyResult {
  const keyList = Array.from(keys);
  return outcome(() => checkInclusionProof(proof, keyList));
}

function checkInclusionProof(proof: unknown, keys: readonly unknown[]): void {
  if (!isObject(proof)) throw new Reject("PARSE_ERROR", "the inclusion proof is not a JSON object");
  const index = BigInt(integer(member(proof, "logIndex"), "logIndex", 0));
  const leaf = wireHash(member(proof, "leafHash"), "leafHash");
  const path = hashList(member(proof, "auditPath"), "auditPath");
  const head = treeHead(member(proof, "signedTreeHead"), "signedTreeHead");
  checkTreeHead("signedTreeHead", head, keys);
  if (index >= head.size) {
    throw new Reject("PARSE_ERROR", `logIndex ${index} is not below signedTreeHead.treeSize ${head.size}`);
  }
  const root = inclusionRoot(index, head.size, leaf, path);
  if (root === null || !root.equals(head.root)) {
    throw new Reject(
      "PROOF_INVALID",
      "the root recomputed from leafHash along auditPath is not signedTreeHead.rootHash",
    );
  }
}

/**
 * Section 5.5: both signed tree heads verify (step 1), then consistencyPath
 * leads to both of their roots (step 2).
 */
export function verifyConsistencyProof(proof: unknown, keys: Iterable<unknown>): VerifyResult {
  const keyList = Array.from(keys);
  return outcome(() => checkConsistencyProof(proof, keyList));
}

function checkConsistencyProof(proof: unknown, keys: readonly unknown[]): void {
  if (!isObject(proof)) throw new Reject("PARSE_ERROR", "the consistency proof is not a JSON object");
  const first = BigInt(integer(member(proof, "fromSize"), "fromSize", 1));
  const second = BigInt(integer(member(proof, "toSize"), "toSize", 1));
  const path = hashList(member(proof, "consistencyPath"), "consistencyPath");
  const from = treeHead(member(proof, "fromSignedTreeHead"), "fromSignedTreeHead");
  const to = treeHead(member(proof, "toSignedTreeHead"), "toSignedTreeHead");
  if (first !== from.size || second !== to.size) {
    throw new Reject("PARSE_ERROR", "fromSize and toSize are not the treeSize of the two tree heads");
  }
  if (first >= second) throw new Reject("PARSE_ERROR", `fromSize ${first} is not below toSize ${second}`);
  checkTreeHead("fromSignedTreeHead", from, keys);
  checkTreeHead("toSignedTreeHead", to, keys);
  const roots = consistencyRoots(first, second, path, from.root);
  if (roots === null || !roots[0].equals(from.root) || !roots[1].equals(to.root)) {
    throw new Reject(
      "PROOF_INVALID",
      "consistencyPath does not lead to fromSignedTreeHead.rootHash and toSignedTreeHead.rootHash",
    );
  }
}

// Revocation (Section 8.1)

/**
 * Section 8.1: the members of a revocation response. A malformed timestamp
 * rejects the whole response; an entry without a transparencyLogIndex, or
 * with a reason this client does not recognise, does not. The response is
 * unsigned, so nothing here is a signature check.
 */
export function verifyRevocationList(body: unknown): VerifyResult {
  return outcome(() => checkRevocationList(body));
}

function checkRevocationList(body: unknown): void {
  if (!isObject(body)) throw new Reject("PARSE_ERROR", "the revocation response is not a JSON object");
  const revocations = member(body, "revocations");
  if (!Array.isArray(revocations)) throw new Reject("PARSE_ERROR", "revocations is missing or not an array");
  instant(member(body, "nextSince"), "nextSince");
  for (const [index, entry] of (revocations as unknown[]).entries()) {
    const name = `revocations[${index}]`;
    if (!isObject(entry)) throw new Reject("PARSE_ERROR", `${name} is not a JSON object`);
    const agent = member(entry, "agentDid");
    if (typeof agent !== "string" || !agent.startsWith("did:")) {
      throw new Reject("PARSE_ERROR", `${name}.agentDid is missing or not a DID`);
    }
    instant(member(entry, "revokedAt"), `${name}.revokedAt`);
    if (!Object.hasOwn(entry, "reason")) throw new Reject("PARSE_ERROR", `${name}.reason is missing`);
    const keyId = member(entry, "revokedByKeyId");
    if (typeof keyId !== "string" || !keyId.includes("#")) {
      throw new Reject("PARSE_ERROR", `${name}.revokedByKeyId is missing or has no fragment`);
    }
    const logIndex = member(entry, "transparencyLogIndex");
    if (logIndex !== undefined && logIndex !== null) integer(logIndex, `${name}.transparencyLogIndex`, 0);
  }
}

// Network

function failure(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const cause: unknown = error.cause;
  const code = typeof cause === "object" && cause !== null && "code" in cause ? String(cause.code) : null;
  return code === null ? error.message : `${error.message} (${code})`;
}

/**
 * A client of one trust authority, named by its base URL.
 *
 * getTrustProof and getDiscovery send requests; verify checks a proof
 * offline against the authority's discovery document, which is fetched once
 * and kept. Pass options.discovery to verify against a stored copy instead.
 */
export class AtpClient {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  #discovery: Promise<JsonObject> | undefined;

  constructor(baseUrl: string, options: AtpClientOptions = {}) {
    let url: URL | null;
    try {
      url = new URL(baseUrl);
    } catch {
      url = null;
    }
    if (
      url === null ||
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      url.host === "" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      throw new TypeError("baseUrl must be an http or https URL without a query or fragment");
    }
    let end = baseUrl.length;
    while (end > 0 && baseUrl[end - 1] === "/") end -= 1;
    this.baseUrl = baseUrl.slice(0, end);
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.#discovery = options.discovery === undefined ? undefined : Promise.resolve(options.discovery);
  }

  /**
   * The Section 7.1 discovery document from /.well-known/atp, or from the
   * legacy /.well-known/opena2a when the first answers 404. A request that
   * fails is not kept, so the next call sends it again.
   */
  getDiscovery(): Promise<JsonObject> {
    if (this.#discovery === undefined) {
      const pending = this.#fetchDiscovery();
      this.#discovery = pending;
      pending.catch(() => {
        if (this.#discovery === pending) this.#discovery = undefined;
      });
    }
    return this.#discovery;
  }

  async #fetchDiscovery(): Promise<JsonObject> {
    let document: unknown;
    try {
      document = await this.#get("/.well-known/atp");
    } catch (error) {
      if (!(error instanceof AtpError) || error.status !== 404) throw error;
      document = await this.#get("/.well-known/opena2a");
    }
    if (!isObject(document)) throw new AtpError("the discovery document is not a JSON object");
    return document;
  }

  /**
   * The current trust proof for did (Section 4.5). A proof the authority
   * wraps under "proof" is unwrapped; a proof about another DID throws.
   */
  async getTrustProof(did: string): Promise<JsonObject> {
    const body = await this.#get(`/api/v1/trust/proof?did=${encodeURIComponent(did)}`);
    const proof = isObject(body) ? (Object.hasOwn(body, "proof") ? body["proof"] : body) : null;
    if (!isObject(proof) || member(proof, "did") !== did) {
      throw new AtpError(`the authority did not answer with a trust proof for ${did}`);
    }
    return proof;
  }

  /**
   * verifyTrustProof against this authority: its discovery document's
   * publicKeys, and its authorityDid as the one trusted issuer. A discovery
   * document that verifyDiscovery refuses, one that declares an issuer key
   * set among them, rejects the proof with that category.
   */
  async verify(proof: unknown, options: VerifyOptions = {}): Promise<VerifyResult> {
    const discovery = await this.getDiscovery();
    const checked = verifyDiscovery(discovery);
    if (!checked.valid) return result(false, checked.category, `discovery document: ${checked.reason}`);
    // verifyDiscovery has checked that publicKeys is an array and authorityDid a string.
    const keys = member(discovery, "publicKeys") as unknown[];
    return verifyTrustProof(proof, keys, member(discovery, "authorityDid") as string, options);
  }

  async #get(path: string): Promise<unknown> {
    let raw: ArrayBuffer;
    try {
      const response = await fetch(this.baseUrl + path, {
        headers: { Accept: "application/json" },
        redirect: "manual",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (response.status < 200 || response.status > 299) {
        await response.body?.cancel().catch(() => undefined);
        const note = response.status >= 300 && response.status < 400 ? "; redirects are not followed" : "";
        throw new AtpError(`GET ${path} answered HTTP ${response.status}${note}`, response.status);
      }
      raw = await response.arrayBuffer();
    } catch (error) {
      if (error instanceof AtpError) throw error;
      throw new AtpError(`GET ${path} failed: ${failure(error)}`);
    }
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    } catch {
      throw new AtpError(`GET ${path} did not answer with JSON`);
    }
  }
}
