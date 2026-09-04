/**
 * CCS Ed25519 receipt signing and verification (pure Node.js stdlib).
 *
 * Key sourcing order:
 *   1. CCS_PRIVATE_KEY / CCS_PUBLIC_KEY env vars (PEM strings)
 *   2. CCS_KEY_DIR / ~/.ccs/ed25519-private.pem + ed25519-public.pem
 *   3. If none found, generate a new keypair and persist it to the key dir.
 *
 * Receipts include:
 *   - all original evidence fields (verdict, dimensions, hashes, ...)
 *   - signer_public_key  (SPKI PEM, multiline preserved)
 *   - signature_alg      "Ed25519"
 *   - signature          base64(crypto.sign over canonical receipt_body)
 *
 * The signed body excludes signer_public_key/signature_alg/signature/verified.
 * Verification uses only the signer_public_key embedded in the receipt itself;
 * auditors can additionally pin a known pubkey out-of-band.
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ALG = "Ed25519";
const ALG_INTERNAL = "ed25519";
const SIGNATURE_FIELDS = ["signer_public_key", "signature_alg", "signature", "verified"];

function canonical(obj) {
  // Recursive JCS-style deterministic JSON: sort object keys at EVERY nesting
  // level, preserve array order. NOTE: a previous implementation used
  // JSON.stringify(obj, Object.keys(obj).sort()) which applies the top-level
  // key list as a recursive whitelist and silently drops all nested fields
  // from the serialized output — meaning signatures/hashes did not cover
  // dimensions, semantic_analysis, etc. That was a security bug fixed in
  // 1.2.2. Receipts issued by <=1.2.1 do not cover nested fields and must be
  // re-issued.
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonical).join(",") + "]";
  }
  if (obj !== null && typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    return "{" + keys
      .map((k) => JSON.stringify(k) + ":" + canonical(obj[k]))
      .join(",") + "}";
  }
  return JSON.stringify(obj);
}

function defaultKeyDir() {
  if (process.env.CCS_KEY_DIR) return process.env.CCS_KEY_DIR;
  return path.join(os.homedir(), ".ccs");
}

function ensureKeypair() {
  // 1. Env vars
  if (process.env.CCS_PRIVATE_KEY && process.env.CCS_PUBLIC_KEY) {
    return {
      privateKey: crypto.createPrivateKey(
        process.env.CCS_PRIVATE_KEY.includes("-----BEGIN")
          ? process.env.CCS_PRIVATE_KEY
          : Buffer.from(process.env.CCS_PRIVATE_KEY, "base64").toString("utf8")
      ),
      publicKey: crypto.createPublicKey(
        process.env.CCS_PUBLIC_KEY.includes("-----BEGIN")
          ? process.env.CCS_PUBLIC_KEY
          : Buffer.from(process.env.CCS_PUBLIC_KEY, "base64").toString("utf8")
      ),
      source: "env",
    };
  }

  // 2. / 3. Disk
  const dir = defaultKeyDir();
  const privPath = path.join(dir, "ed25519-private.pem");
  const pubPath = path.join(dir, "ed25519-public.pem");

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKey: crypto.createPrivateKey(fs.readFileSync(privPath, "utf8")),
      publicKey: crypto.createPublicKey(fs.readFileSync(pubPath, "utf8")),
      source: "file",
    };
  }

  // 3. Generate
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = crypto.generateKeyPairSync(ALG_INTERNAL, {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  // Atomic-ish writes with restrictive perms
  fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });
  return {
    privateKey: crypto.createPrivateKey(privateKey),
    publicKey: crypto.createPublicKey(publicKey),
    source: "generated",
  };
}

let _keypair = null;
function getKeypair() {
  if (!_keypair) _keypair = ensureKeypair();
  return _keypair;
}

function publicKeyPem() {
  const { publicKey } = getKeypair();
  return publicKey.export({ type: "spki", format: "pem" });
}

/**
 * Sign a receipt body. Returns a new object containing all original fields
 * plus signer_public_key / signature_alg / signature. The original object
 * is not mutated.
 */
function signReceipt(body) {
  const { privateKey, publicKey } = getKeypair();

  // Strip any existing signature fields so re-signing is idempotent.
  const cleaned = { ...body };
  for (const k of SIGNATURE_FIELDS) delete cleaned[k];

  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  const payload = canonical(cleaned);
  const sigBuf = crypto.sign(null, Buffer.from(payload, "utf8"), privateKey);

  return {
    ...cleaned,
    signer_public_key: pubPem,
    signature_alg: ALG,
    signature: sigBuf.toString("base64"),
  };
}

/**
 * Verify a signed receipt. Returns { valid, reason?, signer_public_key }.
 * Does NOT require a trusted key — it verifies that the signature matches
 * the body under the embedded signer_public_key. Callers who need to pin
 * a known pubkey should compare signer_public_key themselves after this
 * returns valid=true.
 */
function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") {
    return { valid: false, reason: "receipt is not an object" };
  }
  const sig = receipt.signature;
  const alg = receipt.signature_alg;
  const pubPem = receipt.signer_public_key;
  if (!sig || !pubPem || !alg) {
    return { valid: false, reason: "missing signature/signature_alg/signer_public_key" };
  }
  if (alg !== ALG) {
    return { valid: false, reason: `unsupported signature_alg: ${alg}` };
  }

  const cleaned = { ...receipt };
  for (const k of SIGNATURE_FIELDS) delete cleaned[k];

  let key;
  try {
    key = crypto.createPublicKey(pubPem);
  } catch (e) {
    return { valid: false, reason: `invalid signer_public_key: ${e.message}` };
  }
  if (key.asymmetricKeyType !== ALG_INTERNAL) {
    return { valid: false, reason: `signer_public_key is not ${ALG}` };
  }

  const payload = canonical(cleaned);
  let sigBuf;
  try {
    sigBuf = Buffer.from(sig, "base64");
  } catch (e) {
    return { valid: false, reason: "signature is not valid base64" };
  }

  const ok = crypto.verify(null, Buffer.from(payload, "utf8"), key, sigBuf);
  if (!ok) {
    return {
      valid: false,
      reason: "signature verification failed (body was tampered or signed by a different key)",
      signer_public_key: pubPem,
    };
  }
  return { valid: true, signer_public_key: pubPem };
}

/**
 * Helper: verify a receipt AND pin it to an expected public key fingerprint.
 * expectedPem can be a PEM string, or the string "sha256:<hex>" fingerprint.
 */
function verifyReceiptWithKey(receipt, expectedPemOrFp) {
  const v = verifyReceipt(receipt);
  if (!v.valid) return v;

  if (!expectedPemOrFp) return v;

  if (expectedPemOrFp.startsWith("sha256:")) {
    // Fingerprint: sha256 of DER-encoded SPKI public key
    const der = crypto.createPublicKey(v.signer_public_key).export({ type: "spki", format: "der" });
    const fp = "sha256:" + crypto.createHash("sha256").update(der).digest("hex");
    if (fp !== expectedPemOrFp) {
      return { valid: false, reason: `signer fingerprint mismatch: got ${fp}, expected ${expectedPemOrFp}` };
    }
    return { valid: true, signer_public_key: v.signer_public_key, signer_fingerprint: fp };
  }

  // PEM string compare (normalize whitespace)
  const normA = v.signer_public_key.replace(/\s+/g, "");
  const normB = String(expectedPemOrFp).replace(/\s+/g, "");
  if (normA !== normB) {
    return { valid: false, reason: "signer_public_key does not match the pinned key" };
  }
  return { valid: true, signer_public_key: v.signer_public_key };
}

function publicKeyFingerprint() {
  const { publicKey } = getKeypair();
  const der = publicKey.export({ type: "spki", format: "der" });
  return "sha256:" + crypto.createHash("sha256").update(der).digest("hex");
}

module.exports = {
  ALG,
  canonical,
  getKeypair,
  publicKeyPem,
  publicKeyFingerprint,
  signReceipt,
  verifyReceipt,
  verifyReceiptWithKey,
};
