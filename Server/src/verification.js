import { randomHex, bufferToHex, constantTimeEqual, hexToBuffer, utf8Encode } from "./codec.js";
import { webcrypto } from "node:crypto";
import { Codes, taggedError } from "./codes.js";

export const VerificationTtlMs = 15 * 60 * 1000;
export const VerificationMaxAttempts = 5;

function generateCode() {
  const value = webcrypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(value).padStart(6, "0");
}

async function hashCode(code) {
  const digest = await webcrypto.subtle.digest("SHA-256", utf8Encode(code));
  return bufferToHex(digest);
}

export async function createPendingVerification(db, purpose, identifier, extra = {}, ttlMs = VerificationTtlMs) {
  const id = randomHex(16);
  const code = generateCode();
  const codeHash = await hashCode(code);
  const now = Date.now();
  db.prepare(
    `INSERT INTO pending_verifications (id, purpose, identifier, code_hash, extra, attempts, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, 0, ?, ?)`
  ).run(id, purpose, identifier, codeHash, JSON.stringify(extra), now, now + ttlMs);
  return { id, code };
}

export async function consumePendingVerification(db, purpose, id, code) {
  if (typeof id !== "string" || typeof code !== "string") {
    throw taggedError(Codes.ChallengeInvalid, "Invalid verification code.");
  }
  const row = db.prepare("SELECT * FROM pending_verifications WHERE id = ? AND purpose = ?").get(id, purpose);
  if (!row) {
    throw taggedError(Codes.ChallengeInvalid, "Invalid verification code.");
  }
  if (row.expires_at <= Date.now()) {
    db.prepare("DELETE FROM pending_verifications WHERE id = ?").run(id);
    throw taggedError(Codes.ChallengeExpired, "This code has expired.");
  }
  if (row.attempts >= VerificationMaxAttempts) {
    db.prepare("DELETE FROM pending_verifications WHERE id = ?").run(id);
    throw taggedError(Codes.ChallengeInvalid, "Too many incorrect attempts. Request a new code.");
  }
  const candidateHash = await hashCode(code);
  const matches = constantTimeEqual(hexToBuffer(candidateHash), hexToBuffer(row.code_hash));
  if (!matches) {
    db.prepare("UPDATE pending_verifications SET attempts = attempts + 1 WHERE id = ?").run(id);
    throw taggedError(Codes.ChallengeInvalid, "Incorrect code.");
  }
  db.prepare("DELETE FROM pending_verifications WHERE id = ?").run(id);
  return { identifier: row.identifier, ...JSON.parse(row.extra || "{}") };
}

export function pruneExpiredVerifications(db) {
  db.prepare("DELETE FROM pending_verifications WHERE expires_at < ?").run(Date.now());
}
