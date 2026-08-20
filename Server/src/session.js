import { randomHex, bufferToHex } from "./codec.js";
import { webcrypto } from "node:crypto";
import { Codes, taggedError } from "./codes.js";

export const SessionTtlMs = 30 * 24 * 60 * 60 * 1000;

async function hashToken(token) {
  const digest = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return bufferToHex(digest);
}

export async function issueSession(db, username) {
  const token = randomHex(32);
  const tokenHash = await hashToken(token);
  const now = Date.now();
  const expiresAt = now + SessionTtlMs;
  db.prepare(
    "INSERT INTO sessions (token_hash, username, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)"
  ).run(tokenHash, username, now, expiresAt, now);
  return { sessionToken: token, expiresAt };
}

export async function resumeSession(db, token) {
  if (typeof token !== "string" || !token) {
    throw taggedError(Codes.InvalidCredentials, "Invalid session.");
  }
  const tokenHash = await hashToken(token);
  const row = db.prepare("SELECT * FROM sessions WHERE token_hash = ?").get(tokenHash);
  if (!row || row.expires_at <= Date.now()) {
    throw taggedError(Codes.InvalidCredentials, "Session expired or invalid.");
  }
  const record = db.prepare("SELECT * FROM identities WHERE username = ?").get(row.username);
  if (!record) {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    throw taggedError(Codes.InvalidCredentials, "Session expired or invalid.");
  }
  const now = Date.now();
  const expiresAt = now + SessionTtlMs;
  db.prepare("UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?").run(now, expiresAt, tokenHash);
  return {
    username: record.username,
    deviceId: record.device_id,
    publicKeyHex: record.public_key_hex,
    identityId: record.identity_id
  };
}

export async function revokeSession(db, token) {
  const tokenHash = await hashToken(token);
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
}

export function revokeAllSessionsForUser(db, username, exceptTokenHash) {
  if (exceptTokenHash) {
    db.prepare("DELETE FROM sessions WHERE username = ? AND token_hash != ?").run(username, exceptTokenHash);
  } else {
    db.prepare("DELETE FROM sessions WHERE username = ?").run(username);
  }
}

export function pruneExpiredSessions(db) {
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now());
}
