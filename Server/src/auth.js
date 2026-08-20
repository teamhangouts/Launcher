import {
  subtle,
  randomHex,
  bufferToHex,
  hexToBuffer,
  utf8Encode,
  constantTimeEqual
} from "./codec.js";
import { Codes, taggedError } from "./codes.js";
import { createPendingVerification, consumePendingVerification } from "./verification.js";
import { sendCode } from "./mailer.js";
import { revokeAllSessionsForUser } from "./session.js";

export const ProofOfWorkBits = 18;
export const IdentityTtlMs = 30 * 60 * 1000;
export const ClockSkewToleranceMs = 5 * 60 * 1000;
export const LockoutWindowMs = 15 * 60 * 1000;
export const LockoutThreshold = 5;
export const LockoutBaseMs = 30 * 1000;
export const ServerRehashIterations = 60000;
export const PassChallengeTtlMs = 2 * 60 * 1000;

export const HoneypotIdentifiers = new Set([
  "admin",
  "root",
  "test",
  "administrator",
  "moderator",
  "support"
]);

const UsernamePattern = /^[a-z0-9_.-]{3,32}$/;
const EmailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HexPattern = (byteLength) => new RegExp(`^[0-9a-f]{${byteLength * 2}}$`);
const PublicKeyHexPattern = /^04[0-9a-f]{128}$/;
const SignatureHexPattern = /^[0-9a-f]{128}$/;

function normalizeIdentifier(value) {
  return String(value).trim().toLowerCase();
}

function assertString(value, field, { min = 0, max = Infinity } = {}) {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function assertPattern(value, field, pattern) {
  if (!pattern.test(value)) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function assertNumber(value, field) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function countLeadingZeroBits(buffer) {
  const bytes = new Uint8Array(buffer);
  let count = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    let remaining = byte;
    for (let bit = 7; bit >= 0; bit--) {
      if ((remaining & (1 << bit)) !== 0) {
        break;
      }
      count++;
    }
    break;
  }
  return count;
}

function canonicalPayload(entry) {
  return JSON.stringify({
    identityId: entry.identityId,
    publicKeyHex: entry.publicKeyHex,
    deviceId: entry.deviceId,
    proofOfWorkBits: entry.proofOfWorkBits,
    proofOfWorkNonce: entry.proofOfWorkNonce,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt
  });
}

async function digestPayload(payloadString) {
  const digest = await subtle.digest("SHA-256", utf8Encode(payloadString));
  return bufferToHex(digest);
}

async function verifySignedChallenge(entry) {
  const canonical = canonicalPayload(entry);
  const expectedChallengeHex = await digestPayload(canonical);
  if (expectedChallengeHex !== entry.challengeHex) {
    return false;
  }
  let publicKey;
  try {
    publicKey = await subtle.importKey(
      "raw",
      hexToBuffer(entry.publicKeyHex),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch {
    return false;
  }
  try {
    return await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      hexToBuffer(entry.signatureHex),
      hexToBuffer(entry.challengeHex)
    );
  } catch {
    return false;
  }
}

async function verifyProofOfWork(publicKeyHex, nonce) {
  const digest = await subtle.digest("SHA-256", utf8Encode(`${publicKeyHex}:${nonce}`));
  return countLeadingZeroBits(digest) >= ProofOfWorkBits;
}

async function derivePseudoSaltHex(pepper, identifier) {
  const key = await subtle.importKey("raw", pepper, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await subtle.sign("HMAC", key, utf8Encode(identifier));
  return bufferToHex(mac).slice(0, 32);
}

async function deriveServerHash(pepper, clientHashHex, serverSaltHex) {
  const hmacKey = await subtle.importKey("raw", pepper, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const peppered = await subtle.sign("HMAC", hmacKey, utf8Encode(clientHashHex));
  const keyMaterial = await subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: hexToBuffer(serverSaltHex),
      iterations: ServerRehashIterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return bufferToHex(derivedBits);
}

function assertCredentialHashHex(payload, field = "credentialHashHex") {
  return assertPattern(assertString(payload, field, { min: 64, max: 64 }), field, HexPattern(32));
}

function validateSignupPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const username = assertString(payload.username, "username", { min: 1, max: 64 });
  const identifier = normalizeIdentifier(username);
  assertPattern(identifier, "username", UsernamePattern);
  const email = normalizeIdentifier(assertString(payload.email, "email", { min: 3, max: 254 }));
  assertPattern(email, "email", EmailPattern);
  const clientSaltHex = assertPattern(assertString(payload.clientSaltHex, "clientSaltHex", { min: 32, max: 32 }), "clientSaltHex", HexPattern(16));
  const clientHashHex = assertCredentialHashHex(payload.credentialHashHex);
  const identityId = assertPattern(assertString(payload.identityId, "identityId", { min: 32, max: 32 }), "identityId", HexPattern(16));
  const publicKeyHex = assertPattern(assertString(payload.publicKeyHex, "publicKeyHex", { min: 130, max: 130 }), "publicKeyHex", PublicKeyHexPattern);
  const deviceId = assertPattern(assertString(payload.deviceId, "deviceId", { min: 64, max: 64 }), "deviceId", HexPattern(32));
  const proofOfWorkNonce = assertNumber(payload.proofOfWorkNonce, "proofOfWorkNonce");
  const createdAt = assertNumber(payload.createdAt, "createdAt");
  const expiresAt = assertNumber(payload.expiresAt, "expiresAt");
  const challengeHex = assertPattern(assertString(payload.challengeHex, "challengeHex", { min: 64, max: 64 }), "challengeHex", HexPattern(32));
  const signatureHex = assertPattern(assertString(payload.signatureHex, "signatureHex", { min: 128, max: 128 }), "signatureHex", SignatureHexPattern);
  if (proofOfWorkNonce < 0 || !Number.isInteger(proofOfWorkNonce)) {
    throw taggedError(Codes.MalformedRequest, "Invalid proofOfWorkNonce.");
  }
  return {
    username,
    identifier,
    email,
    clientSaltHex,
    clientHashHex,
    identityId,
    publicKeyHex,
    deviceId,
    proofOfWorkBits: ProofOfWorkBits,
    proofOfWorkNonce,
    createdAt,
    expiresAt,
    challengeHex,
    signatureHex
  };
}

async function getFlag(db, identifier) {
  const row = db.prepare("SELECT * FROM flags WHERE identifier = ?").get(identifier);
  return row || null;
}

function setFlag(db, identifier, { level, lockedUntil, failureCount }) {
  db.prepare(
    `INSERT INTO flags (identifier, level, locked_until, failure_count)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(identifier) DO UPDATE SET level = excluded.level, locked_until = excluded.locked_until, failure_count = excluded.failure_count`
  ).run(identifier, level, lockedUntil, failureCount);
}

function isLocked(flag) {
  return Boolean(flag && flag.locked_until && flag.locked_until > Date.now());
}

async function getMostRestrictiveLock(db, identifier, deviceId) {
  const flags = [await getFlag(db, identifier)];
  if (deviceId) {
    flags.push(await getFlag(db, `${identifier}:${deviceId}`));
  }
  let worst = null;
  for (const flag of flags) {
    if (isLocked(flag) && (!worst || flag.locked_until > worst.locked_until)) {
      worst = flag;
    }
  }
  return worst;
}

function recordAttempt(db, identifier, succeeded) {
  db.prepare("INSERT INTO attempts (identifier, succeeded, timestamp) VALUES (?, ?, ?)").run(
    identifier,
    succeeded ? 1 : 0,
    Date.now()
  );
}

function recentFailureCount(db, identifier) {
  const windowStart = Date.now() - LockoutWindowMs;
  const row = db
    .prepare("SELECT COUNT(*) AS count FROM attempts WHERE identifier = ? AND succeeded = 0 AND timestamp >= ?")
    .get(identifier, windowStart);
  return row.count;
}

function evaluateAbuse(db, identifier) {
  const failureCount = recentFailureCount(db, identifier);
  if (failureCount < LockoutThreshold) {
    setFlag(db, identifier, { level: "Watched", lockedUntil: 0, failureCount });
    return { level: "Watched", failureCount };
  }
  const excess = failureCount - LockoutThreshold;
  const lockMs = LockoutBaseMs * Math.pow(2, excess);
  const lockedUntil = Date.now() + lockMs;
  setFlag(db, identifier, { level: "Locked", lockedUntil, failureCount });
  return { level: "Locked", failureCount, lockedUntil };
}

function flagHoneypot(db, identifier, deviceId) {
  setFlag(db, `${identifier}:${deviceId}`, {
    level: "Locked",
    lockedUntil: Date.now() + LockoutWindowMs * 96,
    failureCount: LockoutThreshold
  });
}

export function pruneOldAttempts(db, olderThanMs = 24 * 60 * 60 * 1000) {
  db.prepare("DELETE FROM attempts WHERE timestamp < ?").run(Date.now() - olderThanMs);
}

function accountFields(record) {
  return {
    username: record.username,
    deviceId: record.device_id,
    publicKeyHex: record.public_key_hex,
    identityId: record.identity_id
  };
}

export async function handleSignupStart(db, pepper, rawPayload) {
  const entry = validateSignupPayload(rawPayload);

  const lockFlag = await getMostRestrictiveLock(db, entry.identifier, entry.deviceId);
  if (lockFlag) {
    throw taggedError(Codes.Locked, "Too many attempts for this identifier.", { retryAfterMs: lockFlag.locked_until - Date.now() });
  }

  const now = Date.now();
  if (entry.expiresAt <= now) {
    throw taggedError(Codes.ChallengeExpired, "Registration challenge expired.");
  }
  if (Math.abs(entry.expiresAt - entry.createdAt - IdentityTtlMs) > 1000) {
    throw taggedError(Codes.ChallengeInvalid, "Registration challenge is malformed.");
  }
  if (entry.createdAt > now + ClockSkewToleranceMs || entry.createdAt < now - IdentityTtlMs - ClockSkewToleranceMs) {
    throw taggedError(Codes.ChallengeInvalid, "Registration challenge is malformed.");
  }

  const consumed = db.prepare("SELECT 1 FROM consumed_identities WHERE identity_id = ?").get(entry.identityId);
  if (consumed) {
    throw taggedError(Codes.ChallengeInvalid, "Registration challenge is malformed.");
  }

  const signatureValid = await verifySignedChallenge(entry);
  if (!signatureValid) {
    throw taggedError(Codes.ChallengeInvalid, "Registration challenge is malformed.");
  }

  const powValid = await verifyProofOfWork(entry.publicKeyHex, entry.proofOfWorkNonce);
  if (!powValid) {
    throw taggedError(Codes.ChallengeInvalid, "Registration challenge is malformed.");
  }

  if (HoneypotIdentifiers.has(entry.identifier)) {
    flagHoneypot(db, entry.identifier, entry.deviceId);
    throw taggedError(Codes.InvalidCredentials, "Invalid username or password.");
  }

  const existingUsername = db.prepare("SELECT 1 FROM identities WHERE username = ?").get(entry.identifier);
  if (existingUsername) {
    throw taggedError(Codes.IdentifierTaken, "That username is already taken.");
  }
  const existingEmail = db.prepare("SELECT 1 FROM identities WHERE email = ?").get(entry.email);
  if (existingEmail) {
    throw taggedError(Codes.IdentifierTaken, "That email is already in use.");
  }

  db.prepare("INSERT INTO consumed_identities (identity_id, consumed_at) VALUES (?, ?)").run(entry.identityId, now);

  const { id, code } = await createPendingVerification(db, "signup", entry.email, {
    username: entry.identifier,
    clientSaltHex: entry.clientSaltHex,
    clientHashHex: entry.clientHashHex,
    deviceId: entry.deviceId,
    identityId: entry.identityId,
    publicKeyHex: entry.publicKeyHex
  }, IdentityTtlMs);
  await sendCode(entry.email, code, "signup");

  return { pendingVerificationId: id };
}

export async function handleSignupVerify(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const pendingVerificationId = assertString(rawPayload.pendingVerificationId, "pendingVerificationId", { min: 1, max: 64 });
  const code = assertString(rawPayload.code, "code", { min: 6, max: 6 });

  const staged = await consumePendingVerification(db, "signup", pendingVerificationId, code);

  const existingUsername = db.prepare("SELECT 1 FROM identities WHERE username = ?").get(staged.username);
  if (existingUsername) {
    throw taggedError(Codes.IdentifierTaken, "That username is already taken.");
  }
  const existingEmail = db.prepare("SELECT 1 FROM identities WHERE email = ?").get(staged.identifier);
  if (existingEmail) {
    throw taggedError(Codes.IdentifierTaken, "That email is already in use.");
  }

  const now = Date.now();
  const serverSaltHex = randomHex(16);
  const serverHashHex = await deriveServerHash(pepper, staged.clientHashHex, serverSaltHex);

  try {
    db.prepare(
      `INSERT INTO identities (username, email, server_salt_hex, credential_hash_hex, device_id, identity_id, public_key_hex, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(staged.username, staged.identifier, `${staged.clientSaltHex}:${serverSaltHex}`, serverHashHex, staged.deviceId, staged.identityId, staged.publicKeyHex, now);
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      throw taggedError(Codes.IdentifierTaken, "That username or email is already taken.");
    }
    throw taggedError(Codes.InternalError, "Could not complete registration.");
  }

  const record = db.prepare("SELECT * FROM identities WHERE username = ?").get(staged.username);
  return accountFields(record);
}

export async function handleSaltByEmail(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const email = normalizeIdentifier(assertString(rawPayload.email, "email", { min: 1, max: 254 }));
  const record = db.prepare("SELECT server_salt_hex FROM identities WHERE email = ?").get(email);
  if (record) {
    const [clientSaltHex] = record.server_salt_hex.split(":");
    return { saltHex: clientSaltHex };
  }
  const pseudoSaltHex = await derivePseudoSaltHex(pepper, email);
  return { saltHex: pseudoSaltHex };
}

export async function handleLoginPassword(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const email = normalizeIdentifier(assertString(rawPayload.email, "email", { min: 1, max: 254 }));
  const clientHashHex = assertCredentialHashHex(rawPayload.credentialHashHex);

  const flag = await getFlag(db, email);
  if (isLocked(flag)) {
    throw taggedError(Codes.Locked, "Too many attempts for this identifier.", { retryAfterMs: flag.locked_until - Date.now() });
  }

  const record = db.prepare("SELECT * FROM identities WHERE email = ?").get(email);
  if (!record) {
    const pseudoSaltHex = await derivePseudoSaltHex(pepper, email);
    await deriveServerHash(pepper, clientHashHex, pseudoSaltHex);
    recordAttempt(db, email, false);
    evaluateAbuse(db, email);
    throw taggedError(Codes.InvalidCredentials, "Invalid email or password.");
  }

  const [, serverSaltHex] = record.server_salt_hex.split(":");
  const candidateHashHex = await deriveServerHash(pepper, clientHashHex, serverSaltHex);
  const matches = constantTimeEqual(hexToBuffer(candidateHashHex), hexToBuffer(record.credential_hash_hex));
  recordAttempt(db, email, matches);
  if (!matches) {
    evaluateAbuse(db, email);
    throw taggedError(Codes.InvalidCredentials, "Invalid email or password.");
  }
  setFlag(db, email, { level: "Clear", lockedUntil: 0, failureCount: 0 });

  if (record.two_factor_enabled) {
    const { id, code } = await createPendingVerification(db, "2fa", email, { username: record.username });
    await sendCode(email, code, "2fa");
    return { requires2fa: true, pendingVerificationId: id };
  }

  return accountFields(record);
}

export async function handleLoginVerify2fa(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const pendingVerificationId = assertString(rawPayload.pendingVerificationId, "pendingVerificationId", { min: 1, max: 64 });
  const code = assertString(rawPayload.code, "code", { min: 6, max: 6 });
  const staged = await consumePendingVerification(db, "2fa", pendingVerificationId, code);
  const record = db.prepare("SELECT * FROM identities WHERE username = ?").get(staged.username);
  if (!record) {
    throw taggedError(Codes.InvalidCredentials, "Invalid email or password.");
  }
  return accountFields(record);
}

export async function handleLoginCodeRequest(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const email = normalizeIdentifier(assertString(rawPayload.email, "email", { min: 1, max: 254 }));
  const record = db.prepare("SELECT username FROM identities WHERE email = ?").get(email);
  if (record) {
    const { id, code } = await createPendingVerification(db, "login-code", email, { username: record.username });
    await sendCode(email, code, "login-code");
    return { sent: true, pendingVerificationId: id };
  }
  return { sent: true, pendingVerificationId: randomHex(16) };
}

export async function handleLoginCodeVerify(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const pendingVerificationId = assertString(rawPayload.pendingVerificationId, "pendingVerificationId", { min: 1, max: 64 });
  const code = assertString(rawPayload.code, "code", { min: 6, max: 6 });
  const staged = await consumePendingVerification(db, "login-code", pendingVerificationId, code);
  const record = db.prepare("SELECT * FROM identities WHERE username = ?").get(staged.username);
  if (!record) {
    throw taggedError(Codes.InvalidCredentials, "Invalid code.");
  }
  return accountFields(record);
}

const passChallenges = new Map();

function prunePassChallenges() {
  const now = Date.now();
  for (const [id, challenge] of passChallenges) {
    if (challenge.expiresAt <= now) {
      passChallenges.delete(id);
    }
  }
}

export function handlePassEnable(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const publicKeyHex = assertPattern(assertString(rawPayload.publicKeyHex, "publicKeyHex", { min: 130, max: 130 }), "publicKeyHex", PublicKeyHexPattern);
  db.prepare("UPDATE identities SET pass_public_key_hex = ? WHERE username = ?").run(publicKeyHex, record.username);
  return { enabled: true };
}

export function handlePassDisable(db, record) {
  db.prepare("UPDATE identities SET pass_public_key_hex = NULL WHERE username = ?").run(record.username);
  return { disabled: true };
}

export function handlePassChallenge(db, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const email = normalizeIdentifier(assertString(rawPayload.email, "email", { min: 1, max: 254 }));
  prunePassChallenges();
  const challengeId = randomHex(16);
  const nonceHex = randomHex(32);
  passChallenges.set(challengeId, { email, nonceHex, expiresAt: Date.now() + PassChallengeTtlMs });
  return { challengeId, nonceHex };
}

export async function handlePassVerify(db, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const challengeId = assertString(rawPayload.challengeId, "challengeId", { min: 1, max: 64 });
  const signatureHex = assertPattern(assertString(rawPayload.signatureHex, "signatureHex", { min: 128, max: 128 }), "signatureHex", SignatureHexPattern);

  const challenge = passChallenges.get(challengeId);
  if (!challenge || challenge.expiresAt <= Date.now()) {
    passChallenges.delete(challengeId);
    throw taggedError(Codes.ChallengeExpired, "This challenge has expired.");
  }
  passChallenges.delete(challengeId);

  const record = db.prepare("SELECT * FROM identities WHERE email = ?").get(challenge.email);
  if (!record || !record.pass_public_key_hex) {
    throw taggedError(Codes.InvalidCredentials, "Pass is not enabled for this account.");
  }

  const publicKey = await subtle.importKey(
    "raw",
    hexToBuffer(record.pass_public_key_hex),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  const valid = await subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    hexToBuffer(signatureHex),
    hexToBuffer(challenge.nonceHex)
  );
  if (!valid) {
    throw taggedError(Codes.InvalidCredentials, "Pass signature invalid.");
  }
  return accountFields(record);
}

export async function handleForgotPasswordRequest(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const email = normalizeIdentifier(assertString(rawPayload.email, "email", { min: 1, max: 254 }));
  const record = db.prepare("SELECT username FROM identities WHERE email = ?").get(email);
  if (record) {
    const { id, code } = await createPendingVerification(db, "reset", email, { username: record.username });
    await sendCode(email, code, "reset");
    return { sent: true, pendingVerificationId: id };
  }
  return { sent: true, pendingVerificationId: randomHex(16) };
}

export async function handleForgotPasswordVerify(db, pepper, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const pendingVerificationId = assertString(rawPayload.pendingVerificationId, "pendingVerificationId", { min: 1, max: 64 });
  const code = assertString(rawPayload.code, "code", { min: 6, max: 6 });
  const clientSaltHex = assertPattern(assertString(rawPayload.clientSaltHex, "clientSaltHex", { min: 32, max: 32 }), "clientSaltHex", HexPattern(16));
  const clientHashHex = assertCredentialHashHex(rawPayload.credentialHashHex);

  const staged = await consumePendingVerification(db, "reset", pendingVerificationId, code);
  const record = db.prepare("SELECT * FROM identities WHERE username = ?").get(staged.username);
  if (!record) {
    throw taggedError(Codes.InvalidCredentials, "Invalid code.");
  }

  const serverSaltHex = randomHex(16);
  const serverHashHex = await deriveServerHash(pepper, clientHashHex, serverSaltHex);
  db.prepare("UPDATE identities SET server_salt_hex = ?, credential_hash_hex = ? WHERE username = ?").run(
    `${clientSaltHex}:${serverSaltHex}`,
    serverHashHex,
    record.username
  );
  revokeAllSessionsForUser(db, record.username);

  return accountFields({ ...record, server_salt_hex: `${clientSaltHex}:${serverSaltHex}`, credential_hash_hex: serverHashHex });
}

export function handleSaltForSession(db, pepper, record) {
  const [clientSaltHex] = record.server_salt_hex.split(":");
  return { saltHex: clientSaltHex };
}

export { deriveServerHash, normalizeIdentifier, assertCredentialHashHex, HexPattern };
