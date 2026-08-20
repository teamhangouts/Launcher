import { hexToBuffer, constantTimeEqual, randomHex } from "./codec.js";
import { Codes, taggedError } from "./codes.js";
import { createPendingVerification, consumePendingVerification } from "./verification.js";
import { sendCode } from "./mailer.js";
import { deriveServerHash, assertCredentialHashHex, HexPattern } from "./auth.js";
import { revokeAllSessionsForUser } from "./session.js";

const EmailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MaxBioLength = 500;
const MaxPfpBytes = 2 * 1024 * 1024;
const AllowedPfpMimeTypes = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

function assertString(value, field, { min = 0, max = Infinity } = {}) {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function normalizeIdentifier(value) {
  return String(value).trim().toLowerCase();
}

export function handleEnable2fa(db, record) {
  db.prepare("UPDATE identities SET two_factor_enabled = 1 WHERE username = ?").run(record.username);
  return { enabled: true };
}

export function handleDisable2fa(db, record) {
  db.prepare("UPDATE identities SET two_factor_enabled = 0 WHERE username = ?").run(record.username);
  return { disabled: true };
}

export async function handleChangeEmailRequest(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const newEmail = normalizeIdentifier(assertString(rawPayload.newEmail, "newEmail", { min: 3, max: 254 }));
  if (!EmailPattern.test(newEmail)) {
    throw taggedError(Codes.MalformedRequest, "Invalid newEmail.");
  }
  const existing = db.prepare("SELECT 1 FROM identities WHERE email = ?").get(newEmail);
  if (existing) {
    throw taggedError(Codes.IdentifierTaken, "That email is already in use.");
  }
  const { id, code } = await createPendingVerification(db, "change-email", newEmail, { username: record.username });
  await sendCode(newEmail, code, "change-email");
  return { pendingVerificationId: id };
}

export async function handleChangeEmailVerify(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const pendingVerificationId = assertString(rawPayload.pendingVerificationId, "pendingVerificationId", { min: 1, max: 64 });
  const code = assertString(rawPayload.code, "code", { min: 6, max: 6 });
  const staged = await consumePendingVerification(db, "change-email", pendingVerificationId, code);
  if (staged.username !== record.username) {
    throw taggedError(Codes.ChallengeInvalid, "This verification does not belong to your session.");
  }
  const existing = db.prepare("SELECT 1 FROM identities WHERE email = ?").get(staged.identifier);
  if (existing) {
    throw taggedError(Codes.IdentifierTaken, "That email is already in use.");
  }
  db.prepare("UPDATE identities SET email = ? WHERE username = ?").run(staged.identifier, record.username);
  return { email: staged.identifier };
}

export async function handleChangePassword(db, pepper, record, sessionTokenHash, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const currentCredentialHashHex = assertCredentialHashHex(rawPayload.currentCredentialHashHex, "currentCredentialHashHex");
  const newClientSaltHex = assertString(rawPayload.newClientSaltHex, "newClientSaltHex", { min: 32, max: 32 });
  if (!HexPattern(16).test(newClientSaltHex)) {
    throw taggedError(Codes.MalformedRequest, "Invalid newClientSaltHex.");
  }
  const newCredentialHashHex = assertCredentialHashHex(rawPayload.newCredentialHashHex, "newCredentialHashHex");

  const [, serverSaltHex] = record.server_salt_hex.split(":");
  const candidateHashHex = await deriveServerHash(pepper, currentCredentialHashHex, serverSaltHex);
  const matches = constantTimeEqual(hexToBuffer(candidateHashHex), hexToBuffer(record.credential_hash_hex));
  if (!matches) {
    throw taggedError(Codes.InvalidCredentials, "Current password is incorrect.");
  }

  const newServerSaltHex = randomHex(16);
  const newServerHashHex = await deriveServerHash(pepper, newCredentialHashHex, newServerSaltHex);
  db.prepare("UPDATE identities SET server_salt_hex = ?, credential_hash_hex = ? WHERE username = ?").run(
    `${newClientSaltHex}:${newServerSaltHex}`,
    newServerHashHex,
    record.username
  );

  revokeAllSessionsForUser(db, record.username, sessionTokenHash);
  return { changed: true };
}

export function handleChangeBio(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const bio = assertString(rawPayload.bio, "bio", { min: 0, max: MaxBioLength });
  db.prepare("UPDATE identities SET bio = ? WHERE username = ?").run(bio, record.username);
  return { bio };
}

export function handleChangePfp(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const mimeType = assertString(rawPayload.mimeType, "mimeType", { min: 1, max: 64 });
  if (!AllowedPfpMimeTypes.has(mimeType)) {
    throw taggedError(Codes.MalformedRequest, "Unsupported image type.");
  }
  const imageBase64 = assertString(rawPayload.imageBase64, "imageBase64", { min: 1, max: Math.ceil((MaxPfpBytes * 4) / 3) + 64 });
  const bytes = Buffer.from(imageBase64, "base64");
  if (bytes.length === 0 || bytes.length > MaxPfpBytes) {
    throw taggedError(Codes.MalformedRequest, "Image is too large.");
  }
  db.prepare("UPDATE identities SET pfp = ?, pfp_mime = ? WHERE username = ?").run(bytes, mimeType, record.username);
  return { updated: true };
}
