import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomHex, constantTimeEqual, hexToBuffer } from "./codec.js";
import { Codes, taggedError } from "./codes.js";

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const defaultSecretsDir = join(rootDir, ".secrets");

function ensureSecretsDir(secretsDir) {
  if (!existsSync(secretsDir)) {
    mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  }
}

export function loadOrCreateAdminToken(secretsDir = defaultSecretsDir) {
  ensureSecretsDir(secretsDir);
  const adminTokenPath = join(secretsDir, "admin-token.hex");
  if (existsSync(adminTokenPath)) {
    return readFileSync(adminTokenPath, "utf8").trim();
  }
  const token = randomHex(32);
  writeFileSync(adminTokenPath, token, { mode: 0o600 });
  return token;
}

export function assertAdminToken(expectedToken, providedToken) {
  if (typeof providedToken !== "string" || !providedToken) {
    throw taggedError(Codes.InvalidCredentials, "Invalid admin token.");
  }
  if (!constantTimeEqual(hexToBuffer(expectedToken), hexToBuffer(providedToken))) {
    throw taggedError(Codes.InvalidCredentials, "Invalid admin token.");
  }
}
