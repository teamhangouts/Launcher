import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { subtle, randomHex, bufferToHex, hexToBuffer } from "./codec.js";

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const defaultSecretsDir = join(rootDir, ".secrets");

function ensureSecretsDir(secretsDir) {
  if (!existsSync(secretsDir)) {
    mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  }
}

export async function loadOrCreateServerIdentity(secretsDir = defaultSecretsDir) {
  ensureSecretsDir(secretsDir);
  const identityPath = join(secretsDir, "identity.json");
  if (existsSync(identityPath)) {
    const stored = JSON.parse(readFileSync(identityPath, "utf8"));
    const privateKey = await subtle.importKey(
      "jwk",
      stored.privateKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    return { privateKey, publicKeyHex: stored.publicKeyHex };
  }
  const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const privateKeyJwk = await subtle.exportKey("jwk", keyPair.privateKey);
  const publicKeyRaw = await subtle.exportKey("raw", keyPair.publicKey);
  const publicKeyHex = bufferToHex(publicKeyRaw);
  writeFileSync(identityPath, JSON.stringify({ privateKeyJwk, publicKeyHex }, null, 2), { mode: 0o600 });
  const nonExtractablePrivateKey = await subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  return { privateKey: nonExtractablePrivateKey, publicKeyHex };
}

export function loadOrCreatePepper(secretsDir = defaultSecretsDir) {
  ensureSecretsDir(secretsDir);
  const pepperPath = join(secretsDir, "pepper.hex");
  if (existsSync(pepperPath)) {
    return hexToBuffer(readFileSync(pepperPath, "utf8").trim());
  }
  const pepperHex = randomHex(32);
  writeFileSync(pepperPath, pepperHex, { mode: 0o600 });
  return hexToBuffer(pepperHex);
}
