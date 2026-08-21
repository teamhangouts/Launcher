import WebSocket from "ws";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  subtle,
  randomBytes,
  base64Encode,
  base64Decode,
  concatBytes,
  seqToBytes,
  hexToBuffer,
  bufferToHex,
  utf8Encode,
  utf8Decode,
  randomHex
} from "../src/codec.js";
import { ProofOfWorkBits, IdentityTtlMs } from "../src/auth.js";

export function createIsolatedSecretsDir() {
  return mkdtempSync(join(tmpdir(), "hangouts-test-secrets-"));
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

export async function solveProofOfWork(publicKeyHex, bits = ProofOfWorkBits) {
  let nonce = 0;
  while (true) {
    const digest = await subtle.digest("SHA-256", utf8Encode(`${publicKeyHex}:${nonce}`));
    if (countLeadingZeroBits(digest) >= bits) {
      return nonce;
    }
    nonce++;
  }
}

export async function deriveCredentialHash(password, saltHex, iterations = 250000) {
  const keyMaterial = await subtle.importKey("raw", utf8Encode(password), "PBKDF2", false, ["deriveBits"]);
  const derivedBits = await subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBuffer(saltHex), iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufferToHex(derivedBits);
}

export async function buildRegistrationEntry({
  bits = ProofOfWorkBits,
  ttlMs = IdentityTtlMs,
  expiresAtOverride,
  createdAtOverride,
  skipProofOfWork = false
} = {}) {
  const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const publicKeyRaw = await subtle.exportKey("raw", keyPair.publicKey);
  const publicKeyHex = bufferToHex(publicKeyRaw);
  const proofOfWorkNonce = skipProofOfWork ? 0 : await solveProofOfWork(publicKeyHex, bits);
  const identityId = randomHex(16);
  const deviceId = randomHex(32);
  const createdAt = createdAtOverride ?? Date.now();
  const expiresAt = expiresAtOverride ?? createdAt + ttlMs;

  const base = {
    identityId,
    publicKeyHex,
    deviceId,
    proofOfWorkBits: bits,
    proofOfWorkNonce,
    createdAt,
    expiresAt
  };
  const canonical = JSON.stringify(base);
  const digest = await subtle.digest("SHA-256", utf8Encode(canonical));
  const challengeHex = bufferToHex(digest);
  const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, hexToBuffer(challengeHex));
  const signatureHex = bufferToHex(signature);

  return { ...base, challengeHex, signatureHex, privateKey: keyPair.privateKey };
}

export class TestPipelineClient {
  constructor(url) {
    this.url = url;
    this.sessionKey = null;
    this.sendSeq = 0;
    this.recvSeq = -1;
    this.requestCounter = 0;
    this.pending = new Map();
    this.pinnedIdentity = null;
    this.pushListeners = new Map();
  }

  onPush(type, handler) {
    if (!this.pushListeners.has(type)) {
      this.pushListeners.set(type, new Set());
    }
    this.pushListeners.get(type).add(handler);
  }

  async connect() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      this.ws.once("open", resolve);
      this.ws.once("error", reject);
    });

    const ephemeral = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const clientEphemeralRaw = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));

    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("HandshakeTimeout")), 10000);
      this.ws.once("message", (raw) => {
        clearTimeout(timer);
        resolve(JSON.parse(raw.toString("utf8")));
      });
      this.ws.send(JSON.stringify({ type: "handshake:init", clientEphemeralPublicKey: base64Encode(clientEphemeralRaw) }));
    });

    const serverEphemeralRaw = base64Decode(response.serverEphemeralPublicKey);
    const nonce = new Uint8Array(base64Decode(response.nonce));
    const signedBlob = concatBytes(clientEphemeralRaw, serverEphemeralRaw, nonce);

    const serverIdentityKey = await subtle.importKey(
      "raw",
      base64Decode(response.serverLongTermPublicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
    const signatureValid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      serverIdentityKey,
      base64Decode(response.signature),
      signedBlob
    );
    if (!signatureValid) {
      throw new Error("HandshakeSignatureInvalid");
    }
    this.pinnedIdentity = response.serverLongTermPublicKey;

    const serverEphemeralPublicKey = await subtle.importKey(
      "raw",
      serverEphemeralRaw,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
    const sharedBits = await subtle.deriveBits({ name: "ECDH", public: serverEphemeralPublicKey }, ephemeral.privateKey, 256);
    const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
    this.sessionKey = await subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: nonce, info: utf8Encode("hangouts-pipeline-v1") },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    this.ws.on("message", (raw) => this.handleMessage(raw));
  }

  async handleMessage(raw) {
    let outer;
    try {
      outer = JSON.parse(raw.toString("utf8"));
    } catch {
      return;
    }
    if (outer.type !== "secure") {
      return;
    }
    let message;
    try {
      const plainBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: base64Decode(outer.iv), additionalData: seqToBytes(outer.seq) },
        this.sessionKey,
        base64Decode(outer.ct)
      );
      message = JSON.parse(utf8Decode(plainBuffer));
    } catch {
      return;
    }
    if (!message.requestId) {
      const handlers = this.pushListeners.get(message.type);
      if (handlers) {
        for (const handler of handlers) {
          handler(message.payload);
        }
      }
      return;
    }
    const pending = this.pending.get(message.requestId);
    if (!pending) {
      return;
    }
    this.pending.delete(message.requestId);
    if (message.error) {
      const error = new Error(message.error);
      error.code = message.errorCode;
      error.extra = message;
      pending.reject(error);
    } else {
      pending.resolve(message.payload);
    }
  }

  async sendRaw(rawObject) {
    const iv = randomBytes(12);
    const seq = this.sendSeq++;
    const plaintext = utf8Encode(JSON.stringify(rawObject));
    const ciphertext = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: seqToBytes(seq) },
      this.sessionKey,
      plaintext
    );
    this.lastSentEnvelope = JSON.stringify({ type: "secure", seq, iv: base64Encode(iv), ct: base64Encode(ciphertext) });
    this.ws.send(this.lastSentEnvelope);
    return seq;
  }

  sendRequest(type, payload, timeoutMs = 5000) {
    const requestId = `Req_${++this.requestCounter}_${Math.random()}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new Error("RequestTimeout"));
      }, timeoutMs);
      this.pending.set(requestId, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        }
      });
      this.sendRaw({ type, payload, requestId, ts: Date.now() });
    });
  }

  close() {
    this.ws.close();
  }
}
