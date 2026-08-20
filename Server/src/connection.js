import {
  subtle,
  randomBytes,
  base64Encode,
  base64Decode,
  concatBytes,
  seqToBytes,
  hexToBuffer,
  utf8Encode,
  utf8Decode
} from "./codec.js";
import { TaggedError, Codes, taggedError } from "./codes.js";

const HandshakeTimeoutMs = 10000;
const MessageWindowMs = 1000;
const MessageWindowMax = 20;
const MaxDecodedMessageBytes = 16 * 1024;

async function performServerHandshake(ws, serverIdentity, initMessage) {
  if (initMessage.type !== "handshake:init" || typeof initMessage.clientEphemeralPublicKey !== "string") {
    throw new Error("HandshakeMalformed");
  }

  const clientEphemeralRaw = base64Decode(initMessage.clientEphemeralPublicKey);
  if (clientEphemeralRaw.byteLength !== 65) {
    throw new Error("HandshakeMalformed");
  }

  const clientEphemeralPublicKey = await subtle.importKey(
    "raw",
    clientEphemeralRaw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  const serverEphemeral = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const serverEphemeralRaw = new Uint8Array(await subtle.exportKey("raw", serverEphemeral.publicKey));
  const nonce = randomBytes(16);

  const signedBlob = concatBytes(clientEphemeralRaw, serverEphemeralRaw, nonce);
  const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, serverIdentity.privateKey, signedBlob);

  ws.send(
    JSON.stringify({
      type: "handshake:response",
      serverEphemeralPublicKey: base64Encode(serverEphemeralRaw),
      nonce: base64Encode(nonce),
      serverLongTermPublicKey: base64Encode(hexToBuffer(serverIdentity.publicKeyHex)),
      signature: base64Encode(signature)
    })
  );

  const sharedBits = await subtle.deriveBits(
    { name: "ECDH", public: clientEphemeralPublicKey },
    serverEphemeral.privateKey,
    256
  );
  const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const sessionKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: nonce, info: utf8Encode("hangouts-pipeline-v1") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return sessionKey;
}

async function encryptEnvelope(sessionKey, sendSeqBox, object) {
  const iv = randomBytes(12);
  const seq = sendSeqBox.value++;
  const plaintext = utf8Encode(JSON.stringify(object));
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: seqToBytes(seq) },
    sessionKey,
    plaintext
  );
  return JSON.stringify({ type: "secure", seq, iv: base64Encode(iv), ct: base64Encode(ciphertext) });
}

async function decryptEnvelope(sessionKey, recvSeqBox, outer) {
  if (typeof outer.seq !== "number" || outer.seq <= recvSeqBox.value) {
    throw new Error("ReplayRejected");
  }
  const plainBuffer = await subtle.decrypt(
    { name: "AES-GCM", iv: base64Decode(outer.iv), additionalData: seqToBytes(outer.seq) },
    sessionKey,
    base64Decode(outer.ct)
  );
  recvSeqBox.value = outer.seq;
  return JSON.parse(utf8Decode(plainBuffer));
}

export function attachConnection(ws, { serverIdentity, dispatch, log, remoteAddress }) {
  const sendSeqBox = { value: 0 };
  const recvSeqBox = { value: -1 };
  let sessionKey = null;
  let closed = false;
  const queue = [];
  let draining = false;
  let messageWindowStart = Date.now();
  let messageWindowCount = 0;
  let authenticatedUsername = null;

  const connectionContext = {
    getAuthenticatedUsername: () => authenticatedUsername,
    setAuthenticatedUsername: (username) => {
      authenticatedUsername = username;
    },
    clearAuthenticatedUsername: () => {
      authenticatedUsername = null;
    }
  };

  const handshakeTimer = setTimeout(() => {
    if (!sessionKey) {
      closeOnce(4000, "HandshakeTimeout");
    }
  }, HandshakeTimeoutMs);

  ws.on("message", (raw) => {
    if (closed) {
      return;
    }
    if (raw.length > MaxDecodedMessageBytes) {
      closeOnce(4002, "MessageTooLarge");
      return;
    }
    queue.push(raw);
    drain();
  });

  ws.on("close", () => {
    closed = true;
  });

  function closeOnce(code, reason) {
    if (closed) {
      return;
    }
    closed = true;
    try {
      ws.close(code, reason);
    } catch {}
  }

  function withinMessageRate() {
    const now = Date.now();
    if (now - messageWindowStart > MessageWindowMs) {
      messageWindowStart = now;
      messageWindowCount = 0;
    }
    messageWindowCount++;
    return messageWindowCount <= MessageWindowMax;
  }

  async function drain() {
    if (draining) {
      return;
    }
    draining = true;
    while (queue.length > 0 && !closed) {
      const raw = queue.shift();
      await processRaw(raw);
    }
    draining = false;
  }

  async function processRaw(raw) {
    if (!sessionKey) {
      await processHandshakeInit(raw);
      return;
    }
    if (!withinMessageRate()) {
      closeOnce(4008, "RateLimited");
      return;
    }
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
      message = await decryptEnvelope(sessionKey, recvSeqBox, outer);
    } catch {
      closeOnce(4009, "DecryptFailed");
      return;
    }
    await handleMessage(message);
  }

  async function processHandshakeInit(raw) {
    let initMessage;
    try {
      initMessage = JSON.parse(raw.toString("utf8"));
    } catch {
      closeOnce(4001, "HandshakeFailed");
      return;
    }
    try {
      sessionKey = await performServerHandshake(ws, serverIdentity, initMessage);
      clearTimeout(handshakeTimer);
    } catch (error) {
      log?.(`handshake failed from ${remoteAddress}: ${error.message}`);
      closeOnce(4001, "HandshakeFailed");
    }
  }

  async function handleMessage(message) {
    const { type, payload, requestId } = message;
    if (!requestId || typeof type !== "string") {
      return;
    }
    try {
      const responsePayload = await dispatch(type, payload, connectionContext);
      const envelope = await encryptEnvelope(sessionKey, sendSeqBox, {
        type: `${type}:response`,
        requestId,
        payload: responsePayload
      });
      if (!closed) {
        ws.send(envelope);
      }
    } catch (error) {
      const tagged = error instanceof TaggedError ? error : taggedError(Codes.InternalError, "Unexpected server error.");
      const envelope = await encryptEnvelope(sessionKey, sendSeqBox, {
        type: `${type}:response`,
        requestId,
        error: tagged.message,
        errorCode: tagged.code,
        ...tagged.extra
      });
      if (!closed) {
        ws.send(envelope);
      }
    }
  }

  async function push(type, payload) {
    if (closed || !sessionKey) {
      return;
    }
    const envelope = await encryptEnvelope(sessionKey, sendSeqBox, { type, payload });
    if (!closed) {
      ws.send(envelope);
    }
  }

  return { push, getAuthenticatedUsername: connectionContext.getAuthenticatedUsername };
}
