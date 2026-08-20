import { webcrypto, timingSafeEqual } from "node:crypto";

export const subtle = webcrypto.subtle;

export function randomBytes(length) {
  return webcrypto.getRandomValues(new Uint8Array(length));
}

export function randomHex(byteLength) {
  return bufferToHex(randomBytes(byteLength));
}

export function base64Encode(buffer) {
  return Buffer.from(buffer).toString("base64");
}

export function base64Decode(value) {
  return new Uint8Array(Buffer.from(value, "base64"));
}

export function bufferToHex(buffer) {
  return Buffer.from(buffer).toString("hex");
}

export function hexToBuffer(hex) {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export function utf8Encode(text) {
  return new TextEncoder().encode(text);
}

export function utf8Decode(buffer) {
  return new TextDecoder().decode(buffer);
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, array) => sum + array.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const array of arrays) {
    out.set(new Uint8Array(array), offset);
    offset += array.byteLength;
  }
  return out;
}

export function seqToBytes(seq) {
  return new Uint8Array(new Uint32Array([seq]).buffer);
}

export function constantTimeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
