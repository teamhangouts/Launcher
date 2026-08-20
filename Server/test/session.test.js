import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { randomHex } from "../src/codec.js";
import { TestPipelineClient, buildRegistrationEntry, deriveCredentialHash } from "./testClient.js";

let server;
let url;

before(async () => {
  server = await createHangoutsServer({
    dbPath: ":memory:",
    maxConnectionsPerIp: 200,
    handshakeBucket: { capacity: 500, refillPerMs: 500 / 1000 }
  });
  const address = await server.listen(0);
  url = `ws://127.0.0.1:${address.port}`;
});

after(() => {
  server.close();
});

function uniqueUsername() {
  return `user_${randomHex(8)}`;
}

async function registerAndGetSession(username, password) {
  const client = new TestPipelineClient(url);
  await client.connect();
  const entry = await buildRegistrationEntry();
  const clientSaltHex = randomHex(16);
  const credentialHashHex = await deriveCredentialHash(password, clientSaltHex);
  const result = await client.sendRequest("auth:register", {
    username,
    clientSaltHex,
    credentialHashHex,
    identityId: entry.identityId,
    publicKeyHex: entry.publicKeyHex,
    deviceId: entry.deviceId,
    proofOfWorkBits: entry.proofOfWorkBits,
    proofOfWorkNonce: entry.proofOfWorkNonce,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    challengeHex: entry.challengeHex,
    signatureHex: entry.signatureHex
  });
  return { client, result };
}

test("registration issues a session token that resumes on a fresh connection", async () => {
  const username = uniqueUsername();
  const { client, result } = await registerAndGetSession(username, "correct horse battery");
  assert.ok(result.sessionToken);
  client.close();

  const fresh = new TestPipelineClient(url);
  await fresh.connect();
  const resumed = await fresh.sendRequest("auth:resume", { sessionToken: result.sessionToken });
  assert.equal(resumed.username, username);
  fresh.close();
});

test("logout revokes the session so resume afterward fails", async () => {
  const username = uniqueUsername();
  const { client, result } = await registerAndGetSession(username, "correct horse battery");
  await client.sendRequest("auth:logout", { sessionToken: result.sessionToken });

  const fresh = new TestPipelineClient(url);
  await fresh.connect();
  await assert.rejects(fresh.sendRequest("auth:resume", { sessionToken: result.sessionToken }), (error) => {
    assert.equal(error.code, "A2");
    return true;
  });
  client.close();
  fresh.close();
});

test("resuming with a bogus token is rejected with A2", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  await assert.rejects(client.sendRequest("auth:resume", { sessionToken: "not-a-real-token" }), (error) => {
    assert.equal(error.code, "A2");
    return true;
  });
  client.close();
});

test("resuming refreshes the session's expiry (sliding window)", async () => {
  const username = uniqueUsername();
  const { client, result } = await registerAndGetSession(username, "correct horse battery");
  client.close();

  const first = new TestPipelineClient(url);
  await first.connect();
  await first.sendRequest("auth:resume", { sessionToken: result.sessionToken });
  first.close();

  const second = new TestPipelineClient(url);
  await second.connect();
  const resumed = await second.sendRequest("auth:resume", { sessionToken: result.sessionToken });
  assert.equal(resumed.username, username);
  second.close();
});
