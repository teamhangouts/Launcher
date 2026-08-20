import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { LockoutThreshold, IdentityTtlMs } from "../src/auth.js";
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

async function registerPayload(username, password, entryOptions) {
  const entry = await buildRegistrationEntry(entryOptions);
  const clientSaltHex = randomHex(16);
  const credentialHashHex = await deriveCredentialHash(password, clientSaltHex);
  return {
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
  };
}

async function loginWithPassword(username, password) {
  const client = new TestPipelineClient(url);
  await client.connect();
  const saltResp = await client.sendRequest("auth:salt", { username });
  const credentialHashHex = await deriveCredentialHash(password, saltResp.saltHex);
  try {
    return { client, result: await client.sendRequest("auth:login", { username, credentialHashHex }) };
  } catch (error) {
    return { client, error };
  }
}

test("register then login succeeds end to end", async () => {
  const username = uniqueUsername();
  const password = "correct horse battery staple";

  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await registerPayload(username, password);
  const registerResult = await client.sendRequest("auth:register", payload);
  assert.equal(registerResult.username, username);
  assert.equal(registerResult.deviceId, payload.deviceId);
  client.close();

  const { client: loginClient, result } = await loginWithPassword(username, password);
  assert.equal(result.username, username);
  assert.equal(result.publicKeyHex, payload.publicKeyHex);
  loginClient.close();
});

test("duplicate username is rejected with A1", async () => {
  const username = uniqueUsername();
  const client = new TestPipelineClient(url);
  await client.connect();
  await client.sendRequest("auth:register", await registerPayload(username, "first-password"));

  const secondClient = new TestPipelineClient(url);
  await secondClient.connect();
  await assert.rejects(
    secondClient.sendRequest("auth:register", await registerPayload(username, "second-password")),
    (error) => {
      assert.equal(error.code, "A1");
      return true;
    }
  );
  client.close();
  secondClient.close();
});

test("wrong password at login is rejected with A2", async () => {
  const username = uniqueUsername();
  const client = new TestPipelineClient(url);
  await client.connect();
  await client.sendRequest("auth:register", await registerPayload(username, "the-real-password"));
  client.close();

  const { client: loginClient, error } = await loginWithPassword(username, "the-wrong-password");
  assert.ok(error);
  assert.equal(error.code, "A2");
  loginClient.close();
});

test("login against a nonexistent username is rejected with A2, not a distinct error", async () => {
  const { client, error } = await loginWithPassword(uniqueUsername(), "whatever");
  assert.ok(error);
  assert.equal(error.code, "A2");
  client.close();
});

test("honeypot usernames are rejected as A2 (invalid), never A1 (taken)", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  await assert.rejects(
    client.sendRequest("auth:register", await registerPayload("admin", "some-password")),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});

test("honeypot registration locks the identifier+device pair for subsequent attempts", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await registerPayload("root", "some-password");
  await assert.rejects(client.sendRequest("auth:register", payload));

  const secondAttempt = await registerPayload("root", "some-other-password");
  secondAttempt.deviceId = payload.deviceId;
  await assert.rejects(
    client.sendRequest("auth:register", secondAttempt),
    (error) => {
      assert.equal(error.code, "A3");
      return true;
    }
  );
  client.close();
});

test("a tampered registration signature is rejected with A5", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await registerPayload(uniqueUsername(), "some-password");
  payload.signatureHex = payload.signatureHex.slice(0, -2) + (payload.signatureHex.slice(-2) === "00" ? "11" : "00");
  await assert.rejects(
    client.sendRequest("auth:register", payload),
    (error) => {
      assert.equal(error.code, "A5");
      return true;
    }
  );
  client.close();
});

test("insufficient proof-of-work is rejected with A5", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await registerPayload(uniqueUsername(), "some-password", { skipProofOfWork: true });
  await assert.rejects(
    client.sendRequest("auth:register", payload),
    (error) => {
      assert.equal(error.code, "A5");
      return true;
    }
  );
  client.close();
});

test("an expired registration challenge is rejected with A4", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const createdAt = Date.now() - IdentityTtlMs - 60000;
  const payload = await registerPayload(uniqueUsername(), "some-password", {
    createdAtOverride: createdAt,
    expiresAtOverride: createdAt + IdentityTtlMs
  });
  await assert.rejects(
    client.sendRequest("auth:register", payload),
    (error) => {
      assert.equal(error.code, "A4");
      return true;
    }
  );
  client.close();
});

test("repeated failed logins lock the identifier with A3 and a retry hint", async () => {
  const username = uniqueUsername();
  const client = new TestPipelineClient(url);
  await client.connect();
  await client.sendRequest("auth:register", await registerPayload(username, "the-real-password"));
  client.close();

  for (let attempt = 0; attempt < LockoutThreshold; attempt++) {
    const { client: attemptClient, error } = await loginWithPassword(username, "wrong-password");
    assert.equal(error.code, "A2");
    attemptClient.close();
  }

  const { client: lockedClient, error } = await loginWithPassword(username, "wrong-password");
  assert.equal(error.code, "A3");
  assert.ok(error.extra.retryAfterMs > 0);
  lockedClient.close();

  const { client: correctPasswordClient, error: stillLockedError } = await loginWithPassword(username, "the-real-password");
  assert.equal(stillLockedError.code, "A3");
  correctPasswordClient.close();
});

test("replaying a previously sent envelope closes the connection instead of being processed twice", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  await client.sendRequest("auth:salt", { username: uniqueUsername() });
  const replayedEnvelope = client.lastSentEnvelope;

  const closed = new Promise((resolve) => client.ws.once("close", resolve));
  client.ws.send(replayedEnvelope);
  await closed;
});
