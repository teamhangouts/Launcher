import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { LockoutThreshold, IdentityTtlMs } from "../src/auth.js";
import { randomHex } from "../src/codec.js";
import { onSend } from "../src/mailer.js";
import { TestPipelineClient, buildRegistrationEntry, deriveCredentialHash, createIsolatedSecretsDir } from "./testClient.js";

let server;
let url;
let lastCode;

before(async () => {
  server = await createHangoutsServer({
    dbPath: ":memory:",
    secretsDir: createIsolatedSecretsDir(),
    maxConnectionsPerIp: 200,
    handshakeBucket: { capacity: 500, refillPerMs: 500 / 1000 }
  });
  const address = await server.listen(0);
  url = `ws://127.0.0.1:${address.port}`;
  onSend(({ code }) => {
    lastCode = code;
  });
});

after(() => {
  server.close();
});

function uniqueUsername() {
  return `user_${randomHex(8)}`;
}

function uniqueEmail() {
  return `${randomHex(8)}@example.com`;
}

async function signupStartPayload(username, email, password, entryOptions) {
  const entry = await buildRegistrationEntry(entryOptions);
  const clientSaltHex = randomHex(16);
  const credentialHashHex = await deriveCredentialHash(password, clientSaltHex);
  return {
    username,
    email,
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

async function signupAndVerify(username, email, password, entryOptions) {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await signupStartPayload(username, email, password, entryOptions);
  const { pendingVerificationId } = await client.sendRequest("auth:signup-start", payload);
  const result = await client.sendRequest("auth:signup-verify", { pendingVerificationId, code: lastCode });
  return { client, result, payload };
}

async function loginWithPassword(email, password) {
  const client = new TestPipelineClient(url);
  await client.connect();
  const saltResp = await client.sendRequest("auth:salt-by-email", { email });
  const credentialHashHex = await deriveCredentialHash(password, saltResp.saltHex);
  try {
    return { client, result: await client.sendRequest("auth:login-password", { email, credentialHashHex }) };
  } catch (error) {
    return { client, error };
  }
}

test("signup then login succeeds end to end", async () => {
  const username = uniqueUsername();
  const email = uniqueEmail();
  const password = "correct horse battery staple";

  const { client, result, payload } = await signupAndVerify(username, email, password);
  assert.equal(result.username, username);
  assert.equal(result.deviceId, payload.deviceId);
  assert.ok(result.sessionToken);
  client.close();

  const { client: loginClient, result: loginResult } = await loginWithPassword(email, password);
  assert.equal(loginResult.username, username);
  assert.equal(loginResult.publicKeyHex, payload.publicKeyHex);
  loginClient.close();
});

test("duplicate username at signup is rejected with A1", async () => {
  const username = uniqueUsername();
  await signupAndVerify(username, uniqueEmail(), "first-password").then(({ client }) => client.close());

  const client = new TestPipelineClient(url);
  await client.connect();
  await assert.rejects(
    client.sendRequest("auth:signup-start", await signupStartPayload(username, uniqueEmail(), "second-password")),
    (error) => {
      assert.equal(error.code, "A1");
      return true;
    }
  );
  client.close();
});

test("duplicate email at signup is rejected with A1", async () => {
  const email = uniqueEmail();
  await signupAndVerify(uniqueUsername(), email, "first-password").then(({ client }) => client.close());

  const client = new TestPipelineClient(url);
  await client.connect();
  await assert.rejects(
    client.sendRequest("auth:signup-start", await signupStartPayload(uniqueUsername(), email, "second-password")),
    (error) => {
      assert.equal(error.code, "A1");
      return true;
    }
  );
  client.close();
});

test("wrong password at login is rejected with A2", async () => {
  const email = uniqueEmail();
  const { client } = await signupAndVerify(uniqueUsername(), email, "the-real-password");
  client.close();

  const { client: loginClient, error } = await loginWithPassword(email, "the-wrong-password");
  assert.ok(error);
  assert.equal(error.code, "A2");
  loginClient.close();
});

test("login against a nonexistent email is rejected with A2, not a distinct error", async () => {
  const { client, error } = await loginWithPassword(uniqueEmail(), "whatever");
  assert.ok(error);
  assert.equal(error.code, "A2");
  client.close();
});

test("honeypot usernames are rejected as A2 (invalid), never A1 (taken)", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  await assert.rejects(
    client.sendRequest("auth:signup-start", await signupStartPayload("admin", uniqueEmail(), "some-password")),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});

test("honeypot signup locks the identifier+device pair for subsequent attempts", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await signupStartPayload("root", uniqueEmail(), "some-password");
  await assert.rejects(client.sendRequest("auth:signup-start", payload));

  const secondAttempt = await signupStartPayload("root", uniqueEmail(), "some-other-password");
  secondAttempt.deviceId = payload.deviceId;
  await assert.rejects(
    client.sendRequest("auth:signup-start", secondAttempt),
    (error) => {
      assert.equal(error.code, "A3");
      return true;
    }
  );
  client.close();
});

test("a tampered signup signature is rejected with A5", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await signupStartPayload(uniqueUsername(), uniqueEmail(), "some-password");
  payload.signatureHex = payload.signatureHex.slice(0, -2) + (payload.signatureHex.slice(-2) === "00" ? "11" : "00");
  await assert.rejects(
    client.sendRequest("auth:signup-start", payload),
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
  const payload = await signupStartPayload(uniqueUsername(), uniqueEmail(), "some-password", { skipProofOfWork: true });
  await assert.rejects(
    client.sendRequest("auth:signup-start", payload),
    (error) => {
      assert.equal(error.code, "A5");
      return true;
    }
  );
  client.close();
});

test("an expired signup challenge is rejected with A4", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const createdAt = Date.now() - IdentityTtlMs - 60000;
  const payload = await signupStartPayload(uniqueUsername(), uniqueEmail(), "some-password", {
    createdAtOverride: createdAt,
    expiresAtOverride: createdAt + IdentityTtlMs
  });
  await assert.rejects(
    client.sendRequest("auth:signup-start", payload),
    (error) => {
      assert.equal(error.code, "A4");
      return true;
    }
  );
  client.close();
});

test("wrong verification code is rejected and does not consume the pending signup", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const payload = await signupStartPayload(uniqueUsername(), uniqueEmail(), "some-password");
  const { pendingVerificationId } = await client.sendRequest("auth:signup-start", payload);
  await assert.rejects(
    client.sendRequest("auth:signup-verify", { pendingVerificationId, code: "000000" }),
    (error) => {
      assert.equal(error.code, "A5");
      return true;
    }
  );
  const result = await client.sendRequest("auth:signup-verify", { pendingVerificationId, code: lastCode });
  assert.equal(result.username, payload.username);
  client.close();
});

test("repeated failed logins lock the identifier with A3 and a retry hint", async () => {
  const email = uniqueEmail();
  const { client } = await signupAndVerify(uniqueUsername(), email, "the-real-password");
  client.close();

  for (let attempt = 0; attempt < LockoutThreshold; attempt++) {
    const { client: attemptClient, error } = await loginWithPassword(email, "wrong-password");
    assert.equal(error.code, "A2");
    attemptClient.close();
  }

  const { client: lockedClient, error } = await loginWithPassword(email, "wrong-password");
  assert.equal(error.code, "A3");
  assert.ok(error.extra.retryAfterMs > 0);
  lockedClient.close();

  const { client: correctPasswordClient, error: stillLockedError } = await loginWithPassword(email, "the-real-password");
  assert.equal(stillLockedError.code, "A3");
  correctPasswordClient.close();
});

test("replaying a previously sent envelope closes the connection instead of being processed twice", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  await client.sendRequest("auth:salt-by-email", { email: uniqueEmail() });
  const replayedEnvelope = client.lastSentEnvelope;

  const closed = new Promise((resolve) => client.ws.once("close", resolve));
  client.ws.send(replayedEnvelope);
  await closed;
});

export { signupAndVerify, loginWithPassword, uniqueUsername, uniqueEmail };
