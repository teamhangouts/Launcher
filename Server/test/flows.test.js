import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { randomHex, bufferToHex, hexToBuffer, subtle } from "../src/codec.js";
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

async function signupAndVerify(username, email, password) {
  const client = new TestPipelineClient(url);
  await client.connect();
  const entry = await buildRegistrationEntry();
  const clientSaltHex = randomHex(16);
  const credentialHashHex = await deriveCredentialHash(password, clientSaltHex);
  const { pendingVerificationId } = await client.sendRequest("auth:signup-start", {
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
  });
  const result = await client.sendRequest("auth:signup-verify", { pendingVerificationId, code: lastCode });
  return { client, result };
}

test("magic-code login end to end", async () => {
  const email = uniqueEmail();
  const { client: signupClient } = await signupAndVerify(uniqueUsername(), email, "some-password-here");
  signupClient.close();

  const client = new TestPipelineClient(url);
  await client.connect();
  const { pendingVerificationId } = await client.sendRequest("auth:login-code-request", { email });
  const result = await client.sendRequest("auth:login-code-verify", { pendingVerificationId, code: lastCode });
  assert.ok(result.sessionToken);
  client.close();
});

test("login-code-request for a nonexistent email still returns sent:true (no enumeration)", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  const result = await client.sendRequest("auth:login-code-request", { email: uniqueEmail() });
  assert.equal(result.sent, true);
  assert.ok(result.pendingVerificationId);
  client.close();
});

test("2fa: enabling it makes login-password return requires2fa, and the emailed code completes login", async () => {
  const email = uniqueEmail();
  const password = "second-factor-please";
  const { client, result } = await signupAndVerify(uniqueUsername(), email, password);
  await client.sendRequest("settings:enable-2fa", { sessionToken: result.sessionToken });
  client.close();

  const loginClient = new TestPipelineClient(url);
  await loginClient.connect();
  const saltResp = await loginClient.sendRequest("auth:salt-by-email", { email });
  const credentialHashHex = await deriveCredentialHash(password, saltResp.saltHex);
  const loginResp = await loginClient.sendRequest("auth:login-password", { email, credentialHashHex });
  assert.equal(loginResp.requires2fa, true);

  const finished = await loginClient.sendRequest("auth:login-verify-2fa", {
    pendingVerificationId: loginResp.pendingVerificationId,
    code: lastCode
  });
  assert.ok(finished.sessionToken);
  loginClient.close();
});

test("pass: enabling it lets a device sign in without a password", async () => {
  const email = uniqueEmail();
  const { client, result } = await signupAndVerify(uniqueUsername(), email, "irrelevant-password");

  const passKeyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const passPublicKeyHex = bufferToHex(await subtle.exportKey("raw", passKeyPair.publicKey));
  await client.sendRequest("auth:pass-enable", { sessionToken: result.sessionToken, publicKeyHex: passPublicKeyHex });
  client.close();

  const loginClient = new TestPipelineClient(url);
  await loginClient.connect();
  const { challengeId, nonceHex } = await loginClient.sendRequest("auth:pass-challenge", { email });
  const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passKeyPair.privateKey, hexToBuffer(nonceHex));
  const loginResp = await loginClient.sendRequest("auth:pass-verify", { challengeId, signatureHex: bufferToHex(signature) });
  assert.ok(loginResp.sessionToken);
  loginClient.close();
});

test("pass: a signature from the wrong key is rejected", async () => {
  const email = uniqueEmail();
  const { client, result } = await signupAndVerify(uniqueUsername(), email, "irrelevant-password");
  const passKeyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const passPublicKeyHex = bufferToHex(await subtle.exportKey("raw", passKeyPair.publicKey));
  await client.sendRequest("auth:pass-enable", { sessionToken: result.sessionToken, publicKeyHex: passPublicKeyHex });
  client.close();

  const attackerKeyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const loginClient = new TestPipelineClient(url);
  await loginClient.connect();
  const { challengeId, nonceHex } = await loginClient.sendRequest("auth:pass-challenge", { email });
  const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, attackerKeyPair.privateKey, hexToBuffer(nonceHex));
  await assert.rejects(
    loginClient.sendRequest("auth:pass-verify", { challengeId, signatureHex: bufferToHex(signature) }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  loginClient.close();
});

test("forgot password: resetting the password revokes other sessions and the new password works", async () => {
  const clients = [];
  try {
    const email = uniqueEmail();
    const { client, result } = await signupAndVerify(uniqueUsername(), email, "old-password-here");
    clients.push(client);

    const otherClient = new TestPipelineClient(url);
    clients.push(otherClient);
    await otherClient.connect();
    await otherClient.sendRequest("auth:resume", { sessionToken: result.sessionToken });

    const resetClient = new TestPipelineClient(url);
    clients.push(resetClient);
    await resetClient.connect();
    const { pendingVerificationId } = await resetClient.sendRequest("auth:forgot-password-request", { email });
    const newClientSaltHex = randomHex(16);
    const newCredentialHashHex = await deriveCredentialHash("brand-new-password", newClientSaltHex);
    const resetResult = await resetClient.sendRequest("auth:forgot-password-verify", {
      pendingVerificationId,
      code: lastCode,
      clientSaltHex: newClientSaltHex,
      credentialHashHex: newCredentialHashHex
    });
    assert.ok(resetResult.sessionToken);

    await assert.rejects(otherClient.sendRequest("auth:resume", { sessionToken: result.sessionToken }), (error) => {
      assert.equal(error.code, "A2");
      return true;
    });

    const loginClient = new TestPipelineClient(url);
    clients.push(loginClient);
    await loginClient.connect();
    const saltResp = await loginClient.sendRequest("auth:salt-by-email", { email });
    const credentialHashHex = await deriveCredentialHash("brand-new-password", saltResp.saltHex);
    const loginResp = await loginClient.sendRequest("auth:login-password", { email, credentialHashHex });
    assert.ok(loginResp.sessionToken);
  } finally {
    for (const client of clients) {
      client.close();
    }
  }
});

test("settings: bio and pfp round-trip entirely over Pipeline", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "settings-password");

  await client.sendRequest("settings:change-bio", { sessionToken: result.sessionToken, bio: "hello from the test suite" });

  const imageBytes = Buffer.from("not-a-real-png-but-fine-for-a-test");
  await client.sendRequest("settings:change-pfp", {
    sessionToken: result.sessionToken,
    imageBase64: imageBytes.toString("base64"),
    mimeType: "image/png"
  });

  const fetched = await client.sendRequest("profile:get-pfp", { username: result.username });
  assert.equal(fetched.mimeType, "image/png");
  assert.deepEqual(Buffer.from(fetched.imageBase64, "base64"), imageBytes);

  const missing = await client.sendRequest("profile:get-pfp", { username: uniqueUsername() });
  assert.equal(missing.imageBase64, null);

  client.close();
});

test("settings: change-password requires the current password to be correct", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "original-password");

  const wrongCurrentHashHex = await deriveCredentialHash("not-the-real-password", "0".repeat(32));
  await assert.rejects(
    client.sendRequest("settings:change-password", {
      sessionToken: result.sessionToken,
      currentCredentialHashHex: wrongCurrentHashHex,
      newClientSaltHex: randomHex(16),
      newCredentialHashHex: await deriveCredentialHash("whatever-new", randomHex(16))
    }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});

test("settings: change-email requires verifying the new address before it takes effect", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "email-change-password");
  const newEmail = uniqueEmail();

  const { pendingVerificationId } = await client.sendRequest("settings:change-email-request", {
    sessionToken: result.sessionToken,
    newEmail
  });
  const changed = await client.sendRequest("settings:change-email-verify", {
    sessionToken: result.sessionToken,
    pendingVerificationId,
    code: lastCode
  });
  assert.equal(changed.email, newEmail);

  const loginClient = new TestPipelineClient(url);
  await loginClient.connect();
  const saltResp = await loginClient.sendRequest("auth:salt-by-email", { email: newEmail });
  assert.ok(saltResp.saltHex);
  loginClient.close();
  client.close();
});

test("settings endpoints reject a missing or invalid session token with A2", async () => {
  const client = new TestPipelineClient(url);
  await client.connect();
  await assert.rejects(
    client.sendRequest("settings:change-bio", { sessionToken: "not-a-real-token", bio: "hi" }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});
