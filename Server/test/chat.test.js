import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { randomHex } from "../src/codec.js";
import { onSend } from "../src/mailer.js";
import { TestPipelineClient, buildRegistrationEntry, deriveCredentialHash, createIsolatedSecretsDir } from "./testClient.js";

let server;
let url;
let adminToken;
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
  adminToken = server.adminToken;
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

test("posting and reading the main room works", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-1");
  const message = await client.sendRequest("chat:send", { sessionToken: result.sessionToken, roomId: "main", body: "hello, hangouts" });
  assert.equal(message.username, result.username);

  const room = await client.sendRequest("chat:get-room", { sessionToken: result.sessionToken, roomId: "main" });
  assert.ok(room.messages.some((m) => m.id === message.id && m.body === "hello, hangouts"));
  client.close();
});

test("main room messages broadcast live to other connected clients", async () => {
  const { client: poster, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-2");
  const { client: watcher } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-3");

  const received = new Promise((resolve) => watcher.onPush("chat:message", resolve));
  await poster.sendRequest("chat:send", { sessionToken: result.sessionToken, roomId: "main", body: "broadcast test" });
  const pushed = await received;
  assert.equal(pushed.body, "broadcast test");

  poster.close();
  watcher.close();
});

test("forking a main message creates one thread, and a second fork joins the same thread", async () => {
  const { client: op, result: opResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-4");
  const rootMessage = await op.sendRequest("chat:send", { sessionToken: opResult.sessionToken, roomId: "main", body: "root message" });

  const first = await op.sendRequest("chat:create-thread", { sessionToken: opResult.sessionToken, rootMessageId: rootMessage.id, body: "first reply" });
  assert.equal(first.created, true);

  const { client: other, result: otherResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-5");
  const second = await other.sendRequest("chat:create-thread", { sessionToken: otherResult.sessionToken, rootMessageId: rootMessage.id, body: "second reply" });
  assert.equal(second.created, false);
  assert.equal(second.room.id, first.room.id);

  const thread = await op.sendRequest("chat:get-thread-for-message", { rootMessageId: rootMessage.id });
  assert.equal(thread.room.id, first.room.id);

  const roomHistory = await op.sendRequest("chat:get-room", { sessionToken: opResult.sessionToken, roomId: first.room.id });
  assert.equal(roomHistory.messages.length, 2);

  op.close();
  other.close();
});

test("threads can only be forked off main-feed messages, not off other thread messages", async () => {
  const { client: op, result: opResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-6");
  const rootMessage = await op.sendRequest("chat:send", { sessionToken: opResult.sessionToken, roomId: "main", body: "root" });
  const thread = await op.sendRequest("chat:create-thread", { sessionToken: opResult.sessionToken, rootMessageId: rootMessage.id, body: "in thread" });

  await assert.rejects(
    op.sendRequest("chat:create-thread", { sessionToken: opResult.sessionToken, rootMessageId: thread.message.id, body: "double fork" }),
    (error) => {
      assert.equal(error.code, "A9");
      return true;
    }
  );
  op.close();
});

test("private custom rooms are only visible to the owner and invited users", async () => {
  const { client: owner, result: ownerResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-7");
  const { client: invited, result: invitedResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-8");
  const { client: outsider, result: outsiderResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-9");

  const created = await owner.sendRequest("chat:create-room", {
    sessionToken: ownerResult.sessionToken,
    name: "Secret Club",
    visibility: "private",
    inviteUsernames: [invitedResult.username]
  });
  const roomId = created.room.id;

  await owner.sendRequest("chat:send", { sessionToken: ownerResult.sessionToken, roomId, body: "welcome" });

  await assert.rejects(
    outsider.sendRequest("chat:get-room", { sessionToken: outsiderResult.sessionToken, roomId }),
    (error) => {
      assert.equal(error.code, "A9");
      return true;
    }
  );

  owner.close();
  invited.close();
  outsider.close();
});

test("private room broadcasts never reach a non-member connection", async () => {
  const { client: owner, result: ownerResult } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-10");
  const { client: outsider } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-11");

  const created = await owner.sendRequest("chat:create-room", { sessionToken: ownerResult.sessionToken, name: "Just Me", visibility: "private" });

  let outsiderSawIt = false;
  outsider.onPush("chat:message", () => {
    outsiderSawIt = true;
  });

  await owner.sendRequest("chat:send", { sessionToken: ownerResult.sessionToken, roomId: created.room.id, body: "private text" });
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(outsiderSawIt, false);

  owner.close();
  outsider.close();
});

test("blocked terms are rejected", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-12");
  await assert.rejects(
    client.sendRequest("chat:send", { sessionToken: result.sessionToken, roomId: "main", body: "you are a badword" }),
    (error) => {
      assert.equal(error.code, "A7");
      return true;
    }
  );
  client.close();
});

test("cursing (non-blocked profanity) is allowed", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-13");
  const message = await client.sendRequest("chat:send", { sessionToken: result.sessionToken, roomId: "main", body: "this is so damn cool" });
  assert.equal(message.body, "this is so damn cool");
  client.close();
});

test("admin can ban an account from chat, and a banned account can't post", async () => {
  const { client, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-14");
  await client.sendRequest("chat:set-banned", { adminToken, username: result.username, banned: true });

  await assert.rejects(
    client.sendRequest("chat:send", { sessionToken: result.sessionToken, roomId: "main", body: "let me in" }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});

test("admin can soft-delete a message and it broadcasts chat:message-deleted", async () => {
  const { client: poster, result } = await signupAndVerify(uniqueUsername(), uniqueEmail(), "chat-password-15");
  const message = await poster.sendRequest("chat:send", { sessionToken: result.sessionToken, roomId: "main", body: "to be deleted" });

  const received = new Promise((resolve) => poster.onPush("chat:message-deleted", resolve));
  await poster.sendRequest("chat:delete-message", { adminToken, messageId: message.id });
  const pushed = await received;
  assert.equal(pushed.id, message.id);

  const room = await poster.sendRequest("chat:get-room", { sessionToken: result.sessionToken, roomId: "main" });
  const found = room.messages.find((m) => m.id === message.id);
  assert.equal(found.deleted, true);
  assert.equal(found.body, null);

  poster.close();
});

test("chat:set-banned without a valid admin token is rejected with A2", async () => {
  const client = await (async () => {
    const c = new TestPipelineClient(url);
    await c.connect();
    return c;
  })();
  await assert.rejects(
    client.sendRequest("chat:set-banned", { adminToken: "wrong", username: "whoever", banned: true }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});
