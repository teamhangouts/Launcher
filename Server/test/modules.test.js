import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { TestPipelineClient, createIsolatedSecretsDir } from "./testClient.js";

let server;
let url;
let adminToken;

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
});

after(() => {
  server.close();
});

async function connectedClient() {
  const client = new TestPipelineClient(url);
  await client.connect();
  return client;
}

test("manifest starts empty for an unused module type", async () => {
  const client = await connectedClient();
  const manifest = await client.sendRequest("module:manifest", { moduleType: "carousel" });
  assert.deepEqual(manifest.modules, []);
  client.close();
});

test("admin can upsert a module, it appears in manifest, get, and get-all", async () => {
  const client = await connectedClient();
  const mod = await client.sendRequest("module:upsert", {
    adminToken,
    moduleType: "news",
    content: { title: "Hangouts is coming", body: "First article." },
    order: 0
  });
  assert.equal(mod.version, 1);
  assert.equal(mod.content.title, "Hangouts is coming");

  const manifest = await client.sendRequest("module:manifest", { moduleType: "news" });
  assert.equal(manifest.modules.length, 1);
  assert.equal(manifest.modules[0].id, mod.id);
  assert.equal(manifest.modules[0].version, 1);

  const fetched = await client.sendRequest("module:get", { moduleType: "news", id: mod.id });
  assert.deepEqual(fetched.content, { title: "Hangouts is coming", body: "First article." });

  const all = await client.sendRequest("module:get-all", { moduleType: "news" });
  assert.equal(all.modules.length, 1);
  assert.equal(all.modules[0].id, mod.id);
  client.close();
});

test("upserting the same id again increments the version instead of duplicating", async () => {
  const client = await connectedClient();
  const first = await client.sendRequest("module:upsert", {
    adminToken,
    moduleType: "legal",
    id: "terms",
    content: { title: "Terms", body: "v1" }
  });
  assert.equal(first.version, 1);

  const second = await client.sendRequest("module:upsert", {
    adminToken,
    moduleType: "legal",
    id: "terms",
    content: { title: "Terms", body: "v2" }
  });
  assert.equal(second.version, 2);
  assert.equal(second.content.body, "v2");

  const all = await client.sendRequest("module:get-all", { moduleType: "legal" });
  assert.equal(all.modules.length, 1);
  assert.equal(all.modules[0].version, 2);
  client.close();
});

test("get-all respects order, then creation time", async () => {
  const client = await connectedClient();
  await client.sendRequest("module:upsert", { adminToken, moduleType: "socials", id: "discord", content: { platform: "discord", url: "https://discord.gg/x" }, order: 1 });
  await client.sendRequest("module:upsert", { adminToken, moduleType: "socials", id: "twitter", content: { platform: "twitter", url: "https://twitter.com/x" }, order: 0 });

  const all = await client.sendRequest("module:get-all", { moduleType: "socials" });
  assert.deepEqual(all.modules.map((m) => m.id), ["twitter", "discord"]);
  client.close();
});

test("different module types with the same id coexist independently", async () => {
  const client = await connectedClient();
  await client.sendRequest("module:upsert", { adminToken, moduleType: "news", id: "launch", content: { title: "News version" } });
  await client.sendRequest("module:upsert", { adminToken, moduleType: "updates", id: "launch", content: { title: "Updates version" } });

  const news = await client.sendRequest("module:get", { moduleType: "news", id: "launch" });
  const updates = await client.sendRequest("module:get", { moduleType: "updates", id: "launch" });
  assert.equal(news.content.title, "News version");
  assert.equal(updates.content.title, "Updates version");
  client.close();
});

test("getting a module that doesn't exist is rejected with A9", async () => {
  const client = await connectedClient();
  await assert.rejects(
    client.sendRequest("module:get", { moduleType: "news", id: "nonexistent" }),
    (error) => {
      assert.equal(error.code, "A9");
      return true;
    }
  );
  client.close();
});

test("upsert without a valid admin token is rejected with A2", async () => {
  const client = await connectedClient();
  await assert.rejects(
    client.sendRequest("module:upsert", { adminToken: "wrong", moduleType: "news", content: {} }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});

test("oversized module content is rejected", async () => {
  const client = await connectedClient();
  await assert.rejects(
    client.sendRequest("module:upsert", {
      adminToken,
      moduleType: "news",
      content: { body: "x".repeat(4500) }
    }),
    (error) => {
      assert.equal(error.code, "A7");
      return true;
    }
  );
  client.close();
});

test("upsert broadcasts module:update, delete broadcasts module:delete", async () => {
  const watcher = await connectedClient();
  const admin = await connectedClient();

  const updateReceived = new Promise((resolve) => watcher.onPush("module:update", resolve));
  const mod = await admin.sendRequest("module:upsert", { adminToken, moduleType: "updates", content: { title: "Release notes" } });
  const pushedUpdate = await updateReceived;
  assert.equal(pushedUpdate.id, mod.id);
  assert.equal(pushedUpdate.content.title, "Release notes");

  const deleteReceived = new Promise((resolve) => watcher.onPush("module:delete", resolve));
  await admin.sendRequest("module:delete", { adminToken, moduleType: "updates", id: mod.id });
  const pushedDelete = await deleteReceived;
  assert.equal(pushedDelete.id, mod.id);

  const all = await admin.sendRequest("module:get-all", { moduleType: "updates" });
  assert.ok(!all.modules.some((entry) => entry.id === mod.id));

  watcher.close();
  admin.close();
});

test("manifest with no moduleType filter returns modules across all types", async () => {
  const client = await connectedClient();
  await client.sendRequest("module:upsert", { adminToken, moduleType: "carousel", content: { title: "Slide" } });
  await client.sendRequest("module:upsert", { adminToken, moduleType: "legal", id: "privacy", content: { title: "Privacy" } });

  const manifest = await client.sendRequest("module:manifest", {});
  const types = new Set(manifest.modules.map((m) => m.moduleType));
  assert.ok(types.has("carousel"));
  assert.ok(types.has("legal"));
  client.close();
});
