import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHangoutsServer } from "../src/server.js";
import { TestPipelineClient } from "./testClient.js";

let server;
let url;
let adminToken;

before(async () => {
  server = await createHangoutsServer({
    dbPath: ":memory:",
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

test("carousel starts empty and admin can upsert a slide", async () => {
  const client = await connectedClient();
  const initial = await client.sendRequest("carousel:get-all", {});
  assert.deepEqual(initial.slides, []);

  const slide = await client.sendRequest("carousel:upsert", {
    adminToken,
    title: "Welcome",
    body: "First slide",
    order: 0
  });
  assert.equal(slide.title, "Welcome");
  assert.ok(slide.id);

  const after1 = await client.sendRequest("carousel:get-all", {});
  assert.equal(after1.slides.length, 1);
  assert.equal(after1.slides[0].id, slide.id);
  client.close();
});

test("carousel upsert without a valid admin token is rejected with A2", async () => {
  const client = await connectedClient();
  await assert.rejects(
    client.sendRequest("carousel:upsert", { adminToken: "wrong", title: "X", order: 0 }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});

test("carousel upsert broadcasts an update to other connected clients", async () => {
  const watcher = await connectedClient();
  const admin = await connectedClient();

  const received = new Promise((resolve) => {
    watcher.onPush("carousel:update", resolve);
  });

  const slide = await admin.sendRequest("carousel:upsert", {
    adminToken,
    title: "Broadcast Test",
    body: "",
    order: 1
  });

  const pushed = await received;
  assert.equal(pushed.id, slide.id);
  assert.equal(pushed.title, "Broadcast Test");

  watcher.close();
  admin.close();
});

test("carousel delete removes the slide and broadcasts carousel:remove", async () => {
  const watcher = await connectedClient();
  const admin = await connectedClient();

  const slide = await admin.sendRequest("carousel:upsert", {
    adminToken,
    title: "To Delete",
    body: "",
    order: 2
  });

  const received = new Promise((resolve) => {
    watcher.onPush("carousel:remove", resolve);
  });

  await admin.sendRequest("carousel:delete", { adminToken, id: slide.id });
  const pushed = await received;
  assert.equal(pushed.id, slide.id);

  const all = await admin.sendRequest("carousel:get-all", {});
  assert.ok(!all.slides.some((entry) => entry.id === slide.id));

  watcher.close();
  admin.close();
});

test("newsletter starts null and admin can publish one", async () => {
  const client = await connectedClient();
  const initial = await client.sendRequest("newsletter:get", {});
  assert.equal(initial.newsletter, null);

  const published = await client.sendRequest("newsletter:upsert", {
    adminToken,
    title: "Issue One",
    body: "Hello, Hangouts."
  });
  assert.equal(published.title, "Issue One");

  const after1 = await client.sendRequest("newsletter:get", {});
  assert.equal(after1.newsletter.title, "Issue One");
  client.close();
});

test("newsletter upsert broadcasts to other connected clients", async () => {
  const watcher = await connectedClient();
  const admin = await connectedClient();

  const received = new Promise((resolve) => {
    watcher.onPush("newsletter:update", resolve);
  });

  await admin.sendRequest("newsletter:upsert", { adminToken, title: "Issue Two", body: "Body" });
  const pushed = await received;
  assert.equal(pushed.title, "Issue Two");

  watcher.close();
  admin.close();
});

test("newsletter upsert without a valid admin token is rejected with A2", async () => {
  const client = await connectedClient();
  await assert.rejects(
    client.sendRequest("newsletter:upsert", { adminToken: "wrong", title: "X", body: "" }),
    (error) => {
      assert.equal(error.code, "A2");
      return true;
    }
  );
  client.close();
});
