import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { openDatabase } from "./db.js";
import { loadOrCreateServerIdentity, loadOrCreatePepper } from "./identity.js";
import { loadOrCreateAdminToken } from "./admin.js";
import { attachConnection } from "./connection.js";
import { handleRegister, handleLogin, handleSaltLookup, pruneOldAttempts } from "./auth.js";
import {
  handleCarouselGetAll,
  handleCarouselUpsert,
  handleCarouselDelete,
  handleNewsletterGet,
  handleNewsletterUpsert
} from "./content.js";
import { Codes, taggedError } from "./codes.js";
import { TokenBucket, ConnectionCounter } from "./ratelimit.js";

const DefaultPort = Number(process.env.PORT || 8443);

export async function createHangoutsServer(options = {}) {
  const db = openDatabase(options.dbPath);
  const pepper = loadOrCreatePepper();
  const adminToken = loadOrCreateAdminToken();
  const serverIdentity = await loadOrCreateServerIdentity();

  const maxConnectionsPerIp = options.maxConnectionsPerIp ?? Number(process.env.MAX_CONNECTIONS_PER_IP || 20);
  const handshakeBucketOptions = options.handshakeBucket ?? { capacity: 10, refillPerMs: 10 / 60000 };
  const handshakeBucket = new TokenBucket(handshakeBucketOptions);
  const connectionCounter = new ConnectionCounter(maxConnectionsPerIp);
  const connections = new Set();

  const httpServer = createServer((req, res) => {
    res.writeHead(404).end();
  });

  const wss = new WebSocketServer({ server: httpServer, maxPayload: 16 * 1024 });

  async function broadcast(type, payload) {
    for (const connection of connections) {
      connection.push(type, payload).catch(() => {});
    }
  }

  async function dispatch(type, payload) {
    switch (type) {
      case "auth:register":
        return handleRegister(db, pepper, payload);
      case "auth:login":
        return handleLogin(db, pepper, payload);
      case "auth:salt":
        return handleSaltLookup(db, pepper, payload);
      case "carousel:get-all":
        return handleCarouselGetAll(db);
      case "carousel:upsert": {
        const slide = handleCarouselUpsert(db, adminToken, payload);
        broadcast("carousel:update", slide);
        return slide;
      }
      case "carousel:delete": {
        const result = handleCarouselDelete(db, adminToken, payload);
        broadcast("carousel:remove", result);
        return result;
      }
      case "newsletter:get":
        return handleNewsletterGet(db);
      case "newsletter:upsert": {
        const newsletter = handleNewsletterUpsert(db, adminToken, payload);
        broadcast("newsletter:update", newsletter);
        return newsletter;
      }
      default:
        throw taggedError(Codes.MalformedRequest, "Unknown request type.");
    }
  }

  wss.on("connection", (ws, req) => {
    const remoteAddress = req.socket.remoteAddress || "unknown";

    if (!connectionCounter.tryAcquire(remoteAddress)) {
      ws.close(4003, "TooManyConnections");
      return;
    }
    if (!handshakeBucket.take(remoteAddress)) {
      connectionCounter.release(remoteAddress);
      ws.close(4008, "RateLimited");
      return;
    }

    ws.on("close", () => connectionCounter.release(remoteAddress));

    const connection = attachConnection(ws, {
      serverIdentity,
      dispatch,
      remoteAddress,
      log: (message) => console.warn(`[connection ${remoteAddress}] ${message}`)
    });
    connections.add(connection);
    ws.on("close", () => connections.delete(connection));
  });

  const pruneInterval = setInterval(() => pruneOldAttempts(db), 10 * 60 * 1000);
  const sweepInterval = setInterval(() => handshakeBucket.sweep(60 * 60 * 1000), 30 * 60 * 1000);
  pruneInterval.unref?.();
  sweepInterval.unref?.();

  function close() {
    clearInterval(pruneInterval);
    clearInterval(sweepInterval);
    wss.close();
    httpServer.close();
    db.close();
  }

  return {
    httpServer,
    wss,
    serverIdentity,
    adminToken,
    listen: (port = DefaultPort) =>
      new Promise((resolve) => {
        httpServer.listen(port, () => resolve(httpServer.address()));
      }),
    close
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = await createHangoutsServer();
  const address = await server.listen();
  console.log(`Hangouts pipeline server listening on ${address.address}:${address.port}`);
  console.log(`Server long-term public key (hex): ${server.serverIdentity.publicKeyHex}`);

  process.on("SIGINT", () => {
    server.close();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    server.close();
    process.exit(0);
  });
}
