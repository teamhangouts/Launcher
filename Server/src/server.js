import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { openDatabase } from "./db.js";
import { loadOrCreateServerIdentity, loadOrCreatePepper } from "./identity.js";
import { loadOrCreateAdminToken } from "./admin.js";
import { attachConnection } from "./connection.js";
import {
  handleSignupStart,
  handleSignupVerify,
  handleSaltByEmail,
  handleLoginPassword,
  handleLoginVerify2fa,
  handleLoginCodeRequest,
  handleLoginCodeVerify,
  handlePassEnable,
  handlePassDisable,
  handlePassChallenge,
  handlePassVerify,
  handleForgotPasswordRequest,
  handleForgotPasswordVerify,
  handleSaltForSession,
  pruneOldAttempts
} from "./auth.js";
import {
  handleEnable2fa,
  handleDisable2fa,
  handleChangeEmailRequest,
  handleChangeEmailVerify,
  handleChangePassword,
  handleChangeBio,
  handleChangePfp,
  handleGetPfp
} from "./profile.js";
import { issueSession, resumeSession, revokeSession, requireSession, pruneExpiredSessions } from "./session.js";
import { pruneExpiredVerifications } from "./verification.js";
import {
  handleModuleManifest,
  handleModuleGet,
  handleModuleGetAll,
  handleModuleUpsert,
  handleModuleDelete
} from "./modules.js";
import { Codes, taggedError } from "./codes.js";
import { TokenBucket, ConnectionCounter } from "./ratelimit.js";

const DefaultPort = Number(process.env.PORT || 443);

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

  async function withSession(payload, handler) {
    const { record, tokenHash } = await requireSession(db, payload && payload.sessionToken);
    return handler(record, tokenHash);
  }

  async function dispatch(type, payload, connectionContext) {
    switch (type) {
      case "auth:signup-start":
        return handleSignupStart(db, pepper, payload);
      case "auth:signup-verify": {
        const result = await handleSignupVerify(db, pepper, payload);
        const session = await issueSession(db, result.username);
        connectionContext.setAuthenticatedUsername(result.username);
        return { ...result, sessionToken: session.sessionToken };
      }
      case "auth:salt-by-email":
        return handleSaltByEmail(db, pepper, payload);
      case "auth:login-password": {
        const result = await handleLoginPassword(db, pepper, payload);
        if (result.requires2fa) {
          return result;
        }
        const session = await issueSession(db, result.username);
        connectionContext.setAuthenticatedUsername(result.username);
        return { ...result, sessionToken: session.sessionToken };
      }
      case "auth:login-verify-2fa": {
        const result = await handleLoginVerify2fa(db, pepper, payload);
        const session = await issueSession(db, result.username);
        connectionContext.setAuthenticatedUsername(result.username);
        return { ...result, sessionToken: session.sessionToken };
      }
      case "auth:login-code-request":
        return handleLoginCodeRequest(db, pepper, payload);
      case "auth:login-code-verify": {
        const result = await handleLoginCodeVerify(db, pepper, payload);
        const session = await issueSession(db, result.username);
        connectionContext.setAuthenticatedUsername(result.username);
        return { ...result, sessionToken: session.sessionToken };
      }
      case "auth:pass-enable":
        return withSession(payload, (record) => handlePassEnable(db, record, payload));
      case "auth:pass-disable":
        return withSession(payload, (record) => handlePassDisable(db, record));
      case "auth:pass-challenge":
        return handlePassChallenge(db, payload);
      case "auth:pass-verify": {
        const result = await handlePassVerify(db, payload);
        const session = await issueSession(db, result.username);
        connectionContext.setAuthenticatedUsername(result.username);
        return { ...result, sessionToken: session.sessionToken };
      }
      case "auth:forgot-password-request":
        return handleForgotPasswordRequest(db, pepper, payload);
      case "auth:forgot-password-verify": {
        const result = await handleForgotPasswordVerify(db, pepper, payload);
        const session = await issueSession(db, result.username);
        connectionContext.setAuthenticatedUsername(result.username);
        return { ...result, sessionToken: session.sessionToken };
      }
      case "auth:salt-for-session":
        return withSession(payload, (record) => handleSaltForSession(db, pepper, record));
      case "auth:resume": {
        const result = await resumeSession(db, payload && payload.sessionToken);
        connectionContext.setAuthenticatedUsername(result.username);
        return result;
      }
      case "auth:logout": {
        if (payload && payload.sessionToken) {
          await revokeSession(db, payload.sessionToken);
        }
        connectionContext.clearAuthenticatedUsername();
        return { loggedOut: true };
      }
      case "settings:enable-2fa":
        return withSession(payload, (record) => handleEnable2fa(db, record));
      case "settings:disable-2fa":
        return withSession(payload, (record) => handleDisable2fa(db, record));
      case "settings:change-email-request":
        return withSession(payload, (record) => handleChangeEmailRequest(db, record, payload));
      case "settings:change-email-verify":
        return withSession(payload, (record) => handleChangeEmailVerify(db, record, payload));
      case "settings:change-password":
        return withSession(payload, (record, tokenHash) => handleChangePassword(db, pepper, record, tokenHash, payload));
      case "settings:change-bio":
        return withSession(payload, (record) => handleChangeBio(db, record, payload));
      case "settings:change-pfp":
        return withSession(payload, (record) => handleChangePfp(db, record, payload));
      case "profile:get-pfp":
        return handleGetPfp(db, payload);
      case "module:manifest":
        return handleModuleManifest(db, payload);
      case "module:get":
        return handleModuleGet(db, payload);
      case "module:get-all":
        return handleModuleGetAll(db, payload);
      case "module:upsert": {
        const mod = handleModuleUpsert(db, adminToken, payload);
        broadcast("module:update", mod);
        return mod;
      }
      case "module:delete": {
        const result = handleModuleDelete(db, adminToken, payload);
        broadcast("module:delete", result);
        return result;
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

  const pruneInterval = setInterval(() => {
    pruneOldAttempts(db);
    pruneExpiredSessions(db);
    pruneExpiredVerifications(db);
  }, 10 * 60 * 1000);
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
