import { randomHex } from "./codec.js";
import { Codes, taggedError } from "./codes.js";
import { assertAdminToken } from "./admin.js";
import { containsBlockedTerm } from "./moderation.js";
import { TokenBucket } from "./ratelimit.js";

const MaxMessageBodyLength = 4000;
const MaxRoomNameLength = 80;
const MaxInvitesPerRoom = 50;
const MaxHistoryLimit = 200;
const DefaultHistoryLimit = 50;
const RoomIdPattern = /^[a-z0-9_-]{1,64}$/;

const sendBucket = new TokenBucket({ capacity: 10, refillPerMs: 10 / 30000 });

function assertString(value, field, { min = 0, max = Infinity } = {}) {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function assertRoomId(value) {
  const roomId = assertString(value, "roomId", { min: 1, max: 64 });
  if (!RoomIdPattern.test(roomId)) {
    throw taggedError(Codes.MalformedRequest, "Invalid roomId.");
  }
  return roomId;
}

function rowToMessage(row) {
  return {
    id: row.id,
    roomId: row.room_id,
    username: row.deleted_at ? null : row.username,
    body: row.deleted_at ? null : row.body,
    deleted: Boolean(row.deleted_at),
    createdAt: row.created_at
  };
}

function rowToRoom(row) {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    visibility: row.visibility,
    ownerUsername: row.owner_username,
    rootMessageId: row.root_message_id,
    createdAt: row.created_at
  };
}

function getRoom(db, roomId) {
  return db.prepare("SELECT * FROM chat_rooms WHERE id = ?").get(roomId);
}

function isRoomVisibleTo(db, room, username) {
  if (!room) {
    return false;
  }
  if (room.visibility === "public") {
    return true;
  }
  if (room.owner_username === username) {
    return true;
  }
  const invite = db.prepare("SELECT 1 FROM chat_room_invites WHERE room_id = ? AND username = ?").get(room.id, username);
  return Boolean(invite);
}

export function resolveRoomAudience(db, roomId) {
  const room = getRoom(db, roomId);
  if (!room || room.visibility === "public") {
    return null;
  }
  const rows = db.prepare("SELECT username FROM chat_room_invites WHERE room_id = ?").all(roomId);
  return new Set(rows.map((row) => row.username));
}

function assertNotChatBanned(record) {
  if (record.chat_banned) {
    throw taggedError(Codes.InvalidCredentials, "This account is banned from chat.");
  }
}

function insertMessage(db, roomId, username, body) {
  const id = randomHex(16);
  const now = Date.now();
  db.prepare("INSERT INTO chat_messages (id, room_id, username, body, created_at) VALUES (?, ?, ?, ?, ?)").run(
    id,
    roomId,
    username,
    body,
    now
  );
  return rowToMessage(db.prepare("SELECT * FROM chat_messages WHERE id = ?").get(id));
}

function assertPostable(record, body) {
  assertNotChatBanned(record);
  assertString(body, "body", { min: 1, max: MaxMessageBodyLength });
  if (containsBlockedTerm(body)) {
    throw taggedError(Codes.MalformedRequest, "That message isn't allowed.");
  }
  if (!sendBucket.take(record.username)) {
    throw taggedError(Codes.RateLimited, "You're sending messages too quickly.");
  }
}

export function handleChatListRooms(db, record) {
  const publicRooms = db.prepare("SELECT * FROM chat_rooms WHERE kind = 'custom' AND visibility = 'public'").all();
  const privateRooms = db
    .prepare(
      `SELECT DISTINCT r.* FROM chat_rooms r
       LEFT JOIN chat_room_invites i ON i.room_id = r.id AND i.username = ?
       WHERE r.kind = 'custom' AND r.visibility = 'private' AND (r.owner_username = ? OR i.username IS NOT NULL)`
    )
    .all(record.username, record.username);
  return { rooms: [...publicRooms, ...privateRooms].map(rowToRoom) };
}

export function handleChatGetRoom(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const roomId = assertRoomId(rawPayload.roomId);
  const room = getRoom(db, roomId);
  if (!room || !isRoomVisibleTo(db, room, record.username)) {
    throw taggedError(Codes.NotFound, "Room not found.");
  }
  const limit = Number.isInteger(rawPayload.limit) ? Math.min(rawPayload.limit, MaxHistoryLimit) : DefaultHistoryLimit;
  const before = Number.isFinite(rawPayload.before) ? rawPayload.before : Date.now() + 1;
  const rows = db
    .prepare("SELECT * FROM chat_messages WHERE room_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?")
    .all(roomId, before, limit);
  return { room: rowToRoom(room), messages: rows.reverse().map(rowToMessage) };
}

export function handleChatSend(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const roomId = assertRoomId(rawPayload.roomId);
  const room = getRoom(db, roomId);
  if (!room || !isRoomVisibleTo(db, room, record.username)) {
    throw taggedError(Codes.NotFound, "Room not found.");
  }
  assertPostable(record, rawPayload.body);
  return insertMessage(db, roomId, record.username, rawPayload.body);
}

export function handleChatGetThreadForMessage(db, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const rootMessageId = assertString(rawPayload.rootMessageId, "rootMessageId", { min: 1, max: 64 });
  const room = db.prepare("SELECT * FROM chat_rooms WHERE kind = 'thread' AND root_message_id = ?").get(rootMessageId);
  return { room: room ? rowToRoom(room) : null };
}

export function handleChatCreateThread(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const rootMessageId = assertString(rawPayload.rootMessageId, "rootMessageId", { min: 1, max: 64 });
  const rootMessage = db.prepare("SELECT * FROM chat_messages WHERE id = ? AND room_id = 'main'").get(rootMessageId);
  if (!rootMessage) {
    throw taggedError(Codes.NotFound, "That message doesn't exist in the main feed.");
  }
  assertPostable(record, rawPayload.body);

  let room = db.prepare("SELECT * FROM chat_rooms WHERE kind = 'thread' AND root_message_id = ?").get(rootMessageId);
  let created = false;
  if (!room) {
    const roomId = randomHex(16);
    db.prepare(
      "INSERT INTO chat_rooms (id, kind, name, visibility, owner_username, root_message_id, created_at) VALUES (?, 'thread', NULL, 'public', NULL, ?, ?)"
    ).run(roomId, rootMessageId, Date.now());
    room = getRoom(db, roomId);
    created = true;
  }

  const message = insertMessage(db, room.id, record.username, rawPayload.body);
  return { room: rowToRoom(room), message, created };
}

export function handleChatCreateRoom(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  assertNotChatBanned(record);
  const name = assertString(rawPayload.name, "name", { min: 1, max: MaxRoomNameLength });
  const visibility = rawPayload.visibility === "private" ? "private" : "public";
  const inviteUsernames = Array.isArray(rawPayload.inviteUsernames) ? rawPayload.inviteUsernames : [];
  if (inviteUsernames.length > MaxInvitesPerRoom) {
    throw taggedError(Codes.MalformedRequest, "Too many invited usernames.");
  }

  const roomId = randomHex(16);
  const now = Date.now();
  db.prepare(
    "INSERT INTO chat_rooms (id, kind, name, visibility, owner_username, root_message_id, created_at) VALUES (?, 'custom', ?, ?, ?, NULL, ?)"
  ).run(roomId, name, visibility, record.username, now);

  if (visibility === "private") {
    db.prepare("INSERT OR IGNORE INTO chat_room_invites (room_id, username, invited_by, created_at) VALUES (?, ?, ?, ?)").run(
      roomId,
      record.username,
      record.username,
      now
    );
    for (const rawUsername of inviteUsernames) {
      const username = String(rawUsername).trim().toLowerCase();
      const identity = db.prepare("SELECT 1 FROM identities WHERE username = ?").get(username);
      if (!identity) {
        continue;
      }
      db.prepare("INSERT OR IGNORE INTO chat_room_invites (room_id, username, invited_by, created_at) VALUES (?, ?, ?, ?)").run(
        roomId,
        username,
        record.username,
        now
      );
    }
  }

  return { room: rowToRoom(getRoom(db, roomId)) };
}

export function handleChatInvite(db, record, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const roomId = assertRoomId(rawPayload.roomId);
  const room = getRoom(db, roomId);
  if (!room || room.kind !== "custom" || room.visibility !== "private" || room.owner_username !== record.username) {
    throw taggedError(Codes.NotFound, "Room not found.");
  }
  const username = assertString(rawPayload.username, "username", { min: 1, max: 64 }).trim().toLowerCase();
  const identity = db.prepare("SELECT 1 FROM identities WHERE username = ?").get(username);
  if (!identity) {
    throw taggedError(Codes.NotFound, "That user doesn't exist.");
  }
  db.prepare("INSERT OR IGNORE INTO chat_room_invites (room_id, username, invited_by, created_at) VALUES (?, ?, ?, ?)").run(
    roomId,
    username,
    record.username,
    Date.now()
  );
  return { roomId, username };
}

export function handleChatDeleteMessage(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const messageId = assertString(rawPayload.messageId, "messageId", { min: 1, max: 64 });
  const row = db.prepare("SELECT * FROM chat_messages WHERE id = ?").get(messageId);
  if (!row) {
    throw taggedError(Codes.NotFound, "Message not found.");
  }
  db.prepare("UPDATE chat_messages SET deleted_at = ?, deleted_by = ? WHERE id = ?").run(Date.now(), "admin", messageId);
  return { id: messageId, roomId: row.room_id, deleted: true };
}

export function handleChatSetBanned(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const username = assertString(rawPayload.username, "username", { min: 1, max: 64 }).trim().toLowerCase();
  const banned = Boolean(rawPayload.banned);
  const result = db.prepare("UPDATE identities SET chat_banned = ? WHERE username = ?").run(banned ? 1 : 0, username);
  if (result.changes === 0) {
    throw taggedError(Codes.NotFound, "That user doesn't exist.");
  }
  return { username, banned };
}
