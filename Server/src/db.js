import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const dataDir = join(rootDir, ".data");
const dbPath = join(dataDir, "hangouts.sqlite");

if (!existsSync(dataDir)) {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
}

export function openDatabase(path = dbPath) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS identities (
      username TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      server_salt_hex TEXT NOT NULL,
      credential_hash_hex TEXT NOT NULL,
      device_id TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      public_key_hex TEXT NOT NULL,
      bio TEXT NOT NULL DEFAULT '',
      pfp BLOB,
      pfp_mime TEXT,
      two_factor_enabled INTEGER NOT NULL DEFAULT 0,
      pass_public_key_hex TEXT,
      chat_banned INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_identities_email ON identities(email);

    CREATE TABLE IF NOT EXISTS consumed_identities (
      identity_id TEXT PRIMARY KEY,
      consumed_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identifier TEXT NOT NULL,
      succeeded INTEGER NOT NULL,
      timestamp INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attempts_identifier_timestamp
      ON attempts(identifier, timestamp);

    CREATE TABLE IF NOT EXISTS flags (
      identifier TEXT PRIMARY KEY,
      level TEXT NOT NULL,
      locked_until INTEGER NOT NULL,
      failure_count INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS modules (
      module_type TEXT NOT NULL,
      id TEXT NOT NULL,
      version INTEGER NOT NULL,
      content TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (module_type, id)
    );
    CREATE INDEX IF NOT EXISTS idx_modules_type_order ON modules(module_type, sort_order, created_at);

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

    CREATE TABLE IF NOT EXISTS pending_verifications (
      id TEXT PRIMARY KEY,
      purpose TEXT NOT NULL,
      identifier TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      extra TEXT,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_pending_verifications_identifier_purpose
      ON pending_verifications(identifier, purpose);

    CREATE TABLE IF NOT EXISTS chat_rooms (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      name TEXT,
      visibility TEXT NOT NULL DEFAULT 'public',
      owner_username TEXT,
      root_message_id TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_rooms_thread_root
      ON chat_rooms(root_message_id) WHERE kind = 'thread';

    INSERT OR IGNORE INTO chat_rooms (id, kind, name, visibility, owner_username, root_message_id, created_at)
      VALUES ('main', 'main', 'Main', 'public', NULL, NULL, 0);

    CREATE TABLE IF NOT EXISTS chat_room_invites (
      room_id TEXT NOT NULL,
      username TEXT NOT NULL,
      invited_by TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (room_id, username)
    );

    CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      username TEXT NOT NULL,
      body TEXT NOT NULL,
      deleted_at INTEGER,
      deleted_by TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_chat_messages_room_created ON chat_messages(room_id, created_at);
  `);
  return db;
}
