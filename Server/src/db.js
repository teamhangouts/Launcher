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

    CREATE TABLE IF NOT EXISTS carousel_slides (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      image_url TEXT,
      link_url TEXT,
      sort_order INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS newsletter (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      published_at INTEGER NOT NULL
    );

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
  `);
  return db;
}
