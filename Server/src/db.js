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
      server_salt_hex TEXT NOT NULL,
      credential_hash_hex TEXT NOT NULL,
      device_id TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      public_key_hex TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

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
  `);
  return db;
}
