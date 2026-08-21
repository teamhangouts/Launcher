import { randomHex } from "./codec.js";
import { Codes, taggedError } from "./codes.js";
import { assertAdminToken } from "./admin.js";

const MaxContentBytes = 4 * 1024;
const ModuleTypePattern = /^[a-z][a-z0-9_-]{1,31}$/;
const ModuleIdPattern = /^[a-z0-9_.-]{1,64}$/;

function assertString(value, field, { min = 0, max = Infinity } = {}) {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function assertModuleType(value) {
  const moduleType = assertString(value, "moduleType", { min: 1, max: 32 });
  if (!ModuleTypePattern.test(moduleType)) {
    throw taggedError(Codes.MalformedRequest, "Invalid moduleType.");
  }
  return moduleType;
}

function assertModuleId(value) {
  const id = assertString(value, "id", { min: 1, max: 64 });
  if (!ModuleIdPattern.test(id)) {
    throw taggedError(Codes.MalformedRequest, "Invalid id.");
  }
  return id;
}

function rowToModule(row) {
  return {
    moduleType: row.module_type,
    id: row.id,
    version: row.version,
    content: JSON.parse(row.content),
    order: row.sort_order,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function handleModuleManifest(db, rawPayload) {
  const moduleType = rawPayload && rawPayload.moduleType ? assertModuleType(rawPayload.moduleType) : null;
  const rows = moduleType
    ? db.prepare("SELECT module_type, id, version FROM modules WHERE module_type = ?").all(moduleType)
    : db.prepare("SELECT module_type, id, version FROM modules").all();
  return {
    modules: rows.map((row) => ({ moduleType: row.module_type, id: row.id, version: row.version }))
  };
}

export function handleModuleGet(db, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const moduleType = assertModuleType(rawPayload.moduleType);
  const id = assertModuleId(rawPayload.id);
  const row = db.prepare("SELECT * FROM modules WHERE module_type = ? AND id = ?").get(moduleType, id);
  if (!row) {
    throw taggedError(Codes.NotFound, "Module not found.");
  }
  return rowToModule(row);
}

export function handleModuleGetAll(db, rawPayload) {
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const moduleType = assertModuleType(rawPayload.moduleType);
  const rows = db.prepare("SELECT * FROM modules WHERE module_type = ? ORDER BY sort_order ASC, created_at ASC").all(moduleType);
  return { modules: rows.map(rowToModule) };
}

export function handleModuleUpsert(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const moduleType = assertModuleType(rawPayload.moduleType);
  const id = rawPayload.id !== undefined ? assertModuleId(rawPayload.id) : randomHex(12);
  const contentString = JSON.stringify(rawPayload.content !== undefined ? rawPayload.content : {});
  if (contentString.length > MaxContentBytes) {
    throw taggedError(Codes.MalformedRequest, "Module content is too large.");
  }
  const order = Number.isInteger(rawPayload.order) ? rawPayload.order : 0;
  const now = Date.now();

  const existing = db.prepare("SELECT version, created_at FROM modules WHERE module_type = ? AND id = ?").get(moduleType, id);
  const version = existing ? existing.version + 1 : 1;
  const createdAt = existing ? existing.created_at : now;

  db.prepare(
    `INSERT INTO modules (module_type, id, version, content, sort_order, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(module_type, id) DO UPDATE SET version = excluded.version, content = excluded.content,
       sort_order = excluded.sort_order, updated_at = excluded.updated_at`
  ).run(moduleType, id, version, contentString, order, createdAt, now);

  const row = db.prepare("SELECT * FROM modules WHERE module_type = ? AND id = ?").get(moduleType, id);
  return rowToModule(row);
}

export function handleModuleDelete(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const moduleType = assertModuleType(rawPayload.moduleType);
  const id = assertModuleId(rawPayload.id);
  db.prepare("DELETE FROM modules WHERE module_type = ? AND id = ?").run(moduleType, id);
  return { moduleType, id };
}
