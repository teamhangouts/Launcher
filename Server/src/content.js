import { randomHex } from "./codec.js";
import { Codes, taggedError } from "./codes.js";
import { assertAdminToken } from "./admin.js";

function assertString(value, field, { min = 0, max = Infinity, optional = false } = {}) {
  if (optional && (value === undefined || value === null)) {
    return null;
  }
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function assertInteger(value, field) {
  if (!Number.isInteger(value)) {
    throw taggedError(Codes.MalformedRequest, `Invalid ${field}.`);
  }
  return value;
}

function rowToSlide(row) {
  return {
    id: row.id,
    title: row.title,
    body: row.body,
    imageUrl: row.image_url,
    linkUrl: row.link_url,
    order: row.sort_order,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function handleCarouselGetAll(db) {
  const rows = db.prepare("SELECT * FROM carousel_slides ORDER BY sort_order ASC, created_at ASC").all();
  return { slides: rows.map(rowToSlide) };
}

export function handleCarouselUpsert(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const id = assertString(rawPayload.id, "id", { min: 1, max: 64, optional: true }) || randomHex(16);
  const title = assertString(rawPayload.title, "title", { min: 1, max: 200 });
  const body = assertString(rawPayload.body, "body", { min: 0, max: 2000 }) ?? "";
  const imageUrl = assertString(rawPayload.imageUrl, "imageUrl", { max: 2000, optional: true });
  const linkUrl = assertString(rawPayload.linkUrl, "linkUrl", { max: 2000, optional: true });
  const order = assertInteger(rawPayload.order ?? 0, "order");
  const now = Date.now();

  const existing = db.prepare("SELECT created_at FROM carousel_slides WHERE id = ?").get(id);
  const createdAt = existing ? existing.created_at : now;

  db.prepare(
    `INSERT INTO carousel_slides (id, title, body, image_url, link_url, sort_order, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET title = excluded.title, body = excluded.body, image_url = excluded.image_url,
       link_url = excluded.link_url, sort_order = excluded.sort_order, updated_at = excluded.updated_at`
  ).run(id, title, body, imageUrl, linkUrl, order, createdAt, now);

  const row = db.prepare("SELECT * FROM carousel_slides WHERE id = ?").get(id);
  return rowToSlide(row);
}

export function handleCarouselDelete(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  const id = assertString(rawPayload && rawPayload.id, "id", { min: 1, max: 64 });
  db.prepare("DELETE FROM carousel_slides WHERE id = ?").run(id);
  return { id };
}

export function handleNewsletterGet(db) {
  const row = db.prepare("SELECT * FROM newsletter WHERE id = 1").get();
  if (!row) {
    return { newsletter: null };
  }
  return { newsletter: { title: row.title, body: row.body, publishedAt: row.published_at } };
}

export function handleNewsletterUpsert(db, adminToken, rawPayload) {
  assertAdminToken(adminToken, rawPayload && rawPayload.adminToken);
  if (!rawPayload || typeof rawPayload !== "object") {
    throw taggedError(Codes.MalformedRequest, "Missing payload.");
  }
  const title = assertString(rawPayload.title, "title", { min: 1, max: 200 });
  const body = assertString(rawPayload.body, "body", { min: 0, max: 20000 }) ?? "";
  const publishedAt = Date.now();

  db.prepare(
    `INSERT INTO newsletter (id, title, body, published_at) VALUES (1, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET title = excluded.title, body = excluded.body, published_at = excluded.published_at`
  ).run(title, body, publishedAt);

  return { title, body, publishedAt };
}
