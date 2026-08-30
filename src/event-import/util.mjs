import { canonicalizeJson } from "../../shared/json.ts";
import { randomBytes, sha256 } from "../crypto/provider.mjs";

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function isSafeSegment(value) {
  return typeof value === "string" && SAFE_SEGMENT.test(value) && value !== "." && value !== "..";
}

export function isUuid(value) {
  return typeof value === "string" && UUID.test(value);
}

export function sha256Tagged(bytes) {
  return `sha256:${sha256(bytes)}`;
}

export function deterministicUuid(value) {
  const hex = sha256(String(value)).slice(0, 32).split("");
  hex[12] = "5";
  hex[16] = ["8", "9", "a", "b"][Number.parseInt(hex[16], 16) % 4];
  const raw = hex.join("");
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
}

export function randomUuid() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const raw = Buffer.from(bytes).toString("hex");
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
}

export function canonicalHash(value) {
  return sha256Tagged(Buffer.from(canonicalizeJson(value), "utf8"));
}

export function isoTimestamp(value) {
  if (typeof value !== "string" && typeof value !== "number" && !(value instanceof Date)) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) return null;
  return date.toISOString();
}

export function jsonClone(value) {
  return JSON.parse(JSON.stringify(value));
}
