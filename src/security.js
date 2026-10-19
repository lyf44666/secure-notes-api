import {
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 64;

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeJsonSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

export function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
  return [
    "scrypt",
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString("base64url"),
    derived.toString("base64url"),
  ].join("$");
}

export function verifyPassword(password, encodedHash) {
  try {
    const [algorithm, n, r, p, saltText, hashText] = encodedHash.split("$");
    if (algorithm !== "scrypt") return false;
    const expected = Buffer.from(hashText, "base64url");
    const actual = scryptSync(
      password,
      Buffer.from(saltText, "base64url"),
      expected.length,
      {
        N: Number(n),
        r: Number(r),
        p: Number(p),
        maxmem: 64 * 1024 * 1024,
      },
    );
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function issueJwt(user, secret, ttlSeconds = 900) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: String(user.id),
    username: user.username,
    role: user.role,
    iat: now,
    exp: now + ttlSeconds,
    iss: "secure-notes-api",
    aud: "secure-notes-web",
  };
  const unsigned = base64url(JSON.stringify(header)) + "." +
    base64url(JSON.stringify(payload));
  const signature = createHmac("sha256", secret)
    .update(unsigned)
    .digest("base64url");
  return unsigned + "." + signature;
}

export function verifyJwt(token, secret) {
  if (typeof token !== "string") return null;
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  const [headerText, payloadText, signatureText] = segments;
  const unsigned = headerText + "." + payloadText;
  const expected = createHmac("sha256", secret).update(unsigned).digest();
  let received;
  try {
    received = Buffer.from(signatureText, "base64url");
  } catch {
    return null;
  }
  if (received.length !== expected.length ||
      !timingSafeEqual(received, expected)) {
    return null;
  }
  try {
    const header = decodeJsonSegment(headerText);
    const payload = decodeJsonSegment(payloadText);
    const now = Math.floor(Date.now() / 1000);
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;
    if (!Number.isInteger(payload.exp) || payload.exp <= now) return null;
    if (!Number.isInteger(payload.iat) || payload.iat > now + 30) return null;
    if (payload.iss !== "secure-notes-api") return null;
    if (payload.aud !== "secure-notes-web") return null;
    if (!payload.sub || typeof payload.sub !== "string") return null;
    return payload;
  } catch {
    return null;
  }
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#x27;")
    .replaceAll("/", "&#x2F;");
}

export function cleanText(value, maxLength = 500) {
  if (typeof value !== "string") return null;
  const normalized = value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .trim();
  if (!normalized || normalized.length > maxLength) return null;
  return normalized;
}
