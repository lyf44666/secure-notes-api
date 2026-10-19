import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { createDatabase } from "./db.js";
import {
  cleanText,
  escapeHtml,
  issueJwt,
  verifyJwt,
  verifyPassword,
} from "./security.js";

const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function sendJson(response, status, body, requestId) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    ...SECURITY_HEADERS,
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "X-Request-Id": requestId,
  });
  response.end(payload);
}

async function readJson(request) {
  if (!request.headers["content-type"]?.startsWith("application/json")) {
    const error = new Error("Content-Type must be application/json");
    error.status = 415;
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 32 * 1024) {
      const error = new Error("Request body is too large");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    const error = new Error("Malformed JSON");
    error.status = 400;
    throw error;
  }
}

function getBearerToken(request) {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice("Bearer ".length);
}

function createLoginLimiter({ windowMs = 60000, maxAttempts = 8 } = {}) {
  const attempts = new Map();
  return {
    allow(key) {
      const now = Date.now();
      const current = attempts.get(key);
      if (!current || current.resetAt <= now) {
        attempts.set(key, { count: 1, resetAt: now + windowMs });
        return true;
      }
      current.count += 1;
      return current.count <= maxAttempts;
    },
    clear(key) {
      attempts.delete(key);
    },
  };
}

export function createApp({
  dbPath = ":memory:",
  jwtSecret,
  jwtTtlSeconds = 900,
} = {}) {
  if (!jwtSecret || jwtSecret.length < 32) {
    throw new Error("jwtSecret must contain at least 32 characters");
  }
  const db = createDatabase(dbPath);
  const loginLimiter = createLoginLimiter();
  const dummyHash =
    "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const findUser = db.prepare(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
  );
  const listUsers = db.prepare("SELECT id, username, role FROM users ORDER BY id");
  const listNotes = db.prepare(
    "SELECT id, content, created_at FROM notes ORDER BY id DESC LIMIT 50",
  );
  const insertNote = db.prepare(
    "INSERT INTO notes (user_id, content) VALUES (?, ?)",
  );
  const getNote = db.prepare(
    "SELECT id, content, created_at FROM notes WHERE id = ?",
  );
  const audit = db.prepare(
    "INSERT INTO audit_log (event, subject, outcome) VALUES (?, ?, ?)",
  );
  const findSessionUser = db.prepare(
    "SELECT id, username, role FROM users WHERE id = ?",
  );

  function authenticate(request) {
    const token = getBearerToken(request);
    if (!token) return null;
    const claims = verifyJwt(token, jwtSecret);
    if (!claims) return null;
    const user = findSessionUser.get(Number(claims.sub));
    if (!user || user.username !== claims.username) return null;
    return user;
  }

  const server = createServer(async (request, response) => {
    const requestId = randomUUID();
    const url = new URL(request.url, "http://localhost");
    try {
      if (request.method === "GET" && url.pathname === "/health") {
        return sendJson(response, 200, { status: "ok" }, requestId);
      }
      if (request.method === "POST" && url.pathname === "/auth/login") {
        const ip = request.socket.remoteAddress ?? "unknown";
        if (!loginLimiter.allow(ip)) {
          audit.run("login", ip, "rate_limited");
          return sendJson(response, 429, { error: "Too many login attempts" }, requestId);
        }
        const body = await readJson(request);
        const username = cleanText(body.username, 80);
        const password = typeof body.password === "string" ? body.password : "";
        if (!username || password.length < 1 || password.length > 256) {
          audit.run("login", username ?? "invalid", "invalid_input");
          return sendJson(response, 400, { error: "Username and password are required" }, requestId);
        }
        const user = findUser.get(username);
        const valid = verifyPassword(password, user?.password_hash ?? dummyHash);
        if (!user || !valid) {
          audit.run("login", username, "denied");
          return sendJson(response, 401, { error: "Invalid credentials" }, requestId);
        }
        loginLimiter.clear(ip);
        audit.run("login", username, "success");
        return sendJson(response, 200, {
          token: issueJwt(user, jwtSecret, jwtTtlSeconds),
          token_type: "Bearer",
          expires_in: jwtTtlSeconds,
          user: {
            id: user.id,
            username: escapeHtml(user.username),
            role: escapeHtml(user.role),
          },
        }, requestId);
      }
      if (request.method === "GET" && url.pathname === "/api/data") {
        const user = authenticate(request);
        if (!user) {
          return sendJson(response, 401, { error: "Unauthorized" }, requestId);
        }
        return sendJson(response, 200, {
          requested_by: escapeHtml(user.username),
          users: listUsers.all().map((row) => ({
            id: row.id,
            username: escapeHtml(row.username),
            role: escapeHtml(row.role),
          })),
          notes: listNotes.all().map((row) => ({
            id: row.id,
            content: escapeHtml(row.content),
            created_at: row.created_at,
          })),
        }, requestId);
      }
      if (request.method === "POST" && url.pathname === "/api/notes") {
        const user = authenticate(request);
        if (!user) {
          return sendJson(response, 401, { error: "Unauthorized" }, requestId);
        }
        const body = await readJson(request);
        const content = cleanText(body.content, 500);
        if (!content) {
          return sendJson(response, 400, { error: "Content must be 1-500 printable characters" }, requestId);
        }
        const result = insertNote.run(user.id, content);
        const created = getNote.get(Number(result.lastInsertRowid));
        audit.run("note.create", String(user.id), "success");
        return sendJson(response, 201, {
          id: created.id,
          content: escapeHtml(created.content),
          created_at: created.created_at,
        }, requestId);
      }
      return sendJson(response, 404, { error: "Not found" }, requestId);
    } catch (error) {
      const status = Number(error.status) || 500;
      if (status >= 500) {
        audit.run("request.error", request.url ?? "unknown", "server_error");
      }
      return sendJson(response, status, {
        error: status >= 500 ? "Internal server error" : error.message,
      }, requestId);
    }
  });
  return {
    server,
    close() {
      db.close();
    },
  };
}
