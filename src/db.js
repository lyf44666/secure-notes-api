import { DatabaseSync } from "node:sqlite";
import { hashPassword } from "./security.js";

const SCHEMA = [
  "PRAGMA journal_mode = WAL;",
  "PRAGMA foreign_keys = ON;",
  "CREATE TABLE IF NOT EXISTS users (",
  "  id INTEGER PRIMARY KEY AUTOINCREMENT,",
  "  username TEXT NOT NULL UNIQUE,",
  "  password_hash TEXT NOT NULL,",
  "  role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),",
  "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
  ");",
  "CREATE TABLE IF NOT EXISTS notes (",
  "  id INTEGER PRIMARY KEY AUTOINCREMENT,",
  "  user_id INTEGER NOT NULL,",
  "  content TEXT NOT NULL,",
  "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,",
  "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
  ");",
  "CREATE TABLE IF NOT EXISTS audit_log (",
  "  id INTEGER PRIMARY KEY AUTOINCREMENT,",
  "  event TEXT NOT NULL,",
  "  subject TEXT NOT NULL,",
  "  outcome TEXT NOT NULL,",
  "  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
  ");",
].join("\n");

export function createDatabase(path = ":memory:") {
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  const userCount = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
  if (userCount === 0) {
    const insert = db.prepare(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
    );
    insert.run("admin", hashPassword("Admin-Demo-2026!"), "admin");
    insert.run("analyst", hashPassword("Analyst-Demo-2026!"), "analyst");
    const admin = db.prepare("SELECT id FROM users WHERE username = ?").get("admin");
    const note = db.prepare(
      "INSERT INTO notes (user_id, content) VALUES (?, ?)",
    );
    note.run(admin.id, "Welcome to the secure notes API.");
    note.run(admin.id, "Use parameterized SQL and escaped output.");
  }
  return db;
}
