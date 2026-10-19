import { randomBytes } from "node:crypto";
import { createApp } from "./app.js";

const port = Number(process.env.PORT ?? 3000);
const isProduction = process.env.NODE_ENV === "production";
const jwtSecret = process.env.JWT_SECRET ?? randomBytes(48).toString("base64url");
if (isProduction && !process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is required in production");
}
const app = createApp({
  dbPath: process.env.DB_PATH ?? ":memory:",
  jwtSecret,
  jwtTtlSeconds: Number(process.env.JWT_TTL_SECONDS ?? 900),
});
app.server.listen(port, "127.0.0.1", () => {
  console.log("Secure Notes API listening on http://127.0.0.1:" + port);
});
function shutdown() {
  app.server.close(() => {
    app.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
