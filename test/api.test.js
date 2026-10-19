import test from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/app.js";

const JWT_SECRET = "test-secret-with-more-than-thirty-two-characters";

async function startTestServer() {
  const app = createApp({ jwtSecret: JWT_SECRET });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const { port } = app.server.address();
  return {
    app,
    base: "http://127.0.0.1:" + port,
    close: async () => {
      await new Promise((resolve) => app.server.close(resolve));
      app.close();
    },
  };
}

async function login(base, username, password) {
  return fetch(base + "/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

test("health endpoint responds", async () => {
  const fixture = await startTestServer();
  try {
    const response = await fetch(fixture.base + "/health");
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });
  } finally {
    await fixture.close();
  }
});

test("protected data endpoint rejects requests without a token", async () => {
  const fixture = await startTestServer();
  try {
    const response = await fetch(fixture.base + "/api/data");
    assert.equal(response.status, 401);
  } finally {
    await fixture.close();
  }
});

test("SQL injection login payload does not bypass authentication", async () => {
  const fixture = await startTestServer();
  try {
    const response = await login(fixture.base, "' OR 1=1--", "anything");
    assert.equal(response.status, 401);
  } finally {
    await fixture.close();
  }
});

test("valid login issues a JWT and data access succeeds", async () => {
  const fixture = await startTestServer();
  try {
    const response = await login(fixture.base, "analyst", "Analyst-Demo-2026!");
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(payload.token, /^[^.]+\.[^.]+\.[^.]+$/);
    const dataResponse = await fetch(fixture.base + "/api/data", {
      headers: { Authorization: "Bearer " + payload.token },
    });
    assert.equal(dataResponse.status, 200);
    const data = await dataResponse.json();
    assert.equal(data.requested_by, "analyst");
    assert.ok(Array.isArray(data.users));
  } finally {
    await fixture.close();
  }
});

test("tampered JWT is rejected", async () => {
  const fixture = await startTestServer();
  try {
    const response = await login(fixture.base, "analyst", "Analyst-Demo-2026!");
    const payload = await response.json();
    const [headerSegment, payloadSegment, signatureSegment] = payload.token.split(".");
    const signatureBytes = Buffer.from(signatureSegment, "base64url");
    signatureBytes[0] ^= 0x01;
    const tampered = [
      headerSegment,
      payloadSegment,
      signatureBytes.toString("base64url"),
    ].join(".");
    const dataResponse = await fetch(fixture.base + "/api/data", {
      headers: { Authorization: "Bearer " + tampered },
    });
    assert.equal(dataResponse.status, 401);
  } finally {
    await fixture.close();
  }
});

test("user content is escaped in API responses", async () => {
  const fixture = await startTestServer();
  try {
    const response = await login(fixture.base, "analyst", "Analyst-Demo-2026!");
    const { token } = await response.json();
    const payload = '<img src=x onerror="alert(1)">';
    const createResponse = await fetch(fixture.base + "/api/notes", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify({ content: payload }),
    });
    assert.equal(createResponse.status, 201);
    const created = await createResponse.json();
    assert.equal(
      created.content,
      "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
    );
    assert.equal(created.content.includes("<img"), false);
  } finally {
    await fixture.close();
  }
});
