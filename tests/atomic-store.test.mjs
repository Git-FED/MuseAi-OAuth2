import test from "node:test";
import assert from "node:assert/strict";
import { OAuthRecord } from "../src/store/oauth-record.js";

// Fake Durable Object storage: a Map with the same async interface the
// class uses (get/put/delete/setAlarm). The class imports nothing
// Cloudflare-specific, so it runs under plain node.
class FakeStorage {
  data = new Map();
  async get(key) { return this.data.get(key) ?? null; }
  async put(key, value) { this.data.set(key, value); }
  async delete(key) { this.data.delete(key); }
  async setAlarm() { /* no-op in tests; expiry is checked lazily */ }
}

function newRecord() {
  return new OAuthRecord({ storage: new FakeStorage() });
}

test("create then read returns the record", async () => {
  const r = newRecord();
  await r.create({ kind: "auth_code", client: "fedpromptly" }, 60_000);
  const rec = await r.read();
  assert.equal(rec.kind, "auth_code");
  assert.equal(rec.client, "fedpromptly");
  assert.ok(rec.exp > Date.now());
});

test("consume returns the record once, then null forever", async () => {
  const r = newRecord();
  await r.create({ kind: "auth_code", code: "abc" }, 60_000);
  const first = await r.consume();
  assert.equal(first.code, "abc");
  assert.equal(await r.consume(), null);
  assert.equal(await r.read(), null);
});

test("expired record reads as null and is cleaned up", async () => {
  const r = newRecord();
  await r.create({ kind: "device_code" }, -1);
  assert.equal(await r.read(), null);
  assert.equal(await r.consume(), null);
});

test("create refuses to overwrite a live record", async () => {
  const r = newRecord();
  await r.create({ kind: "auth_code", code: "one" }, 60_000);
  await assert.rejects(r.create({ kind: "auth_code", code: "two" }, 60_000), /already exists/);
  assert.equal((await r.read()).code, "one");
});

test("create succeeds after the old record is consumed", async () => {
  const r = newRecord();
  await r.create({ kind: "auth_code", code: "old" }, 60_000);
  await r.consume();
  await r.create({ kind: "auth_code", code: "new" }, 60_000);
  assert.equal((await r.read()).code, "new");
});

test("replace swaps the record in one call (refresh rotation)", async () => {
  const r = newRecord();
  await r.create({ kind: "refresh", token: "old-token" }, 60_000);
  await r.replace({ kind: "refresh", token: "new-token" }, 60_000);
  assert.equal((await r.read()).token, "new-token");
});

test("revoke deletes the record", async () => {
  const r = newRecord();
  await r.create({ kind: "refresh", token: "t" }, 60_000);
  await r.revoke();
  assert.equal(await r.read(), null);
});

test("alarm cleans up an expired record", async () => {
  const r = newRecord();
  await r.create({ kind: "pending" }, -1);
  await r.alarm();
  assert.equal(await r.storage.get("record"), null);
});
