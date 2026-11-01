import test from "node:test";
import assert from "node:assert/strict";
import { museUsername } from "../src/lib/username.js";
import { recordSignIn, getProfile } from "../src/lib/profile.js";

test("step23: last 4 digits of a Muse ID become the username", () => {
  assert.equal(museUsername("muse-987654", "Someone"), "7654");
  assert.equal(museUsername("agent1234", "Someone"), "1234");
});

test("step23: short Muse ID falls back to the approved username, no break", () => {
  assert.equal(museUsername("muse3", "Git-FED"), "Git-FED");
});

test("step23: profile username is locked, repeat sign-in cannot change it", async () => {
  const store = new Map();
  const env = { OAUTH_KV: { get: async (k) => store.get(k) ?? null, put: async (k, v) => { store.set(k, v); } } };
  await recordSignIn(env, { sub: "muse:muse-987654", username: "7654", email: "a@example.com" });
  await recordSignIn(env, { sub: "muse:muse-987654", username: "Other", email: "b@example.com" });
  const rec = await getProfile(env, "muse:muse-987654");
  assert.equal(rec.preferred_username, "7654");
  assert.equal(rec.sign_in_count, 2);
  assert.equal(rec.email, "b@example.com");
});
