import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const helper = path.join(root, "tools", "muse-approve.py");
const helperSrc = readFileSync(helper, "utf8");

test("step27: helper exists, takes a pending_id, and never prints a private key", () => {
  assert.match(helperSrc, /muse-approve\.py <pending_id>/);
  assert.match(helperSrc, /pending_id/);
  assert.match(helperSrc, /muse-approval-v1/);
  // The helper must read its key from local config, never embed one.
  assert.match(helperSrc, /muse-approval\.json/);
  assert.doesNotMatch(helperSrc, /print\([^)]*private_key_jwk[^)]*\)/);
  assert.doesNotMatch(helperSrc, /print\([^)]*jwk\["d"\][^)]*\)/);
  assert.match(helperSrc, /never the private key/);
});

test("step27: helper syntax-checks with python", () => {
  const r = spawnSync("python3", ["-m", "py_compile", helper], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("step27: local sign/verify round-trip with a fresh throwaway test key", () => {
  // Throwaway key generated for this test only — never the real muse3 key.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const message = Buffer.from(
    "muse-approval-v1\npending:test-pending-27\nmuse3\nGit-FED\nmuseai@fedpromptly.com",
    "utf8",
  );
  const signature = sign(null, message, privateKey);
  assert.equal(verify(null, message, publicKey, signature), true);
  // A tampered message must fail verification.
  const tampered = Buffer.from(
    "muse-approval-v1\npending:other-pending\nmuse3\nGit-FED\nmuseai@fedpromptly.com",
    "utf8",
  );
  assert.equal(verify(null, tampered, publicKey, signature), false);
});

test("step27: no worker code changed in this step", () => {
  // Step 27 is docs + tools only. The worker sources must not mention
  // the local helper or a Slack lookup — approval logic is untouched.
  const approval = readFileSync(path.join(root, "src", "oauth", "approval.js"), "utf8");
  assert.doesNotMatch(approval, /muse-approve\.py/);
  assert.doesNotMatch(approval, /Slack/);
});
