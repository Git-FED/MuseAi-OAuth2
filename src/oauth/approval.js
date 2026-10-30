// POST /oauth/approval — verifies a Muse-signed approval and turns a
// pending request (or a pending device request) into an authorization
// code (or an approved device).
//
// The signature is Ed25519 over a canonical message, verified against the
// public key in the KV registry (muse_key:<muse_id>), read through the
// strict reader in src/lib/registry.js. If no valid key is registered
// for that Muse, approval FAILS CLOSED. A key supplied in the request
// body is rejected outright — accepting one would be the impersonation
// hole the typed-username design exists to prevent.
//
// Canonical message:
//   muse-approval-v1\n<pending|device>:<id>\n<muse_id>\n<username>\n<email>
//
// Username and email enter the system ONLY here, inside the signed
// payload. There is no other path for them.
//
// Every outcome is audited (success and every denial). Audit entries
// carry only event/actor/client/route/outcome/detail — never the
// signature, the code, or any request body.

import { randomString, verifyEd25519 } from "../lib/crypto.js";
import { audit } from "../lib/audit.js";
import { getMuseKey } from "../lib/registry.js";
import { recordStub } from "../store/oauth-record.js";
import { json, parseFormOrJson } from "../lib/http.js";

export function approvalMessage(kind, id, museId, username, email) {
  return `muse-approval-v1\n${kind}:${id}\n${museId}\n${username}\n${email}`;
}

export async function approvalHandler(request, env) {
  let body = await parseFormOrJson(request);
  // Form posts from the approval page carry the payload as one JSON string.
  if (body && typeof body === "object" && typeof body.payload === "string") {
    try {
      body = JSON.parse(body.payload);
    } catch {
      body = null;
    }
  }
  let auditClientId = null;
  const actor = body && typeof body.muse_id === "string" ? body.muse_id : null;
  const fail = async (status, error, detail, description) => {
    await audit(env, "approval_denied", { actor, clientId: auditClientId, route: "/oauth/approval", outcome: "denied", detail });
    return json({ error, ...(description ? { error_description: description } : {}) }, status);
  };

  if (!body || typeof body !== "object") return fail(400, "invalid_request", "invalid_request");
  // Never accept a self-supplied key.
  if (body.public_key || body.jwk || body.publicKey) {
    return fail(400, "invalid_request", "self_supplied_key", "keys are registered, never supplied");
  }
  const kind = body.pending_id ? "pending" : body.device_code ? "device" : null;
  const id = body.pending_id || body.device_code;
  if (!kind) {
    return fail(400, "invalid_request", "missing_id", "pending_id or device_code required");
  }
  const { muse_id, username, email, signature } = body;
  if (!muse_id || !username || !email || !signature) {
    return fail(400, "invalid_request", "missing_fields");
  }

  const stub = recordStub(env, `${kind}:${id}`);
  const rec = await stub.read();
  if (!rec) {
    return fail(400, kind === "pending" ? "invalid_pending" : "invalid_device", "invalid_record");
  }
  auditClientId = rec.client_id || null;
  if (rec.status === "approved") return fail(400, "already_approved", "already_approved");
  // Denied is terminal: a denied request can never be approved later.
  // The denial itself was audited by POST /oauth/deny; this is the
  // denial surfacing to a late approval attempt.
  if (rec.status === "denied") return fail(400, "access_denied", "access_denied", "this request was denied");

  // Strict reader: missing OR malformed key records both read as null.
  const keyRec = await getMuseKey(env, muse_id);
  if (!keyRec) {
    return fail(403, "unregistered_muse", "unregistered_muse", "no registered public key for this Muse");
  }
  const ok = await verifyEd25519(
    keyRec.public_key_jwk,
    approvalMessage(kind, id, muse_id, username, email),
    signature,
  );
  if (!ok) return fail(403, "invalid_signature", "invalid_signature");

  const remaining = Math.max(rec.exp - Date.now(), 1000);
  if (kind === "pending") {
    const code = randomString(32);
    await recordStub(env, `auth_code:${code}`).create(
      {
        kind: "auth_code",
        client_id: rec.client_id,
        redirect_uri: rec.redirect_uri,
        scope: rec.scope,
        code_challenge: rec.code_challenge,
        state: rec.state,
        nonce: rec.nonce,
        username,
        email,
        muse_id,
      },
      600_000,
    );
    await stub.replace({ ...rec, status: "approved", username, email, muse_id }, remaining);
    await audit(env, "approval_approved", { actor: muse_id, clientId: rec.client_id, route: "/oauth/approval", outcome: "success", detail: "pending" });
    const redirect = new URL(rec.redirect_uri);
    redirect.searchParams.set("code", code);
    if (rec.state) redirect.searchParams.set("state", rec.state);
    return json({ approved: true, redirect_to: redirect.toString() });
  }

  await stub.replace({ ...rec, status: "approved", username, email, muse_id }, remaining);
  await audit(env, "approval_approved", { actor: muse_id, clientId: rec.client_id, route: "/oauth/approval", outcome: "success", detail: "device" });
  return json({ approved: true, device_code: id });
}
