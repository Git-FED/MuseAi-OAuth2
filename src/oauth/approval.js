// POST /oauth/approval — verifies a Muse-signed approval and turns a
// pending request (or a pending device request) into an authorization
// code (or an approved device).
//
// The signature is Ed25519 over a canonical message, verified against the
// public key in the KV registry (muse_key:<muse_id>). If no key is
// registered for that Muse, approval FAILS CLOSED. A key supplied in the
// request body is rejected outright — accepting one would be the
// impersonation hole the typed-username design exists to prevent.
//
// Canonical message:
//   muse-approval-v1\n<pending|device>:<id>\n<muse_id>\n<username>\n<email>
//
// Username and email enter the system ONLY here, inside the signed
// payload. There is no other path for them.

import { randomString, verifyEd25519 } from "../lib/crypto.js";
import { recordStub } from "../store/oauth-record.js";
import { json, parseFormOrJson } from "../lib/http.js";

export function approvalMessage(kind, id, museId, username, email) {
  return `muse-approval-v1\n${kind}:${id}\n${museId}\n${username}\n${email}`;
}

export async function approvalHandler(request, env) {
  let body = await parseFormOrJson(request);
  if (!body || typeof body !== "object") return json({ error: "invalid_request" }, 400);
  // Form posts from the approval page carry the payload as one JSON string.
  if (typeof body.payload === "string") {
    try {
      body = JSON.parse(body.payload);
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
  }
  // Never accept a self-supplied key.
  if (body.public_key || body.jwk || body.publicKey) {
    return json({ error: "invalid_request", error_description: "keys are registered, never supplied" }, 400);
  }
  const kind = body.pending_id ? "pending" : body.device_code ? "device" : null;
  const id = body.pending_id || body.device_code;
  if (!kind) {
    return json({ error: "invalid_request", error_description: "pending_id or device_code required" }, 400);
  }
  const { muse_id, username, email, signature } = body;
  if (!muse_id || !username || !email || !signature) {
    return json({ error: "invalid_request" }, 400);
  }

  const stub = recordStub(env, `${kind}:${id}`);
  const rec = await stub.read();
  if (!rec) {
    return json({ error: kind === "pending" ? "invalid_pending" : "invalid_device" }, 400);
  }
  if (rec.status === "approved") return json({ error: "already_approved" }, 400);

  const rawKey = await env.OAUTH_KV.get(`muse_key:${muse_id}`);
  if (!rawKey) {
    return json({ error: "unregistered_muse", error_description: "no registered public key for this Muse" }, 403);
  }
  let keyRec;
  try {
    keyRec = JSON.parse(rawKey);
  } catch {
    return json({ error: "server_error" }, 500);
  }
  const ok = await verifyEd25519(
    keyRec.public_key_jwk,
    approvalMessage(kind, id, muse_id, username, email),
    signature,
  );
  if (!ok) return json({ error: "invalid_signature" }, 403);

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
    const redirect = new URL(rec.redirect_uri);
    redirect.searchParams.set("code", code);
    if (rec.state) redirect.searchParams.set("state", rec.state);
    return json({ approved: true, redirect_to: redirect.toString() });
  }

  await stub.replace({ ...rec, status: "approved", username, email, muse_id }, remaining);
  return json({ approved: true, device_code: id });
}
