// GET + POST /device — the human user-code entry page for the device
// flow (RFC 8628's verification URI).
//
// GET /device serves a blank code form. POST /device takes a user_code,
// resolves it through the KV index written at device-authorization time
// (device_user_code:<CODE> -> device_code), and:
//   - pending  -> shows the client name + scopes and the approve/deny
//     forms. Approval uses the SAME Muse-signed mechanism as the
//     authorize flow (POST /oauth/approval with device_code); no second
//     authentication mechanism is invented here.
//   - approved -> plain "already approved" page.
//   - denied   -> plain "denied" page.
//   - unknown, malformed, or expired code -> one generic error, in plain
//     language, never a stack trace or an internal detail. The error does
//     not say whether the code ever existed.
// The submitted code value is never logged or audited — audit entries
// carry only the generic "invalid_user_code" detail.

import { audit } from "../lib/audit.js";
import { normalizeBasePath } from "../lib/mount.js";
import { getClient } from "../lib/registry.js";
import { recordStub } from "../store/oauth-record.js";
import { html, json, parseFormOrJson } from "../lib/http.js";
import { deviceDetailPage, deviceEntryPage, deviceStatusPage } from "./approval-page.js";

const USER_CODE_RE = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;
const INVALID_MESSAGE = "That code is invalid or has expired. Check the code on your device and try again.";

export function normalizeUserCode(raw) {
  if (typeof raw !== "string") return null;
  const code = raw.trim().toUpperCase();
  return USER_CODE_RE.test(code) ? code : null;
}

export async function deviceGetHandler(request, env) {
  return html(deviceEntryPage(null, normalizeBasePath(env.BASE_PATH)));
}

export async function devicePostHandler(request, env) {
  const body = await parseFormOrJson(request);
  const basePath = normalizeBasePath(env.BASE_PATH);
  const wantsJson = (request.headers.get("content-type") || "").includes("application/json");
  const failInvalid = async () => {
    await audit(env, "device_entry_invalid", { actor: null, route: "/device", outcome: "denied", detail: "invalid_user_code" });
    return wantsJson
      ? json({ error: "invalid_user_code", error_description: INVALID_MESSAGE }, 400)
      : html(deviceEntryPage(INVALID_MESSAGE, basePath), 400);
  };

  const code = normalizeUserCode(body && body.user_code);
  if (!code) return failInvalid();

  // Resolve the code to its device record through the KV index.
  let deviceCode = null;
  try {
    deviceCode = env.OAUTH_KV ? await env.OAUTH_KV.get(`device_user_code:${code}`) : null;
  } catch {
    deviceCode = null;
  }
  if (!deviceCode) return failInvalid();

  const rec = await recordStub(env, `device:${deviceCode}`).read();
  if (!rec) return failInvalid();

  if (rec.status === "approved") {
    return wantsJson
      ? json({ status: "approved" })
      : html(deviceStatusPage("This device request was already approved. Your device can finish signing in."));
  }
  if (rec.status === "denied") {
    return wantsJson
      ? json({ status: "denied" })
      : html(deviceStatusPage("This device request was denied. The device will stop waiting."));
  }
  if (rec.status !== "pending") return failInvalid();

  const client = await getClient(env, rec.client_id);
  if (!client) {
    // Registry inconsistent (device exists, client gone): fail closed
    // with a plain message, no internal detail.
    return wantsJson
      ? json({ error: "server_error" }, 500)
      : html(deviceStatusPage("Something went wrong. Please try again."), 500);
  }

  if (wantsJson) {
    return json({
      status: "pending",
      client_name: client.name,
      scope: rec.scope,
      device_code: deviceCode,
    });
  }
  return html(deviceDetailPage({
    clientName: client.name,
    scopes: rec.scope,
    deviceCode,
    userCode: code,
    basePath,
  }));
}
