// GET /oauth/authorize — authorization code flow, PKCE S256 mandatory.
// Validates the client + redirect URI, then creates a pending approval
// record in the Durable Object store (TTL 10 minutes) and returns the
// approval page. The page shows the client name and redirect host, and
// accepts ONLY a Muse-signed approval payload — there is no typed
// username or email field anywhere on it.

import { randomString } from "../lib/crypto.js";
import { getClient } from "../lib/registry.js";
import { isValidClientId, parseScope, redirectHost } from "../lib/validate.js";
import { recordStub } from "../store/oauth-record.js";
import { html, json } from "../lib/http.js";

export const PENDING_TTL_MS = 600_000;

function redirectWithError(redirectUri, error, state) {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (state) url.searchParams.set("state", state);
  return Response.redirect(url.toString(), 302);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export async function authorizeHandler(request, env) {
  const url = new URL(request.url);
  const q = url.searchParams;
  const clientId = q.get("client_id");
  const redirectUri = q.get("redirect_uri");
  const state = q.get("state");

  // Until client + redirect URI are verified, errors are plain 400s:
  // redirecting to an unverified URI would leak the error to an attacker.
  if (!isValidClientId(clientId)) return json({ error: "invalid_client" }, 400);
  const client = await getClient(env, clientId);
  if (!client) return json({ error: "invalid_client" }, 400);
  if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
    return json({ error: "invalid_request", error_description: "redirect_uri does not match the registered client" }, 400);
  }

  // Redirect URI is now trusted: further errors go back to the client.
  if (q.get("response_type") !== "code") {
    return redirectWithError(redirectUri, "unsupported_response_type", state);
  }
  const challenge = q.get("code_challenge");
  if (!challenge || q.get("code_challenge_method") !== "S256") {
    return redirectWithError(redirectUri, "invalid_request", state);
  }
  const scope = parseScope(q.get("scope"));
  if (!scope) return redirectWithError(redirectUri, "invalid_scope", state);
  // Per-client scope restriction, when the client record restricts scopes.
  if (client.allowed_scopes && !scope.every((s) => client.allowed_scopes.includes(s))) {
    return redirectWithError(redirectUri, "invalid_scope", state);
  }

  const pendingId = randomString(24);
  try {
    await recordStub(env, `pending:${pendingId}`).create(
      {
        kind: "pending",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        code_challenge: challenge,
        state: state || null,
        nonce: q.get("nonce"),
        status: "awaiting",
      },
      PENDING_TTL_MS,
    );
  } catch {
    return json({ error: "server_error" }, 500);
  }

  const host = redirectHost(redirectUri);
  const page = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in with Muse</title></head><body>
<h1>Sign in with Muse</h1>
<p><strong>${escapeHtml(client.name || clientId)}</strong> is asking you to sign in.</p>
<p>After approval you will be sent back to <strong>${escapeHtml(host)}</strong>.</p>
<p>Your Muse approves this request with its registered signature. There is no username or password field here — approval comes only from your Muse's signed approval.</p>
<p>Pending request: <span id="pending-id">${escapeHtml(pendingId)}</span></p>
<form id="approval-form">
<label for="payload">Muse-signed approval payload (JSON):</label><br>
<textarea id="payload" name="payload" rows="8" cols="80" placeholder='{"pending_id":"...","muse_id":"...","username":"...","email":"...","signature":"..."}'></textarea><br>
<button type="submit">Approve</button>
</form>
<p id="result"></p>
<script>
document.getElementById("approval-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = JSON.parse(document.getElementById("payload").value);
  const res = await fetch("/oauth/approval", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  const data = await res.json();
  const el = document.getElementById("result");
  if (data.redirect_to) { el.innerHTML = 'Approved. <a href="' + data.redirect_to + '">Continue to ' + ${JSON.stringify(host)} + '</a>'; }
  else { el.textContent = "Approval failed: " + (data.error || res.status); }
});
</script>
</body></html>`;
  return html(page);
}
