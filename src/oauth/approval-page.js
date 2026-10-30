// Shared HTML renderers for the human-facing approval surfaces: the
// authorize-flow approval page and the device user-code entry page.
//
// Rules these pages never break:
// - No typed username or email field anywhere. Approval comes only from
//   a Muse-signed payload, pasted by the user (or supplied by their Muse).
// - Every value that comes from a registry record or a request is HTML-
//   escaped before it reaches the page.
// - Error pages say what went wrong in plain language, never a stack
//   trace or an internal detail.

export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pageShell(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body>${body}</body></html>`;
}

function scopeList(scopes) {
  return scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
}

function signedPayloadForm({ idField, idValue, approvePath, resultNote }) {
  return `<form id="approval-form">
<label for="payload">Muse-signed approval payload (JSON):</label><br>
<textarea id="payload" name="payload" rows="8" cols="80" placeholder='{"${idField}":"${escapeHtml(idValue)}","muse_id":"...","username":"...","email":"...","signature":"..."}'></textarea><br>
<button type="submit">Approve</button>
</form>
<p id="result"></p>
<script>
document.getElementById("approval-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  let payload;
  try { payload = JSON.parse(document.getElementById("payload").value); }
  catch { document.getElementById("result").textContent = "Approval failed: that payload is not valid JSON."; return; }
  const res = await fetch("${approvePath}", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  const data = await res.json().catch(() => ({}));
  const el = document.getElementById("result");
  if (data.redirect_to) { el.innerHTML = 'Approved. <a href="' + data.redirect_to + '">Continue</a>'; }
  else if (data.approved) { el.textContent = "${resultNote}"; }
  else { el.textContent = "Approval failed: " + (data.error || res.status); }
});
</script>`;
}

function denyForm({ idField, idValue }) {
  return `<form id="deny-form">
<input type="hidden" name="${idField}" value="${escapeHtml(idValue)}">
<button type="submit">Deny</button>
</form>
<p id="deny-result"></p>
<script>
document.getElementById("deny-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = JSON.stringify({ "${idField}": "${escapeHtml(idValue)}" });
  const res = await fetch("/oauth/deny", { method: "POST", headers: { "content-type": "application/json" }, body });
  const data = await res.json().catch(() => ({}));
  const el = document.getElementById("deny-result");
  if (data.denied && data.redirect_to) { window.location = data.redirect_to; }
  else if (data.denied) { el.textContent = "Denied. The device will stop waiting."; }
  else { el.textContent = "Deny failed: " + (data.error || res.status); }
});
</script>`;
}

// Authorize-flow approval page. Shown BEFORE any approval, so the user
// can see exactly what they are being asked to agree to.
export function authorizeApprovalPage({ clientName, redirectHost, scopes, pendingId }) {
  return pageShell(
    "Sign in with Muse",
    `<h1>Sign in with Muse</h1>
<p><strong>${escapeHtml(clientName)}</strong> is asking you to sign in.</p>
<p>After approval you will be sent back to <strong>${escapeHtml(redirectHost)}</strong>.</p>
<p>Access being requested:</p>
<ul>${scopeList(scopes)}</ul>
<p>Signing in will share your email address with ${escapeHtml(clientName)}. Your email is collected on every sign-in and is returned as unverified (email_verified: false). Verification is a later, separate step and never blocks your sign-in.</p>
<p>Your Muse approves this request with its registered signature. There is no username or password field here — approval comes only from your Muse's signed approval.</p>
<p>Pending request: <span id="pending-id">${escapeHtml(pendingId)}</span></p>
${signedPayloadForm({ idField: "pending_id", idValue: pendingId, approvePath: "/oauth/approval", resultNote: "Approved." })}
${denyForm({ idField: "pending_id", idValue: pendingId })}`,
  );
}

// Device entry page: the blank form a human lands on from a device.
export function deviceEntryPage(error = null) {
  const banner = error ? `<p><strong>${escapeHtml(error)}</strong></p>` : "";
  return pageShell(
    "Sign in with Muse — enter your code",
    `<h1>Sign in with Muse</h1>
${banner}
<p>Enter the code shown on your device.</p>
<form method="POST" action="/device">
<label for="user_code">Device code:</label><br>
<input type="text" id="user_code" name="user_code" autocomplete="off" placeholder="ABCD-1234"><br>
<button type="submit">Continue</button>
</form>`,
  );
}

// Device detail page: shown after a valid user code, BEFORE approval.
export function deviceDetailPage({ clientName, scopes, deviceCode, userCode }) {
  return pageShell(
    "Sign in with Muse — approve this device",
    `<h1>Sign in with Muse</h1>
<p><strong>${escapeHtml(clientName)}</strong> is asking you to sign in from a device.</p>
<p>Access being requested:</p>
<ul>${scopeList(scopes)}</ul>
<p>Signing in will share your email address with ${escapeHtml(clientName)}. Your email is collected on every sign-in and is returned as unverified (email_verified: false). Verification is a later, separate step and never blocks your sign-in.</p>
<p>Your Muse approves this request with its registered signature. There is no username or password field here — approval comes only from your Muse's signed approval.</p>
<p>Device code: <span id="user-code">${escapeHtml(userCode)}</span></p>
${signedPayloadForm({ idField: "device_code", idValue: deviceCode, approvePath: "/oauth/approval", resultNote: "Approved. Your device can now finish signing in." })}
${denyForm({ idField: "device_code", idValue: deviceCode })}`,
  );
}

// Plain status page for a device request that is already decided.
export function deviceStatusPage(message) {
  return pageShell("Sign in with Muse", `<h1>Sign in with Muse</h1><p>${escapeHtml(message)}</p>`);
}
