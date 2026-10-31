// Shared HTML renderers for the human-facing approval surfaces: the
// authorize-flow approval page and the device user-code entry page.
//
// Rules these pages never break:
// - No typed username or email field anywhere, and (step 13) no pasted
//   payload either. Approval comes only from a Muse-signed payload
//   submitted directly by the Muse to POST /oauth/approval; the page
//   polls GET /oauth/pending-status and finishes itself when the
//   request is approved or denied. No paste, no Approve click, no
//   Continue click.
// - (Step 14, speed-up) The page cannot ping a Muse, so it offers a
//   popup instead: "Open Muse AI to approve" opens muse.ai in a popup
//   window (click handler only, so popup blockers let it through),
//   and "Copy approval message" copies a one-line message with the
//   pending/device id for the user to paste into that popup chat.
//   The Muse approves there; this page's poller finishes the sign-in.
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
  // Styling only: one inline <style> block and a <main> card wrapper.
  // No form, script, route, or approval/deny logic is touched here.
  // System font stack, no external stylesheets, fonts, or images, so
  // the worker stays self-contained. Mobile-first: the card fills a
  // phone screen with comfortable padding.
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><style>
*{box-sizing:border-box}
body{margin:0;padding:24px 16px;background:#f2f2f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;line-height:1.5}
main{max-width:560px;margin:0 auto;background:#fff;border:1px solid #e2e2de;border-radius:12px;padding:28px 24px;box-shadow:0 2px 12px rgba(0,0,0,.06)}
h1{font-size:22px;line-height:1.25;margin:0 0 16px}
p{margin:0 0 12px}
ul{margin:0 0 12px;padding-left:20px}
li{margin:2px 0}
label{font-weight:600}
textarea,input[type="text"]{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:8px;font:inherit;margin:6px 0 12px}
button{width:100%;padding:12px;border:0;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
#open-muse-btn{background:#1a1a1a;color:#fff}
#copy-btn{background:transparent;color:#1a1a1a;border:1px solid #ccc;margin-top:8px}
#deny-form button{background:transparent;color:#555;border:1px solid #ccc}
#deny-form{margin-top:8px}
#deny-result{font-weight:600}
span#pending-id,span#user-code{word-break:break-all}
@media(max-width:480px){body{padding:16px 12px}main{padding:20px 16px}}
</style></head><body><main>${body}</main></body></html>`;
}

function scopeList(scopes) {
  return scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
}

// Step 13 auto-finish: the authorize page waits, then navigates
// itself on approval/denial. The Muse approves out-of-band by POSTing
// its signed payload to /oauth/approval — the user never pastes it.
function authorizeAutoFinish({ pendingId, basePath = "" }) {
  return `<p id="auto-status">Waiting for your Muse to approve…</p>
<script>
(function () {
  var statusEl = document.getElementById("auto-status");
  var timer = setInterval(async function () {
    var res;
    try { res = await fetch("${basePath}/oauth/pending-status?pending_id=" + encodeURIComponent("${escapeHtml(pendingId)}")); }
    catch { return; }
    var data = await res.json().catch(function () { return {}; });
    if (data.redirect_to) { clearInterval(timer); window.location = data.redirect_to; }
    else if (data.status === "awaiting") { return; }
    else { clearInterval(timer); statusEl.textContent = "This sign-in request is no longer waiting. Close this page and try signing in again."; }
  }, 2000);
})();
</script>`;
}

// Step 13 auto-finish for the device page: the device client polls
// /oauth/token for its tokens, so this page only shows the outcome.
function deviceAutoFinish({ deviceCode, basePath = "" }) {
  return `<p id="auto-status">Waiting for your Muse to approve…</p>
<script>
(function () {
  var statusEl = document.getElementById("auto-status");
  var timer = setInterval(async function () {
    var res;
    try { res = await fetch("${basePath}/oauth/pending-status?device_code=" + encodeURIComponent("${escapeHtml(deviceCode)}")); }
    catch { return; }
    var data = await res.json().catch(function () { return {}; });
    if (data.status === "awaiting") { return; }
    clearInterval(timer);
    if (data.status === "approved") { statusEl.textContent = "Approved. Your device can now finish signing in."; }
    else { statusEl.textContent = "Denied. The device will stop waiting."; }
  }, 2000);
})();
</script>`;
}

// Step 14 popup helper: open Muse AI in a popup + copy a one-line
// approval message. The copy message carries the exact id the Muse
// needs to sign (pending id for authorize, device code for device),
// so the user pastes one line into the popup chat instead of typing
// an id from memory. window.open runs only inside the click handler.
function musePopupHelper({ copyMessage }) {
  return `<p>Your Muse does not get a ping from this page. Open Muse here, paste the message below into it, and tell it to approve — this page will finish itself.</p>
<button id="open-muse-btn" type="button">Open Muse AI to approve</button>
<button id="copy-btn" type="button">Copy approval message</button>
<p id="copy-result"></p>
<script>
document.getElementById("open-muse-btn").addEventListener("click", function () {
  window.open("https://muse.ai", "muse-approve", "width=480,height=720,noopener");
});
document.getElementById("copy-btn").addEventListener("click", async function () {
  var msg = "${escapeHtml(copyMessage)}";
  var el = document.getElementById("copy-result");
  try { await navigator.clipboard.writeText(msg); el.textContent = "Copied — paste it into Muse in the popup."; }
  catch { el.textContent = "Copy did not work in this browser — paste the request shown above into Muse."; }
});
</script>`;
}

function denyForm({ idField, idValue, basePath = "" }) {
  return `<form id="deny-form">
<input type="hidden" name="${idField}" value="${escapeHtml(idValue)}">
<button type="submit">Deny</button>
</form>
<p id="deny-result"></p>
<script>
document.getElementById("deny-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = JSON.stringify({ "${idField}": "${escapeHtml(idValue)}" });
  const res = await fetch("${basePath}/oauth/deny", { method: "POST", headers: { "content-type": "application/json" }, body });
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
// basePath is the provider's mount prefix ("" at root, "/login" on
// fedpromptly.com): every internal link/form on the page is prefixed
// with it, so the page works at either mount. Client redirect URIs
// are never touched — they are not provider URLs.
export function authorizeApprovalPage({ clientName, redirectHost, scopes, pendingId, basePath = "" }) {
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
${musePopupHelper({ copyMessage: `Please approve my Muse sign-in. Pending request: ${pendingId}` })}
${authorizeAutoFinish({ pendingId, basePath })}
${denyForm({ idField: "pending_id", idValue: pendingId, basePath })}`,
  );
}

// Device entry page: the blank form a human lands on from a device.
export function deviceEntryPage(error = null, basePath = "") {
  const banner = error ? `<p><strong>${escapeHtml(error)}</strong></p>` : "";
  return pageShell(
    "Sign in with Muse — enter your code",
    `<h1>Sign in with Muse</h1>
${banner}
<p>Enter the code shown on your device.</p>
<form method="POST" action="${basePath}/device">
<label for="user_code">Device code:</label><br>
<input type="text" id="user_code" name="user_code" autocomplete="off" placeholder="ABCD-1234"><br>
<button type="submit">Continue</button>
</form>`,
  );
}

// Device detail page: shown after a valid user code, BEFORE approval.
export function deviceDetailPage({ clientName, scopes, deviceCode, userCode, basePath = "" }) {
  return pageShell(
    "Sign in with Muse — approve this device",
    `<h1>Sign in with Muse</h1>
<p><strong>${escapeHtml(clientName)}</strong> is asking you to sign in from a device.</p>
<p>Access being requested:</p>
<ul>${scopeList(scopes)}</ul>
<p>Signing in will share your email address with ${escapeHtml(clientName)}. Your email is collected on every sign-in and is returned as unverified (email_verified: false). Verification is a later, separate step and never blocks your sign-in.</p>
<p>Your Muse approves this request with its registered signature. There is no username or password field here — approval comes only from your Muse's signed approval.</p>
<p>Device code: <span id="user-code">${escapeHtml(userCode)}</span></p>
${musePopupHelper({ copyMessage: `Please approve my Muse device sign-in. Device code: ${deviceCode}` })}
${deviceAutoFinish({ deviceCode, basePath })}
${denyForm({ idField: "device_code", idValue: deviceCode, basePath })}`,
  );
}

// Plain status page for a device request that is already decided.
export function deviceStatusPage(message) {
  return pageShell("Sign in with Muse", `<h1>Sign in with Muse</h1><p>${escapeHtml(message)}</p>`);
}
