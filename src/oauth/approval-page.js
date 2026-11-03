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
// - (Step 17, REMOVED in step 19) "Copy ID" was a duplicate of step 18's
//   combined button, so it was removed — there is only one Copy ID
//   button now, "Copy ID & Open Muse AI".
// - (Step 18, speed-up) "Copy ID & Open Muse AI" does both in one
//   tap, in order: copy the id first, then open muse.ai. One button
//   instead of two separate taps.
// - (Step 21, kill the copy/paste) muse.ai has no documented URL
//   parameter that prefills a chat message (checked 2026-11-01), so
//   a link alone cannot pre-type anything. The closest true version:
//   the primary button now copies the FULL pre-written approval
//   message (not just the id), then opens muse.ai — the user only
//   pastes and hits send, nothing is typed or copied by hand. If
//   clipboard access fails, the full message appears in a selectable
//   box on the page instead of failing silently. The existing 2s
//   poller still finishes the page itself once approved.
// - Every value that comes from a registry record or a request is HTML-
//   escaped before it reaches the page.
// - (Step 26) Remember me, opt-in only, on the authorize approval
//   page: a checkbox, checked only when remember=true arrived.
//   The copied message carries a Remember me line only then.
//   Step 26 is explicitly NOT a persistent session via Muse ID.
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
body{margin:0;padding:24px 16px;background:#8fd8b8;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;line-height:1.5}
main{max-width:560px;margin:0 auto;background:#f7f3ea;border:1px solid #d8d5cf;border-top:4px solid #7c5cf0;border-radius:12px;padding:28px 24px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
h1{font-size:22px;line-height:1.25;margin:0 0 16px}
p{margin:0 0 12px}
ul{margin:0 0 12px;padding-left:20px}
li{margin:2px 0}
label{font-weight:600}
textarea,input[type="text"]{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:8px;font:inherit;margin:6px 0 12px}
button{width:100%;padding:12px;border:0;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
#copy-id-open-btn{background:#7c5cf0;color:#fff;margin-bottom:8px}
#open-muse-btn{background:#22c55e;color:#fff;margin-bottom:8px}
#copy-btn{background:#2563eb;color:#fff;margin-top:8px}
#deny-form button{background:#fff;color:#dc2626;border:1px solid #dc2626}
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
  var currentId = "${escapeHtml(pendingId)}";
  var timer = setInterval(async function () {
    var res;
    try { res = await fetch("${basePath}/oauth/pending-status?pending_id=" + encodeURIComponent(currentId)); }
    catch { return; }
    var data = await res.json().catch(function () { return {}; });
    if (data.redirect_to) { clearInterval(timer); window.location = data.redirect_to; }
    else if (data.status === "awaiting") { return; }
    else if (data.status === "second_approval_required" && data.second_pending_id) {
      currentId = data.second_pending_id;
      statusEl.textContent = "First approval done — second approval needed. Ask your Muse to approve again (same way, new request).";
      var span = document.getElementById("pending-id");
      if (span) span.textContent = currentId;
      var fb = document.getElementById("approval-fallback");
      if (fb) fb.value = fb.value.replace("${escapeHtml(pendingId)}", currentId);
      return;
    }
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
// Step 17's standalone "Copy ID" was removed in step 19 as a duplicate
// of "Copy ID & Open Muse AI".
function musePopupHelper({ copyMessage, copyId }) {
  return `<details style="margin-bottom:12px"><summary style="cursor:pointer;font-weight:600">Having trouble? Read this first</summary><p>“Open Muse AI” opens Muse in your web browser, not the Muse app. Being logged into the phone app does not mean you are logged into the phone browser — if the popup looks logged out, sign in there in the browser, then paste the approval message.</p><p>If the page keeps waiting: make sure you hit send on the pasted message in Muse, then wait a few seconds — this page checks every 2 seconds. If the request expired (10 minutes), close this page and start a fresh sign-in.</p><p>No code, no SMS, no authenticator app is ever needed — your Muse approving is the whole sign-in.</p></details><p>Your Muse does not get a ping from this page. Tap the purple button — it copies your approval message and opens Muse. Paste it in, hit send, and this page will finish itself.</p>
<p>What happens next: your Muse approves, this page checks every 2 seconds, and it finishes itself within a few seconds of approval — you paste nothing back here. This request expires in 10 minutes, so approve soon or start a fresh sign-in.</p>
<button id="copy-id-open-btn" type="button">Approve with Muse AI</button>
<button id="open-muse-btn" type="button">Open Muse AI to approve</button>
<button id="copy-btn" type="button">Copy approval message</button>
<p id="copy-result"></p>
<textarea id="approval-fallback" readonly style="display:none">${escapeHtml(copyMessage)}</textarea>
<script>
document.getElementById("copy-id-open-btn").addEventListener("click", async function () {
  var msg = "${escapeHtml(copyMessage)}";
  var span = document.getElementById("pending-id");
  if (span && span.textContent !== "${escapeHtml(copyId)}") msg = msg.replace("${escapeHtml(copyId)}", span.textContent);
  var el = document.getElementById("copy-result");
  try { await navigator.clipboard.writeText(msg); el.textContent = "Approval message copied — opening Muse AI. Paste it in and hit send."; }
  catch { el.textContent = "Copy did not work in this browser — select and copy the message below, then paste it into Muse."; document.getElementById("approval-fallback").style.display = "block"; }
  window.open("https://muse.ai", "muse-approve", "width=480,height=720,noopener");
});
document.getElementById("open-muse-btn").addEventListener("click", function () {
  window.open("https://muse.ai", "muse-approve", "width=480,height=720,noopener");
});
document.getElementById("copy-btn").addEventListener("click", async function () {
  var msg = "${escapeHtml(copyMessage)}";
  var span = document.getElementById("pending-id");
  if (span && span.textContent !== "${escapeHtml(copyId)}") msg = msg.replace("${escapeHtml(copyId)}", span.textContent);
  var el = document.getElementById("copy-result");
  try { await navigator.clipboard.writeText(msg); el.textContent = "Copied — paste it into Muse in the popup."; }
  catch { el.textContent = "Copy did not work in this browser — select and copy the message below, then paste it into Muse."; document.getElementById("approval-fallback").style.display = "block"; }
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

// Step 26 Muse verification confirmation, shown BEFORE approval.
// Before login completes, the Muse must verify all of this info
// (site, scopes) back to the user, and the user must confirm it.
// Nothing completes without that confirmation.
function museVerificationConfirmation({ clientName, redirectHost, scopes }) {
  return `<section id="muse-verification-confirmation"><h2>Confirm before approval</h2><p>Before this login completes, your Muse must verify all of this information back to you, and you must confirm it:</p><ul><li>Site: ${escapeHtml(clientName)} (${escapeHtml(redirectHost)})</li><li>Access: ${scopes.map((s) => escapeHtml(s)).join(", ")}</li></ul><p>No login completes without that confirmation.</p></section>`;
}

// Authorize-flow approval page. Shown BEFORE any approval, so the user
// can see exactly what they are being asked to agree to.
// basePath is the provider's mount prefix ("" at root, "/login" on
// fedpromptly.com): every internal link/form on the page is prefixed
// with it, so the page works at either mount. Client redirect URIs
// are never touched — they are not provider URLs.
export function authorizeApprovalPage({ clientName, redirectHost, scopes, pendingId, basePath = "", remember = false }) {
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
<p><label><input id="remember-me" type="checkbox"${remember ? " checked" : ""}> Remember me</label></p>
${museVerificationConfirmation({ clientName, redirectHost, scopes })}
${musePopupHelper({ copyMessage: `Hi Muse, I'm signing in to FedPromptly with Sign in with Muse. Please approve my Muse sign-in. Pending request: ${pendingId}.${remember ? ' Remember me: yes, I opted in to Remember me.' : ''} After you approve, my login page finishes itself in a few seconds — it checks every 2 seconds, and I don't need to paste anything back. This request expires in 10 minutes, so please approve soon.`, copyId: pendingId })}
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
${musePopupHelper({ copyMessage: `Hi Muse, I'm signing in to FedPromptly from a device with Sign in with Muse. Please approve my Muse device sign-in. Device code: ${deviceCode}. After you approve, my device finishes signing in within a few seconds. This request expires in 30 minutes, so please approve soon.`, copyId: deviceCode })}
${deviceAutoFinish({ deviceCode, basePath })}
${denyForm({ idField: "device_code", idValue: deviceCode, basePath })}`,
  );
}

// Plain status page for a device request that is already decided.
export function deviceStatusPage(message) {
  return pageShell("Sign in with Muse", `<h1>Sign in with Muse</h1><p>${escapeHtml(message)}</p>`);
}
