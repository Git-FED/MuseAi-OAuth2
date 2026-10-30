// Step 10 — worker-hosted Sign in with Muse page.
//
// The mount root (GET / after BASE_PATH stripping, i.e. /login on www)
// serves this page. It is the embeddable login surface: a site that
// cannot run the button script itself (e.g. Google Sites) embeds this
// page by URL or iframe, and the whole flow — button, approval,
// callback, email display — happens on this page, same origin throughout.
//
// No framing-blocking headers are set anywhere in this worker (see
// lib/http.js: only no-store + nosniff), so the page loads inside an
// iframe. The page never navigates the top frame and never busts out:
// location.href inside an iframe navigates the iframe only, and the
// PKCE verifier lives in that iframe's own sessionStorage, which is
// consistent across the authorize round-trip.
//
// Redirect: the page always uses its own normalized URL (origin +
// path, no trailing slash) as redirect_uri, so the page works on any
// host it is served from — but that exact URL must be a registered
// redirect_uri for client fedpromptly, or authorize answers 400.

import { html } from "../lib/http.js";

export const LOGIN_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in with Muse</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2em auto; max-width: 34em; padding: 0 1em; }
button { font-size: 1.1em; padding: 0.6em 1.2em; cursor: pointer; }
#muse-login-status { margin-top: 1em; }
</style>
</head>
<body>
<div id="muse-login">
  <h1>Sign in with Muse</h1>
  <button id="muse-login-btn" type="button">Sign in with Muse</button>
  <p id="muse-login-status"></p>
</div>
<script>
(function () {
  // API base + redirect are this page's own URL, trailing slash stripped,
  // so the same page works on www and on workers.dev.
  var BASE = location.origin + location.pathname.replace(/\/$/, "");
  var CLIENT_ID = "fedpromptly";
  var REDIRECT_URI = BASE;
  var btn = document.getElementById("muse-login-btn");
  var status = document.getElementById("muse-login-status");

  function b64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function randomString(n) {
    var b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b64url(b);
  }
  async function challengeFor(verifier) {
    var d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return b64url(new Uint8Array(d));
  }

  btn.addEventListener("click", async function () {
    var verifier = randomString(48);
    var state = randomString(24);
    sessionStorage.setItem("muse_verifier", verifier);
    sessionStorage.setItem("muse_state", state);
    var q = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      code_challenge: await challengeFor(verifier),
      code_challenge_method: "S256",
      scope: "openid",
      state: state,
    });
    location.href = BASE + "/oauth/authorize?" + q.toString();
  });

  // Callback: we landed back with ?code=...&state=...
  var params = new URLSearchParams(location.search);
  var code = params.get("code");
  var state = params.get("state");
  var err = params.get("error");
  if (err) {
    status.textContent = "Sign-in was not completed: " + err;
  } else if (code) {
    (async function () {
      try {
        if (state !== sessionStorage.getItem("muse_state")) throw new Error("state mismatch");
        var verifier = sessionStorage.getItem("muse_verifier");
        if (!verifier) throw new Error("missing verifier");
        var tokRes = await fetch(BASE + "/oauth/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code: code,
            redirect_uri: REDIRECT_URI,
            client_id: CLIENT_ID,
            code_verifier: verifier,
          }),
        });
        var tok = await tokRes.json();
        if (!tok.access_token) throw new Error(tok.error || "token exchange failed");
        var uiRes = await fetch(BASE + "/oauth/userinfo", {
          headers: { Authorization: "Bearer " + tok.access_token },
        });
        var ui = await uiRes.json();
        history.replaceState({}, "", REDIRECT_URI);
        status.textContent = "Signed in as " + (ui.email || ui.sub || "unknown");
        btn.style.display = "none";
      } catch (e) {
        status.textContent = "Sign-in failed: " + e.message;
      }
    })();
  }
})();
</script>
</body>
</html>
`;

export async function loginPageHandler() {
  return html(LOGIN_PAGE_HTML);
}
