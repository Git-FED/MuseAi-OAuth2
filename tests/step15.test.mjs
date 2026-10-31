// Step 15 — post-login destination is /social, not /login.
// The OAuth redirect_uri stays the login page itself (it exchanges
// the code); /social is a plain navigation after sign-in completes.
import test from "node:test";
import assert from "node:assert/strict";
import { loginPageHandler } from "../src/oauth/login-page.js";

test("login page: after sign-in it navigates to fedpromptly.com/social", async () => {
  const res = await loginPageHandler();
  const html = await res.text();
  // Signed-in confirmation still shown first.
  assert.match(html, /Signed in as /);
  // Then a timed navigation to /social, not to the login page itself.
  assert.ok(html.includes('location.href = "https://www.fedpromptly.com/social"'));
  assert.match(html, /setTimeout\(function \(\) \{ location\.href = "https:\/\/www\.fedpromptly\.com\/social"; \}, 1500\)/);
});

test("login page: OAuth redirect_uri is still the page itself", async () => {
  const res = await loginPageHandler();
  const html = await res.text();
  // Code exchange still happens on this page; /social is not a
  // redirect_uri, so it must not appear as REDIRECT_URI.
  assert.match(html, /var REDIRECT_URI = BASE;/);
  assert.ok(!html.includes('REDIRECT_URI = "https://www.fedpromptly.com/social"'));
  assert.match(html, /Sign in with Muse/);
});
