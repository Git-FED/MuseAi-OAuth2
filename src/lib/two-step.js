// Step 24 — toggleable Muse two-step authentication.
// Default OFF, never forced: the user turns it on for their own sub,
// and only then does a sign-in require a second Muse signature.
// No codes, SMS, or authenticator app — the Muse signature IS the
// second factor, signed a second time on a second pending request.
// Flag lives in OAUTH_KV next to profiles: two_step:<sub> -> "1"/"0".
export function twoStepKey(sub) {
  return `two_step:${sub}`;
}
export async function getTwoStep(env, sub) {
  if (!env.OAUTH_KV || typeof sub !== "string") return false;
  try {
    return (await env.OAUTH_KV.get(twoStepKey(sub))) === "1";
  } catch {
    return false;
  }
}
export async function setTwoStep(env, sub, enabled) {
  if (!env.OAUTH_KV || typeof sub !== "string") return false;
  try {
    await env.OAUTH_KV.put(twoStepKey(sub), enabled ? "1" : "0");
    return true;
  } catch {
    return false;
  }
}
