// Step 16 — profiles. A profile is the user home a sign-in was missing:
// a KV record keyed by the stable sign-in id (userinfo `sub`), holding
// the latest approved username/email plus first/last sign-in and a
// sign-in count. No password, no Supabase, no new store: profiles live
// in OAUTH_KV next to the registries (non-atomic data, same as the
// client/Muse-key records), and are written only on a fresh sign-in
// (authorization_code or device_code redemption in token.js), never on
// refresh rotation — a refresh is a session continuation, not a sign-in.
//
// Key shape:
//   profile:<sub>  -> { sub, preferred_username, email, email_verified,
//                      first_sign_in, last_sign_in, sign_in_count }
//
// Read-time validation mirrors registry.js: a malformed record reads
// as "no profile" (404 from the endpoint), never as a half-trustworthy
// profile, and a fresh sign-in overwrites it with a valid record.
// Write failures are swallowed on purpose, like audit failures: a down
// KV must not take a login down with it. The trade-off is stated in
// BUILD-LOG.md — a login whose profile write failed simply has no
// profile until its next sign-in.

export function profileKey(sub) {
  return `profile:${sub}`;
}

function isIsoString(v) {
  return typeof v === "string" && !Number.isNaN(Date.parse(v));
}

export function isValidProfile(sub, rec) {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return false;
  if (rec.sub !== sub) return false;
  if (typeof rec.preferred_username !== "string" || !rec.preferred_username.trim() || rec.preferred_username.length > 200) return false;
  if (typeof rec.email !== "string" || !rec.email.includes("@") || rec.email.length > 320) return false;
  if (rec.email_verified !== false) return false;
  if (!isIsoString(rec.first_sign_in) || !isIsoString(rec.last_sign_in)) return false;
  if (!Number.isInteger(rec.sign_in_count) || rec.sign_in_count < 1) return false;
  if (Date.parse(rec.last_sign_in) < Date.parse(rec.first_sign_in)) return false;
  return true;
}

// Returns the validated profile record, or null when none exists or
// the stored record is malformed.
export async function getProfile(env, sub) {
  if (typeof sub !== "string" || !sub.startsWith("muse:") || !env.OAUTH_KV) return null;
  let raw;
  try {
    raw = await env.OAUTH_KV.get(profileKey(sub));
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw);
    return isValidProfile(sub, rec) ? rec : null;
  } catch {
    return null;
  }
}

// Record one fresh sign-in. Keeps first_sign_in and increments the
// count on a repeat sign-in; always updates username/email to the
// latest approved identity (approval is the source of truth). Returns
// true when the record was written, false otherwise (never throws).
export async function recordSignIn(env, { sub, username, email, now = new Date() } = {}) {
  if (typeof sub !== "string" || !sub.startsWith("muse:") || !env.OAUTH_KV) return false;
  if (typeof username !== "string" || !username.trim() || typeof email !== "string" || !email.includes("@")) return false;
  const at = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  try {
    const existing = await getProfile(env, sub);
    const rec = {
      sub,
      preferred_username: username,
      email,
      email_verified: false,
      first_sign_in: existing ? existing.first_sign_in : at,
      last_sign_in: at,
      sign_in_count: existing ? existing.sign_in_count + 1 : 1,
    };
    await env.OAUTH_KV.put(profileKey(sub), JSON.stringify(rec));
    return true;
  } catch {
    return false;
  }
}
