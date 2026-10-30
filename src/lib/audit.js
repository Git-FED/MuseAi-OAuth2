// Append-only audit log in KV. Audit entries are operational evidence,
// never a second copy of secrets: the entry shape is fixed to five fields
// plus one short free-text detail, and anything else a caller passes is
// dropped. Tokens, authorization codes, signatures, secrets, keys, and
// request bodies can never reach an audit entry through this function,
// because there is no field for them.
//
// Key pattern: audit:<epoch-ms>:<random-id> — unique per entry, roughly
// time-ordered, and never overwritten (random suffix, no read-modify-write).
//
// Audit failures are swallowed on purpose: a down audit store must not take
// logins down with it. The trade-off is documented in BUILD-LOG.md.

import { randomString } from "./crypto.js";

const MAX_DETAIL = 200;

export async function audit(env, event, { actor = null, clientId = null, route = null, outcome = null, detail = null } = {}) {
  if (!env.OAUTH_KV) return false;
  const entry = {
    ts: new Date().toISOString(),
    event: String(event),
    actor: typeof actor === "string" ? actor : null,
    client_id: typeof clientId === "string" ? clientId : null,
    route: typeof route === "string" ? route : null,
    outcome: typeof outcome === "string" ? outcome : null,
    detail: typeof detail === "string" ? detail.slice(0, MAX_DETAIL) : null,
  };
  try {
    await env.OAUTH_KV.put(`audit:${Date.now()}:${randomString(12)}`, JSON.stringify(entry));
    return true;
  } catch {
    return false;
  }
}
