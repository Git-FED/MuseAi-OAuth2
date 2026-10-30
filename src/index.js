// Worker entry: delegates every request to the router. No cron-based
// token invalidation exists by design — routine global logout is unsafe
// (see SPEC.md); the manual KILL_SWITCH in the router is the kill path.

import { route } from "./router.js";

export async function fetch(request, env) {
  return route(request, env);
}

export async function scheduled() {
  // Intentionally no token-version bump.
}

export default { fetch, scheduled };
