// NODE-TEST-ONLY shim for the `cloudflare:workers` module (step 9).
// Plain `node --test` cannot import the Workers runtime module, so
// tests/shim-hooks.mjs (via tests/register-shim.mjs, loaded with
// `node --import`) maps it here for tests. The deployed worker MUST NOT
// contain this file: wrangler resolves `cloudflare:workers` to the real
// runtime builtin, and the post-deploy bundle check greps for the marker
// NODE_TEST_SHIM_MARKER_9X7 to prove this shim was not inlined.
// If that marker ever appears in a served bundle, the deploy is broken
// and the DO classes will not receive RPC.
export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}
