// Fail-closed placeholder. The supplied attachment described, but did not include,
// the authoritative v0 worker source. Do not mistake this for an OAuth server.
export default {
  async fetch() {
    return new Response('MuseAI OAuth scaffold is not implemented', {
      status: 503,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
    });
  },
  async scheduled() {
    // Intentionally no token-version bump: routine cron-based global logout is unsafe.
  },
};
