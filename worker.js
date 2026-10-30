// Wrangler entry point. Delegates to src/index.js and re-exports the
// Durable Object class so the OAUTH_STORE binding resolves.
// Nothing here serves OAuth on its own; unconfigured routes fail closed
// through the router.

import index from "./src/index.js";

export { OAuthRecord } from "./src/store/oauth-record.js";

export default index;
