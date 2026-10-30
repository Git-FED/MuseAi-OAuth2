// Test-only loader hook (step 9): plain Node cannot import the
// `cloudflare:workers` module (ERR_UNSUPPORTED_ESM_URL_SCHEME), so this
// file registers a resolve hook that maps it to the local dummy class.
// Loaded via `node --import` (see package.json test script). Never
// imported by worker.js, so it never reaches the deployed bundle.
import { register } from "node:module";

register("./shim-hooks.mjs", import.meta.url);
