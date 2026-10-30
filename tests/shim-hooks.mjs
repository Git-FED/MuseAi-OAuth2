// Resolve hook for tests only: `cloudflare:workers` -> local shim.
// See tests/cloudflare-workers-shim.mjs for the marker check that proves
// this shim never reaches a deployed bundle.
export async function resolve(specifier, context, nextResolve) {
  if (specifier === "cloudflare:workers") {
    return {
      url: new URL("./cloudflare-workers-shim.mjs", import.meta.url).href,
      shortCircuit: true,
    };
  }
  return nextResolve(specifier, context);
}
