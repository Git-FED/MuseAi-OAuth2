// Mount-prefix support (build step 5): the provider can live at a path
// prefix of a larger site — e.g. https://fedpromptly.com/login — instead
// of at a domain root. BASE_PATH is an env variable, default empty
// (root-mounted, the behavior of steps 1–4, unchanged).
//
// Rules, all fail-closed:
// - BASE_PATH is normalized once: leading slash enforced, trailing
//   slashes stripped, "/" or empty means no prefix.
// - Stripping matches exactly one leading segment: "/login" matches
//   "/login" and "/login/<anything>", and NOTHING else. "/loginevil"
//   and "/loginfoo" do not match "/login" — a prefix is a segment
//   boundary, not a string prefix.
// - A request that does not start with the configured prefix is not a
//   provider request at all: the router answers 404, never falling
//   through to a provider route at the wrong mount.
// - "/login/" (prefix + trailing slash) strips to "/" — the mount
//   root, which is not a route, so it 404s like any unknown path.
// - Rate-limit buckets and audit route values use the STRIPPED path,
//   so behavior is identical under either mount.

export function normalizeBasePath(raw) {
  if (!raw || typeof raw !== "string") return "";
  let p = raw.trim();
  if (!p || p === "/") return "";
  if (!p.startsWith("/")) p = `/${p}`;
  p = p.replace(/\/+$/, "");
  return p || "";
}

// Returns { matched: true, stripped } or { matched: false, stripped: null }.
export function stripBasePath(pathname, basePath) {
  if (!basePath) return { matched: true, stripped: pathname };
  if (pathname === basePath) return { matched: true, stripped: "/" };
  if (pathname.startsWith(`${basePath}/`)) {
    return { matched: true, stripped: pathname.slice(basePath.length) };
  }
  return { matched: false, stripped: null };
}
