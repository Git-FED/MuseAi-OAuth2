// Web Crypto helpers. No Node-only or Cloudflare-only APIs: everything
// here runs under plain node and in the Workers runtime.

const subtle = globalThis.crypto.subtle;

export function bytesToBase64Url(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function randomString(bytes = 32) {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return bytesToBase64Url(buf);
}

// Human-readable device user code, unambiguous characters only.
export function randomUserCode() {
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const buf = new Uint8Array(8);
  globalThis.crypto.getRandomValues(buf);
  const chars = [...buf].map((b) => alphabet[b % alphabet.length]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

export async function sha256Base64Url(text) {
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(text));
  return bytesToBase64Url(new Uint8Array(digest));
}

// PKCE S256 only. Plain (S256-less) challenges are never accepted.
export async function pkceChallenge(verifier) {
  return sha256Base64Url(verifier);
}

export async function verifyPkce(verifier, challenge) {
  if (typeof verifier !== "string" || typeof challenge !== "string") return false;
  return (await sha256Base64Url(verifier)) === challenge;
}

export async function importEs256Private(jwk) {
  return subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

export async function importEs256Public(jwk) {
  return subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

export async function importEd25519Public(jwk) {
  return subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
}

// ES256 JWT: signature is the raw R||S output Web Crypto produces.
export async function signJwt(claims, privateJwk) {
  const header = { alg: "ES256", typ: "JWT", kid: "v1" };
  const encoded =
    bytesToBase64Url(new TextEncoder().encode(JSON.stringify(header))) +
    "." +
    bytesToBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const key = await importEs256Private(privateJwk);
  const sig = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(encoded),
  );
  return `${encoded}.${bytesToBase64Url(new Uint8Array(sig))}`;
}

// Returns the payload when signature + expiry check out, else null.
export async function verifyJwt(token, publicJwk) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, payloadPart, signature] = parts;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadPart)));
    const key = await importEs256Public(publicJwk);
    const ok = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      base64UrlToBytes(signature),
      new TextEncoder().encode(`${header}.${payloadPart}`),
    );
    if (!ok) return null;
    if (payload.exp && payload.exp * 1000 <= Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// Unverified decode, for revocation only (extracting a jti to deny).
export function decodeJwtPayload(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[1])));
  } catch {
    return null;
  }
}

export async function verifyEd25519(publicJwk, message, signatureBase64Url) {
  try {
    const key = await importEd25519Public(publicJwk);
    return await subtle.verify(
      "Ed25519",
      key,
      base64UrlToBytes(signatureBase64Url),
      new TextEncoder().encode(message),
    );
  } catch {
    return false;
  }
}
