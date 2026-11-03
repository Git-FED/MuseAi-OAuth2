#!/usr/bin/env python3
"""Fast Login with Muse approval — no Slack search needed.

Reads the muse3 Ed25519 private key from ~/.config/connections/muse-approval.json
(mode 600, set up 2026-11-02), signs the canonical muse-approval-v1 message for a
given pending_id, and POSTs it to the live approval endpoint with a browser
User-Agent (plain Python urllib UA gets a Cloudflare 1010 block on this worker).

Usage: python3 muse-approve.py <pending_id> [username] [email]
Defaults: username Git-FED, email museai@fedpromptly.com, muse_id muse3.
Prints only approved / second-approval status — never the private key, never
the auth code or redirect.
"""
import sys, json, os, base64, urllib.request, urllib.error

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def main():
    if len(sys.argv) < 2:
        print("usage: muse-approve.py <pending_id> [username] [email]")
        return 2
    pending_id = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "Git-FED"
    email = sys.argv[3] if len(sys.argv) > 3 else "museai@fedpromptly.com"
    cfg_path = os.path.expanduser("~/.config/connections/muse-approval.json")
    with open(cfg_path) as f:
        cfg = json.load(f)
    muse_id = cfg.get("muse_id", "muse3")
    jwk = cfg["private_key_jwk"]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(b64d(jwk["d"]))
    msg = f"muse-approval-v1\npending:{pending_id}\n{muse_id}\n{username}\n{email}".encode()
    sig = base64.urlsafe_b64encode(priv.sign(msg)).rstrip(b"=").decode()
    payload = {"pending_id": pending_id, "muse_id": muse_id, "username": username, "email": email, "signature": sig}
    req = urllib.request.Request(
        "https://museai-oauth2.fedos.workers.dev/login/oauth/approval",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read().decode())
            print("approved:", resp.get("approved"), "second_approval_required:", resp.get("second_approval_required"))
            return 0 if resp.get("approved") or resp.get("second_approval_required") else 1
    except urllib.error.HTTPError as e:
        try:
            resp = json.loads(e.read().decode())
            print("approval failed: HTTP", e.code, "error:", resp.get("error"))
        except Exception:
            print("approval failed: HTTP", e.code)
        return 1

if __name__ == "__main__":
    sys.exit(main())
