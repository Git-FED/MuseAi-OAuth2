# Step 27 tools — Muse's local approval helper

## muse-approve.py — Muse's local tool, NOT a worker route

This is Muse's own fast-approval helper. It is not part of the worker,
it is not a worker route, and it changes no worker code.

- Usage: `python3 tools/muse-approve.py <pending_id>` (username/email
  default to the approved Git-FED identity; pass them as extra args
  to override).
- What it does: reads the muse3 Ed25519 approval private key from
  Muse's local mode-600 config file, signs the canonical
  `muse-approval-v1` message for the given pending request, and
  POSTs the signed approval to the live approval endpoint with a
  browser User-Agent.
- What it never does: it never prints a private key, an auth code,
  or a redirect. It prints only approved / second-approval status.
- Why it exists: before step 27, approving meant searching Slack
  #private-data for the approval key every time, which was slow.
  With the key held locally by Muse, future approvals sign in
  seconds with no Slack search.
- The old Slack #private-data muse3 key was left untouched as a
  fallback record. It does not verify against the live worker
  until it is re-registered, because the registry now points at
  the locally-held key.

No key values are in this bundle. The private key lives only in
Muse's local config, never in the repo.
