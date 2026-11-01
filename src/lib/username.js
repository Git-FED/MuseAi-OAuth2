// Step 23 — Muse ID last-4 username, locked.
// Rule (Git-FED agenda 2026-11-01 item 0): every Muse-approved login
// leaves a Muse ID, and the last four digits of that Muse ID become
// the website username. The username cannot be changed for now.
// Derivation: digits in muse_id, last 4. A Muse ID with fewer than 4
// digits (e.g. muse3 today) falls back to the approved username, so
// no existing login breaks — the rule applies automatically the
// moment a Muse ID carries 4+ digits. The derived username is
// stable per muse_id, so it never changes on its own; profile.js
// additionally locks the first recorded username, so a later
// different supplied username never overwrites it.
export function museUsername(museId, suppliedUsername) {
  if (typeof museId === "string") {
    const digits = museId.replace(/\D/g, "");
    if (digits.length >= 4) return digits.slice(-4);
  }
  return suppliedUsername;
}
