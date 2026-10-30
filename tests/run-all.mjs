import { spawnSync } from "node:child_process";
const r = spawnSync(process.execPath, ["--test"], { stdio: "inherit" });
if (r.status !== 0) process.exit(r.status ?? 1);
console.log("ALL TESTS PASSED");
