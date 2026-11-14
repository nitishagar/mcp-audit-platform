#!/usr/bin/env node
// A5: warn (never fail) when the bundled advisory snapshot is older than 30 days.
import { readFileSync } from "node:fs";
const snap = JSON.parse(
  readFileSync(new URL("../packages/scanner/src/data/advisories.json", import.meta.url), "utf8"),
);
const ageDays = Math.floor((Date.now() - new Date(snap.fetched).getTime()) / 86_400_000);
if (ageDays > 30) {
  console.warn(
    `WARNING: advisory snapshot is ${ageDays} days old — run scripts/build-advisories.mjs to refresh`,
  );
} else {
  console.log(`advisory snapshot: ${ageDays} day(s) old`);
}
