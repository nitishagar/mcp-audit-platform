#!/usr/bin/env node
/**
 * M-2 T2: capture the real MCP server's tools/list over stdio, plus the
 * plan's §9.5 behavioural oracle (read tools leave the sandbox unchanged;
 * annotated destructive tools really write; paths outside the allowed
 * directory are refused). Read-only for the HOST: everything happens inside
 * the sandbox passed via --sandbox, which MUST be under os.tmpdir().
 *
 * Usage:
 *   node scripts/mule-capture.mjs --prefix <npm-install-dir> \
 *        --package @modelcontextprotocol/server-filesystem \
 *        --sandbox <dir> --out capture.json [--behavior]
 *
 * Env given to the server is scrubbed to a minimal PATH (plan §9.5).
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const prefix = arg("prefix");
const pkgName = arg("package") ?? "@modelcontextprotocol/server-filesystem";
const sandbox = arg("sandbox") ? path.resolve(arg("sandbox")) : undefined;
const out = arg("out") ?? "capture.json";
const wantBehavior = process.argv.includes("--behavior");
const TIMEOUT_MS = 15_000;

// §9.5 guard: the sandbox must be a throw-away temp dir. Refuse anything else.
function assertSandboxSafe(dir) {
  if (!dir) throw new Error("--sandbox is required");
  const tmp = path.resolve(os.tmpdir());
  if (!(dir === tmp || dir.startsWith(tmp + path.sep))) {
    throw new Error(`refusing: sandbox "${dir}" is not under ${tmp} (plan §9.5)`);
  }
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    throw new Error(`sandbox "${dir}" does not exist or is not a directory`);
  }
}
assertSandboxSafe(sandbox);

// Resolve the installed package's server entry from its own manifest.
const pkgJsonPath = path.join(prefix, "node_modules", ...pkgName.split("/"), "package.json");
const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
const binVal =
  typeof pkgJson.bin === "string" ? pkgJson.bin : pkgJson.bin?.[pkgName.split("/").pop()];
const serverEntry = path.join(path.dirname(pkgJsonPath), binVal ?? pkgJson.main ?? "dist/index.js");
if (!existsSync(serverEntry)) throw new Error(`server entry not found: ${serverEntry}`);

// Seed files for the behavioural oracle.
const seedFile = path.join(sandbox, "seed.txt");
const seedText = `mule-seed-${Date.now()}`;
writeFileSync(seedFile, seedText);

const child = spawn(process.execPath, [serverEntry, sandbox], {
  cwd: sandbox,
  env: { PATH: process.env.PATH ?? "/usr/bin:/bin" }, // §9.5: scrubbed env
  stdio: ["pipe", "pipe", "pipe"],
});

let buf = "";
const pending = new Map();
const notifications = [];
child.stdout.on("data", (chunk) => {
  buf += String(chunk);
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue; // non-JSON stdout noise is ignored, never parsed as a verdict
    }
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    } else {
      notifications.push(msg);
    }
  }
});
const stderrChunks = [];
child.stderr.on("data", (c) => stderrChunks.push(String(c)));

let nextId = 1;
function rpc(method, params) {
  const id = nextId++;
  const line = `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`;
  return new Promise((resolveMsg, rejectMsg) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      rejectMsg(new Error(`timeout waiting for ${method}`));
    }, TIMEOUT_MS);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      resolveMsg(msg);
    });
    child.stdin.write(line);
    void params;
  });
}

function treeSnapshot(dir) {
  const out = {};
  const walk = (d, base) => {
    for (const e of readdirSync(d)) {
      const p = path.join(d, e);
      const st = statSync(p);
      if (st.isDirectory()) walk(p, base);
      else out[path.relative(base, p)] = readFileSync(p, "utf8");
    }
  };
  walk(dir, dir);
  return out;
}

const killed = setTimeout(() => {
  child.kill("SIGKILL");
}, TIMEOUT_MS);

const init = await rpc("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "mule-capture", version: "0.0.0" },
});
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

const list = await rpc("tools/list", {});
const tools = list.result?.tools ?? [];
const capture = {
  capturedAt: new Date().toISOString().slice(0, 10),
  serverInfo: init.result?.serverInfo ?? null,
  protocolVersion: init.result?.protocolVersion ?? null,
  tools,
};

let behavior = null;
if (wantBehavior) {
  const call = async (name, args) => {
    const res = await rpc("tools/call", { name, arguments: args });
    return res.result ?? res;
  };
  const before = treeSnapshot(sandbox);
  const readRes = await call("read_text_file", { path: seedFile });
  const afterRead = treeSnapshot(sandbox);
  const readUnchanged = JSON.stringify(before) === JSON.stringify(afterRead);
  const readOk = JSON.stringify(readRes).includes(seedText);

  const writePath = path.join(sandbox, "written.txt");
  await call("write_file", { path: writePath, content: "written-by-mule" });
  const writtenOk = existsSync(writePath) && readFileSync(writePath, "utf8") === "written-by-mule";

  const outside = path.join(path.dirname(sandbox), "outside-refusal.txt");
  let outsideRefused = false;
  try {
    const res = await call("write_file", { path: outside, content: "nope" });
    outsideRefused = res.isError === true || JSON.stringify(res).includes("must resolve inside");
  } catch {
    outsideRefused = true;
  }
  behavior = { readUnchanged, readOk, writeActs: writtenOk, outsideRefused };
}

child.kill("SIGKILL");
clearTimeout(killed);

writeFileSync(out, `${JSON.stringify({ ...capture, behavior }, null, 2)}\n`);
console.log(
  `captured ${tools.length} tools from ${capture.serverInfo?.name ?? "?"} -> ${out}` +
    (behavior ? ` | behaviour: ${JSON.stringify(behavior)}` : ""),
);
if (behavior) {
  const b = capture.behavior ?? behavior;
  if (!b.readUnchanged || !b.readOk || !b.writeActs || !b.outsideRefused) {
    console.error("behavioural oracle FAILED:", b);
    process.exit(1);
  }
}
