import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildResolutionReport, buildStatusReport } from "../bin/moshpit-dns.mjs";
import { DEFAULT_REGISTRY_BASE } from "../lib/dns.mjs";

const BIN = fileURLToPath(new URL("../bin/cli.mjs", import.meta.url));

function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function startRegistry(t) {
  const server = createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    if (request.url === "/api/moshpit/tlds") {
      response.end(JSON.stringify({ tlds: [{ tld: "Eggs" }, "agent"] }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=blue.eggs") {
      response.end(JSON.stringify({ name_registered: true, target: "203.0.113.9" }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

function jsonOutput(result) {
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

test("tlds stays human-readable by default and supports structured JSON", async (t) => {
  const registry = await startRegistry(t);
  const human = await run(["tlds", "--registry", registry]);
  assert.equal(human.status, 0);
  assert.equal(human.stderr, "");
  assert.equal(human.stdout, ".agent\n.eggs\n");

  const result = await run(["tlds", "--registry", registry, "--json"]);
  assert.equal(result.status, 0);
  assert.deepEqual(jsonOutput(result), {
    registry,
    reachable: true,
    count: 2,
    tlds: ["agent", "eggs"],
    error: null,
  });
});

test("resolve --json reports the address and decision reason", async (t) => {
  const registry = await startRegistry(t);
  const result = await run(["resolve", "blue.eggs", "--registry", registry, "--json"]);

  assert.equal(result.status, 0);
  assert.deepEqual(jsonOutput(result), {
    registry,
    name: "blue.eggs",
    status: "live",
    address: "203.0.113.9",
    target: "203.0.113.9",
    registered: null,
    reason: "registry target",
  });
});

test("resolve --json keeps malformed and missing names machine-readable", async () => {
  const malformed = await run(["resolve", "localhost", "--json"]);
  assert.equal(malformed.status, 1);
  assert.deepEqual(jsonOutput(malformed), {
    registry: DEFAULT_REGISTRY_BASE,
    name: "localhost",
    status: "not-a-name",
    address: null,
    target: null,
    registered: null,
    reason: "not a Moshpit name: one label and one ending",
  });

  const missing = await run(["resolve", "--json"]);
  assert.equal(missing.status, 1);
  assert.deepEqual(jsonOutput(missing), { name: null, error: "missing name" });
});

test("tlds --json returns valid JSON when the registry is unreachable", async () => {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const registry = `http://127.0.0.1:${server.address().port}`;
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });

  const result = await run(["tlds", "--registry", registry, "--json"]);
  assert.equal(result.status, 1);
  assert.deepEqual(jsonOutput(result), {
    registry,
    reachable: false,
    count: null,
    tlds: [],
    error: "registry unreachable",
  });
});

test("status --json emits one parseable diagnostic document", async (t) => {
  const registry = await startRegistry(t);
  const result = await run(["status", "--registry", registry, "--json"]);

  assert.equal(result.status, 0);
  const report = jsonOutput(result);
  assert.equal(typeof report.platform, "string");
  assert.deepEqual(Object.keys(report.bridge).sort(), ["pid", "running", "stale"]);
  assert.ok([true, false, null].includes(report.routing.configured));
  assert.deepEqual(report.registry, { url: registry, reachable: true, count: 2 });
  assert.equal(typeof report.needsRefresh, "boolean");
  assert.ok(Array.isArray(report.warnings));
});

test("buildResolutionReport describes a parked DNS answer", () => {
  assert.deepEqual(
    buildResolutionReport(
      "california.oranges",
      { status: "parked", target: null, registered: true },
      "198.51.100.9",
      "https://pit.example",
    ),
    {
      registry: "https://pit.example",
      name: "california.oranges",
      status: "parked",
      address: "198.51.100.9",
      target: null,
      registered: true,
      reason: "claimed, not pointed at an IP",
    },
  );
});

test("buildStatusReport exposes actionable bridge and routing drift warnings", () => {
  const report = buildStatusReport({
    platform: "linux",
    daemon: { running: false, pid: null, stale: false },
    routed: true,
    marker: "/etc/systemd/resolved.conf.d/moshpit.conf",
    known: ["agent", "eggs", "moshpit"],
    routedCount: 2,
    registry: "https://pit.example",
  });

  assert.equal(report.needsRefresh, true);
  assert.deepEqual(report.warnings, [
    {
      code: "bridge-not-running",
      message: "routing is in place but the bridge is not running",
      fix: "sudo moshpit-dns enable",
      undo: "sudo moshpit-dns disable",
    },
    {
      code: "routing-out-of-date",
      message: "routing covers 2 endings but 3 are claimed",
      fix: "sudo moshpit-dns refresh",
    },
  ]);
});
