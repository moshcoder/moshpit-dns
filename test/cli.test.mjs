import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildRecordsReport,
  buildResolutionReport,
  buildStatusReport,
  mapWithConcurrency,
  parseConcurrency,
  parseTimeout,
  parseTtl,
} from "../bin/moshpit-dns.mjs";
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

async function startRegistry(t, onRequest = () => {}) {
  const server = createServer((request, response) => {
    onRequest(request);
    response.setHeader("content-type", "application/json");
    if (request.url === "/api/moshpit/tlds") {
      response.end(JSON.stringify({ tlds: [{ tld: "Eggs" }, "agent"] }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=blue.eggs"
      || request.url === "/api/moshpit/resolve?name=blue.eggs&records=1") {
      response.end(JSON.stringify({
        name_registered: true,
        target: "203.0.113.9",
        ...(request.url.endsWith("records=1") ? {
          records: [
            { type: "MX", value: "mail.example.com", priority: 10, ttl: 300 },
            { type: "TXT", value: "v=spf1 -all", priority: null, ttl: 60 },
          ],
        } : {}),
      }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=dirty.eggs&records=1") {
      response.end(JSON.stringify({
        name_registered: true,
        target: null,
        records: [
          null,
          { type: "TXT" },
          { value: "missing type" },
          { type: "AAAA", value: "2001:db8::1" },
          {
            type: "mx",
            value: "mail.example.com",
            priority: { invalid: true },
            ttl: "not-a-number",
            extra: "not part of the record contract",
          },
        ],
      }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=free.eggs&records=1") {
      response.end(JSON.stringify({ name_registered: false, target: null, records: [] }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=deep.blue.eggs") {
      response.end(JSON.stringify({ name_registered: true, target: "203.0.113.10" }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=www.blue.eggs&records=1") {
      response.end(JSON.stringify({ name_registered: false, target: null, records: [] }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=*.blue.eggs&records=1") {
      response.end(JSON.stringify({
        name_registered: true,
        target: null,
        records: [
          { type: "AAAA", value: "2001:db8::10", priority: null, ttl: 300 },
          { type: "TXT", value: "wildcard", priority: null, ttl: 60 },
        ],
      }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=nobody.red.eggs"
      || request.url === "/api/moshpit/resolve?name=*.red.eggs") {
      response.end(JSON.stringify({ name_registered: false, target: null }));
      return;
    }
    if (request.url === "/api/moshpit/resolve?name=empty.eggs"
      || request.url === "/api/moshpit/resolve?name=empty.eggs&records=1") {
      response.end(JSON.stringify({ name_registered: true, target: null, records: [] }));
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
  const result = await run([
    "resolve",
    "--timeout",
    "1500",
    "blue.eggs",
    "--registry",
    registry,
    "--json",
  ]);

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

test("resolve reports multiple names in input order", async (t) => {
  let requests = 0;
  const registry = await startRegistry(t, (request) => {
    if (request.url.startsWith("/api/moshpit/resolve")) requests += 1;
  });
  const result = await run([
    "resolve",
    "--timeout",
    "1500",
    "blue.eggs",
    "--registry",
    registry,
    "localhost",
    "blue.eggs",
    "--json",
  ]);

  assert.equal(result.status, 1);
  assert.equal(requests, 1);
  assert.deepEqual(jsonOutput(result), [
    {
      registry,
      name: "blue.eggs",
      status: "live",
      address: "203.0.113.9",
      target: "203.0.113.9",
      registered: null,
      reason: "registry target",
    },
    {
      registry,
      name: "localhost",
      status: "not-a-name",
      address: null,
      target: null,
      registered: null,
      reason: "not a Moshpit name: one label and one ending",
    },
    {
      registry,
      name: "blue.eggs",
      status: "live",
      address: "203.0.113.9",
      target: "203.0.113.9",
      registered: null,
      reason: "registry target",
    },
  ]);

  const human = await run([
    "resolve",
    "blue.eggs",
    "localhost",
    "--registry",
    registry,
  ]);
  assert.equal(human.status, 1);
  assert.equal(human.stderr, "");
  assert.equal(
    human.stdout,
    "blue.eggs → 203.0.113.9\n"
      + "localhost → NXDOMAIN  [not a Moshpit name: one label and one ending]\n",
  );
});

test("resolve returns success when every batch entry resolves", async (t) => {
  const registry = await startRegistry(t);
  const result = await run([
    "resolve",
    "blue.eggs",
    "blue.eggs",
    "--registry",
    registry,
    "--json",
  ]);

  assert.equal(result.status, 0);
  const reports = jsonOutput(result);
  assert.equal(reports.length, 2);
  assert.deepEqual(reports[0], reports[1]);
});

test("resolve reuses lookups for repeated parked names", async (t) => {
  let requests = 0;
  const registry = await startRegistry(t, (request) => {
    if (request.url === "/api/moshpit/resolve?name=empty.eggs") requests += 1;
  });
  const result = await run([
    "resolve",
    "empty.eggs",
    "empty.eggs",
    "--registry",
    registry,
    "--json",
  ]);

  assert.equal(result.status, 0);
  assert.equal(requests, 1);
  const reports = jsonOutput(result);
  assert.equal(reports.length, 2);
  assert.equal(reports[0].status, "parked");
  assert.equal(reports[0].target, null);
  assert.equal(reports[0].registered, true);
  assert.equal(reports[0].reason, "claimed, not pointed at an IP");
  assert.deepEqual(reports[0], reports[1]);
});

test("batch mapping bounds concurrent work and preserves input order", async () => {
  let active = 0;
  let peak = 0;
  const values = [40, 5, 20, 1];
  const results = await mapWithConcurrency(values, 2, async (delay, index) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, delay));
    active -= 1;
    return `${index}:${delay}`;
  });

  assert.equal(peak, 2);
  assert.deepEqual(results, ["0:40", "1:5", "2:20", "3:1"]);
});

test("--concurrency accepts positive integers and rejects ambiguous values", async () => {
  assert.equal(parseConcurrency("1"), 1);
  assert.equal(parseConcurrency("8"), 8);
  assert.equal(parseConcurrency("9007199254740991"), Number.MAX_SAFE_INTEGER);

  for (const value of [undefined, "0", "-1", "1.5", "1e3", "9007199254740992", "nope"]) {
    assert.throws(() => parseConcurrency(value), /--concurrency must be a positive integer/);
    const args = value === undefined ? ["resolve", "blue.eggs", "--concurrency"]
      : ["resolve", "blue.eggs", "--concurrency", value];
    const result = await run(args);
    assert.equal(result.status, 1, String(value));
    assert.equal(result.stderr, "", String(value));
    assert.equal(result.stdout, "--concurrency must be a positive integer\n", String(value));
  }
});

test("records inspects and filters the registry record set", async (t) => {
  const registry = await startRegistry(t);
  const human = await run(["records", "blue.eggs", "mx", "--registry", registry]);
  assert.equal(human.status, 0);
  assert.equal(human.stderr, "");
  assert.equal(human.stdout, "MX 10 mail.example.com (TTL 300)\n");

  const allHuman = await run(["records", "blue.eggs", "--registry", registry]);
  assert.equal(allHuman.status, 0);
  assert.equal(allHuman.stderr, "");
  assert.equal(
    allHuman.stdout,
    "MX 10 mail.example.com (TTL 300)\nTXT v=spf1 -all (TTL 60)\n",
  );

  const result = await run(["records", "blue.eggs", "--registry", registry, "--json"]);
  assert.equal(result.status, 0);
  assert.deepEqual(jsonOutput(result), {
    registry,
    name: "blue.eggs",
    status: "live",
    exists: true,
    registered: true,
    type: null,
    count: 2,
    records: [
      { type: "MX", value: "mail.example.com", priority: 10, ttl: 300 },
      { type: "TXT", value: "v=spf1 -all", priority: null, ttl: 60 },
    ],
    error: null,
  });
});

test("records rejects unsupported types before contacting the registry", async (t) => {
  let requests = 0;
  const registry = await startRegistry(t, () => { requests += 1; });
  const result = await run(["records", "blue.eggs", "SRV", "--registry", registry, "--json"]);

  assert.equal(result.status, 1);
  assert.equal(requests, 0);
  assert.deepEqual(jsonOutput(result), {
    registry,
    name: "blue.eggs",
    status: null,
    exists: false,
    registered: null,
    type: "SRV",
    count: 0,
    records: [],
    error: "unsupported record type",
  });
});

test("records follows a third-level name to its wildcard", async (t) => {
  const asked = [];
  const registry = await startRegistry(t, (request) => {
    if (request.url.startsWith("/api/moshpit/resolve")) asked.push(request.url);
  });

  const human = await run(["records", "www.blue.eggs", "--registry", registry]);
  assert.equal(human.status, 0);
  assert.equal(human.stderr, "");
  assert.equal(human.stdout, "AAAA 2001:db8::10 (TTL 300)\nTXT wildcard (TTL 60)\n");
  assert.deepEqual(asked, [
    // The name as-is first, then the literal wildcard when that missed.
    "/api/moshpit/resolve?name=www.blue.eggs&records=1",
    "/api/moshpit/resolve?name=*.blue.eggs&records=1",
  ]);

  const wild = await run(["records", "*.blue.eggs", "--registry", registry, "--json"]);
  assert.equal(wild.status, 0);
  assert.equal(jsonOutput(wild).count, 2);
});

test("records accepts AAAA as a published type", async (t) => {
  const registry = await startRegistry(t);
  const result = await run(["records", "*.blue.eggs", "aaaa", "--registry", registry, "--json"]);

  assert.equal(result.status, 0);
  assert.deepEqual(jsonOutput(result).records, [
    { type: "AAAA", value: "2001:db8::10", priority: null, ttl: 300 },
  ]);
});

test("resolve accepts third-level names and reports a wildcard miss", async (t) => {
  const registry = await startRegistry(t);

  const deep = await run(["resolve", "deep.blue.eggs", "--registry", registry, "--json"]);
  assert.equal(deep.status, 0);
  assert.equal(jsonOutput(deep).status, "live");
  assert.equal(jsonOutput(deep).address, "203.0.113.10");

  const missing = await run(["resolve", "nobody.red.eggs", "--registry", registry, "--json"]);
  assert.equal(missing.status, 1);
  assert.equal(jsonOutput(missing).status, "nxdomain");
  assert.equal(jsonOutput(missing).reason,
    "no such name — the registry holds neither it nor a wildcard for it");
});

test("records reports an empty published set in human mode", async (t) => {
  const registry = await startRegistry(t);
  const all = await run(["records", "empty.eggs", "--registry", registry]);
  assert.equal(all.status, 0);
  assert.equal(all.stderr, "");
  assert.equal(all.stdout, "no records published for empty.eggs\n");

  const filtered = await run(["records", "empty.eggs", "TXT", "--registry", registry]);
  assert.equal(filtered.status, 0);
  assert.equal(filtered.stderr, "");
  assert.equal(filtered.stdout, "no TXT records published for empty.eggs\n");
});

test("records sanitizes malformed registry entries and normalizes record types", async (t) => {
  const registry = await startRegistry(t);
  const human = await run(["records", "dirty.eggs", "MX", "--registry", registry]);
  assert.equal(human.status, 0);
  assert.equal(human.stderr, "");
  assert.equal(human.stdout, "MX mail.example.com\n");

  const result = await run(["records", "dirty.eggs", "MX", "--registry", registry, "--json"]);

  assert.equal(result.status, 0);
  assert.deepEqual(jsonOutput(result), {
    registry,
    name: "dirty.eggs",
    status: "parked",
    exists: true,
    registered: true,
    type: "MX",
    count: 1,
    records: [{ type: "MX", value: "mail.example.com" }],
    error: null,
  });
});

test("records distinguishes an unregistered name from a parked name", async (t) => {
  const registry = await startRegistry(t);
  const human = await run(["records", "free.eggs", "--registry", registry]);
  assert.equal(human.status, 0);
  assert.equal(human.stderr, "");
  assert.equal(human.stdout, "free.eggs: name is not registered\n");

  const result = await run(["records", "free.eggs", "--registry", registry, "--json"]);
  assert.equal(result.status, 0);
  assert.equal(jsonOutput(result).exists, false);
  assert.equal(jsonOutput(result).registered, false);
});

test("records keeps missing and malformed names machine-readable", async () => {
  const missing = await run(["records", "--json"]);
  assert.equal(missing.status, 1);
  assert.deepEqual(jsonOutput(missing), {
    registry: DEFAULT_REGISTRY_BASE,
    name: null,
    status: null,
    exists: false,
    registered: null,
    type: null,
    count: 0,
    records: [],
    error: "missing name",
  });

  const malformed = await run(["records", "localhost", "--json"]);
  assert.equal(malformed.status, 1);
  assert.deepEqual(jsonOutput(malformed), {
    registry: DEFAULT_REGISTRY_BASE,
    name: "localhost",
    status: "not-a-name",
    exists: false,
    registered: null,
    type: null,
    count: 0,
    records: [],
    error: "invalid Moshpit name",
  });
});

test("buildRecordsReport keeps malformed records out of the JSON contract", () => {
  const report = buildRecordsReport("dirty.eggs", {
    status: "parked",
    registered: true,
    records: [
      null,
      { type: "TXT" },
      {
        type: "txt",
        value: "hello",
        priority: { invalid: true },
        ttl: "bad",
        extra: true,
      },
    ],
  });

  assert.equal(report.count, 1);
  assert.deepEqual(report.records, [{ type: "TXT", value: "hello" }]);
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

  const empty = await run(["resolve", "", "--json"]);
  assert.equal(empty.status, 1);
  assert.deepEqual(jsonOutput(empty), { name: null, error: "missing name" });
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

test("--ttl accepts the DNS wire range and rejects ambiguous values", async () => {
  assert.equal(parseTtl("0"), 0);
  assert.equal(parseTtl("30"), 30);
  assert.equal(parseTtl("4294967295"), 0xffffffff);

  for (const value of [undefined, "-1", "1.5", "1e3", "4294967296", "nope"]) {
    assert.throws(() => parseTtl(value), /--ttl must be an integer from 0 to 4294967295/);
    const args = value === undefined ? ["tlds", "--ttl"] : ["tlds", "--ttl", value];
    const result = await run(args);
    assert.equal(result.status, 1, String(value));
    assert.equal(result.stderr, "", String(value));
    assert.equal(result.stdout, "--ttl must be an integer from 0 to 4294967295\n", String(value));
  }
});

test("--timeout accepts safe positive milliseconds and rejects timer overflow", async () => {
  assert.equal(parseTimeout("1"), 1);
  assert.equal(parseTimeout("4000"), 4000);
  assert.equal(parseTimeout("2147483647"), 0x7fffffff);

  for (const value of [undefined, "0", "-1", "1.5", "1e3", "2147483648", "nope"]) {
    assert.throws(() => parseTimeout(value), /--timeout must be an integer from 1 to 2147483647/);
    const args = value === undefined ? ["tlds", "--timeout"] : ["tlds", "--timeout", value];
    const result = await run(args);
    assert.equal(result.status, 1, String(value));
    assert.equal(result.stderr, "", String(value));
    assert.equal(
      result.stdout,
      "--timeout must be an integer from 1 to 2147483647\n",
      String(value),
    );
  }
});

test("service install records the selected TTL", async () => {
  const result = await run(["service", "install", "--ttl", "86400", "--dry-run"]);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /"?--ttl"?\s+"?86400"?/);
});

test("service install records the selected registry timeout", async () => {
  const result = await run(["service", "--timeout", "1500", "install", "--dry-run"]);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.match(result.stdout, /"?--timeout"?\s+"?1500"?/);
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
