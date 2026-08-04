/**
 * The address a Moshpit name actually has.
 *
 * Two gaps made most of the registry unresolvable, and both failed in the same
 * invisible shape — an authoritative NOERROR with no answers, which a client is
 * entitled to treat as final:
 *
 *   - a published A/AAAA record was never consulted for an address question,
 *     because addresses came only from `target`
 *   - a `target` naming a host rather than an address produced nothing at all,
 *     and most of the registry points at a host
 *
 * `dig` reported the name as existing, nothing could reach it, and no log
 * anywhere showed an error. In practice it surfaced as
 * `curl: (6) Could not resolve host`.
 *
 * Answers are read back off the wire here. A reply of the right shape with the
 * wrong bytes in it is exactly the failure being fixed.
 */
import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";

import {
  addressAnswer, buildChainResponse, createServer, encodeName, parseQuery,
  targetHostname, TYPE_A, TYPE_AAAA, TYPE_CNAME,
} from "../lib/dns.mjs";

const RCODE_OK = 0;
const RCODE_NXDOMAIN = 3;

function query(name, { id = 0x1234, type = TYPE_A, cls = 1, rd = true } = {}) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(rd ? 0x0100 : 0, 2);
  head.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(cls, 2);
  return Buffer.concat([head, encodeName(name), tail]);
}

const rcode = (reply) => reply.readUInt16BE(2) & 0x0f;
const answers = (reply) => reply.readUInt16BE(6);

/** A name written out in full — the chain builder never emits a pointer for one. */
function readName(buf, offset) {
  const labels = [];
  let i = offset;
  for (;;) {
    const len = buf[i];
    if (len === undefined) throw new Error("truncated name");
    if (len === 0) return { name: labels.join("."), offset: i + 1 };
    labels.push(buf.toString("ascii", i + 1, i + 1 + len));
    i += len + 1;
  }
}

/** Every answer, with its owner — a chain carries two different ones. */
function readAnswers(reply, name) {
  const found = [];
  let i = 12 + encodeName(name).length + 4;
  for (let n = 0; n < answers(reply); n++) {
    let owner;
    if (reply.readUInt16BE(i) === 0xc00c) {
      owner = name;
      i += 2;
    } else {
      ({ name: owner, offset: i } = readName(reply, i));
    }
    const type = reply.readUInt16BE(i);
    const ttl = reply.readUInt32BE(i + 4);
    const length = reply.readUInt16BE(i + 8);
    const rdata = reply.subarray(i + 10, i + 10 + length);
    i += 10 + length;
    found.push({ owner, type, ttl, rdata });
  }
  return found;
}

/**
 * A registry that answers the record set only when it was asked for.
 *
 * The `&records=1` split is load-bearing: the address path skips that round
 * trip whenever `target` already holds an address, and a fake ignoring the flag
 * would hide a regression in exactly that.
 */
function registry({ target = null, records = [], registered = true } = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const wants = url.includes("records=1");
    return {
      ok: true,
      json: async () => ({ name_registered: registered, target, ...(wants ? { records } : {}) }),
    };
  };
  return { fetchImpl, calls };
}

const missing = () => ({ fetchImpl: async () => ({ ok: false, json: async () => ({}) }), calls: [] });

async function ask(server, buf) {
  const client = dgram.createSocket("udp4");
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no reply")), 5000);
      client.once("message", (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      client.send(buf, server.port, "127.0.0.1");
    });
  } finally {
    client.close();
  }
}

async function serve(t, { fetchImpl }, extra = {}) {
  const server = await createServer({ port: 0, parkingAddress: "198.51.100.9", fetchImpl, ...extra });
  t.after(() => server.close());
  return server;
}

/* ----------------------------------------------------------- what a target holds */

test("targetHostname reads the host out of a target that is not an address", () => {
  assert.equal(targetHostname("dev.profullstack.com"), "dev.profullstack.com");
  assert.equal(targetHostname("https://dev.profullstack.com/"), "dev.profullstack.com");
  assert.equal(targetHostname("DEV.Profullstack.COM"), "dev.profullstack.com", "case is not identity");
  assert.equal(targetHostname("dev.profullstack.com."), "dev.profullstack.com", "a root dot is not a label");
});

test("targetHostname refuses what no CNAME could carry", () => {
  // Dropping a port quietly would send the client to port 80 of the right
  // host — a wrong answer that looks right.
  assert.equal(targetHostname("example.com:8080"), null);
  assert.equal(targetHostname("https://example.com/path"), null, "a path is not a name");
  assert.equal(targetHostname("203.0.113.7"), null, "an address is targetAddress's job");
  assert.equal(targetHostname("2606:4700::1111"), null);
  assert.equal(targetHostname("localhost"), null, "a single label is not a resolvable target");
  assert.equal(targetHostname(""), null);
  assert.equal(targetHostname(null), null);
});

/* ------------------------------------------------- a record the owner published */

test("a published AAAA record answers the AAAA question", async (t) => {
  // The registry held this the whole time and the bridge never looked.
  const server = await serve(t, registry({
    target: "dev.profullstack.com",
    records: [{ type: "AAAA", value: "2604:a880:400:d1:0:4:c3fe:1", ttl: 300 }],
  }));
  const [record] = readAnswers(await ask(server, query("scrambled.eggs", { type: TYPE_AAAA })), "scrambled.eggs");

  assert.equal(record.type, TYPE_AAAA);
  assert.equal(record.ttl, 300, "the owner's TTL, not the bridge's default");
  assert.equal(record.rdata.length, 16);
  assert.equal(record.rdata.readUInt16BE(0), 0x2604);
});

test("a published A record answers the A question", async (t) => {
  const server = await serve(t, registry({
    target: "dev.profullstack.com",
    records: [{ type: "A", value: "203.0.113.7", ttl: 120 }],
  }));
  const [record] = readAnswers(await ask(server, query("scrambled.eggs")), "scrambled.eggs");
  assert.equal(record.type, TYPE_A);
  assert.deepEqual([...record.rdata], [203, 0, 113, 7]);
});

test("a name with only an AAAA record still exists to the A question", async (t) => {
  const server = await serve(t, registry({ target: null, records: [{ type: "AAAA", value: "2606:4700::1111" }] }));
  const reply = await ask(server, query("scrambled.eggs"));
  assert.equal(rcode(reply), RCODE_OK, "the name is here, it just has no A");
});

test("a third-level name answers AAAA from the wildcard's published records", async (t) => {
  // `www.scrambled.eggs` is not in the registry; `*.scrambled.eggs` is, with an
  // AAAA record and no target. A bare label would park here — a sub-name is
  // never for sale, so the wildcard's records are the answer, owned on the
  // wire by the name that was asked.
  const fetchImpl = async (url) => {
    const name = new URL(url).searchParams.get("name");
    const wants = url.includes("records=1");
    return {
      ok: true,
      json: async () => (name === "*.scrambled.eggs"
        ? {
          name_registered: true,
          target: null,
          ...(wants ? { records: [{ type: "AAAA", value: "2606:4700::1111", ttl: 300 }] } : {}),
        }
        : { name_registered: false, target: null, ...(wants ? { records: [] } : {}) }),
    };
  };
  const server = await serve(t, { fetchImpl });
  const reply = await ask(server, query("www.scrambled.eggs", { type: TYPE_AAAA }));

  assert.equal(rcode(reply), RCODE_OK);
  const [record] = readAnswers(reply, "www.scrambled.eggs");
  assert.equal(record.owner, "www.scrambled.eggs", "answered under the asked name, not the wildcard");
  assert.equal(record.type, TYPE_AAAA);
  assert.equal(record.ttl, 300, "the owner's TTL, not the bridge's default");
  assert.equal(record.rdata.readUInt16BE(0), 0x2606);
});

test("a wildcard CNAME answers an address question like an exact one", async (t) => {
  const fetchImpl = async (url) => {
    const name = new URL(url).searchParams.get("name");
    const wants = url.includes("records=1");
    return {
      ok: true,
      json: async () => (name === "*.scrambled.eggs"
        ? {
          name_registered: true,
          target: null,
          ...(wants ? { records: [{ type: "CNAME", value: "box.example.com", ttl: 300, priority: null }] } : {}),
        }
        : { name_registered: false, target: null, ...(wants ? { records: [] } : {}) }),
    };
  };
  const server = await serve(t, { fetchImpl });
  const reply = await ask(server, query("www.scrambled.eggs"));

  assert.equal(rcode(reply), RCODE_OK);
  const [record] = readAnswers(reply, "www.scrambled.eggs");
  assert.equal(record.owner, "www.scrambled.eggs");
  assert.equal(record.type, TYPE_CNAME);
  assert.equal(readName(record.rdata, 0).name, "box.example.com");
});

test("a third-level name missing everywhere is NXDOMAIN, not parked", async (t) => {
  // Parking sells the bare label; there is nothing to park a sub-name to once
  // the wildcard misses too.
  const server = await serve(t, registry({ target: null, registered: false }));
  assert.equal(rcode(await ask(server, query("nobody.scrambled.eggs"))), RCODE_NXDOMAIN);
});

/* ------------------------------------------------------- a target that is a host */

test("a hostname target is answered as a CNAME to that host", async (t) => {
  const server = await serve(t, registry({ target: "dev.profullstack.com" }));
  const reply = await ask(server, query("scrambled.eggs"));

  assert.equal(rcode(reply), RCODE_OK);
  assert.equal(answers(reply), 1);
  const [record] = readAnswers(reply, "scrambled.eggs");
  assert.equal(record.type, TYPE_CNAME);
  assert.equal(readName(record.rdata, 0).name, "dev.profullstack.com");
});

test("the chain is left for the machine's own resolver to finish", async (t) => {
  // This bridge is routed per-TLD, so the CNAME's target is not a name that
  // comes back here — the system resolver chases it. Resolving it ourselves
  // would be this bridge doing clearnet DNS to answer a question the machine
  // can already answer, which is the thing it deliberately does not do.
  const reg = registry({ target: "dev.profullstack.com" });
  const server = await serve(t, reg);
  await ask(server, query("scrambled.eggs"));
  assert.ok(reg.calls.every((u) => u.includes("pit") || u.includes("resolve")),
    "the registry is the only thing this bridge talks to");
});

test("a target naming a port stays NODATA rather than lying about the port", async (t) => {
  const server = await serve(t, registry({ target: "example.com:8080" }));
  const reply = await ask(server, query("scrambled.eggs"));
  assert.equal(rcode(reply), RCODE_OK);
  assert.equal(answers(reply), 0);
});

test("an address in the target still short-circuits the record lookup", async (t) => {
  // The fast path every page load takes.
  const reg = registry({ target: "203.0.113.7" });
  const server = await serve(t, reg);
  await ask(server, query("scrambled.eggs"));
  assert.equal(reg.calls.filter((u) => u.includes("records=1")).length, 0);
});

/* ------------------------------------------------------------- the chain on the wire */

test("a completed chain carries the CNAME and the leaf under their own owners", () => {
  const name = "scrambled.eggs";
  const buf = query(name);
  const reply = buildChainResponse(parseQuery(buf), buf, {
    cname: "dev.profullstack.com", addresses: ["67.205.189.229"],
  });

  assert.equal(answers(reply), 2);
  const [cname, leaf] = readAnswers(reply, name);
  assert.equal(cname.owner, name, "the CNAME is owned by the name that was asked about");
  assert.equal(cname.type, TYPE_CNAME);
  assert.equal(leaf.owner, "dev.profullstack.com", "the address is owned by the CNAME's target");
  assert.deepEqual([...leaf.rdata], [67, 205, 189, 229]);
});

test("a leaf of the wrong family is dropped, not encoded as garbage", () => {
  const buf = query("scrambled.eggs", { type: TYPE_AAAA });
  const reply = buildChainResponse(parseQuery(buf), buf, {
    cname: "dev.profullstack.com", addresses: ["67.205.189.229"],
  });
  assert.equal(answers(reply), 1, "an IPv4 address cannot answer an AAAA question");
});

/* --------------------------------------------------------------- the plan itself */

test("addressAnswer parks a claimed name before reading any record", async () => {
  const reg = registry({ target: null });
  const plan = await addressAnswer("scrambled.eggs", {
    fetchImpl: reg.fetchImpl, parkingAddress: "198.51.100.9",
  });
  assert.equal(plan.kind, "address");
  assert.equal(plan.address, "198.51.100.9");
  assert.equal(reg.calls.filter((u) => u.includes("records=1")).length, 0);
});

test("a name the registry does not hold is still NXDOMAIN", async (t) => {
  // The one answer the new paths must never swallow: adding CNAMEs and record
  // lookups above this must not turn a name nobody holds into one that exists.
  const server = await serve(t, missing());
  assert.equal(rcode(await ask(server, query("scrambled.eggs"))), RCODE_NXDOMAIN);
});
