// IPv6 targets, and the NXDOMAIN-vs-NODATA distinction they forced.
//
// A name pointed at an IPv6 address did not resolve at all: the bridge only
// answered A, and the v6 target went through the IPv4 encoder, came back null,
// and was reported as "no such name". Fixing that surfaced the second bug —
// "we have no address for this question" was being answered as "this name does
// not exist", which a resolver is entitled to apply to every other record type
// for the same name.
import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";

import {
  answerFor,
  answerPolicy,
  buildResponse,
  createServer,
  encodeName,
  parseQuery,
  targetAddress,
  TYPE_A,
  TYPE_AAAA,
} from "../lib/dns.mjs";

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

const okJson = (body) => async () => ({ ok: true, json: async () => body });
const rcode = (reply) => reply.readUInt16BE(2) & 0x000f;
const answers = (reply) => reply.readUInt16BE(6);

/* ---------------------------------------------------------------- encoding */

test("an AAAA query is answered with 16 bytes of address", () => {
  const buf = query("a.eggs", { type: TYPE_AAAA });
  const res = buildResponse(parseQuery(buf), buf, "2606:4700:4700::1111", 30);
  assert.equal(answers(res), 1);
  assert.equal(rcode(res), 0);
  assert.deepEqual([...res.subarray(res.length - 16)], [
    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0,
    0, 0, 0, 0, 0, 0, 0x11, 0x11,
  ]);
  // The answer must claim AAAA, not the A it was copied from.
  assert.equal(res.readUInt16BE(res.length - 16 - 12 + 2), TYPE_AAAA);
});

test("the :: run expands to exactly the zero groups it stands for", () => {
  const cases = {
    "::1": [...new Array(15).fill(0), 1],
    "::": new Array(16).fill(0),
    "2001:db8::": [0x20, 0x01, 0x0d, 0xb8, ...new Array(12).fill(0)],
    "2001:db8:0:0:0:0:0:1": [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 1],
    "fe80::1": [0xfe, 0x80, ...new Array(13).fill(0), 1],
  };
  for (const [address, bytes] of Object.entries(cases)) {
    const buf = query("a.eggs", { type: TYPE_AAAA });
    const res = buildResponse(parseQuery(buf), buf, address, 30);
    assert.deepEqual([...res.subarray(res.length - 16)], bytes, address);
  }
});

test("a v4 address is still a v4 answer, byte for byte as before", () => {
  const buf = query("a.eggs");
  const res = buildResponse(parseQuery(buf), buf, "203.0.113.7", 30);
  assert.equal(answers(res), 1);
  assert.deepEqual([...res.subarray(res.length - 4)], [203, 0, 113, 7]);
  assert.equal(res.readUInt16BE(res.length - 4 - 12 + 2), TYPE_A);
});

/* ------------------------------------------------- exists versus has-address */

test("an A query for a v6-only name is NODATA, not NXDOMAIN", () => {
  // Browsers ask A and AAAA together. NXDOMAIN on the A half says the name
  // does not exist, which is entitled to take the AAAA answer down with it.
  const buf = query("a.eggs", { type: TYPE_A });
  const res = buildResponse(parseQuery(buf), buf, "2606:4700:4700::1111", 30);
  assert.equal(answers(res), 0);
  assert.equal(rcode(res), 0, "the name exists");
});

test("a name nobody holds is NXDOMAIN in both families", () => {
  for (const type of [TYPE_A, TYPE_AAAA]) {
    const buf = query("a.eggs", { type });
    const res = buildResponse(parseQuery(buf), buf, null);
    assert.equal(rcode(res), 3, `type ${type}`);
  }
});

test("exists is carried separately from having an address", () => {
  const buf = query("a.eggs", { type: 16 }); // TXT
  const parsed = parseQuery(buf);
  assert.equal(rcode(buildResponse(parsed, buf, null, 30, true)), 0, "exists → NODATA");
  assert.equal(rcode(buildResponse(parsed, buf, null, 30, false)), 3, "absent → NXDOMAIN");
});

/* ------------------------------------------------------------------ policy */

test("targetAddress digs the address out of what owners actually type", () => {
  assert.equal(targetAddress("2606:4700:4700::1111"), "2606:4700:4700::1111");
  assert.equal(targetAddress("[2606:4700:4700::1111]:8080"), "2606:4700:4700::1111");
  assert.equal(targetAddress("http://[2606:4700::1]/"), "2606:4700::1");
  assert.equal(targetAddress("203.0.113.7"), "203.0.113.7");
  assert.equal(targetAddress("203.0.113.7:8080"), "203.0.113.7");
  // A hostname is not an address, and resolving it here would mean this bridge
  // doing clearnet DNS on behalf of whoever typed it.
  assert.equal(targetAddress("box.example.com"), null);
  assert.equal(targetAddress(""), null);
  assert.equal(targetAddress(null), null);
});

test("answerFor hands back a bare address, not the stored target", async () => {
  const address = await answerFor("a.eggs", {
    fetchImpl: okJson({ name_registered: true, target: "[2606:4700:4700::1111]:8080" }),
  });
  assert.equal(address, "2606:4700:4700::1111");
});

test("answerPolicy reports existence for questions it cannot answer", async () => {
  const live = okJson({ name_registered: true, target: "2606:4700::1" });

  assert.deepEqual(await answerPolicy("a.eggs", { fetchImpl: live }),
    { exists: true, address: "2606:4700::1" });
  // The name still exists; we simply serve no TXT for it.
  assert.deepEqual(await answerPolicy("a.eggs", { fetchImpl: live, wantsAddress: false }),
    { exists: true, address: null });

  // "Nobody holds it" is not "it does not exist". An unclaimed but well-formed
  // name under a known ending is parked, and the bridge answers the parking
  // address for it — so it exists as far as DNS is concerned. Only something
  // that is not a Moshpit name at all is absent.
  const unheld = okJson({ registered: false, name_registered: false, target: null });
  assert.deepEqual(await answerPolicy("a.eggs", { fetchImpl: unheld, parkingAddress: "198.51.100.9" }),
    { exists: true, address: "198.51.100.9" });
  assert.deepEqual(await answerPolicy("nodots", { fetchImpl: unheld }),
    { exists: false, address: null });
});

/* -------------------------------------------------------------- over UDP */

/** Ask the running server one question and hand back the raw reply. */
async function ask(server, name, type) {
  const client = dgram.createSocket("udp4");
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no reply")), 5000);
      client.once("message", (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      client.send(query(name, { type }), server.port, "127.0.0.1");
    });
  } finally {
    client.close();
  }
}

test("a v6 name answers AAAA and NODATAs everything else, over the wire", async (t) => {
  const server = await createServer({
    port: 0,
    fetchImpl: okJson({ name_registered: true, target: "2606:4700:4700::1111" }),
  });
  t.after(() => server.close());

  const aaaa = await ask(server, "blue.eggs", TYPE_AAAA);
  assert.equal(answers(aaaa), 1, "AAAA answered");
  assert.deepEqual([...aaaa.subarray(aaaa.length - 16).subarray(0, 4)], [0x26, 0x06, 0x47, 0x00]);

  // Every other question about the same name must agree that it exists.
  for (const [label, type] of [["A", TYPE_A], ["TXT", 16], ["MX", 15], ["HTTPS", 65]]) {
    const reply = await ask(server, "blue.eggs", type);
    assert.equal(rcode(reply), 0, `${label} should be NODATA, not NXDOMAIN`);
    assert.equal(answers(reply), 0, `${label} carries no answer`);
  }
});

test("what is not a Moshpit name is NXDOMAIN over the wire, in every type", async (t) => {
  const server = await createServer({
    port: 0,
    fetchImpl: okJson({ registered: false, name_registered: false, target: null }),
  });
  t.after(() => server.close());

  // Two labels is the whole grammar, so neither of these is ours to answer —
  // and saying so is the point, since claiming them would hijack real lookups.
  for (const name of ["nodots", "too.many.labels"]) {
    for (const type of [TYPE_A, TYPE_AAAA, 16]) {
      assert.equal(rcode(await ask(server, name, type)), 3, `${name} type ${type}`);
    }
  }
});

test("an unclaimed name is parked, which is NODATA rather than absent", async (t) => {
  // The distinction that the previous test is the other half of: parked names
  // exist and answer, so denying them would break the parking page.
  const server = await createServer({
    port: 0,
    parkingAddress: "198.51.100.9",
    fetchImpl: okJson({ registered: false, name_registered: false, target: null }),
  });
  t.after(() => server.close());

  const a = await ask(server, "nope.eggs", TYPE_A);
  assert.equal(rcode(a), 0);
  assert.deepEqual([...a.subarray(a.length - 4)], [198, 51, 100, 9], "parked → parking address");

  // No AAAA for a v4 parking address, but the name is still there.
  const aaaa = await ask(server, "nope.eggs", TYPE_AAAA);
  assert.equal(rcode(aaaa), 0, "NODATA, not NXDOMAIN");
  assert.equal(answers(aaaa), 0);
});
