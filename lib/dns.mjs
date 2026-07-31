// The Moshpit DNS bridge: a tiny authoritative resolver for Moshpit endings.
//
// The registry speaks HTTP, not DNS — pit.moshcode.sh answers
// /api/moshpit/resolve?name=… and nothing listens on port 53. So `curl
// https://california.oranges/` fails everywhere, while a browser extension that
// redirects tabs works, because redirecting is not resolving and nothing
// outside that browser benefits from it.
//
// This bridges the two: A queries for Moshpit endings answered out of the
// registry's HTTP API, and nothing else. It is authoritative for claimed
// endings and deliberately silent about everything else, so the machine's
// normal nameserver keeps handling the rest of the internet.
//
// The wire codec is pure and separate from the socket, so the whole protocol is
// testable without binding a port.

import dgram from "node:dgram";

export const DEFAULT_REGISTRY_BASE = "https://pit.moshcode.sh";
export const DEFAULT_PARKING_HOST = "moshcoding.com";
export const DEFAULT_PORT = 5354;
export const DEFAULT_HOST = "127.0.0.1";

// Short, because a name's target can change the moment its owner points it
// somewhere. A stale A record is the one failure mode users cannot debug.
export const DEFAULT_TTL = 30;

const TYPE_A = 1;
const CLASS_IN = 1;
const RCODE_OK = 0;
const RCODE_NXDOMAIN = 3;

/* ---------------------------------------------------------------- wire codec */

/** Encode a hostname as DNS labels. */
export function encodeName(name) {
  const labels = String(name).replace(/\.$/, "").split(".").filter(Boolean);
  const parts = labels.map((l) => {
    const b = Buffer.from(l, "ascii");
    if (b.length > 63) throw new Error(`label too long: ${l}`);
    return Buffer.concat([Buffer.from([b.length]), b]);
  });
  return Buffer.concat([...parts, Buffer.from([0])]);
}

/**
 * Read a QNAME starting at `offset`. Returns { name, offset } where offset is
 * the first byte AFTER the name. Compression pointers are rejected rather than
 * followed: they cannot legally appear in a question, and quietly accepting
 * them in a parser that only reads questions invites a pointer loop.
 */
export function decodeName(buf, offset) {
  const labels = [];
  let i = offset;
  for (;;) {
    if (i >= buf.length) throw new Error("truncated name");
    const len = buf[i];
    if (len === 0) return { name: labels.join("."), offset: i + 1 };
    if ((len & 0xc0) === 0xc0) throw new Error("compression pointer in question");
    i += 1;
    if (i + len > buf.length) throw new Error("truncated label");
    labels.push(buf.toString("ascii", i, i + len));
    i += len;
  }
}

/** Parse a query. Returns null for anything we should not try to answer. */
export function parseQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  const flags = buf.readUInt16BE(2);
  if (flags & 0x8000) return null; // a response, not a query
  if (buf.readUInt16BE(4) !== 1) return null; // exactly one question
  let name;
  let offset;
  try {
    ({ name, offset } = decodeName(buf, 12));
  } catch {
    return null;
  }
  if (offset + 4 > buf.length) return null;
  return {
    id: buf.readUInt16BE(0),
    recursionDesired: !!(flags & 0x0100),
    name: name.toLowerCase(),
    type: buf.readUInt16BE(offset),
    class: buf.readUInt16BE(offset + 2),
    questionEnd: offset + 4,
  };
}

function header(id, { rcode, answers, recursionDesired }) {
  const buf = Buffer.alloc(12);
  buf.writeUInt16BE(id, 0);
  // QR=1 (response), AA=1 (we are authoritative for the TLDs we serve), RD
  // echoed back per RFC 1035, RA=0 — we do not offer recursion for anything.
  buf.writeUInt16BE(0x8400 | (recursionDesired ? 0x0100 : 0) | rcode, 2);
  buf.writeUInt16BE(1, 4); // QDCOUNT — the question is echoed
  buf.writeUInt16BE(answers, 6);
  return buf;
}

function ipv4(address) {
  const parts = String(address).split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => Number(p));
  if (bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) return null;
  return Buffer.from(bytes);
}

/** Build an A-record response, or NXDOMAIN when `address` is null. */
export function buildResponse(query, buf, address, ttl = DEFAULT_TTL) {
  const question = buf.subarray(12, query.questionEnd);
  const rdata = address ? ipv4(address) : null;
  if (!rdata) {
    return Buffer.concat([
      header(query.id, { rcode: RCODE_NXDOMAIN, answers: 0, recursionDesired: query.recursionDesired }),
      question,
    ]);
  }
  const answer = Buffer.alloc(12);
  answer.writeUInt16BE(0xc00c, 0); // pointer to the question's name
  answer.writeUInt16BE(TYPE_A, 2);
  answer.writeUInt16BE(CLASS_IN, 4);
  answer.writeUInt32BE(ttl, 6);
  answer.writeUInt16BE(4, 10);
  return Buffer.concat([
    header(query.id, { rcode: RCODE_OK, answers: 1, recursionDesired: query.recursionDesired }),
    question,
    answer,
    rdata,
  ]);
}

/* ------------------------------------------------------------------ registry */

/** Names the registry can hold: exactly one label and one TLD. */
export function parseRegistryName(hostname) {
  const host = String(hostname || "").trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.includes(":")) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null;
  const parts = host.split(".");
  if (parts.length !== 2) return null;
  const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const [label, tld] = parts;
  if (!LABEL.test(label) || !LABEL.test(tld)) return null;
  return { label, tld };
}

/** The TLDs currently claimed in the Pit — what we route to this resolver. */
export async function fetchTlds({ registryBase = DEFAULT_REGISTRY_BASE, fetchImpl = fetch } = {}) {
  const res = await fetchImpl(`${registryBase.replace(/\/+$/, "")}/api/moshpit/tlds`);
  if (!res.ok) throw new Error(`registry returned ${res.status}`);
  const json = await res.json();
  return (json?.tlds || [])
    .map((t) => (typeof t === "string" ? t : t?.tld))
    .filter((t) => typeof t === "string" && t)
    .map((t) => t.toLowerCase())
    .sort();
}

/**
 * What address a Moshpit name should resolve to.
 *
 * Three outcomes, and the middle one is the whole point of parking: a claimed
 * name with no target is NOT an error, it is a name waiting to be pointed
 * somewhere. Handing back the parking host means `curl california.oranges`
 * reaches a page that explains itself instead of failing to resolve.
 */
export async function resolveName(
  name,
  { registryBase = DEFAULT_REGISTRY_BASE, fetchImpl = fetch, timeoutMs = 4000 } = {},
) {
  const parsed = parseRegistryName(name);
  if (!parsed) return { status: "not-a-name", target: null };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = `${registryBase.replace(/\/+$/, "")}/api/moshpit/resolve?name=${encodeURIComponent(
      `${parsed.label}.${parsed.tld}`,
    )}`;
    const res = await fetchImpl(url, { signal: controller.signal });
    if (!res.ok) return { status: "unreachable", target: null };
    const json = await res.json();
    const claimed =
      typeof json?.name_registered === "boolean" ? json.name_registered : json?.registered;
    if (typeof claimed !== "boolean") return { status: "unreachable", target: null };
    const target = typeof json.target === "string" && json.target ? json.target : null;
    if (target) return { status: "live", target };
    return { status: "parked", target: null, registered: claimed };
  } catch {
    return { status: "unreachable", target: null };
  } finally {
    clearTimeout(timer);
  }
}

/* -------------------------------------------------------------------- server */

/**
 * The address to answer with, or null for NXDOMAIN.
 *
 * Kept separate from the socket so the policy is testable on its own. A name we
 * could not look up gets NXDOMAIN rather than the parking address: a registry
 * outage must not silently redirect every name on the machine to a parking page.
 */
export async function answerFor(name, options = {}) {
  const { parkingAddress } = options;
  const result = await resolveName(name, options);
  if (result.status === "live") return result.target;
  if (result.status === "parked") return parkingAddress || null;
  return null;
}

/**
 * Start the bridge. Returns { port, address, close() }.
 *
 * `parkingAddress` is resolved once by the caller (an A record must carry an
 * IP, not a name) and passed in, so the server itself never does clearnet DNS.
 */
export function createServer(options = {}) {
  const {
    port = DEFAULT_PORT,
    host = DEFAULT_HOST,
    ttl = DEFAULT_TTL,
    onQuery = () => {},
  } = options;
  const socket = dgram.createSocket("udp4");

  socket.on("message", async (msg, rinfo) => {
    const query = parseQuery(msg);
    if (!query) return; // malformed, or a response — say nothing at all
    let address = null;
    // Only A/IN questions can be answered with an address; everything else
    // (AAAA, MX, TXT) gets an honest empty NOERROR/NXDOMAIN rather than a lie.
    if (query.type === TYPE_A && query.class === CLASS_IN) {
      address = await answerFor(query.name, options).catch(() => null);
    }
    onQuery({ name: query.name, type: query.type, address });
    try {
      socket.send(buildResponse(query, msg, address, ttl), rinfo.port, rinfo.address);
    } catch {
      /* client vanished — nothing useful to do */
    }
  });

  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(port, host, () => {
      const addr = socket.address();
      resolve({
        port: addr.port,
        address: addr.address,
        close: () => new Promise((done) => socket.close(done)),
      });
    });
  });
}

/* ------------------------------------------------------- system integration */

/**
 * systemd-resolved drop-in routing just the Moshpit TLDs at the bridge.
 *
 * `~tld` is a routing-only domain: it sends queries for that suffix here
 * without making this resolver the default for anything else on the machine.
 */
export function resolvedConf(tlds, { host = DEFAULT_HOST, port = DEFAULT_PORT } = {}) {
  return [
    "# Written by `moshpit-dns install`. Routes Moshpit TLDs to the local",
    "# bridge; every other name keeps using your normal resolver.",
    "[Resolve]",
    `DNS=${host}:${port}`,
    `Domains=${tlds.map((t) => `~${t}`).join(" ")}`,
    "",
  ].join("\n");
}

/** The dnsmasq equivalent, for machines not running systemd-resolved. */
export function dnsmasqConf(tlds, { host = DEFAULT_HOST, port = DEFAULT_PORT } = {}) {
  return [
    "# Written by `moshpit-dns install`.",
    ...tlds.map((t) => `server=/${t}/${host}#${port}`),
    "",
  ].join("\n");
}
