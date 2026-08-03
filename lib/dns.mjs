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
import { isIP } from "node:net";

export const DEFAULT_REGISTRY_BASE = "https://pit.moshcode.sh";
export const DEFAULT_PARKING_HOST = "moshcoding.com";
export const DEFAULT_PORT = 5354;
export const DEFAULT_HOST = "127.0.0.1";

// Short, because a name's target can change the moment its owner points it
// somewhere. A stale A record is the one failure mode users cannot debug.
export const DEFAULT_TTL = 30;
export const DEFAULT_TIMEOUT_MS = 4000;

export const TYPE_A = 1;
export const TYPE_AAAA = 28;
export const TYPE_CNAME = 5;
export const TYPE_MX = 15;
export const TYPE_TXT = 16;
const CLASS_IN = 1;
const RCODE_OK = 0;
const RCODE_NXDOMAIN = 3;

/**
 * The question types answered out of the registry's record set, mapped to the
 * name the registry calls them.
 *
 * Address questions are not in here. They are answered from `target`, which the
 * registry keeps in step with the address records and which this bridge has
 * read since before records existed — routing them through here would change
 * how a name already resolving today gets its answer, to arrive at the same
 * address.
 */
export const RECORD_TYPES = new Map([
  [TYPE_CNAME, "CNAME"],
  [TYPE_MX, "MX"],
  [TYPE_TXT, "TXT"],
]);

/**
 * What fits in a UDP answer without EDNS.
 *
 * 512 bytes is the floor every resolver accepts. Beyond it a datagram may be
 * dropped by a middlebox rather than delivered short, so the reply is trimmed
 * to what fits and marked truncated instead of being sent oversized and lost.
 */
export const UDP_SAFE_BYTES = 512;

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

/**
 * 16 bytes of AAAA rdata.
 *
 * `isIP` has already ruled on the grammar, so the work here is expanding what
 * the text form is allowed to leave out: the `::` run of zero groups, and the
 * trailing dotted-quad an IPv4-mapped address is written with.
 */
function ipv6(address) {
  const raw = String(address).trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (isIP(raw) !== 6) return null;

  let text = raw;
  const mapped = text.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    const octets = mapped[2].split(".").map(Number);
    text = `${mapped[1]}${(((octets[0] << 8) | octets[1]) >>> 0).toString(16)}:${(((octets[2] << 8) | octets[3]) >>> 0).toString(16)}`;
  }

  const [head, tail] = text.split("::");
  const left = head ? head.split(":").filter(Boolean) : [];
  const right = tail ? tail.split(":").filter(Boolean) : [];
  const groups = text.includes("::")
    ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]
    : left;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;

  const buf = Buffer.alloc(16);
  groups.forEach((group, i) => buf.writeUInt16BE(parseInt(group, 16), i * 2));
  return buf;
}


/**
 * TXT rdata: one or more length-prefixed strings.
 *
 * Split at 255 bytes because that is the largest a single DNS character-string
 * can be, and long TXT values are normal rather than exceptional — a DKIM key
 * does not fit in one and is always carried as several. A client joins them
 * back together, so the split is invisible above the wire.
 *
 * Split on bytes, not characters: a multi-byte character straddling the
 * boundary would be cut in half and neither piece would decode.
 */
export function rdataTxt(value) {
  const bytes = Buffer.from(String(value), "utf8");
  if (!bytes.length) return Buffer.from([0]);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += 255) {
    const chunk = bytes.subarray(i, i + 255);
    chunks.push(Buffer.concat([Buffer.from([chunk.length]), chunk]));
  }
  return Buffer.concat(chunks);
}

/** MX rdata: a 16-bit preference, then the exchange as labels. */
export function rdataMx(priority, value) {
  const preference = Buffer.alloc(2);
  preference.writeUInt16BE(Math.min(65_535, Math.max(0, Number(priority) || 0)), 0);
  return Buffer.concat([preference, encodeName(value)]);
}

/**
 * The rdata for one record from the registry, or null when it cannot be
 * encoded.
 *
 * Null rather than a throw: one malformed record must not take down the answer
 * for the ones beside it that are fine. The registry validates on the way in,
 * so this is the second line — it is reading data over HTTP from a service that
 * may be a different version than this bridge.
 */
export function encodeRdata(record) {
  try {
    if (record?.type === "TXT") return rdataTxt(record.value);
    if (record?.type === "MX") return rdataMx(record.priority, record.value);
    if (record?.type === "CNAME") return encodeName(record.value);
    if (record?.type === "AAAA") return ipv6(record.value);
    if (record?.type === "A") return ipv4(record.value);
  } catch {
    return null;
  }
  return null;
}

const TYPE_NUMBERS = new Map([["A", TYPE_A], ["CNAME", TYPE_CNAME], ["MX", TYPE_MX],
  ["TXT", TYPE_TXT], ["AAAA", TYPE_AAAA]]);

/**
 * A response carrying whole records rather than a bare address.
 *
 * Answers are fitted to `limit` and TC is set only if something was left out. A
 * name with nine MX records should hand back the seven that fit and say it was
 * truncated, not nothing at all — this bridge speaks UDP only, so a client that
 * retries over TCP finds no one listening.
 *
 * `exists` carries the same NODATA/NXDOMAIN distinction buildResponse draws: a
 * name with no TXT record still exists, and answering NXDOMAIN would deny it
 * for every other type at once.
 */
export function buildRecordResponse(query, buf, records = [], { ttl = DEFAULT_TTL, exists = true, limit = UDP_SAFE_BYTES } = {}) {
  const question = buf.subarray(12, query.questionEnd);
  const encoded = [];
  let dropped = false;
  let size = 12 + question.length;

  for (const record of records) {
    const rdata = encodeRdata(record);
    const type = TYPE_NUMBERS.get(record?.type);
    if (!rdata || !type) continue;
    const answer = Buffer.alloc(12);
    answer.writeUInt16BE(0xc00c, 0); // the question's name, by pointer
    answer.writeUInt16BE(type, 2);
    answer.writeUInt16BE(CLASS_IN, 4);
    // The record's own TTL when it has one. An owner who set 60 on an address
    // that moves meant it, and overriding it with the bridge's default would
    // quietly hold the old answer for longer than they asked.
    answer.writeUInt32BE(Number.isFinite(record.ttl) ? Math.max(0, Math.floor(record.ttl)) : ttl, 6);
    answer.writeUInt16BE(rdata.length, 10);

    if (size + answer.length + rdata.length > limit) { dropped = true; continue; }
    size += answer.length + rdata.length;
    encoded.push(answer, rdata);
  }

  const answers = encoded.length / 2;
  const head = header(query.id, {
    rcode: answers || exists ? RCODE_OK : RCODE_NXDOMAIN,
    answers,
    recursionDesired: query.recursionDesired,
  });
  if (dropped) head.writeUInt16BE(head.readUInt16BE(2) | 0x0200, 2); // TC
  return Buffer.concat([head, question, ...encoded]);
}

/**
 * Build an address-record response for the family the query asked for.
 *
 * Three outcomes, and the difference between the last two is the whole reason
 * this is not a one-liner. NXDOMAIN says the name does not exist, and a
 * resolver is entitled to apply that to every record type at once. A name
 * pointed at an IPv6 address *does* exist — it just has no A record — so the A
 * query every browser sends alongside the AAAA one has to come back NOERROR
 * with no answers. Answering NXDOMAIN there teaches the resolver the name is
 * gone and takes the AAAA lookup down with it.
 *
 * `exists` is that distinction on its own. Holding an address implies the name
 * exists, so it defaults to exactly that, but the reverse does not hold: a name
 * can exist and have no address to hand back — because the question was for a
 * type this bridge does not serve, or because the target is a hostname rather
 * than an address. Those are NODATA, not NXDOMAIN.
 */
export function buildResponse(query, buf, address, ttl = DEFAULT_TTL, exists = Boolean(address)) {
  const question = buf.subarray(12, query.questionEnd);
  const wantsV6 = query.type === TYPE_AAAA;
  const rdata = address ? (wantsV6 ? ipv6(address) : ipv4(address)) : null;

  if (!rdata) {
    return Buffer.concat([
      header(query.id, {
        // The name is here, we just have nothing to say for this question: NODATA.
        rcode: exists ? RCODE_OK : RCODE_NXDOMAIN,
        answers: 0,
        recursionDesired: query.recursionDesired,
      }),
      question,
    ]);
  }

  const answer = Buffer.alloc(12);
  answer.writeUInt16BE(0xc00c, 0); // pointer to the question's name
  answer.writeUInt16BE(wantsV6 ? TYPE_AAAA : TYPE_A, 2);
  answer.writeUInt16BE(CLASS_IN, 4);
  answer.writeUInt32BE(ttl, 6);
  answer.writeUInt16BE(rdata.length, 10);
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
  // Letters and digits only, matching the registry. A dash is the cheapest way
  // to mint a look-alike of an ending someone else holds, and in a namespace
  // one level deep and first come first served there is nowhere to retreat to.
  // Keeping this identical to the registry matters more than the rule itself:
  // a name this bridge accepts and the registry rejects resolves to a page
  // saying it does not exist.
  const LABEL = /^[a-z0-9]{1,63}$/;
  const [label, tld] = parts;
  if (!LABEL.test(label) || !LABEL.test(tld)) return null;
  return { label, tld };
}

/** The TLDs currently claimed in the Pit — what we route to this resolver. */
async function fetchJsonWithTimeout(fetchImpl, url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { signal: controller.signal });
    const json = res.ok ? await res.json() : null;
    return { res, json };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchTlds({
  registryBase = DEFAULT_REGISTRY_BASE,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const url = `${registryBase.replace(/\/+$/, "")}/api/moshpit/tlds`;
  const { res, json } = await fetchJsonWithTimeout(fetchImpl, url, timeoutMs);
  if (!res.ok) throw new Error(`registry returned ${res.status}`);
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
  { registryBase = DEFAULT_REGISTRY_BASE, fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS, records = false } = {},
) {
  const parsed = parseRegistryName(name);
  if (!parsed) return { status: "not-a-name", target: null };

  try {
    // `&records=1` only when the question needs the whole set. Every address
    // lookup on the machine comes through here, and the registry does a second
    // query to answer it — a browser opening a page must not pay for records it
    // will never read.
    const url = `${registryBase.replace(/\/+$/, "")}/api/moshpit/resolve?name=${encodeURIComponent(
      `${parsed.label}.${parsed.tld}`,
    )}${records ? "&records=1" : ""}`;
    const { res, json } = await fetchJsonWithTimeout(fetchImpl, url, timeoutMs);
    if (!res.ok) return { status: "unreachable", target: null };
    const claimed =
      typeof json?.name_registered === "boolean" ? json.name_registered : json?.registered;
    if (typeof claimed !== "boolean") return { status: "unreachable", target: null };
    // The `records` key appears only when it was asked for. Every caller that
    // wants an address deep-compares this shape, and an empty array they never
    // requested is a difference they would have to be taught to ignore.
    const found = records ? { records: Array.isArray(json.records) ? json.records : [] } : {};
    const target = typeof json.target === "string" && json.target ? json.target : null;
    if (target) return { status: "live", target, ...found };
    return { status: "parked", target: null, registered: claimed, ...found };
  } catch {
    return { status: "unreachable", target: null };
  }
}

/**
 * The records of one type a name publishes, and whether the name is here.
 *
 * Both halves matter and they are not the same question: a name with no MX
 * record still exists, so the answer is NODATA, while a name nobody holds is
 * NXDOMAIN. Collapsing them would let a missing MX deny the name's address too.
 */
export async function answerRecords(name, options = {}) {
  const { type } = options;
  const result = await resolveName(name, { ...options, records: true });
  const exists = result.status === "live" || result.status === "parked";
  if (!exists || !type) return { exists, records: [] };
  return { exists, records: (result.records || []).filter((r) => r?.type === type) };
}

/**
 * Is an address question on this name worth a second look for a CNAME?
 *
 * True when the name is here and has no address to give. A CNAME is the one
 * thing that can still answer such a question, and finding out costs another
 * round trip to the registry — so it is asked only on the path that would
 * otherwise return nothing at all, never on a name that already has an address.
 */
export function mayHaveCname({ exists, address }) {
  return Boolean(exists) && !address;
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
  const { address } = await answerPolicy(name, options);
  return address;
}

/**
 * Whether the name exists, and the address to hand back if we have one.
 *
 * The two are separate questions and conflating them is what produced a name
 * that answered "I exist" to A and "no such name" to TXT in the same second.
 * `wantsAddress` is false for every question type this bridge does not serve —
 * the name is still looked up, because the answer to "does it exist" decides
 * between NODATA and NXDOMAIN, and a browser asks HTTPS/SVCB beside every A
 * and AAAA. NXDOMAIN to that one denies the name for the whole page load.
 */
export async function answerPolicy(name, options = {}) {
  const { parkingAddress, wantsAddress = true } = options;
  const result = await resolveName(name, options);
  const exists = result.status === "live" || result.status === "parked";
  if (!exists || !wantsAddress) return { exists, address: null };
  if (result.status === "live") return { exists, address: targetAddress(result.target) };
  return { exists, address: parkingAddress || null };
}

/**
 * The bare address inside a stored target, or null when there isn't one.
 *
 * Targets are typed by hand and come back from the registry as `2606:...`,
 * `[2606:...]:8080`, `example.com`, or with a scheme still attached. A record
 * carries an address and nothing else, so the port is dropped here — a name
 * whose target names a non-default port cannot be served by the resolver path
 * at all, because there is no way to say "port 8080" in an A or AAAA record and
 * the browser will go to 80 regardless. A hostname target is null for the same
 * reason: turning it into an address would mean this bridge doing clearnet DNS.
 */
export function targetAddress(target) {
  const raw = String(target || "").trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  if (!raw) return null;

  const bracketed = raw.match(/^\[([0-9a-f:.]+)\](?::\d+)?$/i);
  const host = bracketed ? bracketed[1] : raw;
  if (isIP(host)) return host;

  const at = host.lastIndexOf(":");
  if (at > 0 && /^\d+$/.test(host.slice(at + 1))) {
    const bare = host.slice(0, at);
    if (isIP(bare) === 4) return bare;
  }
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
    let exists = false;
    let reply = null;

    // Three shapes of question. CNAME, MX and TXT are answered from the record
    // set; addresses are answered from `target` as they always have been;
    // everything else (HTTPS/SVCB and the rest) still gets an honest empty
    // NOERROR rather than a lie — a browser asks HTTPS beside every A and AAAA,
    // and NXDOMAIN to that one denies the name for the whole page load.
    const wanted = query.class === CLASS_IN ? RECORD_TYPES.get(query.type) : null;
    if (wanted) {
      const found = await answerRecords(query.name, { ...options, type: wanted }).catch(() => null);
      exists = Boolean(found?.exists);
      reply = buildRecordResponse(query, msg, found?.records || [], { ttl, exists });
    } else if (query.class === CLASS_IN) {
      const wantsAddress = query.type === TYPE_A || query.type === TYPE_AAAA;
      const policy = await answerPolicy(query.name, { ...options, wantsAddress }).catch(() => null);
      if (policy) ({ exists, address } = policy);
      // A name that is here with no address to give may still have published a
      // CNAME, which is the one record that can answer an address question.
      // Handing it back lets the client chase it through its own resolver — the
      // only party here that may do clearnet DNS — instead of the NODATA that
      // made a pointed name look broken.
      if (wantsAddress && mayHaveCname(policy || {})) {
        const found = await answerRecords(query.name, { ...options, type: "CNAME" }).catch(() => null);
        if (found?.records?.length) {
          reply = buildRecordResponse(query, msg, found.records, { ttl, exists });
        }
      }
    }
    onQuery({ name: query.name, type: query.type, address });
    try {
      socket.send(reply || buildResponse(query, msg, address, ttl, exists), rinfo.port, rinfo.address);
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
