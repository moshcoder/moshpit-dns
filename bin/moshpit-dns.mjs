#!/usr/bin/env node
// The Moshpit DNS bridge, as a command.
//
// Three verbs do the work and the rest explain it:
//
//   enable   route the Moshpit endings here and start the bridge
//   disable  undo both
//   status   what is running, what is routed, and whether they agree
//
// `enable` edits system DNS and needs root. Nothing else does — the bridge
// listens on 5354 and the service that keeps it alive is a user service, so
// only the one privileged act asks for privileges.

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { promises as dnsPromises } from "node:dns";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_HOST, DEFAULT_PARKING_HOST, DEFAULT_PORT, DEFAULT_REGISTRY_BASE,
  createServer, dnsmasqConf, fetchTlds, resolvedConf, resolveName,
} from "../lib/dns.mjs";
import {
  applyPlan, daemonStatus, describePlan, detectPlatform, disablePlan, enablePlan,
  requiredPort, startDaemon, stopDaemon,
} from "../lib/system.mjs";
import { installPlan, uninstallPlan } from "../lib/service.mjs";

const USAGE = `moshpit-dns — resolve Moshpit names on this machine

  moshpit-dns enable            route the Moshpit endings here and start the bridge
  moshpit-dns disable           stop it and remove the routing
  moshpit-dns status [--json]   what is running, what is routed, does it work
  moshpit-dns refresh           re-apply routing for endings claimed since

  moshpit-dns service install   keep the bridge running across reboots
  moshpit-dns service uninstall stop doing that

  moshpit-dns tlds [--json]     list the endings claimed in the Pit
  moshpit-dns resolve <name> [--json]
                               show what a name resolves to, and why
  moshpit-dns start             run the bridge in the foreground
  moshpit-dns install           print the resolver config without applying it

  --dry-run   with enable/disable/refresh/service: print what would be done
  --json      with tlds/resolve/status: print machine-readable diagnostics
  --backend   linux only: systemd-resolved (default) or dnsmasq
  --port N    the bridge's port (Windows must use 53 — NRPT carries no port)

The registry speaks HTTP, not DNS, so nothing outside a browser can reach a
Moshpit name until this bridge is running and your resolver points at it.
\`enable\` edits system DNS and needs root; it routes only the Moshpit endings,
so every other name keeps using your normal resolver.`;

let sub, rest, flag, has, registryBase, port;
const setup = (argv) => {
  [sub, ...rest] = argv;
  flag = (name, fallback) => {
    const i = rest.indexOf(`--${name}`);
    return i >= 0 && rest[i + 1] ? rest[i + 1] : fallback;
  };
  has = (name) => rest.includes(`--${name}`);
  registryBase = flag("registry", DEFAULT_REGISTRY_BASE);
  port = Number(flag("port", DEFAULT_PORT));
};
const out = console.log;
const entry = fileURLToPath(new URL("./moshpit-dns.mjs", import.meta.url));

const parkingAddress = async (host = DEFAULT_PARKING_HOST) => {
  try { const [ip] = await dnsPromises.resolve4(host); return ip || null; } catch { return null; }
};

/** The marker whose presence means routing is installed. */
const routingMarker = (platform) =>
  platform === "macos" ? "/etc/resolver" : "/etc/systemd/resolved.conf.d/moshpit.conf";

const resolutionReasons = {
  live: "registry target",
  parked: "claimed, not pointed at an IP",
  unreachable: "registry unreachable — not parking a name we could not look up",
  "not-a-name": "not a Moshpit name: one label and one ending",
};

/** A stable resolution record for scripts, including the address DNS will answer. */
export function buildResolutionReport(name, result, address, registry = DEFAULT_REGISTRY_BASE) {
  return {
    registry,
    name,
    status: result.status,
    address,
    target: result.target,
    registered: result.registered ?? null,
    reason: resolutionReasons[result.status],
  };
}

/** Turn the platform probes into one machine-readable diagnostic snapshot. */
export function buildStatusReport({
  platform,
  daemon,
  routed,
  marker,
  known,
  routedCount,
  registry,
}) {
  const needsRefresh = Boolean(routedCount && known && routedCount !== known.length);
  const warnings = [];
  if (routed && !daemon.running) {
    warnings.push({
      code: "bridge-not-running",
      message: "routing is in place but the bridge is not running",
      fix: "sudo moshpit-dns enable",
      undo: "sudo moshpit-dns disable",
    });
  }
  if (needsRefresh) {
    warnings.push({
      code: "routing-out-of-date",
      message: `routing covers ${routedCount} endings but ${known.length} are claimed`,
      fix: "sudo moshpit-dns refresh",
    });
  }

  return {
    platform: platform || process.platform,
    bridge: daemon,
    routing: {
      configured: routed,
      marker: routed === null ? null : marker,
      count: routedCount,
    },
    registry: {
      url: registry,
      reachable: known !== null,
      count: known?.length ?? null,
    },
    needsRefresh,
    warnings,
  };
}

/**
 * The whole command, as a function.
 *
 * A bin is a script and cannot be called; this can. `moshcode dns …` delegates
 * straight to it, so the wrapper gets every verb this grows without either
 * copying the code or spawning a process to reach it.
 */
export async function run(argv = process.argv.slice(2)) {
  setup(argv);
  const json = has("json");
  const outJson = (value) => out(JSON.stringify(value, null, 2));
  if (!sub || sub === "help" || sub === "--help") { out(USAGE); return 0; }

  if (sub === "tlds") {
    try {
      const tlds = await fetchTlds({ registryBase });
      if (json) {
        outJson({
          registry: registryBase,
          reachable: true,
          count: tlds.length,
          tlds,
          error: null,
        });
      } else {
        out(tlds.length ? tlds.map((t) => `.${t}`).join("\n") : "no endings claimed yet");
      }
      return 0;
    } catch (error) {
      if (json) {
        outJson({
          registry: registryBase,
          reachable: false,
          count: null,
          tlds: [],
          error: "registry unreachable",
        });
      } else {
        const detail = error instanceof Error ? error.message : String(error);
        out(`registry unreachable — ${detail}`);
      }
      return 1;
    }
  }

  if (sub === "resolve") {
    const name = rest.find((a) => !a.startsWith("-"));
    if (!name) {
      if (json) outJson({ name: null, error: "missing name" });
      else out("usage: moshpit-dns resolve <name>");
      return 1;
    }
    const result = await resolveName(name, { registryBase });
    const park = result.status === "parked" ? await parkingAddress() : null;
    const address = result.status === "live" ? result.target : park;
    const report = buildResolutionReport(name, result, address, registryBase);
    if (json) {
      outJson(report);
    } else {
      out({
        live: () => `${name} → ${result.target}`,
        parked: () => `${name} → ${park || "(parking host unresolvable)"}  [${report.reason}]`,
        unreachable: () => `${name} → NXDOMAIN  [${report.reason}]`,
        "not-a-name": () => `${name} → NXDOMAIN  [${report.reason}]`,
      }[result.status]());
    }
    return result.status === "live" || result.status === "parked" ? 0 : 1;
  }

  if (sub === "start") {
    const park = await parkingAddress();
    if (!park) out("! parking host did not resolve — unpointed names will return NXDOMAIN");
    const server = await createServer({
      port, registryBase, parkingAddress: park,
      onQuery: ({ name, address }) => out(`  ${name} → ${address || "NXDOMAIN"}`),
    });
    out(`moshpit-dns on ${server.address}:${server.port} (registry ${registryBase})`);
    return new Promise(() => {});
  }

  if (sub === "install") {
    const tlds = await fetchTlds({ registryBase });
    if (!tlds.length) { out("no endings claimed yet — nothing to route"); return 1; }
    out(resolvedConf(tlds, { port }));
    out("# ...or, for dnsmasq:");
    out(dnsmasqConf(tlds, { port }));
    return 0;
  }

  if (sub === "service") {
    const platform = detectPlatform();
    if (!platform) { out(`unsupported platform: ${process.platform}`); return 1; }
    const verb = rest.find((a) => !a.startsWith("-"));
    if (verb !== "install" && verb !== "uninstall") {
      out("usage: moshpit-dns service <install|uninstall>");
      return 1;
    }
    const plan = verb === "install"
      ? installPlan({ platform, node: process.execPath, entry, port: requiredPort(platform, port), registryBase })
      : uninstallPlan({ platform });

    if (has("dry-run")) { out(`# service ${verb} on ${platform} — nothing below has been run`); out(describePlan(plan)); return 0; }

    const applied = await applyPlan(plan);
    for (const r of applied.results) {
      const what = r.step.kind === "run" ? `${r.step.command} ${r.step.args.join(" ")}` : r.step.path;
      out(`  ${r.ok ? "ok  " : "FAIL"} ${r.step.kind.padEnd(6)} ${what}${r.ok ? "" : ` — ${r.error}`}`);
    }
    for (const n of plan.notes || []) out(`  note   ${n}`);
    out(verb === "install"
      ? "\nThe bridge now comes back on its own. Routing is separate — `sudo moshpit-dns enable` if you have not."
      : "\nThe bridge no longer restarts itself. Routing is untouched: `sudo moshpit-dns disable` removes that.");
    return applied.ok ? 0 : 1;
  }

  if (sub === "enable" || sub === "disable" || sub === "refresh") {
    const platform = detectPlatform();
    if (!platform) { out(`unsupported platform: ${process.platform}`); return 1; }
    const wanted = requiredPort(platform, port);
    const linuxBackend = flag("backend", "systemd-resolved");

    let tlds = [];
    try { tlds = await fetchTlds({ registryBase }); } catch { tlds = []; }
    if (sub !== "disable" && !tlds.length) { out("no endings claimed yet — nothing to route"); return 1; }

    let plan;
    try {
      plan = sub === "disable"
        ? disablePlan({ platform, tlds, linuxBackend })
        : enablePlan({ platform, tlds, port: wanted, linuxBackend });
    } catch (err) { out(err.message); return 1; }

    if (has("dry-run")) { out(`# ${sub} on ${platform} — nothing below has been run`); out(describePlan(plan)); return 0; }

    if (plan.elevated && typeof process.getuid === "function" && process.getuid() !== 0) {
      out(`dns ${sub} edits system DNS and needs root.`);
      out(`  sudo moshpit-dns ${sub}${rest.length ? " " + rest.join(" ") : ""}`);
      out(`\nor see exactly what it would do first:\n  moshpit-dns ${sub} --dry-run`);
      return 1;
    }

    const applied = await applyPlan(plan);
    for (const r of applied.results) {
      const what = r.step.kind === "run" ? `${r.step.command} ${r.step.args.join(" ")}` : r.step.path;
      out(`  ${r.ok ? "ok  " : "FAIL"} ${r.step.kind.padEnd(6)} ${what}${r.ok ? "" : ` — ${r.error}`}`);
    }
    for (const n of plan.notes || []) out(`  note   ${n}`);

    if (sub === "refresh") {
      // Routing is a snapshot: arbitrary endings share no suffix, so each is
      // listed by name and one claimed later does not resolve until this runs.
      out(`\nRouting now covers ${tlds.length} endings.`);
      return applied.ok ? 0 : 1;
    }
    if (sub === "enable") {
      const started = await startDaemon({ port: wanted, registryBase, entry });
      out(started.alreadyRunning
        ? `  ok   bridge already running (pid ${started.pid})`
        : `  ok   bridge started on ${DEFAULT_HOST}:${wanted} (pid ${started.pid})`);
      out(`\nMoshpit names now resolve on this machine. Try: moshpit-dns resolve a.${tlds[0]}`);
      out("Routing covers the endings claimed right now — `sudo moshpit-dns refresh` after new ones.");
      out("The bridge does not survive a reboot yet: `moshpit-dns service install`.");
    } else {
      const stopped = await stopDaemon();
      out(stopped.stopped ? "  ok   bridge stopped" : "  ok   bridge was not running");
      out("\nMoshpit endings are back to your normal resolver.");
    }
    return applied.ok ? 0 : 1;
  }

  if (sub === "status") {
    const platform = detectPlatform();
    const daemon = await daemonStatus();
    const marker = routingMarker(platform);
    const routed = platform === "windows" ? null : existsSync(marker);
    const known = await fetchTlds({ registryBase }).catch(() => null);
    let routedCount = null;
    if (routed && known && platform === "linux") {
      const conf = await readFile(marker, "utf8").catch(() => "");
      routedCount = (conf.match(/~[a-z0-9-]+/g) || []).length;
    }

    const report = buildStatusReport({
      platform,
      daemon,
      routed,
      marker,
      known,
      routedCount,
      registry: registryBase,
    });

    if (json) {
      outJson(report);
      return 0;
    }

    out(`platform   ${platform || process.platform}`);
    out(`bridge     ${daemon.running ? `running (pid ${daemon.pid})`
      : daemon.stale ? `NOT running — stale pidfile for ${daemon.pid}` : "not running"}`);
    out(`routing    ${routed === null ? "(check NRPT: Get-DnsClientNrptRule)"
      : routed ? `configured (${marker})` : "not configured"}`);

    // The one state that makes names fail instead of falling through.
    if (routed && !daemon.running) {
      out("\n! routing is in place but the bridge is not running — Moshpit names will fail.");
      out("  fix: sudo moshpit-dns enable    undo: sudo moshpit-dns disable");
    }

    out(known ? `registry   reachable — ${known.length} endings claimed` : "registry   unreachable");

    if (report.needsRefresh) {
      out(`\n! routing covers ${routedCount} endings but ${known.length} are claimed — run \`sudo moshpit-dns refresh\``);
    }
    return 0;
  }

  out(`unknown: ${sub}\n\n${USAGE}`);
  return 1;
}
