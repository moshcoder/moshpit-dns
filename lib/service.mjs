// Keeping the bridge alive across a reboot.
//
// Without this the bridge is a detached process: it dies with the machine while
// the routing it was installed alongside survives, and every Moshpit ending
// then points at a port nothing is listening on. That failure is worse than
// never having enabled it, because names stop resolving instead of falling
// through to the normal resolver.
//
// Each OS gets its own supervisor, and each is a *user* service rather than a
// system one — the bridge listens on 5354 and needs no privileges, so asking
// for root to keep it running would be asking for more than the job requires.
// Routing is the part that needs root, and that is a separate, one-off act.
//
//   macOS    ~/Library/LaunchAgents plist, RunAtLoad + KeepAlive
//   Linux    systemd --user unit, Restart=always, lingering for boot
//   Windows  a scheduled task at logon
//
// Plans are data here for the same reason they are in system.mjs: this writes
// files that survive reboots, and being able to read exactly what will be
// written before it is written is worth more than the brevity of not doing it.

import { homedir } from "node:os";
import { join } from "node:path";

export const SERVICE_NAME = "moshpit-dns";
export const SERVICE_LABEL = "sh.moshcode.moshpit-dns";

const write = (path, content, why) => ({ kind: "write", path, content, why });
const remove = (path, why) => ({ kind: "remove", path, why });
const run = (command, args, why) => ({ kind: "run", command, args, why });

/**
 * Install the bridge as something that comes back on its own.
 *
 * `node` and `entry` are passed in rather than discovered, because a service
 * definition outlives the shell that created it: whatever is on PATH today may
 * not be on the service's PATH tomorrow, and an absolute path is the only kind
 * that keeps meaning the same thing.
 */
export function installPlan({ platform, node, entry, port, registryBase, home = homedir() }) {
  const args = [entry, "start", "--port", String(port)];
  if (registryBase) args.push("--registry", registryBase);

  if (platform === "macos") {
    const path = join(home, "Library", "LaunchAgents", `${SERVICE_LABEL}.plist`);
    const argv = [node, ...args].map((a) => `    <string>${a}</string>`).join("\n");
    return {
      platform,
      elevated: false,
      steps: [
        write(path, plist(argv, home), "run the bridge at login and keep it up"),
        // Unload first so a reinstall replaces the old definition rather than
        // failing because the label is already loaded.
        run("launchctl", ["unload", "-w", path], "drop any previous definition"),
        run("launchctl", ["load", "-w", path], "start it now and at every login"),
      ],
      notes: ["launchd starts this at login, not at boot — it needs someone signed in."],
    };
  }

  if (platform === "linux") {
    const path = join(home, ".config", "systemd", "user", `${SERVICE_NAME}.service`);
    return {
      platform,
      elevated: false,
      steps: [
        write(path, unit(node, args), "run the bridge, restart it if it dies"),
        run("systemctl", ["--user", "daemon-reload"], "pick up the new unit"),
        run("systemctl", ["--user", "enable", "--now", `${SERVICE_NAME}.service`], "start it now and at login"),
        // Without lingering a --user service only runs while someone is logged
        // in, which is not what "survives a reboot" means on a server.
        run("loginctl", ["enable-linger"], "keep it running with nobody logged in"),
      ],
      notes: [],
    };
  }

  if (platform === "windows") {
    const cmd = `"${node}" ${args.map((a) => `"${a}"`).join(" ")}`;
    return {
      platform,
      elevated: false,
      steps: [
        run("schtasks", ["/create", "/f", "/tn", SERVICE_NAME, "/sc", "onlogon", "/tr", cmd],
          "run the bridge at logon"),
        run("schtasks", ["/run", "/tn", SERVICE_NAME], "and start it now"),
      ],
      notes: ["A scheduled task runs at logon. Windows has no per-user boot-time equivalent."],
    };
  }

  throw new Error(`unsupported platform: ${platform}`);
}

/** Take it back out. Leaves the routing alone — that is `disable`'s job. */
export function uninstallPlan({ platform, home = homedir() }) {
  if (platform === "macos") {
    const path = join(home, "Library", "LaunchAgents", `${SERVICE_LABEL}.plist`);
    return {
      platform,
      elevated: false,
      steps: [run("launchctl", ["unload", "-w", path], "stop it"), remove(path, "and forget it")],
      notes: [],
    };
  }
  if (platform === "linux") {
    const path = join(home, ".config", "systemd", "user", `${SERVICE_NAME}.service`);
    return {
      platform,
      elevated: false,
      steps: [
        run("systemctl", ["--user", "disable", "--now", `${SERVICE_NAME}.service`], "stop it"),
        remove(path, "and forget it"),
        run("systemctl", ["--user", "daemon-reload"], "pick up the removal"),
      ],
      notes: ["Lingering is left on — other user services may rely on it."],
    };
  }
  if (platform === "windows") {
    return {
      platform,
      elevated: false,
      steps: [run("schtasks", ["/delete", "/f", "/tn", SERVICE_NAME], "remove the scheduled task")],
      notes: [],
    };
  }
  throw new Error(`unsupported platform: ${platform}`);
}

function unit(node, args) {
  return `# Written by \`moshpit-dns service install\`.
[Unit]
Description=Moshpit DNS bridge
Documentation=https://github.com/moshcoder/moshpit-dns
After=network-online.target

[Service]
ExecStart=${node} ${args.join(" ")}
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`;
}

function plist(argv, home) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!-- Written by \`moshpit-dns service install\`. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${argv}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>${home}/Library/Logs/${SERVICE_NAME}.log</string>
</dict>
</plist>
`;
}
