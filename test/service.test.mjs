// Keeping the bridge alive across a reboot.
//
// Plans are data, so every OS is testable from any OS — which is the only way
// the launchd and Windows paths get exercised at all.
import assert from "node:assert/strict";
import test from "node:test";

import { SERVICE_LABEL, SERVICE_NAME, installPlan, uninstallPlan } from "../lib/service.mjs";

const HOME = "/home/someone";
const base = { node: "/usr/bin/node", entry: "/opt/moshpit-dns/bin/moshpit-dns.mjs", port: 5354, home: HOME };

test("linux installs a user unit that restarts and survives logout", () => {
  const plan = installPlan({ ...base, platform: "linux" });
  const unit = plan.steps.find((s) => s.kind === "write");

  assert.equal(unit.path, `${HOME}/.config/systemd/user/${SERVICE_NAME}.service`);
  assert.match(unit.content, /Restart=always/);
  assert.match(unit.content, /ExecStart=\/usr\/bin\/node \/opt\/moshpit-dns/);

  // A --user service without lingering only runs while someone is logged in,
  // which is not what "survives a reboot" means on a server.
  assert.ok(plan.steps.some((s) => s.command === "loginctl" && s.args.includes("enable-linger")));
  assert.equal(plan.elevated, false, "the bridge needs no privileges — only routing does");
});

test("macOS installs a LaunchAgent that reloads cleanly", () => {
  const plan = installPlan({ ...base, platform: "macos" });
  const agent = plan.steps.find((s) => s.kind === "write");

  assert.equal(agent.path, `${HOME}/Library/LaunchAgents/${SERVICE_LABEL}.plist`);
  assert.match(agent.content, /<key>RunAtLoad<\/key>\s*<true\/>/);
  assert.match(agent.content, /<key>KeepAlive<\/key>\s*<true\/>/);

  // Unload before load, or a reinstall fails because the label is already there.
  const cmds = plan.steps.filter((s) => s.kind === "run").map((s) => s.args[0]);
  assert.deepEqual(cmds, ["unload", "load"]);
  assert.match(plan.notes.join(" "), /at login, not at boot/);
});

test("windows registers a logon task", () => {
  const plan = installPlan({ ...base, platform: "windows", port: 53 });
  const create = plan.steps[0];

  assert.equal(create.command, "schtasks");
  assert.ok(create.args.includes("onlogon"));
  assert.ok(create.args.includes("/f"), "overwrite, so reinstalling is not an error");
  // The command has to survive being read back out of the task scheduler.
  assert.match(create.args.at(-1), /"\/usr\/bin\/node" "\/opt\/moshpit-dns/);
});

test("absolute paths, because a service outlives the shell that made it", () => {
  for (const platform of ["linux", "macos", "windows"]) {
    const text = JSON.stringify(installPlan({ ...base, platform }));
    assert.ok(text.includes("/usr/bin/node"), `${platform} should not rely on PATH`);
  }
});

test("the port and registry ride along into the definition", () => {
  const plan = installPlan({
    ...base,
    platform: "linux",
    port: 5399,
    ttl: 86400,
    registryBase: "https://my.pit",
  });
  const unit = plan.steps.find((s) => s.kind === "write");
  assert.match(unit.content, /--port 5399/);
  assert.match(unit.content, /--ttl 86400/);
  assert.match(unit.content, /--registry https:\/\/my\.pit/);
});

test("the TTL is preserved by every service definition", () => {
  const linux = installPlan({ ...base, platform: "linux", ttl: 0 });
  assert.match(linux.steps.find((s) => s.kind === "write").content, /--ttl 0/);

  const macos = installPlan({ ...base, platform: "macos", ttl: 0 });
  assert.match(
    macos.steps.find((s) => s.kind === "write").content,
    /<string>--ttl<\/string>\s*<string>0<\/string>/,
  );

  const windows = installPlan({ ...base, platform: "windows", ttl: 0 });
  assert.match(windows.steps[0].args.at(-1), /"--ttl" "0"/);
});

test("the registry timeout is preserved by every service definition", () => {
  const linux = installPlan({ ...base, platform: "linux", timeoutMs: 1500 });
  assert.match(linux.steps.find((s) => s.kind === "write").content, /--timeout 1500/);

  const macos = installPlan({ ...base, platform: "macos", timeoutMs: 1500 });
  assert.match(
    macos.steps.find((s) => s.kind === "write").content,
    /<string>--timeout<\/string>\s*<string>1500<\/string>/,
  );

  const windows = installPlan({ ...base, platform: "windows", timeoutMs: 1500 });
  assert.match(windows.steps[0].args.at(-1), /"--timeout" "1500"/);
});

test("uninstall stops it and forgets it, and leaves routing alone", () => {
  for (const platform of ["linux", "macos", "windows"]) {
    const plan = uninstallPlan({ platform, home: HOME });
    const text = JSON.stringify(plan);
    // Routing is root's business and a separate act; pulling the service must
    // not silently un-route the machine.
    assert.ok(!text.includes("/etc/resolver"), platform);
    assert.ok(!text.includes("resolved.conf.d"), platform);
    assert.ok(plan.steps.length > 0, platform);
  }
});

test("an unsupported platform is an error, not a silent no-op", () => {
  assert.throws(() => installPlan({ ...base, platform: "plan9" }), /unsupported platform/);
  assert.throws(() => uninstallPlan({ platform: "plan9" }), /unsupported platform/);
});
