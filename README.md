# @moshcoder/moshpit-dns

Resolve Moshpit names on this machine — from curl, any browser, any program.

```sh
npm i -g @moshcoder/moshpit-dns
sudo moshpit-dns enable
moshpit-dns service install     # keep it running across reboots
```

Zero dependencies. Everything comes from `node:` builtins.

## Why it exists

The Moshpit registry speaks HTTP, not DNS. `pit.moshcode.sh` answers
`/api/moshpit/resolve?name=…` and nothing listens on port 53, so
`curl https://california.oranges/` fails everywhere. A browser extension that
redirects tabs works, but redirecting is not resolving, and nothing outside that
browser benefits from it.

This is the bridge: a tiny authoritative resolver that answers A queries for
Moshpit endings out of the registry's HTTP API, and is deliberately silent about
everything else.

## One suffix, not your whole resolver

Each OS has a way to send *one suffix* to a different nameserver without
becoming the resolver for everything, and this uses that on each:

| | |
|---|---|
| macOS | `/etc/resolver/<tld>`, read per query — nothing to restart |
| Linux | systemd-resolved `Domains=~tld` routing-only domains, or dnsmasq |
| Windows | one NRPT rule per namespace |

That choice is the whole safety story. Becoming the machine's nameserver would
put every lookup on the box behind this bridge; routing only Moshpit endings
means the worst failure is that Moshpit names stop working.

## Commands

```
moshpit-dns enable            route the endings here and start the bridge
moshpit-dns disable           undo both
moshpit-dns status            what is running, what is routed, does it work
moshpit-dns refresh           re-apply routing for endings claimed since

moshpit-dns service install   keep the bridge running across reboots
moshpit-dns service uninstall stop doing that

moshpit-dns tlds              list the endings claimed in the Pit
moshpit-dns resolve <name>    what a name resolves to, and why
moshpit-dns start             run the bridge in the foreground
moshpit-dns install           print the resolver config without applying it
```

`--dry-run` prints the exact file contents and commands before anything runs.
This edits system DNS under sudo, so being inspectable first is the point.

## What needs root, and what does not

Only `enable`, `disable` and `refresh` — the acts that edit system DNS. The
bridge listens on 5354 and the service that keeps it alive is a *user* service,
so nothing else asks for privileges.

**Windows is the exception on port**: an NRPT rule has nowhere to put one, so
the bridge must be on 53 there. Refused at plan time with the reason, rather
than producing a rule that points at a port nothing is listening on.

## Two states worth knowing

**Routing up, bridge down.** Names *fail* instead of falling through to your
normal resolver. `status` says so loudly, and `service install` is what stops it
happening after a reboot.

**Routing is a snapshot.** Arbitrary endings share no common suffix, so every
one is listed by name. An ending claimed after you enabled will not resolve
until `sudo moshpit-dns refresh`. `status` compares the counts and tells you
when they have drifted.

## Self-hosting

`--registry https://your.pit` anywhere, and the routing follows it. Nothing
here is specific to `pit.moshcode.sh` beyond the default.

## License

MIT.
