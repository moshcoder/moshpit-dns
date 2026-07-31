#!/usr/bin/env node
// The command-line entry. Everything it does lives in run(), so `moshcode dns`
// and anything else can call the same code without spawning a process.
import { run } from "./moshpit-dns.mjs";
process.exitCode = (await run()) || 0;
