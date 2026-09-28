# wblv-lab — agent briefing

You are helping rebuild `wblv-lab`: a **read-only** tool that reports what is alive in the
lab and how to reach it. Read `legacy/README.md` before changing anything.

## Doctrine (do not trade these away)

- **Checked, not remembered.** Every run asks the authorities again. No caches, no stored
  inventory, no hardcoded addresses or hostnames.
- **The config holds pointers, never facts.** It may say *where* the inventory lives
  ("the member whose Platform is opnsense, Dnsmasq backend"). It must never say *what* is in
  the lab (an IP, a hostname, a member list). If you are about to put a lab fact in config or
  code, stop.
- **Vendor knowledge lives in code; lab knowledge lives in the vault or the config.** An API
  path, a token format, a DSM session name are vendor facts. A host name is not.
- **Tri-state results.** `True` = succeeded, `False` = the far end said no, `None` = not
  measured. Never collapse `None` into `False`. A dash in output means *untested*, not *down*.
- **It will not guess.** No fallback addresses, no default hosts. A failed lookup dies loud
  with one clean root cause (`die()`), never a traceback and never a plausible wrong answer.
- **It will not turn the key.** It reports which credential opens a member; it never
  performs changes. Probes are real *read-only* logins.
- **Credentials never reach output.** Output rows are built from an explicit whitelist;
  secrets are held apart (`CREDS`) and never in argv (use stdin / `--config -`).
- **AI-agnostic.** No assistant/vendor names in code, config keys, vault conventions or
  output. The Jira "hands" value for the assistant is a config setting.

## Working rules

- `legacy/` is the original implementation, kept verbatim as reference. Do not edit it.
- Comments marked `deliberate` or `⚠ deliberate` encode a past incident. Preserve the
  behaviour when porting, even if it looks odd; ask before changing it.
- Unknown CLI flags and unknown config keys must fail loudly, never be ignored.
- This sandbox has no lab network access and no 1Password token by design. Write code and
  offline tests (fixtures of API responses); do not try to reach lab hosts.
- Never write a secret, token, or real lab address into this repository, including tests.
  Fixtures use documentation ranges (192.0.2.0/24, 198.51.100.0/24) and example.test names.

## Target layout

```
wblv_lab/
  config.py     load + validate TOML (tomllib), die on unknown keys
  secrets/      1password.py      — list members, read fields
  ipam/         opnsense.py       — dnsmasq | kea | unbound backends
  probes/       one module per vendor dialect
  tasks/        jira.py
  render.py     table / --brief / --json / --howto / --tasks / --others
  cli.py        flags -> views
  mcp.py        read-only MCP wrapper
tests/          offline, fixture-driven
```

## Known porting defects in legacy (macOS -> Linux)

- `ping -c 1 -t N` — on Linux `-t` is TTL, not timeout. Use `-W N` on Linux.
- `nc -z -G N` — `-G` is macOS-only. Use `-w N` on Linux.
- Prober identity/zone is derived from the local hostname; in a WSL/Tailscale setup the
  traffic egresses as a different device. Report what is known, do not guess a zone.
