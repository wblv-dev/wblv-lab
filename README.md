# wblv-lab

**A dynamic information and context tool for Claude Code.**

`wblv-lab` tells you what is alive in the lab and how to reach it. That is all it does.

```
wblv-lab            every host and service
wblv-lab -p         physical hosts
wblv-lab -v         virtual hosts
wblv-lab -s         services
wblv-lab --mac      add the MAC column
wblv-lab --check    swap ACCESS for what each probe actually did
wblv-lab --json     machine-readable
```

## Why it exists

An assistant working on live infrastructure fails in one specific way: it answers from
something *remembered* instead of something *checked*. A note written last week, a value
that moved, an address it never had access to and quietly guessed at.

`wblv-lab` exists so the answer is always taken from the thing itself. It runs at session
start, so the context window opens with current state rather than recalled state. Nothing
it reports is cached, and nothing it reports is written down anywhere.

**If it is not in `wblv-lab`, it does not exist.** The tool is a whitelist, not a
catalogue — something appears because it is registered, not because someone remembered to
add it to a list.

## Where the truth comes from

| Question | Authority |
|---|---|
| What is in the lab? | **1Password** — a vault item is what makes something a member |
| What is its name, address, MAC? | **OPNsense** — DNS and Dnsmasq reservations are the IPAM |
| Is it up? | **A live probe**, not a status field |
| Can I actually log in? | **A real read-only login**, attempted every run |
| How do I get in? | The access mechanism, and which 1Password item holds the credential |

Two things fall out of that rather than being designed in:

- **Onboarding is data, not code.** Add a `WBLV-<HOST> / CLAUDE` item with the host URL
  set and it appears. Nothing to edit, nothing to deploy.
- **Non-members never appear.** The workstation and the control node have no vault item,
  so they are absent from the directory — because they are not lab infrastructure.

## REACH and AUTH are different questions

Kept separate deliberately, because health checks lie.

- **REACH** — a heartbeat: is it answering. Can be a false negative; some hosts drop ICMP
  entirely.
- **AUTH** — a real read-only login actually succeeded. This is the signal to trust.

A host can be reachable and still be useless to you. Only `AUTH` proves otherwise.

### What REACH measures depends on what the member is

A host has an address, so the heartbeat is that address answering. A service has no address
in this lab — only a vendor's URL — and a TCP handshake with `portal.azure.com` proves
Microsoft is running. That is true on every day this tool will ever run, and says nothing
about whether *your* tenant exists. A green light wired to the wrong thing is worse than no
light at all.

So `REACH` is measured three ways, and `--json` reports which one in `reach_basis`:

| basis | meaning |
|---|---|
| `endpoint` | the member's own address answered (`nc` / `ping`, raced) |
| `tenant` | a tenant-scoped call answered — proof *this* tenant is there. M365 uses Entra's per-tenant OIDC discovery document, which needs no credential and returns `400 AADSTS90002` for a tenant that does not exist |
| `derived` | the auth probe reached it, and nothing weaker could. You cannot be rejected by something you did not reach, so a *rejected* credential proves reach as well as an accepted one |
| `untested` | nothing could be measured — no probe exists, or every probe failed in transit. `REACH` is `-`, never `up` |

`derived` is not a weaker answer, it is a narrower one: a Tailscale tailnet is deliberately
not publicly discoverable, and neither is a 1Password account, so there is nothing to
measure there without authenticating. The two signals then carry one measurement between
them — which `reach_basis` makes visible rather than leaving implied.

Deriving reach only works because a probe now reports **untested** (`None`) when the
transfer never completed, and **failed** (`False`) only when the far end actually said no.
Conflating those meant an outage rendered as `REACH up / AUTH fail` — every service green
on the heartbeat while nothing had been reached, and the credential wrongly blamed.

Both are measured **from the machine running the tool**, which is why its own zone is
printed. `rpi-01 / LAN / up` only means "a pinhole is open" if you know the prober is in
`ADM`.

## ACCESS is where you connect, not what was checked

`ACCESS` answers *how do I get in*. For a host that is also what the probe hit, so the two
coincide. For a service it is the **admin console** — `portal.azure.com`, not
`login.microsoftonline.com` — and deliberately not what the probe talks to. Nobody logs in
to `api.github.com`.

Sitting between `ADDRESS` and `REACH`, that column reads as the thing those signals
measured, and for a service it never was. `--check` swaps it for what was actually
contacted:

```
rpi-01   physical   up     ok    ssh claude@rpi-01.wblv.uk (3)
wap-01   physical   down   -     tcp wap-01.wblv.uk:443 (2)
365-01   service    up     ok    login.microsoftonline.com (4)
git-01   service    up     ok    api.github.com (4)
ops-01   service    up     ok    op whoami
```

The cell names the operation that produced `AUTH` — or the reach test, where no login was
attempted — and in brackets how many operations ran in total. So `wap-01`, which has no
probe written, still reports what was tried instead of going blank.

Same column, so the table does not grow. `--json` adds `probe_ops` with every operation in
full — paths included — since there is no width to spend there. That is where you can see
`365-01` verified `portal.azure.com` as well as authenticating against
`login.microsoftonline.com`: `CHECK` covers both `REACH` and `AUTH`.

**It is recorded, not described.** The probe helpers append what they ran, and the column
reads that back. A hand-written table of "what each platform does" would be a fact that
goes stale silently: add an Omada probe and it would still say *no probe*; change how a
credential is exercised and it would still claim the old method. Same failure as writing a
device's address into a note. Adding a probe makes its row describe itself, with no second
place to update.

A member with nothing recorded shows `-` — the same dash `REACH` and `AUTH` use, meaning
the same thing: nothing was measured. `wap-01` reports its reach test today and will name
an Omada endpoint the moment that probe exists, without anyone editing a description.

Only the operation is recorded, never its credentials — the URL without its query string,
the command without its arguments.

## ZONE and FAULT

Two columns that exist to stop different things from looking alike.

**ZONE** is the OPNsense interface a host answers on. Zones do not route to each other
freely, so it is frequently *why* a host is unreachable — and without it, "blocked by
design" and "broken" are the same output.

**FAULT** is blank on a healthy row, so the absence of a fault is as visible as its
presence. It names what disagrees and nothing else:

| | |
|---|---|
| `url` | the vault item's URL field holds no usable hostname |
| `ip` | the DHCP reservation and the live address differ — a lease that outlived the change that created it |
| `tag` | the declared type and what the wire says disagree |

A fault is a defect in the **vault entry or the IPAM**, never in the host. Without the
column a broken entry rendered exactly like a service that legitimately has no endpoint.

`Non-members` counts addresses OPNsense can see that no vault item claims — how much of
the wire the directory accounts for. It is a coverage figure, not a fault.

## What it will not do

- **It will not guess.** No fallback addresses, no default hosts, no assumed values. If a
  lookup fails it errors and names the fault. A wrong answer that looks right is worse
  than no answer at all.
- **It will not remember.** No hardcoded addresses, no cached inventory, no local copy of
  state. The only seed is the machine's own resolver; everything else is asked for, every
  time. That costs response time and buys accuracy.
- **It will not turn the key.** It tells you which credential opens a host; reading it and
  connecting is yours to do. The read-only guarantee therefore lives in the **host
  account**, where it cannot be bypassed by using a different tool.

## Layout

```
wblv_lab.py       the tool
wblv_lab_mcp.py   MCP server exposing it as a single read-only tool
```

Credentials and tokens live in `~/.config/wblv/` and are never in this repository.

## Requirements

macOS or Linux · [`op`](https://developer.1password.com/docs/cli/) (1Password CLI, as a
read-only service account scoped to one vault) · `python3` · `nc` · `curl`

---

*Read-only by design. It can look; it can never touch. Device changes are done by hand,
deliberately.*
