# wblv-lab

**A dynamic information and context tool for Claude Code.**

`wblv-lab` tells you what is alive in the lab and how to reach it. That is all it does.

It is **not** a broker. It does not run your queries, wrap device APIs, or invent
vocabulary for things the device already names. It answers one question — *what exists,
is it up, and how do I get in* — then gets out of the way. You connect to the host
yourself, using the credential it points you at, and run commands there directly.

```
wblv-lab            every host and service
wblv-lab -p         physical hosts
wblv-lab -v         virtual hosts
wblv-lab -s         services
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

- **REACH** — a heartbeat: is it answering on the network. Can be a false negative; some
  hosts drop ICMP entirely.
- **AUTH** — a real read-only login actually succeeded. This is the signal to trust.

A host can be reachable and still be useless to you. Only `AUTH` proves otherwise.

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
