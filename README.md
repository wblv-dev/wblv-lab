# wblv-lab-mcp

**Read-only homelab access for Claude Code, via MCP, with credentials vaulted in 1Password.**

Gives an AI assistant safe, live, *read-only* visibility into a homelab — query the OPNsense
firewall's state and logs, browse the Synology NAS, run Aruba switch `show` commands — without
ever holding an admin credential or being able to change anything. Creds are fetched from a
scoped 1Password vault at call time; nothing is persisted in plaintext.

---

## How it works

```
Claude ──MCP──▶ lab_mcp.py ──▶ labctl ──▶ op (1Password)  ──▶  lab devices
 (tools)        (FastMCP)      (backend)   curl / ssh           (read-only accounts)
                                              ▲
                              read-only creds from a scoped vault, per call
```

- **`lab_mcp.py`** — a FastMCP stdio server exposing structured tools to Claude.
- **`labctl`** — the backend CLI (also usable by a human). GET/`show`-only.
- **`op`** — the 1Password CLI, authenticated as a **read-only service account**, fetches creds
  on demand. No secrets on disk, no secrets in git.
- **`lab_discover.py`** — treats the vault as a host registry: resolves each device's **vendor
  live from the router's ARP table**, maps that to a role/access mechanism, and runs a **real
  liveness auth** per host (`alive:true` means a read-only login actually succeeded).

## Repo contents

| File | Purpose |
|------|---------|
| `scripts/lab_mcp.py`      | MCP server (the tools Claude sees) |
| `scripts/labctl`          | Backend CLI / human interface |
| `scripts/lab_discover.py` | `labctl hosts` — dynamic discovery + liveness |
| `scripts/switch_show.py`  | Aruba operator SSH driver (`pexpect`) |

## Prerequisites

- **macOS** (tested on macOS 26) or Linux
- CLI tools: [`op`](https://developer.1password.com/docs/cli/) ≥ 2.34, [`uv`](https://docs.astral.sh/uv/), `jq`, `nc`, `curl`, `ssh`
- **Claude Code**
- A 1Password plan that supports **service accounts** (Business/Teams)
- Read-only accounts on the devices you want to reach (see *Device setup*)

## Install

```bash
# 1. Drop the scripts in place
mkdir -p ~/.config/wblv && chmod 700 ~/.config/wblv
cp scripts/lab_mcp.py scripts/lab_discover.py scripts/switch_show.py ~/.config/wblv/
cp scripts/labctl /opt/homebrew/bin/labctl
chmod +x /opt/homebrew/bin/labctl ~/.config/wblv/*.py

# 2. (macOS only) if `op` was just installed via Homebrew and hangs on first run,
#    clear the notarization quarantine flag:
xattr -dr com.apple.quarantine "$(dirname "$(readlink -f "$(command -v op)")")" 2>/dev/null || true

# 3. Register the MCP server with Claude Code (user scope = all projects)
claude mcp add wblv-lab --scope user -- \
  "$(command -v uv)" run --with mcp --quiet python ~/.config/wblv/lab_mcp.py

# 4. Confirm
claude mcp list        # expect: wblv-lab ... ✔ Connected
```

The tools appear in Claude at the **start of the next session**.

## 1Password setup

1. **Create a dedicated vault** (e.g. `Lab-Claude`) that holds **only** read-only device creds.
   Keep your admin/root creds in a *separate* vault so the service account can never read them.
2. **Create a service account** with **read-only** access to *just* that vault. Copy its token.
3. **Store the token locally** (never in git or a synced folder):
   ```bash
   umask 077
   read -rs TOK && printf '%s' "$TOK" > ~/.config/wblv/op-token && unset TOK
   ```
4. **Add one item per device.** Put the device's address in the item's **website/URL** field so
   discovery can find and probe it. Read-only creds by device:

   | Device | Item fields | Notes |
   |--------|-------------|-------|
   | OPNsense  | `Key`, `Secret` | API key/secret of a **view-only** user (Diagnostics/Status/Firmware privileges). `key=`/`secret=` prefixes are stripped automatically. |
   | Synology  | `username`, `password` | Non-admin user, shares set to **Read-only**. |
   | Aruba sw  | `password`      | The **operator** password (login user is always `operator` = show-only). |

## Usage

**MCP tools** (what Claude calls):

| Tool | What it does |
|------|--------------|
| `lab_hosts()` | Inventory as JSON: vendor, role, access mechanism, reachability, **liveness**. Call first. |
| `lab_opnsense(path)` | Read-only GET of the OPNsense API, e.g. `diagnostics/firewall/log`. |
| `lab_nas(action, folder)` | `shares` lists readable shares; `ls` lists a folder. |
| `lab_switch(command)` | An Aruba operator `show` command, e.g. `show vlans`. |

**CLI** (same thing, for humans):

```bash
labctl hosts                     # inventory + liveness
labctl opnsense diagnostics/firewall/log
labctl nas shares
labctl switch "show version"
```

## Security model

- **Read-only by construction**, not just by convention: Synology ACL (`write=false`), Aruba
  **operator** level (no config mode), OPNsense scoped privileges — plus the tooling only ever
  issues GET/`show` requests.
- **Never** calls destructive/action endpoints (halt, reboot, apply, add, delete).
- Service account is **read-only and scoped to one vault**, so it can't even *read* admin creds.
- Credentials are fetched from 1Password **per call** and never written to disk.

## Extending

- **Add a host:** create a 1Password item in the vault with the device's URL + read-only creds.
  It shows up in `lab_hosts` automatically — the vault is the registry.
- **Add a device type:** add a `vendor → (role, access, port, verb)` entry in `lab_discover.py`
  and a handler branch in `labctl`.

## Gotchas learned the hard way

- **macOS Local Network Privacy** blocks Python sockets to *local-subnet* hosts (`No route to
  host`) while `nc`/`curl` work — so all probes use `nc`/`curl`, never `socket`.
- **Freshly Homebrew-cask-installed signed binaries** (like `op`) can hang on first launch during
  macOS notarization assessment. Clear the quarantine flag (install step 2) and let it cache.

---

> ⚠️ **Publishing note:** this repo documents a specific network (internal IPs, hostnames, device
> models). If you push it public, sanitize those or — simpler — **keep the repo private**.

_Built for the WBLV homelab. MIT-licensed; adapt freely._
