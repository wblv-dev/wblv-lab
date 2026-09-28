# wblv-lab

What is alive in the lab, and how to reach it — **read-only**.

`wblv-lab` asks the lab's own authorities every time it runs — a password-manager vault for
*who belongs*, the router's IPAM for *where they are*, a real read-only login for *whether a
credential still works* — and prints one table. Nothing is cached or remembered, and it never
changes anything: it tells you which key opens a door; it does not turn it.

> **Status: rebuild in progress.** The 1Password layer works today (`wblv-lab` shows the
> *vault view*: what the vault declares, nothing probed yet). OPNsense IPAM and the live
> probes are next. The original macOS tool is kept verbatim in [`legacy/`](legacy/).

## Install

Ubuntu 22.04+ (including WSL2) or macOS, Python 3.10+:

```bash
curl -fsSL https://raw.githubusercontent.com/wblv-dev/wblv-lab/main/install.sh | bash
```

This installs for **your user** (`~/.local/share/wblv-lab`, command in `~/.local/bin`). It uses
sudo only to install missing system packages (`python3-venv`, `keyutils`, and optionally the
1Password CLI from 1Password's signed apt repo), and asks first. To read it before running it:

```bash
curl -fsSLO https://raw.githubusercontent.com/wblv-dev/wblv-lab/main/install.sh
less install.sh && bash install.sh
```

For every user on the machine: `... | sudo bash -s -- --system` (`/opt/wblv-lab`,
`/usr/local/bin`). `bash install.sh --help` lists `--ref`, `--dry-run`, `--uninstall` and more.

## Set up

1. **A vault and a read-only token.** In 1Password, put the lab's members in one vault and
   create a [service account](https://developer.1password.com/docs/service-accounts/) with
   **read-only** access to that vault only.
2. **Config.** `wblv-lab --init` writes `~/.config/wblv-lab/config.toml` (mode 600). Set
   `vault` to the vault's exact name — everything else has a working default, and every
   setting is explained in the file.
3. **Unlock.** `wblv-lab --unlock` asks for the service-account token (input hidden),
   checks it with 1Password, and holds it in the Linux kernel keyring for `unlock_hours`
   (default 12). It is never written to disk. `wblv-lab --lock` drops it early.
4. **Run.** `wblv-lab`

With no config at all, `wblv-lab` prints its header with dashes and says *Not configured* —
never an empty table, because "nothing found" and "never looked" are different answers.

## Vault conventions

Each member is an item whose fields carry what the tool needs. The labels are configurable
(`[fields]`); the defaults are `DNS Name`, `Website`, `Platform`, `Role`, `Expiry Date`. A member can have several credentials; the one the tool uses for its
read-only login is the item whose title ends with an identity suffix — `/READONLY` by default
(`[membership].identity_suffixes`), e.g. `NAS-01 / READONLY` next to `NAS-01 / BACKUP`.

## Output and exit codes

`--json` for scripts. Exit codes: **0** ran, **1** a fault (named, with one root cause),
**2** not configured. `wblv-lab -h` lists every flag; until the IPAM and probes land, a
configured run shows the vault view (and exits 1, because nothing was probed).

## Design

[`NOTES.md`](NOTES.md) records why the tool behaves as it does — including the places it
refuses to guess. [`legacy/NOTES.md`](legacy/NOTES.md) holds the original tool's rationale,
which still applies.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]' && .venv/bin/pytest
```

All tests are offline, against fixtures with fictional data.

## License

MIT — see [`LICENSE`](LICENSE).
