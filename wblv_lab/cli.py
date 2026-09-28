"""wblv-lab command line: flags -> views.

Exit codes are part of the interface, because a hook or a script cannot read a table:
  0  a run completed
  1  a fault — bad flag, broken config, an authority that could not be read
  2  not configured — no config at the default location, so nothing was probed
See NOTES.md#cli-unconfigured-is-not-empty.
"""
from __future__ import annotations

import difflib
import json
import os
import socket
import sys
import time
from importlib import resources

from . import config as C

EXIT_OK, EXIT_FAULT, EXIT_UNCONFIGURED = 0, 1, 2

VIEW_FLAGS = ("-p", "-v", "-s", "--mac", "--check", "--json", "--test", "--brief", "--howto",
              "--others")
ACTION_FLAGS = ("--init",)
VALUE_FLAGS = ("--config",)
HELP_WORDS = ("-h", "--help", "help")
KNOWN = VIEW_FLAGS + ACTION_FLAGS + VALUE_FLAGS + HELP_WORDS[:2]

EXAMPLE = "config.example.toml"

HELP = f"""wblv-lab — what is alive in the lab, and how to reach it. Read-only.

  wblv-lab              every host and service
  wblv-lab -p | -v | -s physical hosts | virtual hosts | services only
  wblv-lab --mac        add the MAC column
  wblv-lab --check      swap ACCESS for what each probe actually did
  wblv-lab --json       machine-readable
  wblv-lab --brief      counts + members + only what is NOT normal
  wblv-lab --howto [ID] the exact call that logs in to each member (or just one)
  wblv-lab --others     what is on the wire that the directory does NOT claim
  wblv-lab --test       every view in turn, from a single probe pass
  wblv-lab --init       write a starter config (never overwrites one)
  wblv-lab --config PATH   use this config file
  wblv-lab -h           this text

Configuration says WHERE to ask — which vault, which token, which platform serves the IPAM —
never what the answer is. It is read from exactly one place, first match wins:
  --config PATH   >   ${C.ENV_VAR}   >   $XDG_CONFIG_HOME/{C.APP_DIR}/{C.FILE_NAME}
                                        (~/.config/{C.APP_DIR}/{C.FILE_NAME})

Membership comes from the secrets vault: an item is what makes something a member, so adding
one is the whole of onboarding. Detail comes from the IPAM. Nothing is cached.

REACH is a heartbeat. AUTH is a real read-only login. Trust AUTH. A dash means NOT MEASURED,
never "down" and never "fine".

Exit codes: 0 ran, 1 fault, 2 not configured (nothing was probed)."""


class Usage(Exception):
    pass


def parse_args(argv: list[str]) -> dict:
    """Unknown flags die loud — an ignored typo silently renders a different view than the one
    asked for (legacy NOTES.md#unknown-flag-dies)."""
    flags, cfg, only = set(), None, None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--config" or a.startswith("--config="):
            if a == "--config":
                i += 1
                if i >= len(argv) or argv[i].startswith("-"):
                    raise Usage("--config needs a path")
                cfg = argv[i]
            else:
                cfg = a.split("=", 1)[1]
                if not cfg:
                    raise Usage("--config needs a path")
        elif a.startswith("-"):
            if a not in KNOWN:
                near = difflib.get_close_matches(a, KNOWN, n=1)
                raise Usage(f"unknown option: {a}" + (f" — did you mean {near[0]}?" if near else ""))
            flags.add(a)
        else:
            # one positional, and only where it means something — a bare word must never
            # silently become a filter
            if "--howto" not in argv or only is not None:
                raise Usage(f"unexpected argument: {a}")
            only = a
        i += 1
    if "--init" in flags and flags - {"--init", "--json"}:
        raise Usage("--init takes only --config and --json")
    return {"flags": flags, "config": cfg, "only": only}


# --- output ---------------------------------------------------------------------------------

def _console(cfg: C.Config | None = None):
    from rich.console import Console
    fallback = cfg.output.non_tty_columns if cfg else C.Output().non_tty_columns
    width = None if sys.stdout.isatty() else int(os.environ.get("COLUMNS") or fallback)
    return Console(width=width, highlight=False)


def _field(con, label, value, style=""):
    v = f"[{style}]{value}[/]" if style else str(value)
    con.print(f"[dim]{label + ':':<15}[/]{v}")


def _now():
    # Time leads: everything below it is a measurement (legacy NOTES.md#time-leads)
    return (time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            + f"  [dim](local {time.strftime('%H:%M %Z', time.localtime())})[/]")


def _prober():
    return socket.gethostname().split(".")[0].lower()


def die(msg: str, json_mode: bool, lines: list[str] | None = None, **extra) -> int:
    """One clean root cause, never a stack trace (legacy tool's die(), unchanged in spirit)."""
    if json_mode:
        payload = {"error": msg, **extra}
        if lines:
            payload["problems"] = lines
        print(json.dumps(payload, indent=2))
    else:
        print(f"wblv-lab: {msg}", file=sys.stderr)
        for line in lines or []:
            print(f"  {line}", file=sys.stderr)
        for k, v in extra.items():
            print(f"          {k}: {v}", file=sys.stderr)
    return EXIT_FAULT


def unconfigured(e: C.ConfigNotFound, json_mode: bool) -> int:
    """Nothing was probed, and the output must say so in every field — dashes, never zeros.
    A zero is a measurement; see NOTES.md#cli-unconfigured-is-not-empty."""
    hint = f"run `wblv-lab --init`, or pass --config PATH, or set ${C.ENV_VAR}"
    if json_mode:
        print(json.dumps({"error": "not configured", "config_path": str(e.path),
                          "config_from": e.why, "hint": hint}, indent=2))
        return EXIT_UNCONFIGURED
    con = _console()
    DASH = "[grey35]-[/]"
    _field(con, "Time", _now())
    _field(con, "Config", f"[yellow]not found[/] — {e.path} [dim]({e.why})[/]")
    _field(con, "Vault", DASH)
    _field(con, "Source", DASH)
    _field(con, "Probing from", _prober())
    con.print()
    for label in ("Hosts", "Services", "Reachable", "Authenticated", "Faults", "Non-members"):
        _field(con, label, DASH)
    con.print()
    con.print("[bold yellow]Not configured. Nothing was probed.[/]")
    con.print(f"  Create one:       [cyan]wblv-lab --init[/]   [dim]writes {e.path}[/]")
    con.print(f"  Or point at one:  [cyan]wblv-lab --config PATH[/]  [dim]or[/]  "
              f"[cyan]export {C.ENV_VAR}=PATH[/]")
    con.print("  Only [bold]\\[secrets].vault[/] is required.")
    return EXIT_UNCONFIGURED


def do_init(opts: dict, env, json_mode: bool) -> int:
    path, why = C.resolve(opts["config"], env)
    if path.exists():
        return die(f"refusing to overwrite the existing config at {path}", json_mode,
                   hint="edit it, or move it aside first")
    text = resources.files("wblv_lab").joinpath(EXAMPLE).read_text(encoding="utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # O_EXCL: if something appears at the path between the check and the write, fail
        # rather than overwrite it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as err:
        return die(f"could not write {path}: {err.strerror or err}", json_mode)
    if json_mode:
        print(json.dumps({"created": str(path), "config_from": why}, indent=2))
    else:
        print(f"wrote {path}\n"
              "next:  set [secrets].vault in it, and put the secrets-provider token at the\n"
              "       [secrets].token_file path (default: next to the config). Then run wblv-lab.")
    return EXIT_OK


# --- entry ----------------------------------------------------------------------------------

def main(argv: list[str] | None = None, env=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    env = os.environ if env is None else env
    # help is read before any work, and before flag validation, so it always answers
    if set(HELP_WORDS) & set(argv):
        print(HELP)
        return EXIT_OK
    json_mode = "--json" in argv
    try:
        opts = parse_args(argv)
    except Usage as e:
        return die(str(e), json_mode, hint="wblv-lab -h")

    if "--init" in opts["flags"]:
        return do_init(opts, env, json_mode)

    try:
        cfg = C.load(opts["config"], env)
    except C.ConfigNotFound as e:
        if e.why == C.ConfigNotFound.DEFAULT:
            return unconfigured(e, json_mode)
        # a path someone NAMED that is not there is a typo, not a first run
        return die(e.problems[0], json_mode)
    except C.ConfigError as e:
        return die(f"invalid config {e.source}", json_mode, lines=e.problems)

    # The directory itself (vault -> IPAM -> probes -> table) is the next layer to be built.
    # Until it exists, a valid config must not render anything that looks like a result.
    return die("configured, but this build cannot read the lab yet — the member directory "
               "is still being written", json_mode, config=str(cfg.source),
               vault=cfg.secrets.vault)


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
