#!/usr/bin/env -S uv run --with mcp --quiet --script
"""wblv-lab as an MCP tool — one tool, read-only, no state.

WHY THIS SHELLS OUT INSTEAD OF IMPORTING
wblv_lab.py does its work at module level, so importing it would run the probes exactly once
and every later call would answer from that first result. A long-lived server holding a frozen
inventory is the precise failure this tool exists to prevent: no error, no staleness warning,
just a confident answer from a dead copy.

Spawning the CLI per call makes freshness structural rather than a thing to remember. It also
means the MCP surface and the human surface cannot drift, because they are the same program —
the same reasoning that put the deployed CLI behind a symlink instead of a second copy.

The CLI is located as a sibling of this file via a resolved path, so the server finds it
whether it is launched from the repository or through a symlink, and there is no absolute
path written down anywhere to go stale.
"""
import json
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

CLI = Path(__file__).resolve().parent / "wblv_lab.py"
KINDS = {"physical": "-p", "virtual": "-v", "service": "-s"}
TIMEOUT = 120   # every probe is bounded and they run in parallel; this is the outer backstop

mcp = FastMCP("wblv-lab")


@mcp.tool(
    annotations=ToolAnnotations(
        title="wblv-lab — lab directory",
        readOnlyHint=True,      # it only ever reads; it cannot change a device
        destructiveHint=False,
        idempotentHint=True,    # safe to repeat; repeating is in fact the point
        openWorldHint=True,     # answers come off the network, not from a fixed set
    )
)
def wblv_lab(kind: str = "") -> str:
    """What is alive in the lab and how to reach it.

    Returns every lab member with its address, MAC, whether it is reachable, whether a real
    read-only login actually succeeded, the URI to connect on, and which 1Password item holds
    the credential. Read the credential yourself and connect to the host directly — this tool
    reports, it does not broker.

    Membership comes from 1Password, detail from OPNsense, and state from a live probe run on
    every call. Nothing is cached, so a result is true when you receive it and not before.

    REACH and AUTH are separate answers to separate questions. REACH is a heartbeat and can be
    a false negative, because some hosts drop ICMP entirely. AUTH means a read-only login
    genuinely succeeded. Trust AUTH.

    Args:
        kind: optional filter — "physical", "virtual" or "service". Empty returns everything.
    """
    if kind and kind not in KINDS:
        raise ToolError(f"unknown kind {kind!r}; expected one of {', '.join(sorted(KINDS))}")

    argv = [str(CLI), "--json"] + ([KINDS[kind]] if kind else [])
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ToolError(f"wblv-lab exceeded {TIMEOUT}s — the probes did not all return")
    except OSError as e:
        raise ToolError(f"cannot execute {CLI}: {e}")

    # An empty result and a broken run must never look alike, so anything that is not valid
    # JSON is a fault and is reported as one rather than being passed on as an answer.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        detail = (proc.stderr or proc.stdout or "no output").strip()
        raise ToolError(f"wblv-lab produced no usable result (exit {proc.returncode}): {detail}")

    # The CLI reports its own faults as a single clean root cause; surface it as a tool error
    # so the failure arrives as a failure instead of as data with a hole in it.
    if "error" in data:
        raise ToolError(f"{data['error']}" + "".join(
            f"\n  {k}: {v}" for k, v in data.items() if k != "error"))

    return json.dumps(data, indent=2)


if __name__ == "__main__":
    mcp.run()
