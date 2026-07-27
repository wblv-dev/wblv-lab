#!/usr/bin/env python3
"""wblv-lab MCP server — READ-ONLY live access to the WBLV lab for Claude.
Thin stdio server over the `labctl` CLI (single backend). Headless: creds come from the
1Password service-account token file via labctl/op; no desktop app, no prompts.
"""
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
import subprocess, json

mcp = FastMCP("wblv-lab")
LABCTL = "/opt/homebrew/bin/labctl"

def _run(args, timeout=45):
    """Run labctl and return its stdout. RAISES on any failure — never returns an error string.

    A failure must be distinguishable from data at the PROTOCOL level, not by the caller noticing
    a word in the text. Returning "ERROR: ... timed out" made a dead probe indistinguishable from
    a successful result that happens to mention an error, so the model would reason over a failure
    as though it were a fact — the exact thing this tool exists to prevent.

    FastMCP converts a raised exception into a CallToolResult with isError=true, so the client can
    tell the difference without parsing prose.
    """
    cmd = "labctl " + " ".join(args)
    try:
        r = subprocess.run([LABCTL, *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ToolError(
            f"labctl not found at {LABCTL}. The lab tooling is not installed or not on PATH on "
            f"this host, so NO lab state can be read. Do not answer from memory or from notes.")
    except subprocess.TimeoutExpired:
        raise ToolError(
            f"`{cmd}` timed out after {timeout}s. The lab may be unreachable. Lab state is "
            f"UNKNOWN for this call — do not substitute a remembered or previously-seen value.")
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise ToolError(f"`{cmd}` failed (exit {r.returncode}): {detail[:800] or 'no output'}")
    return r.stdout or ""

def _slice_rows(out, limit, action):
    """For JSON-array API responses, optionally filter by an 'action' field and cap to the
    newest `limit` rows (OPNsense returns the firewall log newest-first). Wraps the result so
    truncation is explicit. Non-array / non-JSON output is returned unchanged, so this stays
    safe for every other OPNsense path."""
    if not (limit or action):
        return out
    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        return out
    if not isinstance(data, list):
        return out
    total = len(data)
    if action:
        data = [r for r in data if isinstance(r, dict) and r.get("action") == action]
    matched = len(data)
    if limit and limit > 0:
        data = data[:limit]
    return json.dumps({"returned": len(data), "matched": matched, "total": total,
                       "note": "newest-first; filtered/truncated by lab_opnsense", "rows": data})

@mcp.tool()
def lab_hosts() -> str:
    """List the lab inventory as JSON, sourced from OPNsense host entries (the authoritative IPAM).
    Per host: ip, mac, role, has_creds, and TWO liveness signals — `reach` (mgmt-port/ICMP heartbeat:
    is it up on the network) and `auth` (did a READ-ONLY login/query actually succeed: true/false, or
    null where there are no creds / no read-only interface). Plus an `ipam_drift` check (inventory vs
    live ARP). Call this FIRST to see what you can actually reach before querying a specific host."""
    return _run(["hosts", "--json"])

@mcp.tool()
def lab_opnsense(path: str = "core/firmware/status", limit: int = 0, action: str = "") -> str:
    """Read-only GET against the OPNsense firewall REST API (returns JSON). Useful paths:
    'diagnostics/firewall/log' (live pass/block log — "what's breaking"),
    'diagnostics/firewall/pf_states', 'diagnostics/interface/get_arp',
    'diagnostics/system/system_resources', 'core/firmware/status'.
    Large array endpoints (esp. diagnostics/firewall/log — ~1000 rows / ~1MB) blow the token
    cap: pass limit=N to return only the newest N rows (the log is newest-first). Optionally
    pass action='block' (or 'pass') to keep only firewall-log rows with that action. limit and
    action are ignored for non-array responses, so they're safe on any path."""
    return _slice_rows(_run(["opnsense", path]), limit, action)

@mcp.tool()
def lab_nas(action: str = "shares", folder: str = "/") -> str:
    """Read-only Synology NAS (DS418play) query. action='shares' lists readable shares with
    read/write flags; action='ls' lists the folder given by `folder` (e.g. '/Media')."""
    args = ["nas", action] + ([folder] if action == "ls" else [])
    return _run(args)

@mcp.tool()
def lab_switch(command: str = "show system") -> str:
    """Run a read-only Aruba 2930F operator 'show' command over SSH. Operator level = show-only
    (no config). Examples: 'show version', 'show system', 'show vlans', 'show interfaces brief',
    'show lldp info remote-device', 'show mac-address'."""
    return _run(["switch", command])

if __name__ == "__main__":
    mcp.run()
