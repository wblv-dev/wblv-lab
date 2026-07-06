#!/usr/bin/env python3
"""wblv-lab MCP server — READ-ONLY live access to the WBLV lab for Claude.
Thin stdio server over the `labctl` CLI (single backend). Headless: creds come from the
1Password service-account token file via labctl/op; no desktop app, no prompts.
"""
from mcp.server.fastmcp import FastMCP
import subprocess, json

mcp = FastMCP("wblv-lab")
LABCTL = "/opt/homebrew/bin/labctl"

def _run(args, timeout=45):
    try:
        r = subprocess.run([LABCTL, *args], capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.returncode and r.stderr else "")
    except subprocess.TimeoutExpired:
        return f"ERROR: `labctl {' '.join(args)}` timed out after {timeout}s"

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
    """List every WBLV lab host from the 1Password registry as JSON. For each host: vendor (live from
    the router's ARP), role, access mechanism, reachability, and a REAL liveness test — `alive:true`
    means a read-only auth actually SUCCEEDED (not just that it's listed). Call this FIRST to see what
    you can actually reach before querying a specific host."""
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
