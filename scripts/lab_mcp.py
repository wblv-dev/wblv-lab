#!/usr/bin/env python3
"""wblv-lab MCP server — READ-ONLY live access to the WBLV lab for Claude.
Thin stdio server over the `labctl` CLI (single backend). Headless: creds come from the
1Password service-account token file via labctl/op; no desktop app, no prompts.
"""
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("wblv-lab")
LABCTL = "/opt/homebrew/bin/labctl"

def _run(args, timeout=45):
    try:
        r = subprocess.run([LABCTL, *args], capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.returncode and r.stderr else "")
    except subprocess.TimeoutExpired:
        return f"ERROR: `labctl {' '.join(args)}` timed out after {timeout}s"

@mcp.tool()
def lab_hosts() -> str:
    """List every WBLV lab host from the 1Password registry as JSON. For each host: vendor (live from
    the router's ARP), role, access mechanism, reachability, and a REAL liveness test — `alive:true`
    means a read-only auth actually SUCCEEDED (not just that it's listed). Call this FIRST to see what
    you can actually reach before querying a specific host."""
    return _run(["hosts", "--json"])

@mcp.tool()
def lab_opnsense(path: str = "core/firmware/status") -> str:
    """Read-only GET against the OPNsense firewall REST API (returns JSON). Useful paths:
    'diagnostics/firewall/log' (live pass/block log — "what's breaking"),
    'diagnostics/firewall/pf_states', 'diagnostics/interface/get_arp',
    'diagnostics/system/system_resources', 'core/firmware/status'."""
    return _run(["opnsense", path])

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
