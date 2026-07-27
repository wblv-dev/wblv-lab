#!/usr/bin/env python3
"""wblv-lab MCP server — READ-ONLY live access to the WBLV lab for Claude.
Thin stdio server over the `labctl` CLI (single backend). Headless: creds come from the
1Password service-account token file via labctl/op; no desktop app, no prompts.
"""
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
import subprocess, json, shutil

mcp = FastMCP("wblv-lab")

# Resolved from PATH, not hardcoded to a Homebrew prefix — the install location is not this
# tool's business to know. No fallback path: if labctl is absent, `subprocess.run` raises
# FileNotFoundError and _run turns that into a named ToolError. A fallback would only convert a
# clear "not installed" into a confusing "not found at some path you don't use".
LABCTL = shutil.which("labctl") or "labctl"

# The read-only contract, expressed in the protocol rather than in prose. A docstring can only
# CLAIM read-only; an annotation lets a client enforce it.
#   readOnlyHint  — true for every tool here: every path is a GET / show / read-only login.
#   openWorldHint — true: these query live external devices whose state we do not control.
#   idempotentHint— only set where repeat calls genuinely have no additional effect. Deliberately
#                   NOT set on lab_hosts/lab_nas: both perform DSM logins, and repeated Synology
#                   auth cycles churn sessions and can trip DSM's auto-block. "Read-only" and
#                   "free to repeat" are different claims and conflating them would be a lie.
RO = dict(readOnlyHint=True, openWorldHint=True)

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
        where = f"at {LABCTL}" if LABCTL != "labctl" else "on PATH"
        raise ToolError(
            f"labctl not found {where}. The lab tooling is not installed on this host, so NO lab "
            f"state can be read at all. Do not answer from memory or from notes — say so instead.")
    except subprocess.TimeoutExpired:
        raise ToolError(
            f"`{cmd}` timed out after {timeout}s. The lab may be unreachable. Lab state is "
            f"UNKNOWN for this call — do not substitute a remembered or previously-seen value.")
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise ToolError(f"`{cmd}` failed (exit {r.returncode}): {detail[:800] or 'no output'}")
    return r.stdout or ""

# Context-safety ceilings. These are DEFAULTS, not opt-ins — a guard you have to remember to
# switch on is not a guard. `diagnostics/firewall/log` returns ~830,000 characters (~200k tokens):
# one unguarded call ends the session, with no error, because an oversized success is still a
# success. The row cap handles arrays; the char ceiling is the backstop for everything else,
# since a non-array endpoint can be just as large.
MAX_CHARS = 40_000     # hard ceiling on any single response, applied last, always
DEFAULT_ROWS = 50      # default row cap for JSON arrays; limit<=0 lifts it (ceiling still applies)

def _cap(out):
    """Final backstop. Applied to every response after row-limiting.

    Truncating JSON mid-structure would emit something that looks parseable and isn't, so an
    oversized JSON payload is replaced by a structured notice instead of a mangled fragment.
    Plain text is safe to cut, and is cut with a visible marker."""
    if len(out) <= MAX_CHARS:
        return out
    stripped = out.lstrip()
    if stripped.startswith(("{", "[")):
        return json.dumps({
            "error": "response too large to return",
            "chars": len(out), "ceiling": MAX_CHARS,
            "hint": "Narrow the query: pass limit=N for array endpoints, action='block'/'pass' "
                    "for the firewall log, or request a more specific API path. Nothing was "
                    "returned — this is NOT an empty result.",
        }, indent=2)
    return out[:MAX_CHARS] + (f"\n\n[TRUNCATED: {len(out):,} chars exceeded the "
                              f"{MAX_CHARS:,}-char ceiling. Narrow the query.]")

def _slice_rows(out, limit, action):
    """For JSON-array API responses: optionally filter by an 'action' field, then cap to the
    newest `limit` rows (OPNsense returns the firewall log newest-first). The wrapper always
    reports returned/matched/total, so truncation is never silent. Non-array and non-JSON output
    passes through to the char ceiling unchanged."""
    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        return _cap(out)
    if not isinstance(data, list):
        return _cap(out)
    total = len(data)
    if action:
        data = [r for r in data if isinstance(r, dict) and r.get("action") == action]
    matched = len(data)
    if limit > 0:
        data = data[:limit]

    # Shrink to fit rather than refuse. Row size varies hugely by endpoint — a firewall-log row
    # is ~900 chars, an ARP row ~60 — so no constant row cap is right for every path. Returning
    # the largest prefix that fits, and saying so, beats returning nothing: the caller asked for
    # rows, and "here are 40 of 1000" is useful where "too large" is not.
    n = len(data)
    while n > 0:
        payload = json.dumps({
            "returned": n, "matched": matched, "total": total,
            "note": ("newest-first. " +
                     (f"Showing {n} of {matched} matching rows"
                      if n < matched else f"Showing all {n} matching rows") +
                     (f" (of {total} before the action filter)." if action else ".") +
                     (" Reduced to fit the response ceiling — narrow with action= or a more "
                      "specific path to see different rows." if n < min(limit or matched, matched)
                      else "")),
            "rows": data[:n]}, indent=1)
        if len(payload) <= MAX_CHARS:
            return payload
        n = n - 1 if n <= 5 else int(n * 0.75)
    return json.dumps({
        "error": "even a single row exceeds the response ceiling",
        "matched": matched, "total": total, "ceiling": MAX_CHARS,
        "hint": "Request a more specific API path. This is NOT an empty result."}, indent=1)

@mcp.tool(title="Lab inventory + liveness",
          annotations=ToolAnnotations(title="Lab inventory + liveness", **RO))
def lab_hosts(host: str = "") -> str:
    """List the lab inventory as JSON, sourced from OPNsense host entries (the authoritative IPAM).
    Per host: ip, mac, role, has_creds, and TWO liveness signals — `reach` (mgmt-port/ICMP heartbeat:
    is it up on the network) and `auth` (did a READ-ONLY login/query actually succeed: true/false, or
    null where there are no creds / no read-only interface). Plus an `ipam_drift` check (inventory vs
    live ARP). Call this FIRST to see what you can actually reach before querying a specific host.

    Pass `host` to get detail for one host instead of the whole estate — accepts the short name
    (opn-01), the device hostname (wblv-opn-01) or the FQDN. Much faster, since only that host is
    probed, and it includes the auth detail string (firmware version, or why a probe failed).
    An unknown name is an error listing the hosts that DO exist, never an empty result."""
    return _run(["hosts", "--json"] + ([host] if host else []))

@mcp.tool(title="Query a lab host",
          annotations=ToolAnnotations(title="Query a lab host", **RO))
def lab_host(host: str, query: str = "", limit: int = DEFAULT_ROWS, action: str = "") -> str:
    """Run a read-only query against ONE lab host. The host is dispatched by its role, so this is
    the single entry point for every device type — there is no per-device tool to remember.

    host  — short name (opn-01), device hostname (wblv-opn-01) or FQDN. Get names from lab_hosts.
    query — role-dependent:
      opnsense      an API path, e.g. 'diagnostics/firewall/log', 'diagnostics/interface/get_arp',
                    'diagnostics/system/system_resources', 'core/firmware/status' (default)
      synology      'shares', or 'ls <folder>' e.g. 'ls /Media'
      aruba-switch  an operator show command, e.g. 'show vlans', 'show interfaces brief'
      raspberry-pi  a read-only shell command, e.g. 'hostname', 'systemctl is-active pihole-FTL'

    Array responses are capped at `limit` rows (default 50) and always report
    returned/matched/total; a 40,000-character ceiling applies regardless, refusing with a size
    and a hint rather than truncating into invalid JSON. `action='block'|'pass'` filters
    firewall-log rows. Both are ignored for non-array responses, so they are safe on any query.

    An unknown host, a host with no credentials, or a role with no read-only handler is an ERROR
    naming the cause — never an empty result."""
    args = [host] + ([query] if query else [])
    return _slice_rows(_run(args), limit, action)

if __name__ == "__main__":
    mcp.run()
