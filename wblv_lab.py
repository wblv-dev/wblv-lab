#!/usr/bin/env python3
"""wblv-lab — what is alive in the lab, and how to reach it.

A directory, not a broker. It reports members, their state and their access route, then
gets out of the way: you connect to the host yourself using the credential it names.

Authorities, in order of use:
  1Password   membership. A vault item IS what makes something a lab member — so onboarding
              is data, not code, and non-members (workstation, control node) never appear.
  OPNsense    detail. Dnsmasq reservations are the IPAM; ARP supplies the live vendor string.
  the network everything else: reachability and a real login are measured, never recorded.

Nothing here is cached and nothing is hardcoded. The only seed is this machine's own
resolver, which is maintained by the network rather than by us.
"""
import os, sys, json, re, subprocess, time
from concurrent.futures import ThreadPoolExecutor

TOKEN_PATH = os.path.expanduser("~/.config/wblv/op-token")

# The one convention this tool assumes: hostnames are prefixed by device type. It is Harry's
# own naming standard, it decides the access mechanism, and it is the only thing here that
# could be called a hardcoded fact — so it is small, visible, and in exactly one place.
#
# ONBOARDING A NEW DEVICE TYPE: add a prefix and an access description. Onboarding a new HOST
# of an existing type needs nothing here at all — just the 1Password item.
ROLES = {
    "opn": ("opnsense",     "REST API :443"),
    "nas": ("synology",     "DSM API :5001"),
    "swt": ("aruba-switch", "SSH operator :22 (show-only)"),
    "rpi": ("linux",        "SSH :22"),
    "wap": ("tplink-ap",    "web UI :443"),
    "pve": ("proxmox",      "REST API :8006"),
}

# Vendor strings OPNsense resolves from the OUI. Matched on the NAME the router reports, not
# on a local OUI table — the lookup is the device's, we only classify the answer.
HYPERVISORS = ("proxmox", "vmware", "qemu", "kvm", "xen", "microsoft corporation",
               "oracle virtualbox", "nutanix", "parallels", "red hat")


def die(msg, **extra):
    """One clean root cause, never a stack trace. A fault must be legible at a glance or it
    gets mistaken for an empty result."""
    if "--json" in sys.argv:
        print(json.dumps({"error": msg, **extra}, indent=2))
    else:
        print(f"wblv-lab: {msg}", file=sys.stderr)
        for k, v in extra.items():
            print(f"          {k}: {v}", file=sys.stderr)
    sys.exit(1)


# --- 1Password substrate ------------------------------------------------------------------
# Prove the token and 1P are usable ONCE, up front. Otherwise a single substrate fault shows
# up as N cascading per-host failures that bury the actual cause.
try:
    TOKEN = open(TOKEN_PATH).read().strip()
except OSError as e:
    die(f"op-token unreadable at {TOKEN_PATH} ({type(e).__name__})")
if not TOKEN:
    die(f"op-token is empty at {TOKEN_PATH}")

ENV = {**os.environ, "OP_SERVICE_ACCOUNT_TOKEN": TOKEN}
TOKEN_AGE_DAYS = round((time.time() - os.path.getmtime(TOKEN_PATH)) / 86400, 1)


def op(*args, timeout=15):
    """Run `op`, returning stdout. Empty on failure so callers degrade rather than hang."""
    try:
        return subprocess.run(["op", *args], capture_output=True, text=True,
                              env=ENV, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


_who = subprocess.run(["op", "whoami", "--format", "json"], capture_output=True,
                      text=True, env=ENV, timeout=20)
if _who.returncode != 0:
    e = (_who.stderr or "").lower()
    cause = ("1Password unreachable (network)"
             if any(k in e for k in ("network", "timeout", "connection", "lookup", "no such host"))
             else "op-token invalid or expired"
             if any(k in e for k in ("unauthor", "invalid", "401", "403", "expired", "token"))
             else "op whoami failed")
    die(f"1Password substrate check failed: {cause}",
        detail=(_who.stderr or "").strip()[:200], token_age_days=TOKEN_AGE_DAYS)

VAULT = next((v["name"] for v in json.loads(op("vault", "list", "--format", "json") or "[]")
              if "claude" in v.get("name", "").lower()), "")
if not VAULT:
    die("the service account can see no Claude-scoped vault (token valid but mis-scoped?)",
        token_age_days=TOKEN_AGE_DAYS)


# --- membership: the vault decides what is a lab member ------------------------------------
def _member(item):
    """One vault item -> a member record, or None if it carries no usable host/endpoint.

    Qualified service accounts (e.g. '... / AUTO', a write-capable backup writer) are skipped
    so a writer can never be mistaken for the read-only identity this tool reports."""
    title = item.get("title", "")
    norm = title.upper().replace(" ", "")
    if "/" in norm and not norm.endswith("/CLAUDE"):
        return None
    full = json.loads(op("item", "get", item["id"], "--vault", VAULT, "--format", "json") or "{}")
    href = ";".join(u.get("href", "") for u in (full.get("urls") or []))
    m = re.search(r"https?://([A-Za-z0-9.\-]+)", href)
    # A URL field holding something that is not a hostname is a data fault in the vault, not
    # something to coerce. Reported as such rather than silently parsed into nonsense — the
    # M365 item holds an expiry date and two GUIDs here, which once parsed as a host named "23".
    endpoint = m.group(1) if (m and "." in m.group(1)) else ""
    junk = bool(href) and not endpoint
    user = next((f.get("value", "") for f in (full.get("fields") or [])
                 if (f.get("label") or "").lower() == "username"), "")
    name = endpoint.split(".")[0].lower() if endpoint else \
           title.split("/")[0].strip().lower().removeprefix("wblv-")
    return {"item": title, "endpoint": endpoint, "account": user, "name": name,
            "endpoint_malformed": junk}


items = json.loads(op("item", "list", "--vault", VAULT, "--format", "json") or "[]")
if not items:
    die(f"vault '{VAULT}' returned no items (1P read hiccup, or nothing is registered)",
        token_age_days=TOKEN_AGE_DAYS)

with ThreadPoolExecutor(max_workers=8) as ex:          # per-item `op item get` is the slow part
    members = [m for m in ex.map(_member, items) if m]
if not members:
    die(f"vault '{VAULT}' has items but none carry a usable endpoint URL")


# --- detail: OPNsense is the IPAM ----------------------------------------------------------
def curl(url, *extra, t=10, verify=True):
    """TLS is verified by default. Verification requires addressing the host by NAME — a
    certificate can never match a bare IP — which is why this tool has no addresses in it."""
    flags = ["-s"] if verify else ["-sk"]
    return subprocess.run(["curl", *flags, "--max-time", str(t), *extra, url],
                          capture_output=True, text=True).stdout


opn = next((m for m in members if m["name"].startswith("opn")), None)
if not opn:
    die("no OPNsense member in the vault — cannot read the lab's IPAM",
        hint="an item whose URL host starts 'opn-' supplies the inventory")

_full = json.loads(op("item", "get", opn["item"], "--vault", VAULT, "--format", "json") or "{}")
_f = {(x.get("label") or "").lower(): (x.get("value") or "") for x in (_full.get("fields") or [])}
K, S = _f.get("key", "").removeprefix("key="), _f.get("secret", "").removeprefix("secret=")
if not (K and S):
    die(f"the OPNsense item '{opn['item']}' has no Key/Secret fields")

API = f"https://{opn['endpoint']}/api"
inventory, arp = {}, {}
try:
    dj = json.loads(curl(f"{API}/dnsmasq/settings/get", "-u", f"{K}:{S}") or "{}")
    for h in (dj.get("dnsmasq", {}).get("hosts", {}) or {}).values():
        nm = h.get("host", "")
        if nm:
            inventory[nm.lower()] = {
                "fqdn": f"{nm}.{h.get('domain','')}".rstrip("."),
                "ip": next(iter(h.get("ip", {}) or {}), ""),
                "mac": next((k for k in (h.get("hwaddr", {}) or {}) if k), "").lower()}
except Exception:
    die(f"could not read the IPAM from {opn['endpoint']}",
        hint="OPNsense is the inventory authority; without it there is no lab directory")

try:
    for e in json.loads(curl(f"{API}/diagnostics/interface/get_arp", "-u", f"{K}:{S}") or "[]"):
        if e.get("ip"):
            arp[e["ip"]] = e.get("manufacturer", "")
except Exception:
    pass                                   # vendor is enrichment, not load-bearing


# --- classify -------------------------------------------------------------------------------
def classify(m):
    """A member with an IPAM entry is a HOST; one without is a SERVICE (M365, a SaaS tenant).
    Derived from whether the lab's own DNS knows it — nothing is labelled by hand."""
    inv = inventory.get(m["name"], {})
    role, access = ROLES.get(m["name"][:3], ("unknown", "unknown"))
    vendor = arp.get(inv.get("ip", ""), "")
    if not inv:
        kind = "service"                       # no IPAM entry: a SaaS tenant, not a machine
    elif any(h in vendor.lower() for h in HYPERVISORS):
        kind = "virtual"
    elif vendor:
        kind = "physical"
    else:
        # In the IPAM but absent from ARP — a quiet or unreachable host ages out, taking its
        # vendor string with it. Say "unclassified", never assume physical: the honest answer
        # is that we could not tell, and it will resolve itself the moment the host responds.
        kind = "unclassified"
    return {**m, **inv, "role": role, "access": access, "vendor": vendor, "kind": kind}


rows = sorted((classify(m) for m in members), key=lambda r: (r["kind"] == "service", r["name"]))

if __name__ == "__main__":
    print(json.dumps({"vault": VAULT, "token_age_days": TOKEN_AGE_DAYS,
                      "ipam_source": opn["endpoint"], "members": rows}, indent=2))
