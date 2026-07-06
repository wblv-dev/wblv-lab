#!/usr/bin/env python3
"""labctl hosts [--json] — lab inventory with a real liveness test.

Data model (2026-07): OPNsense is the authoritative IPAM/inventory source.
 list    <- OPNsense Dnsmasq host entries (name / ip / mac / descr)  ← source of truth
 creds   <- 1Password Lab-Claude vault, READ-ONLY, attached BY HOSTNAME (no IPs/MACs in 1P)
 role    <- stable hostname-prefix map (not volatile ARP)
 vendor  <- OPNsense ARP (informational only, no longer load-bearing)
 reach   <- nc probe on the mgmt port (L4), else ICMP
 alive   <- a REAL read-only auth/query per host (L7), only where a cred exists
Read-only. Uses nc/curl/ssh (NOT python sockets — macOS Local Network Privacy blocks those).
"""
import os, sys, subprocess, json, re

JSON = "--json" in sys.argv
TOKEN = open(os.path.expanduser("~/.config/wblv/op-token")).read().strip()
ENV = {**os.environ, "OP_SERVICE_ACCOUNT_TOKEN": TOKEN}
HELPER = os.path.expanduser("~/.config/wblv/switch_show.py")

def op(*a): return subprocess.run(["op", *a], capture_output=True, text=True, env=ENV).stdout
def field(iid, label): return op("item", "get", iid, "--vault", VAULT, "--fields", f"label={label}", "--reveal").strip()
def full(iid): return json.loads(op("item", "get", iid, "--vault", VAULT, "--format", "json") or "{}")
def hostof(f):
    href = ";".join(u.get("href", "") for u in (f.get("urls") or []))
    m = re.search(r"https?://([A-Za-z0-9.\-]+)", href); return m.group(1) if m else ""
def nc_open(ip, p, t=2):
    return subprocess.run(["nc", "-z", "-G", str(t), "-w", str(t), ip, str(p)], capture_output=True).returncode == 0
def ping_ok(ip, t=2):  # macOS: -t is timeout-in-seconds. L3 liveness for hosts with no reachable mgmt port.
    return subprocess.run(["ping", "-c", "1", "-t", str(t), ip], capture_output=True).returncode == 0
def curl(url, *extra, t=8):
    return subprocess.run(["curl", "-sk", "--max-time", str(t), *extra, url], capture_output=True, text=True).stdout

# prefer the Claude-scoped vault by name (robust if the token ever sees >1 vault), else first
_vaults = json.loads(op("vault", "list", "--format", "json") or "[]") or []
VAULT = next((v["name"] for v in _vaults if "claude" in v.get("name", "").lower()),
             (_vaults or [{}])[0].get("name", ""))
items = json.loads(op("item", "list", "--vault", VAULT, "--format", "json") or "[]")

# --- bootstrap OPNsense API creds from its vault item (needed to read inventory + ARP) ---
OPN = {}
opn = next((i for i in items if "OPN" in i["title"].upper()), None)
if opn:
    K = field(opn["id"], "Key");    K = K[4:] if K.startswith("key=") else K
    S = field(opn["id"], "Secret"); S = S[7:] if S.startswith("secret=") else S
    oip = ""  # resolved from inventory below; fall back to the well-known gateway
    OPN = {"k": K, "s": S}

OGW = "10.19.0.1"  # OPNsense API endpoint (gateway); inventory/ARP are read from here
vendor, arp_mac, inventory = {}, {}, {}
if OPN:
    try:
        for e in json.loads(curl(f"https://{OGW}/api/diagnostics/interface/get_arp", "-u", f"{OPN['k']}:{OPN['s']}") or "[]"):
            if e.get("manufacturer"): vendor[e["ip"]] = e["manufacturer"]
            if e.get("ip") and e.get("mac"): arp_mac[e["ip"]] = e["mac"].lower()
    except Exception: pass
    # authoritative inventory = OPNsense Dnsmasq host entries
    try:
        dj = json.loads(curl(f"https://{OGW}/api/dnsmasq/settings/get", "-u", f"{OPN['k']}:{OPN['s']}") or "{}")
        for h in (dj.get("dnsmasq", {}).get("hosts", {}) or {}).values():
            nm = h.get("host", "");  dom = h.get("domain", "")
            if not nm: continue
            ipk = next(iter(h.get("ip", {}) or {}), "")
            mck = next((k for k in (h.get("hwaddr", {}) or {}) if k), "")
            inventory[nm] = {"fqdn": f"{nm}.{dom}" if dom else nm, "ip": ipk,
                             "mac": mck.lower(), "descr": h.get("descr", "")}
    except Exception: pass

# --- creds index: short hostname -> vault item id (attach read-only creds by hostname) ---
cred_item = {}
for it in items:
    fq = hostof(full(it["id"]))
    if fq: cred_item[fq.split(".")[0].lower()] = it["id"]

ROLE_BY_PREFIX = {"nas": "synology", "opn": "opnsense", "swt": "aruba-switch", "wap": "tplink-ap"}
ROLE_PROFILE = {
    "synology":     ("DSM API :5001 + SMB :445",        5001, "labctl nas"),
    "aruba-switch": ("SSH operator :22 (show-only)",    22,   'labctl switch "<cmd>"'),
    "opnsense":     ("REST API :443",                   443,  "labctl opnsense <path>"),
    "tplink-ap":    ("web UI :80/443 (no RO handler)",  443,  "—"),
}
def role_of(name): return ROLE_BY_PREFIX.get(name.split("-")[0].lower())

def alive(role, ip, iid):
    """Real read-only auth test. Returns (ok: bool, detail). Only called where a cred exists."""
    try:
        if role == "opnsense":
            r = curl(f"https://{ip}/api/core/firmware/status", "-u", f"{OPN['k']}:{OPN['s']}")
            j = json.loads(r or "{}"); v = j.get("product_version")
            return (bool(v), f"OPNsense {v}" if v else "auth failed")
        if role == "synology":
            U = field(iid, "username"); P = field(iid, "password") or field(iid, "confirmpassword")
            r = subprocess.run(["curl", "-sk", "--max-time", "10", "-G", f"https://{ip}:5001/webapi/entry.cgi",
                                "--data-urlencode", "api=SYNO.API.Auth", "--data-urlencode", "version=7",
                                "--data-urlencode", "method=login", "--data-urlencode", f"account={U}",
                                "--data-urlencode", f"passwd={P}", "--data-urlencode", "session=FileStation",
                                "--data-urlencode", "format=sid"], capture_output=True, text=True).stdout
            j = json.loads(r or "{}")
            sid = j.get("data", {}).get("sid")
            if sid:
                # release the session — repeated probes otherwise exhaust DSM's session pool / trip auto-block
                subprocess.run(["curl", "-sk", "--max-time", "8", "-G", f"https://{ip}:5001/webapi/entry.cgi",
                                "--data-urlencode", "api=SYNO.API.Auth", "--data-urlencode", "version=7",
                                "--data-urlencode", "method=logout", "--data-urlencode", "session=FileStation",
                                "--data-urlencode", f"_sid={sid}"], capture_output=True)
                return (True, "DSM login ok")
            return (False, f"login err {j.get('error',{}).get('code')}")
        if role == "aruba-switch":
            pw = field(iid, "password") or field(iid, "Operator Password")
            # Execute the helper directly so its `uv run --with pexpect` shebang applies.
            r = subprocess.run([HELPER, ip, "operator", "show system"],
                               env={**os.environ, "SWT_PW": pw}, capture_output=True, text=True, timeout=30)
            ok = "System Name" in r.stdout
            return (ok, "operator login ok" if ok else "ssh/login failed")
    except Exception as e:
        return (False, f"err {type(e).__name__}")
    return (None, "no handler")

def drift_of(ip, mac):
    """Inventory-vs-live check: does the OPNsense-reserved IP appear live on the expected MAC?
    Flags an IP conflict (someone else is using the reserved address)."""
    live = arp_mac.get(ip, "")
    if mac and live and live != mac:
        return f"IP conflict: {ip} live on {live} not {mac}"
    return "ok"

rows = []
for name in sorted(inventory):
    inv = inventory[name]
    ip, mac, descr, fqdn = inv["ip"], inv["mac"], inv["descr"], inv["fqdn"]
    role = role_of(name)
    access, port, verb = ROLE_PROFILE.get(role, ("host / no mgmt tool", None, "—"))
    iid = cred_item.get(name)                      # read-only cred, if one exists
    cred_title = next((i["title"] for i in items if i["id"] == iid), None) if iid else None
    port_open = nc_open(ip, port) if (port and ip) else False
    up = port_open or (ping_ok(ip) if ip else False)
    if iid and port_open and role in ROLE_PROFILE and role != "tplink-ap":
        ok, detail = alive(role, ip, iid)          # authenticated read-only check
    elif up:
        ok, detail = (None, "up (ICMP); no reachable read-only interface"
                      + (f" — port {port} closed" if port else ""))
    else:
        ok, detail = (False, "unreachable")
    rows.append({"host": name, "fqdn": fqdn, "cred_item": cred_title,
                 "vendor": vendor.get(ip) or None, "role": role or "?", "ip": ip or None, "mac": mac or None,
                 "access": access, "has_creds": bool(iid), "reachable": up, "alive": ok,
                 "detail": detail, "drift": drift_of(ip, mac), "descr": descr or None, "use": verb})

issues = [f"{r['host']}: {r['drift']}" for r in rows if r["drift"] != "ok"]
drift_summary = {"checked": len(rows), "ok": sum(1 for r in rows if r["drift"] == "ok"), "issues": issues}

if JSON:
    print(json.dumps({"vault": VAULT, "source": "OPNsense Dnsmasq host entries",
                      "ipam_drift": drift_summary, "hosts": rows}, indent=2))
else:
    def flag(r):
        if r["alive"] is True: return "ALIVE"
        if r["alive"] is False: return "DOWN"
        return "?"
    print(f"inventory: OPNsense host entries   creds: {VAULT} (read-only, by hostname)")
    hdr = f"{'HOST':<10}{'ROLE':<14}{'IP':<14}{'CRED':<6}{'LIVE':<7}{'DETAIL'}"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        print(f"{r['host']:<10}{r['role']:<14}{(r['ip'] or '—'):<14}{('yes' if r['has_creds'] else '—'):<6}{flag(r):<7}{r['detail']}")
        if r["drift"] != "ok": print(f"{'':<10}⚠ {r['drift']}")
    print("-" * len(hdr))
    print(f"IPAM: {drift_summary['ok']}/{drift_summary['checked']} inventory entries consistent with live ARP"
          + (f"   ⚠ {'; '.join(issues)}" if issues else "   ✓"))
