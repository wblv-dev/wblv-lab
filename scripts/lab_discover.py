#!/usr/bin/env python3
"""labctl hosts [--json] — dynamic lab discovery WITH a real liveness test.
 vendor  <- OPNsense ARP (live OUI->manufacturer)
 role    <- vendor profile map (data-driven, not the item title)
 reach   <- nc probe on the access port (L4)
 alive   <- a REAL read-only auth/query per host (L7): proves it's a working thing, not just a list row
Read-only. Uses nc/curl (NOT python sockets — macOS Local Network Privacy blocks python local-subnet connects).
"""
import os, sys, subprocess, json, re

JSON = "--json" in sys.argv
TOKEN = open(os.path.expanduser("~/.config/wblv/op-token")).read().strip()
ENV = {**os.environ, "OP_SERVICE_ACCOUNT_TOKEN": TOKEN}
HELPER = os.path.expanduser("~/.config/wblv/switch_show.py")

def op(*a): return subprocess.run(["op", *a], capture_output=True, text=True, env=ENV).stdout
def field(iid, label): return op("item", "get", iid, "--vault", VAULT, "--fields", f"label={label}", "--reveal").strip()
def full(iid): return json.loads(op("item", "get", iid, "--vault", VAULT, "--format", "json") or "{}")
def ipof(f):
    href = ";".join(u.get("href", "") for u in (f.get("urls") or []))
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", href); return m.group(1) if m else ""
def nc_open(ip, p, t=2):
    return subprocess.run(["nc", "-z", "-G", str(t), "-w", str(t), ip, str(p)], capture_output=True).returncode == 0
def curl(url, *extra, t=8):
    return subprocess.run(["curl", "-sk", "--max-time", str(t), *extra, url], capture_output=True, text=True).stdout

VAULT = (json.loads(op("vault", "list", "--format", "json") or "[]") or [{}])[0].get("name", "")
items = json.loads(op("item", "list", "--vault", VAULT, "--format", "json") or "[]")

# --- live vendor map from OPNsense ARP; also stash OPN creds for its alive test ---
vendor, OPN = {}, {}
opn = next((i for i in items if "OPN" in i["title"].upper()), None)
if opn:
    K = field(opn["id"], "Key");    K = K[4:] if K.startswith("key=") else K
    S = field(opn["id"], "Secret"); S = S[7:] if S.startswith("secret=") else S
    oip = ipof(full(opn["id"])) or "10.19.0.1"
    OPN = {"ip": oip, "k": K, "s": S}
    try:
        for e in json.loads(curl(f"https://{oip}/api/diagnostics/interface/get_arp", "-u", f"{K}:{S}") or "[]"):
            if e.get("manufacturer"): vendor[e["ip"]] = e["manufacturer"]
    except Exception: pass

PROFILES = [
    ("Synology",   ("synology",     "DSM API :5001 + SMB :445",       5001, "labctl nas")),
    ("Hewlett",    ("aruba-switch", "SSH operator :22 (show-only)",   22,   'labctl switch "<cmd>"')),
    ("Aruba",      ("aruba-switch", "SSH operator :22 (show-only)",   22,   'labctl switch "<cmd>"')),
    ("WatchGuard", ("opnsense",     "REST API :443",                  443,  "labctl opnsense <path>")),
    ("TP-Link",    ("tplink-ap",    "web UI :80/443 (no RO handler)", 443,  "—")),
]
def profile(ven):
    for key, prof in PROFILES:
        if key.lower() in (ven or "").lower(): return prof
    return None

def alive(role, ip, iid):
    """Real read-only auth test. Returns (ok: bool, detail)."""
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
            if j.get("data", {}).get("sid"): return (True, "DSM login ok")
            return (False, f"login err {j.get('error',{}).get('code')}")
        if role == "aruba-switch":
            pw = field(iid, "password") or field(iid, "Operator Password")
            r = subprocess.run(["python3", HELPER, ip, "operator", "show system"],
                               env={**os.environ, "SWT_PW": pw}, capture_output=True, text=True, timeout=30)
            ok = "System Name" in r.stdout
            return (ok, "operator login ok" if ok else "ssh/login failed")
    except Exception as e:
        return (False, f"err {type(e).__name__}")
    return (None, "no handler")

rows = []
for it in sorted(items, key=lambda x: x["title"]):
    ip = ipof(full(it["id"]))
    ven = vendor.get(ip, "")
    prof = profile(ven)
    role, access, port, verb = (prof if prof else ("?", "unknown / needs profiling", None, "—"))
    if not ip:
        row = {"host": it["title"], "vendor": None, "role": "?", "ip": None,
               "access": "no IP in item — add its URL", "reachable": None, "alive": None, "detail": "no-ip", "use": "—"}
    else:
        reachable = nc_open(ip, port) if port else False
        ok, detail = (alive(role, ip, it["id"]) if reachable else (False, "unreachable"))
        row = {"host": it["title"], "vendor": ven or None, "role": role, "ip": ip, "access": access,
               "reachable": reachable, "alive": ok, "detail": detail, "use": verb}
    rows.append(row)

if JSON:
    print(json.dumps({"vault": VAULT, "hosts": rows}, indent=2))
else:
    def flag(r):
        if r["alive"] is True: return "ALIVE"
        if r["alive"] is False: return "DOWN"
        return "?"
    print(f"vault: {VAULT}   (role/access from live MAC-vendor; ALIVE = real read-only auth succeeded)")
    hdr = f"{'HOST':<13}{'VENDOR':<18}{'ROLE':<14}{'ACCESS MECHANISM':<32}{'LIVE':<7}{'USE'}"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        print(f"{r['host']:<13}{(r['vendor'] or '—')[:16]:<18}{r['role']:<14}{r['access']:<32}{flag(r):<7}{r['use']}")
        print(f"{'':<13}{('@ '+(r['ip'] or 'no-ip')):<18}{'':<14}{('· '+r['detail']):<32}")
