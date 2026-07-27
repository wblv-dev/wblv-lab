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
import os, sys, subprocess, json, re, time
from concurrent.futures import ThreadPoolExecutor

JSON = "--json" in sys.argv
TOKEN_PATH = os.path.expanduser("~/.config/wblv/op-token")
HELPER = os.path.expanduser("~/.config/wblv/switch_show.py")
RPI_HELPER = os.path.expanduser("~/.config/wblv/rpi_show.py")

def die(msg, **extra):
    """Single, clean fail-fast (lab-20b). In JSON mode emit ONE error object so the MCP shows one
    root cause (not a Python traceback); in text mode a one-line stderr note. Never a stack trace."""
    print(json.dumps({"error": msg, **extra}, indent=2) if JSON else f"labctl hosts: {msg}",
          file=(sys.stdout if JSON else sys.stderr))
    sys.exit(1)

def _token_age_days():
    try: return round((time.time() - os.path.getmtime(TOKEN_PATH)) / 86400, 1)
    except OSError: return None

# --- 1Password substrate pre-check (lab-20b) --------------------------------------------------
# Prove the token + 1P are usable ONCE, up front. A token/1P fault otherwise surfaces as N
# cascading per-host "auth failed" rows that hide the real, single root cause — fail fast here
# instead. Also surfaces op-token age (file mtime = install/rotation date; a service account
# can't read its own expiry via the CLI) for the lab-61 expiry monitor.
try:
    TOKEN = open(TOKEN_PATH).read().strip()
except OSError as e:
    die(f"op-token unreadable at {TOKEN_PATH} ({e.__class__.__name__})")
if not TOKEN:
    die(f"op-token empty at {TOKEN_PATH}")
ENV = {**os.environ, "OP_SERVICE_ACCOUNT_TOKEN": TOKEN}

def op(*a, timeout=12):
    """Run `op`; return '' on any failure/timeout so callers degrade gracefully (never hang)."""
    try:
        return subprocess.run(["op", *a], capture_output=True, text=True, env=ENV, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""

# `op whoami` = the cheapest proof the token is valid AND 1P is reachable. Name the actual cause
# from stderr so the single message we print points at the real fault (bad token vs. no network).
try:
    _who = subprocess.run(["op", "whoami", "--format", "json"], capture_output=True, text=True, env=ENV, timeout=15)
    _rc, _err = _who.returncode, (_who.stderr or "")
except subprocess.TimeoutExpired:
    _rc, _err = 1, "timed out contacting 1Password (network)"
if _rc != 0:
    e = _err.lower()
    cause = ("1Password unreachable (network)" if any(k in e for k in
                ("network", "timeout", "timed out", "connection", "dial", "lookup", "no such host", "temporarily"))
             else "op-token invalid or expired" if any(k in e for k in
                ("unauthor", "invalid", "401", "403", "expired", "authenticate", "token"))
             else "op whoami failed")
    die(f"1P substrate check failed: {cause}", detail=_err.strip()[:200], token_age_days=_token_age_days())

TOKEN_AGE_DAYS = _token_age_days()

def field(iid, label): return op("item", "get", iid, "--vault", VAULT, "--fields", f"label={label}", "--reveal").strip()
def full(iid): return json.loads(op("item", "get", iid, "--vault", VAULT, "--format", "json") or "{}")
def hostof(f):
    href = ";".join(u.get("href", "") for u in (f.get("urls") or []))
    m = re.search(r"https?://([A-Za-z0-9.\-]+)", href); return m.group(1) if m else ""
def nc_open(ip, p, t=2):
    return subprocess.run(["nc", "-z", "-G", str(t), "-w", str(t), ip, str(p)], capture_output=True).returncode == 0
def ping_ok(ip, t=2):  # macOS: -t is timeout-in-seconds. L3 liveness for hosts with no reachable mgmt port.
    return subprocess.run(["ping", "-c", "1", "-t", str(t), ip], capture_output=True).returncode == 0
def curl(url, *extra, t=8, verify=False):
    """HTTP GET. `verify=True` enforces TLS validation and REQUIRES the url to address the host
    by hostname — a certificate can never match a bare IP, so verification and IP-addressing are
    mutually exclusive. Verification is on for OPNsense (valid LE wildcard, lab-9) and off for
    hosts still presenting self-signed certs (DSM, until the lab-9 remainder redeploys there)."""
    flags = ["-s"] if verify else ["-sk"]
    return subprocess.run(["curl", *flags, "--max-time", str(t), *extra, url], capture_output=True, text=True).stdout

# prefer the Claude-scoped vault by name (robust if the token ever sees >1 vault), else first
_vaults = json.loads(op("vault", "list", "--format", "json") or "[]") or []
VAULT = next((v["name"] for v in _vaults if "claude" in v.get("name", "").lower()),
             (_vaults or [{}])[0].get("name", ""))
if not VAULT:
    die("service account sees no vault (token valid but mis-scoped?)", token_age_days=TOKEN_AGE_DAYS)
items = json.loads(op("item", "list", "--vault", VAULT, "--format", "json") or "[]")
if not items:
    die(f"vault '{VAULT}' returned no items (1P read hiccup or empty vault?)", token_age_days=TOKEN_AGE_DAYS)

# --- bootstrap OPNsense API creds from its vault item (needed to read inventory + ARP) ---
OPN = {}
opn = next((i for i in items if "OPN" in i["title"].upper()), None)
if opn:
    K = field(opn["id"], "Key");    K = K[4:] if K.startswith("key=") else K
    S = field(opn["id"], "Secret"); S = S[7:] if S.startswith("secret=") else S
    OPN = {"k": K, "s": S}

# OPNsense is addressed by HOSTNAME, never by IP (standard #3). The name comes from the router's
# own 1Password item URL and is resolved by the system resolver — which IS OPNsense — so the chain
# terminates at the authority in one hop and nothing in this file needs to know an address. That
# moves the last bootstrap seed out of the code and into OS network config, where the network
# maintains it. Addressing by name is also what makes TLS verification possible at all.
# Costs one extra `op item get` at startup; the alternative is a constant that can go stale.
OPN_HOST = (hostof(full(opn["id"])) if opn else "") or "opn-01.wblv.uk"
vendor, arp_mac, inventory = {}, {}, {}
if OPN:
    try:
        for e in json.loads(curl(f"https://{OPN_HOST}/api/diagnostics/interface/get_arp", "-u", f"{OPN['k']}:{OPN['s']}", verify=True) or "[]"):
            if e.get("manufacturer"): vendor[e["ip"]] = e["manufacturer"]
            if e.get("ip") and e.get("mac"): arp_mac[e["ip"]] = e["mac"].lower()
    except Exception: pass
    # authoritative inventory = OPNsense Dnsmasq host entries
    try:
        dj = json.loads(curl(f"https://{OPN_HOST}/api/dnsmasq/settings/get", "-u", f"{OPN['k']}:{OPN['s']}", verify=True) or "{}")
        for h in (dj.get("dnsmasq", {}).get("hosts", {}) or {}).values():
            nm = h.get("host", "");  dom = h.get("domain", "")
            if not nm: continue
            ipk = next(iter(h.get("ip", {}) or {}), "")
            mck = next((k for k in (h.get("hwaddr", {}) or {}) if k), "")
            inventory[nm] = {"fqdn": f"{nm}.{dom}" if dom else nm, "ip": ipk,
                             "mac": mck.lower(), "descr": h.get("descr", "")}
    except Exception: pass

# --- creds index: short hostname -> vault item id (attach read-only creds by hostname) ---
# Only PLAIN device-login items map here. Qualified/service accounts (title contains "/", e.g.
# "WBLV-NAS-01 / AUTO", a write-capable backup account) are skipped so a read/write service
# credential can never be picked up as the read-only device liveness/auth probe cred.
cred_item = {}
def _cred_for(it):
    # Index only the read-only device-login creds. Convention: 'WBLV-<HOST>' or
    # 'WBLV-<HOST> / CLAUDE' are the read-only probe logins; write/service accounts
    # (e.g. '/ AUTO') are excluded so a writer can never be used as the probe cred.
    norm = it.get("title", "").upper().replace(" ", "")
    if "/" in norm and not norm.endswith("/CLAUDE"):
        return None
    fq = hostof(full(it["id"]))                           # one `op item get` per item — the slow part
    return (fq.split(".")[0].lower(), it["id"]) if fq else None
# Parallelised (lab-20d): the per-item `op` fetches are independent and network-bound. ex.map
# preserves input order, so same-host collisions still resolve last-wins as the serial loop did.
with ThreadPoolExecutor(max_workers=min(8, len(items)) or 1) as _ex:
    for _res in _ex.map(_cred_for, items):
        if _res: cred_item[_res[0]] = _res[1]

ROLE_BY_PREFIX = {"nas": "synology", "opn": "opnsense", "swt": "aruba-switch", "wap": "tplink-ap", "rpi": "raspberry-pi"}
ROLE_PROFILE = {
    "synology":     ("DSM API :5001 + SMB :445",        5001, "labctl nas"),
    "aruba-switch": ("SSH operator :22 (show-only)",    22,   'labctl switch "<cmd>"'),
    "opnsense":     ("REST API :443",                   443,  "labctl opnsense <path>"),
    "tplink-ap":    ("web UI :80/443 (no RO handler)",  443,  "—"),
    "raspberry-pi": ("SSH :22 (read-only claude)",      22,   'labctl rpi "<cmd>"'),
}
def role_of(name): return ROLE_BY_PREFIX.get(name.split("-")[0].lower())

def alive(role, ip, iid):
    """Real read-only auth test. Returns (ok: bool, detail). Only called where a cred exists."""
    try:
        if role == "opnsense":
            # hostname, not the passed ip — verification needs a name (see curl docstring)
            r = curl(f"https://{OPN_HOST}/api/core/firmware/status", "-u", f"{OPN['k']}:{OPN['s']}", verify=True)
            j = json.loads(r or "{}"); v = j.get("product_version")
            return (bool(v), f"OPNsense {v}" if v else "auth failed")
        if role == "synology":
            U = field(iid, "username"); P = field(iid, "password") or field(iid, "confirmpassword")
            if not (U and P):
                # 1Password read hiccup during a heavy run — not an auth failure (lab-22)
                return (None, "cred fetch failed (1P)")
            def _login():
                return subprocess.run(["curl", "-sk", "--max-time", "12", "-G", f"https://{ip}:5001/webapi/entry.cgi",
                                       "--data-urlencode", "api=SYNO.API.Auth", "--data-urlencode", "version=7",
                                       "--data-urlencode", "method=login", "--data-urlencode", f"account={U}",
                                       "--data-urlencode", f"passwd={P}", "--data-urlencode", "session=FileStation",
                                       "--data-urlencode", "format=sid"], capture_output=True, text=True).stdout
            r = _login()
            if not r.strip():
                # empty = curl timed out on a briefly-busy DSM; retry once. Only on a timeout,
                # never on a real auth-error code, so a misconfig can't escalate DSM auto-block (lab-22)
                time.sleep(3); r = _login()
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
            un = field(iid, "username") or "operator"   # SSH user = item username (e.g. 'claude'); legacy fallback
            pw = field(iid, "password") or field(iid, "Operator Password")
            # Execute the helper directly so its `uv run --with pexpect` shebang applies.
            r = subprocess.run([HELPER, ip, un, "show system"],
                               env={**os.environ, "SWT_PW": pw}, capture_output=True, text=True, timeout=30)
            ok = "System Name" in r.stdout
            return (ok, "login ok" if ok else "ssh/login failed")
        if role == "raspberry-pi":
            U = field(iid, "username"); P = field(iid, "password") or field(iid, "confirmpassword")
            U = U[9:] if U.startswith("username=") else U
            P = P[9:] if P.startswith("password=") else P
            if not (U and P):
                return (None, "cred fetch failed (1P)")   # 1P hiccup, not auth failure (lab-22)
            # read-only SSH as the no-sudo 'claude' user; the localhost DNS query doubles as an
            # auth proof AND a Pi-hole resolver-health proof (must resolve + forward wblv.uk)
            r = subprocess.run([RPI_HELPER, ip, U, "dig +short @127.0.0.1 nas-01.wblv.uk"],
                               env={**os.environ, "RPI_PW": P}, capture_output=True, text=True, timeout=30)
            ok = "10.19.10.10" in r.stdout
            return (ok, "ssh + pihole resolve ok" if ok else "ssh/login or resolve failed")
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

def probe(name):
    """Reach + auth probe for one inventory host. Independent per host → safe to run concurrently."""
    inv = inventory[name]
    ip, mac, descr, fqdn = inv["ip"], inv["mac"], inv["descr"], inv["fqdn"]
    role = role_of(name)
    access, port, verb = ROLE_PROFILE.get(role, ("host / no mgmt tool", None, "—"))
    iid = cred_item.get(name)                             # read-only cred, if one exists
    # No special case for opn-01 any more: lab-9 repointed its reservation and DNS record to the
    # ADM address, so the inventory IP is the one mac-01 can actually reach. Probing the inventory
    # entry (rather than a constant) is also what makes the IPAM drift check meaningful for it.
    probe_ip = ip
    port_open = nc_open(probe_ip, port) if (port and probe_ip) else False
    reach = port_open or (ping_ok(probe_ip) if probe_ip else False)   # REACH: heartbeat (mgmt port OR ICMP)
    if iid and port_open and role in ROLE_PROFILE and role != "tplink-ap":
        auth = alive(role, probe_ip, iid)[0]              # AUTH: did a read-only login/query succeed?
    else:
        auth = None                                       # no creds / no read-only interface → n/a
    return {"host": name, "fqdn": fqdn, "ip": ip or None, "mac": mac or None,
            "role": role or "?", "has_creds": bool(iid), "reach": reach, "auth": auth,
            "use": verb, "drift": drift_of(ip, mac)}

# Parallelised (lab-20d): per-host probes are independent and I/O-bound (nc/ping/curl/ssh), so
# wall-clock drops from sum-of-hosts (~39s serial) to the slowest single host. ex.map preserves
# order so the table stays name-sorted; the lone DSM login stays single (no concurrent NAS auth).
_names = sorted(inventory)
with ThreadPoolExecutor(max_workers=min(8, len(_names)) or 1) as _ex:
    rows = list(_ex.map(probe, _names))

issues = [f"{r['host']}: {r['drift']}" for r in rows if r["drift"] != "ok"]
drift_summary = {"checked": len(rows), "ok": sum(1 for r in rows if r["drift"] == "ok"), "issues": issues}

if JSON:
    print(json.dumps({"vault": VAULT, "source": "OPNsense Dnsmasq host entries",
                      "substrate": {"ok": True, "op_token_age_days": TOKEN_AGE_DAYS},
                      "ipam_drift": drift_summary, "hosts": rows}, indent=2))
else:
    R = lambda b: "up" if b else "down"
    A = lambda v: "ok" if v is True else ("fail" if v is False else "—")
    print(f"inventory: OPNsense host entries   creds: {VAULT} (read-only, by hostname)")
    print(f"1P substrate: OK   op-token age: {TOKEN_AGE_DAYS}d (mtime → lab-61)")
    print("REACH = mgmt-port/ICMP heartbeat   AUTH = read-only login (ok / fail / — = no creds)")
    hdr = f"{'HOST':<10}{'IP':<15}{'MAC':<20}{'REACH':<7}{'AUTH'}"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        print(f"{r['host']:<10}{(r['ip'] or '—'):<15}{(r['mac'] or '—'):<20}{R(r['reach']):<7}{A(r['auth'])}")
    print("-" * len(hdr))
    print(f"IPAM: {drift_summary['ok']}/{drift_summary['checked']} inventory entries consistent with live ARP"
          + (f"   ⚠ {'; '.join(issues)}" if issues else "   ✓"))
