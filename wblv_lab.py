#!/usr/bin/env -S uv run --with pexpect --with rich --quiet --script
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
import os, sys, json, re, socket, subprocess, time
try:
    import pexpect
except ImportError:
    pexpect = None   # SSH probes report this rather than failing silently
from concurrent.futures import ThreadPoolExecutor

_T0 = time.time()          # for the Runtime stat: measured, not estimated

TOKEN_PATH = os.path.expanduser("~/.config/wblv/op-token")

# The one convention this tool assumes: hostnames are prefixed by device type. It is Harry's
# own naming standard, it decides the access mechanism, and it is the only thing here that
# could be called a hardcoded fact — so it is small, visible, and in exactly one place.
#
# ONBOARDING A NEW DEVICE TYPE: add a prefix and an access description. Onboarding a new HOST
# of an existing type needs nothing here at all — just the 1Password item.
ROLES = {                     # prefix -> (role, protocol, port)
    "opn": ("opnsense",     "https",  443),
    "nas": ("synology",     "https", 5001),
    "swt": ("aruba-switch", "ssh",     22),
    "rpi": ("linux",        "ssh",     22),
    "wap": ("tplink-ap",    "https",  443),
    "pve": ("proxmox",      "https", 8006),
}

# Credentials are held OUT of the member records so they cannot reach stdout. Output rows are
# built from an explicit whitelist below; a secret must never be one accidental print away.
CREDS = {}

# Vendor strings OPNsense resolves from the OUI. Matched on the NAME the router reports, not
# on a local OUI table — the lookup is the device's, we only classify the answer.
# Roles whose auth probe talks to no host, so neither an endpoint nor a successful REACH is a
# precondition for testing them. Kept explicit: the default stays "do not attempt a login
# against something that did not answer", which is what stops repeated probes tripping lockouts.
HOSTLESS_ROLES = ("1password",)

# 1Password's own UI names some things for you (a Login item always carries username/password;
# autofill leaves newUserName behind), and the same value has been written under different
# labels over time. Aliases are ADDITIVE — the original label is kept too — so tidying an item
# can never break the tool, and items can be migrated one at a time rather than in lockstep.
ALIASES = {
    "newusername": "username", "user": "username", "login": "username",
    "pass": "password", "passwd": "password",
    "key": "api_key", "secret": "api_secret",
    "apikey": "api_key", "apisecret": "api_secret",
    "clientid": "client_id", "clientsecret": "client_secret", "tenantid": "tenant_id",
    "url": "website", "endpoint": "website",
}

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


HELP = """wblv-lab — what is alive in the lab, and how to reach it.

  wblv-lab              every host and service
  wblv-lab -p           physical hosts only
  wblv-lab -v           virtual hosts only
  wblv-lab -s           services only
  wblv-lab --json       machine-readable
  wblv-lab -h           this text

Membership comes from 1Password: an item is what makes something a member, so adding one
is the whole of onboarding. Detail comes from OPNsense, which is the IPAM. Nothing is
cached — every run asks again, which costs a few seconds and buys accuracy.

REACH is a heartbeat. AUTH is a real read-only login. Trust AUTH: a host can answer on
the network and still be useless to you.

ZONE is the OPNsense interface the host answers on. LAN cannot reach ADM, so it is often
why a host is unreachable, or legitimately is not. REACH and AUTH are measured from the
machine named in "Probing from", whose own zone is shown for exactly that reason.

FAULT names what disagrees, and is blank when nothing does. 'url' -- the item's URL field
holds no usable hostname. 'ip' -- the DHCP reservation and the live address differ, a lease
that outlived the change which created it. 'tag' -- the declared type and the wire disagree.

Non-members counts addresses OPNsense can see that no vault item claims. It says how much
of the wire this directory accounts for; it is not a fault.

This tool tells you which credential opens a host. It does not turn the key — you connect
and run commands yourself, so the read-only limit lives in the host account."""

# Both are read before any work is done. Printing help used to cost a full probe run, and a
# filtered view used to probe every host and then throw most of the results away — the flags
# were parsed in __main__, which runs last.
if {"-h", "--help", "help"} & set(sys.argv[1:]):
    print(HELP); sys.exit(0)

WANT = ({"physical"} if "-p" in sys.argv else set()) | \
       ({"virtual"} if "-v" in sys.argv else set()) | \
       ({"service"} if "-s" in sys.argv else set())


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
TOKEN_FILE_AGE_DAYS = round((time.time() - os.path.getmtime(TOKEN_PATH)) / 86400, 1)


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
        detail=(_who.stderr or "").strip()[:200], token_file_age_days=TOKEN_FILE_AGE_DAYS)

VAULT = next((v["name"] for v in json.loads(op("vault", "list", "--format", "json") or "[]")
              if "claude" in v.get("name", "").lower()), "")
if not VAULT:
    die("the service account can see no Claude-scoped vault (token valid but mis-scoped?)",
        token_file_age_days=TOKEN_FILE_AGE_DAYS)


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
    # Any slot may carry the URL: the built-in website entry, or a custom field. Reading only
    # the urls array meant a correctly-built item had no endpoint at all.
    href = ";".join([u.get("href", "") or "" for u in (full.get("urls") or [])] +
                    [f.get("value") or "" for f in (full.get("fields") or [])
                     if "://" in (f.get("value") or "")])
    # Any scheme, not just http(s): an SSH-managed host should be able to say so, rather than
    # being described by a web URL it does not serve. The scheme is how you reach it.
    m = re.search(r"([a-z][a-z0-9+.\-]*)://([A-Za-z0-9.\-]+)(?::(\d+))?", href, re.I)
    # A URL field holding something that is not a hostname is a data fault in the vault, not
    # something to coerce. Reported as such rather than silently parsed into nonsense — the
    # M365 item holds an expiry date and two GUIDs here, which once parsed as a host named "23".
    endpoint = m.group(2) if (m and "." in m.group(2)) else ""
    # A missing endpoint is only a FAULT if something was clearly meant to be one. An item
    # whose only URL-slot entries are labelled data (role: 1password) has no endpoint because it
    # needs none — reporting that as a malformed URL would be the tool inventing a problem.
    intended = any(("://" in (u.get("href") or "")) or
                   (u.get("label") or "").strip().lower() in ("website", "url")
                   for u in (full.get("urls") or []))
    junk = intended and not endpoint
    # A service has no meaningful hostname prefix — a SaaS tenant is not identified by the
    # first three letters of its portal's DNS name — so the URL is the only thing that states
    # how to reach it. Read the scheme and port from it rather than inferring them.
    scheme = (m.group(1).lower() if endpoint else "")
    DEFAULT_PORT = {"https": 443, "http": 80, "ssh": 22}
    url_port = (int(m.group(3)) if (endpoint and m.group(3))
                else DEFAULT_PORT.get(scheme) if endpoint else None)
    user = next((f.get("value", "") for f in (full.get("fields") or [])
                 if (f.get("label") or "").lower() == "username"), "")
    # A machine's DNS name IS its identity, so the endpoint names it. A service's URL is the
    # vendor's domain and names nothing useful — portal.azure.com would be "portal",
    # login.tailscale.com "login", my.1password.com "my". For those the item title is the
    # identity, which is also how Harry has been controlling the name all along.
    is_service = any(t.lower() == "service" for t in (full.get("tags") or []))
    from_title = title.split("/")[0].strip().lower().removeprefix("wblv-")
    name = from_title if (is_service or not endpoint) else endpoint.split(".")[0].lower()
    # 1Password's Login item offers custom fields and labelled website entries, and Harry uses
    # both — the M365 tenant_id and client_id live as LABELLED URLS because that is the slot the
    # UI made easy. Reading only `fields` threw those labels away and made the data look like a
    # malformed endpoint. Both are read; `fields` wins a clash, being the more deliberate slot.
    #
    # Labels are typed by hand in a GUI, so they are matched forgivingly: stored under both the
    # plain lowercase form and one with spaces and hyphens folded to underscores, so "Client ID",
    # "client-id" and "client_id" all resolve. A label that silently fails to match would look
    # exactly like a field that was never filled in.
    def _keys(label):
        low = (label or "").strip().lower()
        return {low, re.sub(r"[\s\-]+", "_", low)} - {""}

    # A set value never loses to an empty one. 1Password's built-in username/password sit in
    # the fields array whether or not they are used, so an unfilled built-in would otherwise
    # clobber a custom field of the same name purely on array order — which is luck, not design.
    c = {}
    def put(label, value):
        for k in _keys(label):
            for k2 in {k, ALIASES.get(k, k)}:
                if value or k2 not in c:
                    c[k2] = value
    for u in (full.get("urls") or []):
        put(u.get("label"), u.get("href") or "")
    for f in (full.get("fields") or []):
        put(f.get("label"), f.get("value") or "")
    # Keyed by the ITEM's id, never by the resolved name. Two items can resolve to the same
    # name — a duplicate made while migrating a format, say — and a name-keyed store lets one
    # silently overwrite the other, so a member is probed with a different member's credentials
    # and the result still reads "ok". Decided by thread scheduling, and invisible.
    CREDS[item["id"]] = c
    return {"id": item["id"], "item": title, "endpoint": endpoint, "account": user, "name": name,
            "scheme": scheme, "url_port": url_port,
            "endpoint_malformed": junk, "tags": full.get("tags") or []}


items = json.loads(op("item", "list", "--vault", VAULT, "--format", "json") or "[]")
if not items:
    die(f"vault '{VAULT}' returned no items (1P read hiccup, or nothing is registered)",
        token_file_age_days=TOKEN_FILE_AGE_DAYS)

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

# Every item's fields were already read when membership was resolved. Fetching this one
# again cost a second `op item get` — about a second — for bytes we were already holding.
_f = CREDS.get(opn["id"], {})
K = (_f.get("api_key") or _f.get("key") or "").removeprefix("key=")
S = (_f.get("api_secret") or _f.get("secret") or "").removeprefix("secret=")
if not (K and S):
    die(f"the OPNsense item '{opn['item']}' has no API Key / API Secret fields")

API = f"https://{opn['endpoint']}/api"
inventory, arp = {}, {}
# Independent endpoints, so they are read at the same time rather than one after the other.
with ThreadPoolExecutor(max_workers=2) as ex:
    _dns = ex.submit(curl, f"{API}/dnsmasq/settings/get", "-u", f"{K}:{S}")
    _arp = ex.submit(curl, f"{API}/diagnostics/interface/get_arp", "-u", f"{K}:{S}")
try:
    dj = json.loads(_dns.result() or "{}")
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

if not inventory:
    # Empty is not "no reservations" — it is a read that failed without raising. Left alone it
    # yields a full table with every address, MAC and zone blank, and every host flagged as
    # type-drifted because the wire appears to say nothing. Confident and wrong is the one
    # outcome this tool may not produce.
    die(f"the IPAM at {opn['endpoint'] or '(no endpoint)'} returned no host entries",
        hint="the OPNsense member has no usable endpoint, or its API credential was rejected")

try:
    # Keyed by MAC, not by the reserved IP. A host that is live on a different address than
    # its reservation would silently fall out of an IP-keyed lookup, and the missing vendor
    # would read as "aged out of ARP" — a data drift disguised as a stale cache entry.
    for e in json.loads(_arp.result() or "[]"):
        if e.get("mac"):
            arp[e["mac"].lower()] = e
except Exception:
    pass                                   # vendor and zone are enrichment, not load-bearing


# Every REACH result is measured FROM HERE, and "rpi-01 / LAN / up" only means "a pinhole is
# open" if you know the prober sits in ADM. That fact was living in a note; this reads it off
# the same IPAM as everything else. The machine is asked what it calls itself rather than
# being told — nothing here names a host — and it degrades to no zone if this machine has no
# reservation or has aged out of ARP.
PROBER = socket.gethostname().split(".")[0].lower()
PROBER_ZONE = arp.get(inventory.get(PROBER, {}).get("mac", ""), {}).get("intf_description", "")


# --- classify -------------------------------------------------------------------------------
TAG_TYPES = ("physical", "virtual", "service")

def classify(m):
    """Two independent answers to the same question, kept apart on purpose.

    DECLARED — a 1Password tag: Harry stating what a thing is. Authoritative, and the only
    signal that works for members with no MAC at all, or whose ARP entry has aged out.
    OBSERVED — what the wire says: an IPAM entry means it is a machine, and the vendor string
    OPNsense resolves from the OUI says whether that machine is virtual.

    The declaration wins. The observation corroborates it, and a disagreement is reported
    rather than quietly resolved — same idea as the IPAM reserved-vs-live drift check. Neither
    signal is discarded, because each catches what the other cannot."""
    inv = inventory.get(m["name"], {})
    role, proto, port = ROLES.get(m["name"][:3], ("", "", None))
    # A `role` field on the vault item wins over the hostname prefix. The prefix table is a
    # naming convention for machines Harry racked; it says nothing useful about a tenant. This
    # keeps onboarding a service to "add an item", with no code change.
    # Two attributes, deliberately separate. PLATFORM is the API dialect and selects the auth
    # probe — it changes entirely if OPNsense becomes pfSense. ROLE is what the thing is for and
    # survives that swap untouched. Collapsing them made "role" mean two things at once.
    # While items are being migrated, a lone `role` is still accepted as the platform.
    _c = CREDS.get(m["id"], {})
    platform = (_c.get("platform") or _c.get("role") or role).strip().lower()
    role = (_c.get("role") if _c.get("platform") else "").strip().lower()
    # Fall back to what the URL states. ROLES still wins where it has an entry, because it
    # names the MANAGEMENT port, which is often not the port in the browser URL (DSM: 5001).
    if port is None and m.get("url_port"):
        proto, port = (proto or m.get("scheme") or "https"), m["url_port"]
    _a = arp.get(inv.get("mac", ""), {})
    vendor = _a.get("manufacturer", "")
    zone = _a.get("intf_description", "")      # LAN / ADM / PLY, straight off the interface
    # The reservation says where it should be; ARP says where it is. Disagreement is the
    # lease that outlived the misconfig which created it — silent until someone looks.
    ip_drift = bool(_a.get("ip") and inv.get("ip") and _a["ip"] != inv["ip"])

    declared = next((t.lower() for t in m["tags"] if t.lower() in TAG_TYPES), "")
    if not inv:
        observed = "service"                  # no IPAM entry: a SaaS tenant, not a machine
    elif any(h in vendor.lower() for h in HYPERVISORS):
        observed = "virtual"
    elif vendor:
        observed = "physical"
    else:
        observed = ""                         # aged out of ARP — the wire cannot tell us

    drift = (f"tagged {declared}, but the wire says {observed}"
             if declared and observed and declared != observed else "")
    return {**m, **inv, "role": role, "platform": platform, "port": port,
            "access": (f"{proto}://{inv.get('fqdn') or m['endpoint']}:{port}"
                       if port and (inv.get('fqdn') or m['endpoint']) else ""),
            "vendor": vendor, "zone": zone,
            "live_ip": _a.get("ip", ""), "ip_drift": ip_drift,
            "type": declared or observed or "unclassified",
            "source": "tag" if declared else ("wire" if observed else "none"),
            "type_drift": drift}


# --- REACH and AUTH: measured, never recorded ----------------------------------------------
def nc_open(host, port, t=3):
    return subprocess.run(["nc", "-z", "-G", str(t), "-w", str(t), host, str(port)],
                          capture_output=True).returncode == 0

def ping_ok(host, t=2):
    return subprocess.run(["ping", "-c", "1", "-t", str(t), host], capture_output=True).returncode == 0

def ssh_probe(user, host, pw, expect_token, cmd):
    """Password SSH, one mechanism for every host — consistency over key management.

    PubkeyAuthentication=no and PreferredAuthentications=password force the path we are
    actually testing: without them SSH may succeed on a key and report a password login that
    never happened. NumberOfPasswordPrompts=1 makes a bad credential fail rather than retry.

    The password is passed to pexpect at the prompt, never as an argument, so it cannot appear
    in the process list or in any transcript of the command."""
    if pexpect is None:
        return None, "pexpect unavailable (run via uv, not bare python3)"
    if not pw:
        return None, "no password field on the 1Password item"
    args = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=password",
            f"{user}@{host}", cmd]
    c = pexpect.spawn("ssh", args, encoding="utf-8", timeout=25)
    try:
        if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) != 0:
            return False, "no password prompt (SSH refused before auth)"
        c.sendline(pw)
        i = c.expect([expect_token, r"[Pp]ermission denied", r"[Aa]uthentication failed",
                      pexpect.EOF, pexpect.TIMEOUT])
        if i == 0:
            return True, "login ok"
        return False, ("credential rejected" if i in (1, 2) else
                       "connected but no expected response")
    finally:
        try: c.close(force=True)
        except Exception: pass

def aruba_probe(user, host, pw):
    """ArubaOS does not accept a command as an SSH argument — it opens an interactive session
    with a banner and a keypress gate. Reaching the prompt IS the proof of login, so the probe
    stops there rather than running anything.

    The prompt character is the useful part: '>' is operator (show-only), '#' is manager. That
    reports the PRIVILEGE LEVEL as observed on the device, which is the read-only guarantee
    demonstrated rather than assumed — and it would catch the account being promoted."""
    if pexpect is None:
        return None, "pexpect unavailable (run via uv, not bare python3)"
    if not pw:
        return None, "no password field on the 1Password item"
    opts = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "-o ConnectTimeout=12 -o PubkeyAuthentication=no "
            "-o NumberOfPasswordPrompts=1 "
            "-o PreferredAuthentications=password,keyboard-interactive")
    c = pexpect.spawn(f"ssh {opts} {user}@{host}", encoding="utf-8",
                      timeout=25, dimensions=(200, 400))
    try:
        if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) != 0:
            return False, "no password prompt (SSH refused before auth)"
        c.sendline(pw)
        i = c.expect([r"[Pp]ress any key to continue", r"[A-Za-z0-9._\-]+[>#]",
                      r"[Pp]assword:", r"nvalid", pexpect.EOF, pexpect.TIMEOUT])
        if i in (2, 3):
            return False, "credential rejected"
        if i == 0:
            c.send("\r")
            if c.expect([r"[A-Za-z0-9._\-]+[>#]", pexpect.TIMEOUT], timeout=15) != 0:
                return False, "banner cleared but no prompt"
        prompt = (c.after or "").strip()
        level = "manager (#) — EXPECTED OPERATOR" if prompt.endswith("#") else "operator (>)"
        return True, f"login ok, {level}"
    finally:
        try:
            c.sendline("exit"); c.close(force=True)
        except Exception:
            pass


def auth_probe(r):
    """A REAL read-only login, using the host's own mechanism. Returns (ok|None, detail).
    None means 'cannot be tested', which is different from 'failed' and must stay different."""
    c, host = CREDS.get(r["id"], {}), r.get("fqdn") or r["endpoint"]
    try:
        if r["platform"] == "1password":
            # Deliberately ahead of the host check: this probe talks to no host. It already ran
            # as the substrate pre-check before any member was resolved, so it costs nothing to
            # report, and requiring a URL purely to satisfy the plumbing would be ceremony —
            # my.1password.com being reachable proves nothing about this account.
            w = json.loads(op("whoami", "--format", "json") or "{}")
            return (bool(w.get("user_uuid")),
                    f"service account on {w.get('url','?').split('//')[-1]}" if w.get("user_uuid")
                    else "op whoami returned nothing")
        if not host:
            return None, "no endpoint to test"
        if r["platform"] == "opnsense":
            k = (c.get("api_key") or c.get("key") or "").removeprefix("key=")
            sec = (c.get("api_secret") or c.get("secret") or "").removeprefix("secret=")
            j = json.loads(curl(f"https://{host}/api/core/firmware/status", "-u", f"{k}:{sec}") or "{}")
            v = j.get("product_version")
            return (bool(v), f"OPNsense {v}" if v else "API rejected the credential")
        if r["platform"] == "synology":
            u = c.get("username", ""); pw = c.get("password") or c.get("confirmpassword", "")
            base = f"https://{host}:5001/webapi/entry.cgi"
            out = subprocess.run(["curl", "-sk", "--max-time", "15", "-G", base,
                "--data-urlencode", "api=SYNO.API.Auth", "--data-urlencode", "version=7",
                "--data-urlencode", "method=login", "--data-urlencode", f"account={u}",
                "--data-urlencode", f"passwd={pw}", "--data-urlencode", "session=FileStation",
                "--data-urlencode", "format=sid"], capture_output=True, text=True).stdout
            sid = (json.loads(out or "{}").get("data") or {}).get("sid")
            if sid:   # release it: repeated DSM logins churn sessions and can trip auto-block
                subprocess.run(["curl", "-sk", "--max-time", "8", "-G", base,
                    "--data-urlencode", "api=SYNO.API.Auth", "--data-urlencode", "version=7",
                    "--data-urlencode", "method=logout", "--data-urlencode", "session=FileStation",
                    "--data-urlencode", f"_sid={sid}"], capture_output=True)
            return (bool(sid), "DSM login ok" if sid else "DSM rejected the credential")
        if r["platform"] in ("aruba-switch", "linux"):
            u = c.get("username", "").removeprefix("username=") or r.get("account") or ""
            pw = (c.get("password") or c.get("confirmpassword")
                  or c.get("operator password", "")).removeprefix("password=")
            if not u:
                return None, "no username field on the 1Password item"
            # Prove the session is really established, not merely connected: the switch echoes
            # its own name, the shell echoes a token we chose.
            if r["platform"] == "aruba-switch":
                return aruba_probe(u, host, pw)
            return ssh_probe(u, host, pw, r"wblv-ok", "echo wblv-ok")
        if r["platform"] == "microsoft-graph":
            # Client-credentials against the tenant. A token issued is proof the app
            # registration, the secret and the tenant are all live — which is what "is M365
            # reachable" actually means. TLS to a Microsoft endpoint only proves Microsoft is up.
            tid, cid = c.get("tenant_id", ""), c.get("client_id", "")
            sec = c.get("client_secret", "")
            if not (tid and cid and sec):
                return None, "needs tenant_id, client_id and client_secret fields on the item"
            j = json.loads(curl(f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token",
                                "-d", f"client_id={cid}", "-d", f"client_secret={sec}",
                                "-d", "scope=https://graph.microsoft.com/.default",
                                "-d", "grant_type=client_credentials") or "{}")
            if j.get("access_token"):
                return True, "Graph token issued"
            return False, (j.get("error_description", "").split(".")[0][:70]
                           or "token endpoint rejected the credential")
        if r["platform"] == "tailscale":
            # The API key's own tailnet, via the "-" alias, so no tailnet name is written down.
            # Tailscale API keys authenticate as basic auth with an empty password.
            # An OAuth client can be scoped (devices:read); a raw API key cannot — it is
            # full-access and could delete or re-authorise nodes. Prefer the scoped one, and
            # say so in the detail when the blunt instrument is in use.
            cid, sec = c.get("client_id", ""), c.get("client_secret", "")
            k, how = c.get("api_key", "") or c.get("password", ""), "API key (full-access)"
            if cid and sec:
                tok = json.loads(curl("https://api.tailscale.com/api/v2/oauth/token",
                                      "-d", f"client_id={cid}", "-d", f"client_secret={sec}",
                                      "-d", "grant_type=client_credentials") or "{}")
                k, how = tok.get("access_token", ""), "OAuth client"
                if not k:
                    return False, "OAuth client rejected"
                auth = ["-H", f"Authorization: Bearer {k}"]
            elif k:
                auth = ["-u", f"{k}:"]
            else:
                return None, "needs client_id + client_secret (scoped OAuth) or api_key"
            j = json.loads(curl("https://api.tailscale.com/api/v2/tailnet/-/devices",
                                *auth) or "{}")
            devs = j.get("devices")
            if devs is None:
                return False, (j.get("message", "")[:60] or "API rejected the credential")
            return True, f"{len(devs)} devices, via {how}"
        return None, ""
    except Exception as e:
        return None, f"probe error: {type(e).__name__}"

def reach_probe(host, port):
    """The two tests are raced, not tried in turn. Either one answering is proof of life, so
    waiting for the first to time out before starting the second simply adds one timeout to
    the other — and that only ever happens on a host that is down, which is precisely the host
    that sets the wall-clock for the whole run.

    The timeouts themselves are deliberately NOT reduced. They are what stops a slow-but-alive
    host being reported as down, and a false 'down' is the failure this tool exists to avoid."""
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = ([ex.submit(nc_open, host, port)] if port else []) + [ex.submit(ping_ok, host)]
        return any(f.result() for f in futures)


def probe(r):
    """REACH is a heartbeat; AUTH is proof. Kept apart because health checks lie: a host can
    answer on the network and still be useless to you, and some hosts drop ICMP entirely."""
    host = r.get("fqdn") or r["endpoint"]
    port = r.get("port")
    hostless = r["platform"] in HOSTLESS_ROLES
    if not host and not hostless:
        return {**r, "reach": None, "auth": None, "auth_detail": ""}
    reach = reach_probe(host, port) if host else None
    ok, detail = auth_probe(r) if (reach or hostless) else (None, "")
    return {**r, "reach": reach, "auth": ok, "auth_detail": detail}


# Filtering here rather than at print time: a filtered view has no reason to probe hosts it
# will not show, and `-s` was paying for five host probes to print one service row.
_all = [classify(m) for m in members]
# Two vault items resolving to one name is a data fault: whichever the eye lands on, the other
# is a member you are not seeing. Surfaced on both rows rather than silently de-duplicated.
_seen = {}
for _r in _all:
    _seen.setdefault(_r["name"], []).append(_r)
for _n, _rs in _seen.items():
    if len(_rs) > 1:
        for _r in _rs:
            _r["name_collision"] = len(_rs)
# How much of the wire the directory accounts for. A property of the DIRECTORY, not of any
# host, which is why it is counted here and not attached to a row. Counted before the filter,
# because a filtered view does not make the rest of the lab stop existing.
_member_macs = {r["mac"] for r in _all if r.get("mac")}
OFF_DIRECTORY = sum(1 for mac in arp if mac not in _member_macs)
_classified = [c for c in _all if not WANT or c["type"] in WANT]
with ThreadPoolExecutor(max_workers=6) as ex:      # independent and I/O-bound; NAS stays single
    rows = list(ex.map(probe, _classified))
rows.sort(key=lambda r: (r["type"] == "service", r["name"]))

def render(rows, meta):
    """A table for humans. Colour encodes STATE and nothing else — green up, red down, dim
    untested. Every glyph maps to a measured value; none of it is commentary.

    The counts go ABOVE the table because they are the answer to "is the lab healthy"; the
    table is the detail you read only when a count is wrong.

    rich drops colour automatically when stdout is not a terminal, so a pipe or the session
    hook gets clean text and only a human at a prompt sees the colour."""
    from rich.console import Console
    from rich.table import Table
    from rich.measure import Measurement
    from rich import box

    # Off-TTY there is no width to detect and rich would assume 80, shrinking columns to
    # ellipses. Honour COLUMNS if set, else give it room.
    con = Console(width=None if sys.stdout.isatty() else int(os.environ.get("COLUMNS") or 200),
                  highlight=False)

    def field(label, value, style=""):
        v = f"[{style}]{value}[/]" if style else str(value)
        con.print(f"[dim]{label + ':':<15}[/]{v}")

    field("Vault", meta["vault"])
    field("Source", meta["ipam_source"])
    field("Probing from", f"{meta['prober']} ({meta['prober_zone']})"
                          if meta["prober_zone"] else meta["prober"])
    field("Runtime", f"{meta['runtime_s']}s")
    con.print()

    if not rows:
        con.print("[dim]no members match[/]")
        return

    hosts = sum(1 for r in rows if r["type"] != "service")
    reachable = sum(1 for r in rows if r["reach"] is True)
    authed = sum(1 for r in rows if r["auth"] is True)
    tested = sum(1 for r in rows if r["auth"] is not None)
    field("Hosts", hosts)
    field("Services", len(rows) - hosts)
    field("Reachable", f"{reachable}/{len(rows)}",
          "green" if reachable == len(rows) else "yellow")
    field("Authenticated", f"{authed}/{tested}",
          "green" if tested and authed == tested else "yellow" if authed else "red")
    field("Non-members", meta["off_directory"])
    con.print()

    # SIMPLE without an edge is the only box that starts at column 0 — every bordered style
    # reserves a blank edge column and indents the whole block by one. It gives the rule under
    # the header; the rules above and below are drawn here, at the table's measured width.
    t = Table(box=box.SIMPLE, show_edge=False, header_style="bold", border_style="grey35",
              pad_edge=False, padding=(0, 1))
    # Atomic values are no_wrap so they are never broken mid-token; the state columns carry a
    # min_width floor. Narrowing therefore lands on CREDENTIAL, which has wrap points, instead
    # of collapsing the columns that answer the actual question.
    t.add_column("HOST", style="bold", no_wrap=True)
    t.add_column("TYPE", no_wrap=True)
    t.add_column("ADDRESS", no_wrap=True)
    # Zone sits beside the address because it qualifies it: it is why a host is reachable, or
    # legitimately is not. LAN cannot reach ADM, so an unreachable PLY host is the firewall
    # working, not a fault — and without this the two are indistinguishable in the output.
    t.add_column("ZONE", no_wrap=True)
    t.add_column("MAC", style="grey50", no_wrap=True)
    t.add_column("REACH", justify="center", no_wrap=True, min_width=5)
    t.add_column("AUTH", justify="center", no_wrap=True, min_width=4)
    t.add_column("ACCESS", style="cyan", no_wrap=True)   # connectable URI: never mangle it
    t.add_column("CREDENTIAL", style="grey50")
    # Blank on a healthy row, so the absence of a fault is as visible as its presence. It names
    # the field that is wrong and nothing else — the sentence explaining it lives in --json.
    # A fault here is a defect in the VAULT ENTRY, not in the host: without it a broken URL
    # field renders exactly like a service that legitimately has no endpoint.
    t.add_column("FAULT", style="red", no_wrap=True)

    TYPE = {"physical": "default", "virtual": "cyan", "service": "magenta",
            "unclassified": "yellow"}
    DASH = "[grey35]-[/]"
    for r in rows:
        t.add_row(r["name"],
                  f"[{TYPE.get(r['type'], 'yellow')}]{r['type']}[/]",
                  r.get("ip") or DASH,
                  r.get("zone") or DASH,
                  r.get("mac") or DASH,
                  "[green]up[/]" if r["reach"] is True else
                  "[red]down[/]" if r["reach"] is False else DASH,
                  "[green]ok[/]" if r["auth"] is True else
                  "[bold red]fail[/]" if r["auth"] is False else DASH,
                  r.get("access") or DASH,
                  r["item"],
                  ",".join(f for f, bad in (("url", r.get("endpoint_malformed")),
                                            ("ip", r.get("ip_drift")),
                                            ("tag", r.get("type_drift")),
                                            ("dup", r.get("name_collision"))) if bad))

    # Rich compresses columns to fit the terminal, and under real pressure it will squeeze a
    # column down to a single character — a stack of ellipses that looks like output while
    # carrying nothing. min_width does not hold at that point. For a directory tool a mangled
    # value is worse than an ugly one, so the table is rendered at its NATURAL width and a
    # narrow terminal is left to soft-wrap: every value survives, legibly, at the cost of
    # looking untidy below about 120 columns.
    probe = Console(width=10_000, no_color=True)
    natural = Measurement.get(probe, probe.options, t).maximum
    out = con if natural <= con.width else Console(width=natural, highlight=False)
    rule = "[grey35]" + "─" * natural + "[/]"
    out.print(rule)
    out.print(t)
    out.print(rule)


if __name__ == "__main__":
    shown = rows                       # WANT was applied before the probes, not after them

    # Token age is the age of the token FILE, not time until expiry — 1Password exposes no
    # expiry to read. It stays in --json as a diagnostic, named for what it measures, and is
    # kept off the table so it cannot be mistaken for a warning.
    meta = {"vault": VAULT, "ipam_source": opn["endpoint"],
            "prober": PROBER, "prober_zone": PROBER_ZONE,
            "runtime_s": round(time.time() - _T0, 1), "off_directory": OFF_DIRECTORY,
            "token_file_age_days": TOKEN_FILE_AGE_DAYS}
    if "--json" in sys.argv:
        # Explicit whitelist: credentials live in CREDS and must never be one careless print away.
        KEEP = ("name", "type", "source", "type_drift", "fqdn", "ip", "mac", "vendor", "role",
                "access", "reach", "auth", "auth_detail", "item", "account", "endpoint",
                "endpoint_malformed", "zone", "live_ip", "ip_drift", "platform",
                "name_collision")
        print(json.dumps({**meta, "members": [{k: r.get(k) for k in KEEP} for r in shown]},
                         indent=2))
    else:
        render(shown, meta)
