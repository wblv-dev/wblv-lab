#!/usr/bin/env -S uv run --with pexpect<5 --with rich<16 --quiet --script
"""wblv-lab — what is alive in the lab, and how to reach it.

Design rationale and incident history: see README.md and NOTES.md.
"""
import os, sys, json, re, base64, socket, subprocess, tempfile, threading, time, datetime
try:
    import pexpect
except ImportError:
    pexpect = None   # SSH probes report this rather than failing silently
from concurrent.futures import ThreadPoolExecutor

_T0 = time.time()          # for the Runtime stat: measured, not estimated

TOKEN_PATH = os.path.expanduser("~/.config/wblv/op-token")

# Platforms whose API can serve the lab's IPAM — a vendor fact, not a Harry-lab fact.
# deliberate — replaced a hostname-prefix table, see NOTES.md#ipam-platform-prefix-table
IPAM_PLATFORMS = ("opnsense",)

# Credentials are held OUT of the member records so they cannot reach stdout. Output rows are
# built from an explicit whitelist below; a secret must never be one accidental print away.
CREDS = {}

# Item ids whose auth actually used a credential this MACHINE holds, not the vault's own —
# surfaced as the 'cred' fault, since the row's claim is "this item opens it".
CRED_FALLBACK = set()

# Vendor strings resolved from the router's OUI lookup, not a local table.
# deliberate — roles whose probe talks to no host, so REACH is not a precondition,
# see NOTES.md#hostless-roles
HOSTLESS_ROLES = ("1password", "github")

# RFC 6749 §5.2 (plus Azure's spelling) for "this is us, not you" — NOT a rejection.
# deliberate — misreading these as failed sends Harry rotating a live secret, see NOTES.md#transient-oauth
TRANSIENT_OAUTH = ("temporarily_unavailable", "server_error", "slow_down")

# What each probe actually DID, recorded rather than hand-described so it can't go stale.
# CHECK is read back from this; --check swaps it in for ACCESS. Never records credentials.
# deliberate — see NOTES.md#probe-ops-recorded-not-described
PROBE_OPS = {}
_CUR = threading.local()


def note_op(text):
    """Record one operation against the member currently being probed. A no-op outside a
    probe (the IPAM read runs before any member exists), so it cannot misattribute."""
    mid = getattr(_CUR, "id", None)
    if mid and text:
        PROBE_OPS.setdefault(mid, [])
        if text not in PROBE_OPS[mid]:      # a retry is the same check, not a second one
            PROBE_OPS[mid].append(text)

# 1Password/autofill label variants, folded to one canonical name. ADDITIVE — original kept too.
ALIASES = {
    "newusername": "username", "user": "username", "login": "username",
    "pass": "password", "passwd": "password",
    "key": "api_key", "secret": "api_secret",
    "apikey": "api_key", "apisecret": "api_secret",
    "clientid": "client_id", "clientsecret": "client_secret", "tenantid": "tenant_id",
    "url": "website", "endpoint": "website",
}


def _fold(label):
    """One spelling for a hand-typed GUI label: lowercased, spaces and hyphens to underscores.

    'DNS Name', 'dns name' and 'dns-name' are the same field. A label that silently failed to
    match would be indistinguishable from a field nobody filled in."""
    return re.sub(r"[\s\-]+", "_", (label or "").strip().lower())


# How near is near. A credential is worth warning about while there is still time to rotate it
# calmly; earlier than this and the warning is permanent furniture, which is the same as absent.
EXPIRY_WARN_DAYS = 45


def _expiry_days(value):
    """Days until a recorded credential expiry, or None if none is recorded or it is unparseable.
    Day-first parsing — deliberate, see NOTES.md#day-first-dates"""
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%y"):
        try:
            due = datetime.datetime.strptime(value, fmt).date()
        except ValueError:
            continue
        return (due - datetime.date.today()).days
    return None


def _field(full, *names):
    """First non-empty value among the given field labels, matched forgivingly.

    Reads `fields` only. The vault's items keep every real value there -- their `urls` arrays
    are empty -- so a reader that consults only `urls` sees nothing at all."""
    want = {_fold(n) for n in names}
    return next((f.get("value").strip() for f in (full.get("fields") or [])
                 if _fold(f.get("label")) in want and (f.get("value") or "").strip()), "")

# Explicit whitelist for --json — credentials live in CREDS, never here.
# reach_basis: WHICH measurement produced REACH — "endpoint" | "tenant" | "derived" | "untested".
# Never absent/empty: see NOTES.md#reach-basis
KEEP_JSON = ("name", "type", "source", "type_drift", "fqdn", "ip", "mac", "vendor", "role",
             "access", "check", "probe_ops", "reach", "reach_basis", "auth", "auth_detail",
             "item", "account", "endpoint", "endpoint_malformed", "access_unreachable",
             # arp_seen distinguishes "no ARP entry" from "legitimately nothing" — see NOTES.md#arp-seen
             "cred_fallback", "zone", "arp_seen", "live_ip", "ip_drift", "platform",
             "name_collision",
             # declared_name/derived_name both kept — see NOTES.md#declared-vs-derived-name
             "declared_name", "derived_name", "name_mismatch", "cred_expiry")

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
  wblv-lab --mac        add the MAC column
  wblv-lab --check      swap ACCESS for what each probe actually did
  wblv-lab --json       machine-readable
  wblv-lab --others     what is on the wire that the directory does NOT claim
  wblv-lab --howto      the exact call that logs in to each member\n  wblv-lab --howto nas-01  just that one\n  wblv-lab --brief      counts + Members + only what is NOT normal (what the hook reads)
  wblv-lab --test       every view in turn, from a single probe pass
  wblv-lab -h           this text

Membership comes from 1Password: an item is what makes something a member, so adding one
is the whole of onboarding. Detail comes from OPNsense, which is the IPAM. Nothing is
cached — every run asks again, which costs a few seconds and buys accuracy.

REACH is a heartbeat. AUTH is a real read-only login. Trust AUTH: a host can answer on
the network and still be useless to you.

For a HOST, reach is its address answering. For a SERVICE there is no address, so reach is
scoped to the tenant -- a call that proves YOUR tenant is there, not that the vendor is up.
Where no such call exists without a credential, reach comes from the auth probe, because
you cannot be rejected by something you did not reach. --json says which, in reach_basis:
'endpoint', 'tenant', 'derived', or 'untested' when nothing could be measured at all.

ZONE is the OPNsense interface the host answers on. LAN cannot reach ADM, so it is often
why a host is unreachable, or legitimately is not. REACH and AUTH are measured from the
machine named in "Probing from", whose own zone is shown for exactly that reason.

ACCESS is where YOU connect -- for a service that is the admin console, which is
deliberately not what the probe talks to (nobody logs in to api.github.com). --check
swaps the column for what was actually contacted: the operation that produced AUTH, or
the reach test where no login was attempted, and in brackets how many ran in total.
Every operation in full is in --json under probe_ops. Both are RECORDED during the run,
so they describe what happened rather than what the code is expected to do.

A member's identity is DECLARED, in the item's 'DNS Name' field, not derived from its URL or
its title. A derived name moves when something unrelated changes -- repoint a host and it was
renamed -- and the name is what the drift and duplicate checks key off. Derivation remains
only as the fallback for an item that has not declared one.

FAULT names what disagrees, and is blank when nothing does. 'url' -- the item's URL field
holds no usable hostname. 'ip' -- the DHCP reservation and the live address differ, a lease
that outlived the change which created it. 'tag' -- the declared type and the wire disagree.
'name' -- the declared name and the endpoint disagree, so one of the two fields is stale and
the tool cannot tell which. Services are exempt: their endpoint is the vendor's domain, so
365-01 pointing at portal.azure.com is correct, not broken. 'access' -- the member answered,
but the URI in the ACCESS column did not. 'cred' -- AUTH passed on a credential this machine
holds, not the one the item carries, so the item is untested. 'expiry' -- a recorded
credential expiry is near or already past; a secret that expires silently takes its probe
with it, and the probe goes red long after the warning would have been useful. 'dup' -- two
items resolve to one name, so one of them is a member you cannot see.

Non-members counts addresses OPNsense can see that no vault item claims. It says how much
of the wire this directory accounts for; it is not a fault.

This tool tells you which credential opens a host. It does not turn the key — you connect
and run commands yourself, so the read-only limit lives in the host account."""

# read before any work is done, deliberately — printing help used to cost a full probe run
if {"-h", "--help", "help"} & set(sys.argv[1:]):
    print(HELP); sys.exit(0)

# ⚠ deliberate — unknown flags die loud, an unrecognised flag used to be silently ignored,
# see NOTES.md#unknown-flag-dies
KNOWN = {"-p", "-v", "-s", "--mac", "--check", "--json", "--test", "--brief", "--howto", "--others",
         "-h", "--help", "help"}
_bad = [a for a in sys.argv[1:] if a.startswith("-") and a not in KNOWN]
if _bad:
    die(f"unknown option: {', '.join(_bad)}",
        hint=f"known options: {' '.join(sorted(KNOWN - {'help'}))}   (wblv-lab -h)")

WANT = ({"physical"} if "-p" in sys.argv else set()) | \
       ({"virtual"} if "-v" in sys.argv else set()) | \
       ({"service"} if "-s" in sys.argv else set())

# hidden by default (costs 20 columns); --json always carries it — see NOTES.md#show-mac-width
SHOW_MAC = "--mac" in sys.argv

# same slot as ACCESS, not an added column, so the table stays at its width
SHOW_CHECK = "--check" in sys.argv

# every view from one probe pass, so a whole-surface check needs one paste, not nine runs
SHOW_TEST = "--test" in sys.argv

# deliberate — exceptions only, a wall of green teaches skimming, see NOTES.md#show-brief-exceptions
SHOW_BRIEF = "--brief" in sys.argv

# deliberate — recipes live in the session brief, not behind a flag, see NOTES.md#howto-always-shown
SHOW_HOWTO = "--howto" in sys.argv

# same slot/reasoning as --check — "what do I have" vs "what's here that I don't"
SHOW_OTHERS = "--others" in sys.argv

# no -j alias — would shadow --json's short form and pipe a Rich table into a JSON parser

# one positional, narrowing --howto to a single member; guarded so a bare `wblv-lab foo`
# cannot silently filter the table
ONLY_ID = (next((a for a in sys.argv[1:] if not a.startswith("-")), None)
           if SHOW_HOWTO else None)


# --- 1Password substrate ------------------------------------------------------------------
# proved once, up front — one substrate fault must not read as N cascading host failures
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
    # Subcommand only — `op item get <id>` would record an id, and the verb is the point.
    note_op("op " + " ".join(a for a in args[:2] if not a.startswith("-")))
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
    slots = [u.get("href", "") or "" for u in (full.get("urls") or [])] + \
            [f.get("value") or "" for f in (full.get("fields") or [])
             if "://" in (f.get("value") or "")]
    href = ";".join(slots)
    # deliberate — URL kept whole, not rebuilt from parts, see NOTES.md#url-kept-whole
    website = next((s.strip() for s in slots if "://" in s), "")
    # Any scheme, not just http(s): an SSH-managed host should be able to say so, rather than
    # being described by a web URL it does not serve. The scheme is how you reach it.
    m = re.search(r"([a-z][a-z0-9+.\-]*)://([A-Za-z0-9.\-]+)(?::(\d+))?", href, re.I)
    # deliberate — malformed URL is reported, never coerced, see NOTES.md#m365-host-named-23
    endpoint = m.group(2) if (m and "." in m.group(2)) else ""
    # ⚠ deliberate — a check that could never fire, see NOTES.md#url-fault-could-never-fire
    intended = any(("://" in (u.get("href") or "")) or
                   _fold(u.get("label")) in ("website", "url")
                   for u in (full.get("urls") or [])) or \
               bool(_field(full, "website", "url", "endpoint"))
    junk = intended and not endpoint
    # A service's URL is the only thing that states how to reach it — read scheme/port from it.
    scheme = (m.group(1).lower() if endpoint else "")
    DEFAULT_PORT = {"https": 443, "http": 80, "ssh": 22}
    url_port = (int(m.group(3)) if (endpoint and m.group(3))
                else DEFAULT_PORT.get(scheme) if endpoint else None)
    # deliberate — a set value never loses to an empty one, see NOTES.md#set-value-wins-empty
    user = next((f.get("value") for f in (full.get("fields") or [])
                 if (f.get("label") or "").lower() == "username" and f.get("value")), "")
    # IDENTITY IS DECLARED, NOT DERIVED — `DNS Name` is authoritative; derivation is fallback only.
    # deliberate — see NOTES.md#declared-vs-derived-name
    is_service = any(t.lower() == "service" for t in (full.get("tags") or []))
    declared = _field(full, "dns name").lower()
    # ⚠ deliberate — the last lab-specific fact removed from this file, see NOTES.md#wblv-prefix-removed
    from_title = title.split("/")[0].strip().lower()
    derived = from_title if (is_service or not endpoint) else endpoint.split(".")[0].lower()
    # Tolerated rather than required: someone may reasonably write the FQDN here. The short name
    # is the identity either way, so both spellings resolve to the same member.
    name = declared.split(".")[0] if declared else derived
    # Reported, not resolved — no way to tell which field is stale. Services exempt BY DESIGN.
    name_mismatch = bool(declared and endpoint and not is_service
                         and declared.split(".")[0] != endpoint.split(".")[0].lower())
    # deliberate — labels matched forgivingly across fields AND labelled URLs, see NOTES.md#field-label-matching
    def _keys(label):
        low = (label or "").strip().lower()
        return {low, re.sub(r"[\s\-]+", "_", low)} - {""}

    # deliberate — set value never loses to empty, see NOTES.md#set-value-wins-empty
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
    # ⚠ deliberate — keyed by item id, not name, see NOTES.md#creds-keyed-by-id
    CREDS[item["id"]] = c
    return {"id": item["id"], "item": title, "endpoint": endpoint, "account": user, "name": name,
            "scheme": scheme, "url_port": url_port, "website": website,
            "endpoint_malformed": junk, "tags": full.get("tags") or [],
            "declared_name": declared, "derived_name": derived, "name_mismatch": name_mismatch,
            "cred_expiry": _expiry_days(_field(full, "expiry date", "expiry"))}


items = json.loads(op("item", "list", "--vault", VAULT, "--format", "json") or "[]")
if not items:
    die(f"vault '{VAULT}' returned no items (1P read hiccup, or nothing is registered)",
        token_file_age_days=TOKEN_FILE_AGE_DAYS)

with ThreadPoolExecutor(max_workers=8) as ex:          # per-item `op item get` is the slow part
    members = [m for m in ex.map(_member, items) if m]
if not members:
    die(f"vault '{VAULT}' has items but none carry a usable endpoint URL")


# --- detail: OPNsense is the IPAM ----------------------------------------------------------
def curl(url, *extra, t=10, verify=True, stdin=None):
    """TLS is verified by default. Verification requires addressing the host by NAME — a
    certificate can never match a bare IP — which is why this tool has no addresses in it.

    Returns (REACHED, body). REACHED is curl's own exit status: did the transfer complete at
    all. Discarding it was a real defect — an unreachable host and a host that answered
    "no" both arrive as an empty string, so every caller that parsed the body alone reported
    a network outage as a rejected credential, and the reach derived from that as "up".
    Callers MUST branch on REACHED before reading the body: no answer is None (untested),
    never False (failed). That distinction is the one this whole tool is built on.

    Note an HTTP error is a COMPLETED transfer — 400 or 401 means the far end answered, and
    curl exits 0. Only a transport failure (DNS, refused, TLS, timeout) exits non-zero."""
    # The method is inferred from the flags rather than stated, so it stays true if a call
    # changes shape. Query string dropped: it is where secrets ride.
    note_op(f"{'POST' if any(a in ('-d', '--data') for a in extra) else 'GET'} "
            f"{re.sub(r'^[a-z]+://', '', url).split('?')[0]}")
    flags = ["-s"] if verify else ["-sk"]
    r = subprocess.run(["curl", *flags, "--max-time", str(t), *extra, url],
                       capture_output=True, text=True,
                       input=stdin, timeout=t + 5)
    return r.returncode == 0, r.stdout


def _platform_of(m):
    return (CREDS.get(m["id"], {}).get("platform")
            or CREDS.get(m["id"], {}).get("role") or "").strip().lower()


opn = next((m for m in members if _platform_of(m) in IPAM_PLATFORMS), None)
if not opn:
    die("no member declares a platform that can serve the IPAM — cannot read the lab",
        hint=f"one vault item needs Platform set to one of: {', '.join(IPAM_PLATFORMS)}")

# reuses the fields already read during membership — no second `op item get`
_f = CREDS.get(opn["id"], {})
K = (_f.get("api_key") or _f.get("key") or "").removeprefix("key=")
S = (_f.get("api_secret") or _f.get("secret") or "").removeprefix("secret=")
if not (K and S):
    die(f"the OPNsense item '{opn['item']}' has no API Key / API Secret fields")

API = f"https://{opn['endpoint']}/api"
inventory, arp, ROUTER_MACS = {}, {}, set()
# Independent endpoints, so they are read at the same time rather than one after the other.
with ThreadPoolExecutor(max_workers=3) as ex:
    _dns = ex.submit(curl, f"{API}/dnsmasq/settings/get", "-u", f"{K}:{S}")
    _arp = ex.submit(curl, f"{API}/diagnostics/interface/get_arp", "-u", f"{K}:{S}")
    # deliberate — router's own interfaces derived, not vault-declared, see NOTES.md#router-macs-derived
    _ifs = ex.submit(curl, f"{API}/interfaces/overview/interfacesInfo", "-u", f"{K}:{S}")
try:
    dj = json.loads(_dns.result()[1] or "{}")
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
    # deliberate — empty is a failed read, not "no reservations", see NOTES.md#empty-ipam-dies
    die(f"the IPAM at {opn['endpoint'] or '(no endpoint)'} returned no host entries",
        hint="the OPNsense member has no usable endpoint, or its API credential was rejected")

try:
    # keyed by MAC, not reserved IP — a live-but-drifted host must not fall out of the lookup
    for e in json.loads(_arp.result()[1] or "[]"):
        if e.get("mac"):
            arp[e["mac"].lower()] = e
except Exception:
    pass                                   # vendor and zone are enrichment, not load-bearing

try:
    _ij = json.loads(_ifs.result()[1] or "{}")
    for _r in (_ij.get("rows") if isinstance(_ij, dict) else _ij) or []:
        _m = (_r.get("macaddr") or _r.get("mac") or "").lower()
        # 00:00:00:00:00:00 is what a PPPoE/loopback pseudo-interface reports; claiming it
        # would swallow every device that also reports all-zeroes.
        if _m and _m != "00:00:00:00:00:00":
            ROUTER_MACS.add(_m)
except Exception:
    pass          # unclaimed interfaces inflate the count again -- visibly, not silently


# Every REACH result is measured FROM HERE — "up" only means "a pinhole is open" if you know
# the prober's own zone. Asked, not told: nothing here names a host.
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
    # PLATFORM is the API dialect (selects the auth probe) — ROLE is what it's for, survives a
    # product swap. Kept deliberately separate. A lone `role` is still accepted mid-migration.
    _c = CREDS.get(m["id"], {})
    platform = (_c.get("platform") or _c.get("role") or "").strip().lower()
    role = (_c.get("role") if _c.get("platform") else "").strip().lower()
    # deliberate — replaced a management-port prefix table, see NOTES.md#scheme-from-item
    proto, port = (m.get("scheme") or ""), m.get("url_port")
    _a = arp.get(inv.get("mac", ""), {})
    # arp_seen: was this member measured at all — see NOTES.md#arp-seen
    arp_seen = bool(_a)
    vendor = _a.get("manufacturer", "")
    zone = _a.get("intf_description", "")      # LAN / ADM / PLY, straight off the interface
    # ⚠ deliberate — TRI-STATE, same reason REACH/AUTH are; "DHCP leases outlive the misconfig
    # that created them" — see NOTES.md#ip-drift-tri-state
    ip_drift = (None if not (arp_seen and _a.get("ip") and inv.get("ip"))
                else _a["ip"] != inv["ip"])

    declared = next((t.lower() for t in m["tags"] if t.lower() in TAG_TYPES), "")
    if not inv:
        observed = "service"                  # no IPAM entry: a SaaS tenant, not a machine
    elif any(h in vendor.lower() for h in HYPERVISORS):
        observed = "virtual"
    elif vendor:
        observed = "physical"
    else:
        observed = ""                         # aged out of ARP — the wire cannot tell us

    # ⚠ deliberate — same untested-vs-clean trap as ip_drift, see NOTES.md#type-drift-trap
    drift = (f"tagged {declared}, but the wire says {observed}"
             if declared and observed and declared != observed else "")
    declared_svc = any(t.lower() == "service" for t in m["tags"])
    return {**m, **inv, "role": role, "platform": platform, "port": port,
            "access": (m.get("website") or "") if (declared_svc and not inv) else
                      (f"{proto}://{inv.get('fqdn') or m['endpoint']}:{port}"
                       if port and (inv.get('fqdn') or m['endpoint']) else ""),
            "vendor": vendor, "zone": zone, "arp_seen": arp_seen,
            "live_ip": _a.get("ip", ""), "ip_drift": ip_drift,
            "type": declared or observed or "unclassified",
            "source": "tag" if declared else ("wire" if observed else "none"),
            "type_drift": drift}


# --- REACH and AUTH: measured, never recorded ----------------------------------------------
def nc_open(host, port, t=3):
    """A DROPPED SYN never returns: macOS nc ignores -G and -w, so the caller must bound it.

    deliberate — the flags are kept in case Apple honours them, see NOTES.md#nc-ignores-its-own-timeouts"""
    try:
        return subprocess.run(["nc", "-z", "-G", str(t), "-w", str(t), host, str(port)],
                              capture_output=True, timeout=t + 1).returncode == 0
    except subprocess.TimeoutExpired:
        return False       # no answer inside t is exactly what "not open" means

def ping_ok(host, t=2):
    # ping -t IS honoured today. So was nc -G, right up until a dropped SYN proved otherwise:
    # the bound belongs here, where no vendor can withdraw it. NOTES.md#nc-ignores-its-own-timeouts
    try:
        return subprocess.run(["ping", "-c", "1", "-t", str(t), host],
                              capture_output=True, timeout=t + 1).returncode == 0
    except subprocess.TimeoutExpired:
        return False

# These four literals are exactly the ones that were got wrong by hand — each is now named
# once and referenced by BOTH the probe that uses it and the recipe that documents it, so a
# recipe cannot describe a login the probe does not perform.
SSH_LEGACY_OPTS = ["HostKeyAlgorithms=+ssh-rsa",
                   "PubkeyAcceptedAlgorithms=+ssh-rsa",
                   "KexAlgorithms=+diffie-hellman-group14-sha1"]
DSM_AUTH_VERSION = "7"
# Not an arbitrary label: DSM scopes a session to an application, and an account restricted
# to FileStation is refused 402 under any other name. Discovered by getting it wrong.
DSM_SESSION = "FileStation"
# OPNsense items store the credential with a literal prefix in the field value.
OPN_PREFIXES = {"api_key": "key=", "api_secret": "secret="}


def ssh_probe(user, host, pw, expect_token, cmd, legacy=False):
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
            "-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=password"]
    if legacy:
        # deliberate — legacy appliances only, never globally, see NOTES.md#ssh-legacy-opts
        args += [x for o in SSH_LEGACY_OPTS for x in ("-o", o)] + [
                 "-o", "Ciphers=+aes128-cbc"]
    args += [f"{user}@{host}", cmd]
    note_op(f"ssh {user}@{host}" + (f" -- {cmd}" if cmd else ""))
    c = pexpect.spawn("ssh", args, encoding="utf-8", timeout=25)
    try:
        if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) != 0:
            return False, "no password prompt (SSH refused before auth)"
        c.sendline(pw)
        i = c.expect([expect_token, r"[Pp]ermission denied", r"[Aa]uthentication failed",
                      pexpect.EOF, pexpect.TIMEOUT])
        if i == 0:
            # Drain the session so a capability check rides the SAME login, not a second one.
            try:
                c.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=8)
            except Exception:
                pass
            tail = c.before or ""
            if "NOSUDO" in tail:
                return True, "login ok, no sudo"
            if "SUDO" in tail:
                return True, "login ok, SUDO"
            return True, "login ok"
        return False, ("credential rejected" if i in (1, 2) else
                       "connected but no expected response")
    finally:
        try: c.close(force=True)
        except Exception: pass

def aruba_probe(user, host, pw, private_key=None):
    """ArubaOS takes no command as an SSH argument — it opens an interactive session behind a
    keypress gate. Reaching the prompt IS the login proof; '>' is operator, '#' is manager,
    which reports privilege level as observed, not assumed. Key and password paths are kept
    separate (never blended) so which mechanism succeeded is part of what's reported.
    See NOTES.md#aruba-probe-shape for the full rationale."""
    if pexpect is None:
        return None, "pexpect unavailable (run via uv, not bare python3)"
    if not private_key and not pw:
        return None, "no private key or password on the 1Password item"
    base = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=12 ")
    keyfile = None
    if private_key:
        # deliberate — bounded exposure: 0600, temp dir, this probe's lifetime only.
        fd, keyfile = tempfile.mkstemp(prefix="wblv-probe-", suffix=".key")
        os.write(fd, (private_key if private_key.endswith("\n") else private_key + "\n").encode())
        os.close(fd)
        os.chmod(keyfile, 0o600)
        # ⚠ deliberate — offline key-shape check before spending an auth attempt,
        # see NOTES.md#aruba-key-quoting
        # An ENCRYPTED key makes ssh-keygen wait on a passphrase prompt for ever — measured.
        # A probe may not block on a terminal nobody is watching.
        try:
            _shape = subprocess.run(["ssh-keygen", "-y", "-f", keyfile],
                                    capture_output=True, stdin=subprocess.DEVNULL, timeout=5)
            _bad, _why = _shape.returncode, "(malformed)"
        except subprocess.TimeoutExpired:
            _bad, _why = 1, "(it asks for a passphrase, so it cannot be used unattended)"
        if _bad:
            os.unlink(keyfile)
            return None, ("private key material on the item is not a usable key file "
                          f"{_why}; nothing was sent, so this is untested, not rejected")
        # deliberate — IdentitiesOnly/IdentityAgent=none pin THIS key; RSA sig-algs needed for
        # Mocana SSH 6.3 — see NOTES.md#aruba-rsa-sig-algs
        opts = base + ("-o PasswordAuthentication=no -o PreferredAuthentications=publickey "
                       "-o IdentitiesOnly=yes -o IdentityAgent=none "
                       f"-o PubkeyAcceptedAlgorithms=+ssh-rsa -i {keyfile}")
    else:
        opts = base + ("-o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "
                       "-o PreferredAuthentications=password,keyboard-interactive")
    note_op(f"ssh {user}@{host} -- prompt ({'key' if private_key else 'password'})")
    c = pexpect.spawn(f"ssh {opts} {user}@{host}", encoding="utf-8",
                      timeout=25, dimensions=(200, 400))
    try:
        if not private_key:
            if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) != 0:
                return False, "no password prompt (SSH refused before auth)"
            c.sendline(pw)
        i = c.expect([r"[Pp]ress any key to continue", r"[A-Za-z0-9._\-]+[>#]",
                      r"[Pp]assword:", r"nvalid", r"[Pp]ermission denied",
                      pexpect.EOF, pexpect.TIMEOUT])
        if i in (2, 3, 4):
            return False, "credential rejected"
        if i == 0:
            c.send("\r")
            if c.expect([r"[A-Za-z0-9._\-]+[>#]", pexpect.TIMEOUT], timeout=15) != 0:
                return False, "banner cleared but no prompt"
        prompt = (c.after or "").strip()
        level = "manager (#) — EXPECTED OPERATOR" if prompt.endswith("#") else "operator (>)"
        return True, f"login ok by {'key' if private_key else 'password'}, {level}"
    finally:
        try:
            c.sendline("exit"); c.close(force=True)
        except Exception:
            pass
        if keyfile:
            try:
                os.unlink(keyfile)
            except OSError:
                pass


def _undecorate(v):
    """Strip what a copy-paste adds to a credential but a credential never contains:
    surrounding whitespace, and ONE matching pair of wrapping quotes. Nothing else — must
    never massage a wrong value into a plausible one. See NOTES.md#undecorate-history for
    the three real credentials this was built to catch."""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def auth_probe_1password():
    w = json.loads(op("whoami", "--format", "json") or "{}")
    return (bool(w.get("user_uuid")),
            f"service account on {w.get('url','?').split('//')[-1]}" if w.get("user_uuid")
            else "op whoami returned nothing")


def auth_probe_opnsense(c, host):
    # deliberate — undecorate before stripping the key=/secret= prefix: a dirty paste wraps
    # the WHOLE field (prefix included) in quotes, same failure family as the PVE token-id
    # incident. See NOTES.md#undecorate-history.
    k = _undecorate(c.get("api_key") or c.get("key") or "").removeprefix(OPN_PREFIXES["api_key"])
    sec = _undecorate(c.get("api_secret") or c.get("secret") or "").removeprefix(OPN_PREFIXES["api_secret"])
    got, body = curl(f"https://{host}/api/core/firmware/status", "-u", f"{k}:{sec}",
                     "-w", "\n%{http_code}")
    if not got:
        return None, "no answer from the API"
    body, _, code = body.rpartition("\n")
    # deliberate — HTTP 401 is checked FIRST, not just the body's own status field: the body
    # check alone fails OPEN on any rejection OPNsense ever answers in a shape other than
    # {"status": 401, ...} — a differently-shaped error read as "authenticated, schema not
    # recognised" instead of rejected. The protocol-level code is the reliable signal;
    # see NOTES.md#opnsense-schema-move.
    if code.strip() == "401":
        return False, "API rejected the credential (401)"
    j = json.loads(body or "{}")
    if not j:
        return None, "API answered with nothing parseable"
    # deliberate — kept as a second check, not a fixed version-field path: assert on
    # REJECTION, not on where the version string lives. See NOTES.md#opnsense-schema-move.
    if j.get("status") == 401:
        return False, "API rejected the credential"
    v = (j.get("product") or {}).get("product_version") or j.get("product_version")
    return True, f"OPNsense {v}" if v else "authenticated; firmware/status schema not recognised"


def auth_probe_proxmox(r, c, host):
    # Token id is not secret (USER@REALM!TOKENID); UUID is. Fixed Proxmox header form:
    #   Authorization: PVEAPIToken=USER@REALM!TOKENID=UUID
    tid = _undecorate(c.get("api_key") or c.get("username") or "")
    uuid = _undecorate(c.get("api_secret") or c.get("password") or "")
    if not (tid and uuid):
        return None, "needs the token id (API Key) and its UUID (API Secret)"
    # deliberate — SHAPE checked offline before spending an auth attempt. `=` is excluded
    # too: a secret pasted into this field by mistake (token-id and UUID both contain no
    # `=`, but `PVEAPIToken=id=secret` does) would otherwise pass this check and fail later
    # with a generic rejection instead of the specific diagnostic below.
    # See NOTES.md#undecorate-history
    if not re.fullmatch(r"[^\s@!=]+@[^\s@!=]+![^\s@!=]+", tid):
        return False, "token id is malformed — expected USER@REALM!TOKENID"
    if not re.fullmatch(r"(?i)[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", uuid):
        return False, "token secret is not a UUID — check the API Secret field"
    hdr = ["-H", f"Authorization: PVEAPIToken={tid}={uuid}"]
    port = r.get('port') or 8006
    # deliberate — two calls separate "secret works" from "can read anything", fired
    # concurrently rather than back to back since neither depends on the other's result;
    # see NOTES.md#pve-two-call-auth
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_ver = ex.submit(curl, f"https://{host}:{port}/api2/json/version", *hdr)
        f_nodes = ex.submit(curl, f"https://{host}:{port}/api2/json/nodes", *hdr)
        got, body = f_ver.result()
        got_n, body_n = f_nodes.result()
    if not got:
        return None, "no answer from the API"
    try:
        j = json.loads(body or "{}")
    except ValueError:
        return False, "API answered but not with JSON — check the token id form"
    ver = (j.get("data") or {}).get("version")
    if not ver:
        return False, "API rejected the credential"
    try:
        nodes = (json.loads(body_n or "{}").get("data") or []) if got_n else None
    except ValueError:
        nodes = None
    if nodes is None:
        return True, f"PVE {ver} (node list unreadable — ACL not checked)"
    if not nodes:
        return False, f"PVE {ver}: token valid but reads nothing — no PVEAuditor ACL"
    return True, f"PVE {ver}, {len(nodes)} node{'s' if len(nodes) != 1 else ''}"


def auth_probe_synology(r, c, host):
    u = c.get("username", ""); pw = c.get("password") or c.get("confirmpassword", "")
    dsm = r.get("port") or 5001
    base = f"https://{host}:{dsm}/webapi/entry.cgi"
    # deliberate — manual note_op since this bypasses curl(); api= named, not query-lifted,
    # see NOTES.md#dsm-note-op
    note_op(f"GET {host}:{dsm}/webapi/entry.cgi api=SYNO.API.Auth (login)")
    out = subprocess.run(["curl", "-sk", "--max-time", "15", "-G", base,
        "--data-urlencode", "api=SYNO.API.Auth",
        "--data-urlencode", f"version={DSM_AUTH_VERSION}",
        "--data-urlencode", "method=login", "--data-urlencode", f"account={u}",
        "--data-urlencode", f"passwd={pw}",
        "--data-urlencode", f"session={DSM_SESSION}",
        "--data-urlencode", "format=sid"], capture_output=True, text=True).stdout
    sid = (json.loads(out or "{}").get("data") or {}).get("sid")
    if not sid:
        return False, "DSM rejected the credential"
    # ⚠ deliberate — ORDER IS LOAD-BEARING, capability read before logout,
    # see NOTES.md#dsm-order-load-bearing
    note_op(f"GET {host}:{dsm}/webapi/entry.cgi api=SYNO.Core.System")
    info = subprocess.run(["curl", "-sk", "--max-time", "10", "-G", base,
        "--data-urlencode", "api=SYNO.Core.System", "--data-urlencode", "version=1",
        "--data-urlencode", "method=info", "--data-urlencode", f"_sid={sid}"],
        capture_output=True, text=True).stdout
    try:
        ok = bool(json.loads(info or "{}").get("success"))
    except ValueError:
        ok = False
    # Released only now, once nothing else needs the session. Repeated DSM logins churn
    # sessions and can trip the auto-block, so every run must hand its own back.
    note_op(f"GET {host}:{dsm}/webapi/entry.cgi api=SYNO.API.Auth (logout)")
    subprocess.run(["curl", "-sk", "--max-time", "8", "-G", base,
        "--data-urlencode", "api=SYNO.API.Auth",
        "--data-urlencode", f"version={DSM_AUTH_VERSION}",
        "--data-urlencode", "method=logout",
        "--data-urlencode", f"session={DSM_SESSION}",
        "--data-urlencode", f"_sid={sid}"], capture_output=True)
    # named after the one API actually tried — not generalised to "Core APIs refused"
    return True, ("DSM login ok, Core.System readable" if ok
                  else "DSM login ok, Core.System REFUSED (105)")


def _ssh_login_creds(r, c):
    # shared by aruba-switch/linux/tplink-eap — proves the session is established, not merely
    # connected — see NOTES.md#echo-proves-session
    u = c.get("username", "").removeprefix("username=") or r.get("account") or ""
    pw = (c.get("password") or c.get("confirmpassword")
          or c.get("operator password", "")).removeprefix("password=")
    return u, pw


def auth_probe_aruba_switch(r, c, host):
    u, pw = _ssh_login_creds(r, c)
    if not u:
        return None, "no username field on the 1Password item"
    return aruba_probe(u, host, pw, c.get("private_key") or "")


def auth_probe_linux(r, c, host):
    u, pw = _ssh_login_creds(r, c)
    if not u:
        return None, "no username field on the 1Password item"
    cmd = "echo wblv-ok; sudo -n true 2>/dev/null && echo SUDO || echo NOSUDO"
    return ssh_probe(u, host, pw, r"wblv-ok", cmd, legacy=False)


def auth_probe_tplink_eap(r, c, host):
    # TP-Link EAP: unprivileged BusyBox shell, legacy host keys only, no sudo to ask.
    u, pw = _ssh_login_creds(r, c)
    if not u:
        return None, "no username field on the 1Password item"
    return ssh_probe(u, host, pw, r"wblv-ok", "echo wblv-ok", legacy=True)


def auth_probe_microsoft_graph(c):
    # client-credentials against the tenant — a token issued proves app+secret+tenant live
    tid, cid = c.get("tenant_id", ""), c.get("client_id", "")
    sec = c.get("client_secret", "")
    if not (tid and cid and sec):
        return None, "needs tenant_id, client_id and client_secret fields on the item"
    got, body = curl(f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token",
                     "-d", f"client_id={cid}", "-d", f"client_secret={sec}",
                     "-d", "scope=https://graph.microsoft.com/.default",
                     "-d", "grant_type=client_credentials")
    if not got:
        return None, "no answer from the token endpoint"
    j = json.loads(body or "{}")
    if j.get("access_token"):
        # deliberate — decode roles claim so read-only-doctrine compliance is visible,
        # see NOTES.md#graph-roles-claim
        try:
            _pl = j["access_token"].split(".")[1]
            _pl += "=" * (-len(_pl) % 4)
            _roles = json.loads(base64.urlsafe_b64decode(_pl)).get("roles") or []
            _w = [x for x in _roles if ".ReadWrite." in x or x.endswith(".Write")]
            if _roles:
                return True, (f"Graph token, {len(_roles)} roles, "
                              + (f"{len(_w)} WRITE" if _w else "all read"))
        except Exception:
            pass          # a token that will not decode is still a token that issued
        return True, "Graph token issued"
    # not-a-token is not automatically a rejection — see NOTES.md#transient-oauth
    if (j.get("error") or "") in TRANSIENT_OAUTH:
        return None, f"token endpoint unavailable ({j['error']})"
    return False, (j.get("error_description", "").split(".")[0][:70]
                   or "token endpoint rejected the credential")


def auth_probe_tailscale(c):
    # "-" alias — own tailnet, no name written down. Prefer scoped OAuth over a raw
    # full-access API key; say so in the detail when the blunt instrument is in use.
    cid, sec = c.get("client_id", ""), c.get("client_secret", "")
    k, how = c.get("api_key", "") or c.get("password", ""), "API key (full-access)"
    if cid and sec:
        got, body = curl("https://api.tailscale.com/api/v2/oauth/token",
                         "-d", f"client_id={cid}", "-d", f"client_secret={sec}",
                         "-d", "grant_type=client_credentials")
        if not got:
            return None, "no answer from the OAuth endpoint"
        tok = json.loads(body or "{}")
        k, how = tok.get("access_token", ""), "OAuth client"
        if not k:
            if (tok.get("error") or "") in TRANSIENT_OAUTH:
                return None, f"OAuth endpoint unavailable ({tok['error']})"
            return False, "OAuth client rejected"
        auth = ["-H", f"Authorization: Bearer {k}"]
    elif k:
        auth = ["-u", f"{k}:"]
    else:
        return None, "needs client_id + client_secret (scoped OAuth) or api_key"
    got, body = curl("https://api.tailscale.com/api/v2/tailnet/-/devices", *auth)
    if not got:
        return None, "no answer from the API"
    j = json.loads(body or "{}")
    devs = j.get("devices")
    if devs is None:
        return False, (j.get("message", "")[:60] or "API rejected the credential")
    return True, f"{len(devs)} devices, via {how}"


def auth_probe_jira(r, c):
    # Basic auth email:token — the only scheme that survives SSO; deliberate,
    # see NOTES.md#jira-basic-auth-survives-sso
    user, k = c.get("username") or "", c.get("api_key") or c.get("password") or ""
    # Website, not DNS Name — the API host, vs the service's canonical short name.
    host = re.sub(r"^[a-z]+://", "", (r.get("endpoint") or "")).split("/")[0].strip()
    if not (user and k and host):
        return None, "item needs username, API Key and a Website URL"
    # credentials via STDIN/--config, never argv — see NOTES.md#creds-never-in-argv
    got, body = curl(f"https://{host}/rest/api/3/myself",
                     "-H", "Accept: application/json", "--config", "-",
                     stdin=f'user = "{user}:{k}"\n')
    if not got:
        return None, "no answer from the API"
    try:
        j = json.loads(body or "{}")
    except ValueError:
        return None, "unreadable answer from the API"
    who = j.get("displayName") or j.get("emailAddress") or ""
    if not who:
        return False, "API rejected the token"
    # deliberate — enumerate authority, not a single word; best-effort/non-fatal,
    # see NOTES.md#jira-permission-enumeration
    grant = ""
    try:
        ok2, b2 = curl(f"https://{host}/rest/api/3/mypermissions"
                       "?permissions=BROWSE_PROJECTS,CREATE_ISSUES,EDIT_ISSUES,"
                       "DELETE_ISSUES,ADMINISTER",
                       "-H", "Accept: application/json", "--config", "-",
                       stdin=f'user = "{user}:{k}"\n')
        if ok2:
            P = (json.loads(b2 or "{}") or {}).get("permissions", {})
            def has(x): return bool(P.get(x, {}).get("havePermission"))
            held = [n for n, key in (("admin", "ADMINISTER"), ("create", "CREATE_ISSUES"),
                                     ("edit", "EDIT_ISSUES"), ("delete", "DELETE_ISSUES"))
                    if has(key)]
            if held:
                grant = ", " + "+".join(held)
            elif has("BROWSE_PROJECTS"):
                grant = ", read-only"      # the goal; say so when it is true
    except Exception:
        grant = ""      # untested authority is not the same as no authority
    return True, f"{who}{grant}"


def auth_probe_github(r, c):
    # PAT as bearer token, /user is the cheapest live READ. deliberate — vault first,
    # then gh's own store, source REPORTED not silently resolved,
    # see NOTES.md#github-vault-then-gh
    k, src = (c.get("api_key") or c.get("password") or ""), "vault"
    if not k:
        # bounded like every probe — an unbounded gh keychain prompt hangs the whole pool
        try:
            note_op("gh auth token")
            k, src = subprocess.run(["gh", "auth", "token"], capture_output=True,
                                    text=True, timeout=10).stdout.strip(), "gh"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            k, src = "", "gh"
        if k:
            CRED_FALLBACK.add(r["id"])
    if not k:
        return None, "no api_key on the item, and gh holds no token"
    # ⚠ deliberate — headers to stderr/body to stdout (not `-D -`, which interleaves
    # unreliably); token via STDIN never argv — see NOTES.md#github-header-body-split
    note_op("GET api.github.com/user")
    r_ = subprocess.run(["curl", "-s", "-D", "/dev/stderr", "--max-time", "10",
                         "--config", "-",
                         "-H", "Accept: application/vnd.github+json",
                         "https://api.github.com/user"],
                        input=f'header = "Authorization: Bearer {k}"\n',
                        capture_output=True, text=True, timeout=15)
    if r_.returncode != 0:
        return None, "no answer from the API"
    head = r_.stderr
    login = (json.loads(r_.stdout or "{}") or {}).get("login")
    if not login:
        return False, "API rejected the token"
    # deliberate — PRESENT-but-empty header vs ABSENT header are different PAT kinds,
    # see NOTES.md#github-scopes-header
    scoped = next((l.split(":", 1)[1].strip() for l in head.splitlines()
                   if l.lower().startswith("x-oauth-scopes:")), None)
    grants = [s.strip() for s in (scoped or "").split(",") if s.strip()]
    admin = [s for s in grants if s.startswith("admin:")]
    kind = (f"{len(grants)} scopes" + (f" incl. {len(admin)} admin" if admin else "")
            if grants else "classic, no scopes" if scoped is not None
            else "fine-grained")
    return True, f"{login}, {kind}, via {src}"


# deliberate — one function per vendor dialect, dispatched by table: see NOTES.md for why the
# interpretation layer can't be generic (OPNsense vs Proxmox vs DSM all mean "authenticated"
# differently) even though the mechanics (curl/ssh_probe) already are.
AUTH_PROBES = {
    "opnsense": lambda r, c, host: auth_probe_opnsense(c, host),
    "proxmox": auth_probe_proxmox,
    "synology": auth_probe_synology,
    "aruba-switch": auth_probe_aruba_switch,
    "linux": auth_probe_linux,
    "tplink-eap": auth_probe_tplink_eap,
    "microsoft-graph": lambda r, c, host: auth_probe_microsoft_graph(c),
    "tailscale": lambda r, c, host: auth_probe_tailscale(c),
    "jira": lambda r, c, host: auth_probe_jira(r, c),
    "github": lambda r, c, host: auth_probe_github(r, c),
}


def auth_probe(r):
    """A REAL read-only login, using the host's own mechanism. Returns (ok|None, detail).
    None means 'cannot be tested', which is different from 'failed' and must stay different."""
    c, host = CREDS.get(r["id"], {}), r.get("fqdn") or r["endpoint"]
    try:
        if r["platform"] == "1password":
            # ahead of the host check on purpose — this probe talks to no host
            return auth_probe_1password()
        if not host:
            return None, "no endpoint to test"
        fn = AUTH_PROBES.get(r["platform"])
        return fn(r, c, host) if fn else (None, "")
    except Exception as e:
        return None, f"probe error: {type(e).__name__}"

def reach_probe(host, port):
    """Raced, not tried in turn — either test answering is proof of life. Timeouts are
    deliberately NOT reduced, see NOTES.md#reach-probe-timeouts"""
    # Recorded like every other operation, so CHECK accounts for REACH as well as AUTH. Both
    # are noted because both are attempted: they are raced, and either answering is the result.
    if port:
        note_op(f"tcp {host}:{port}")
    note_op(f"ping {host}")
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = ([ex.submit(nc_open, host, port)] if port else []) + [ex.submit(ping_ok, host)]
        return any(f.result() for f in futures)


def tenant_reach(r):
    """REACH for a service has to mean "I can see THIS tenant", not "the vendor is up".

    A TCP handshake with portal.azure.com proves Microsoft is running — true on every day this
    tool will ever be run, and silent on whether the tenant exists. That is a green light
    wired to the wrong thing, which is worse than no light at all.

    Where the vendor publishes a tenant-scoped endpoint needing no credential, that is the real
    signal. Where none does, there is nothing to measure without authenticating: a Tailscale
    tailnet is deliberately not publicly discoverable, and neither is a 1Password account. For
    those, reach is derived from the auth probe in probe() rather than faked from a front door.

    Returns (True|False|None, basis). None means "no unauthenticated tenant probe exists here",
    which is a different statement from False, and must stay different."""
    c = CREDS.get(r["id"], {})
    if r["platform"] == "microsoft-graph":
        tid = c.get("tenant_id", "")
        if not tid:
            return None, ""
        # Entra OIDC discovery, no credential — issuer id CHECKED, not just the status.
        got, body = curl(f"https://login.microsoftonline.com/{tid}"
                         "/v2.0/.well-known/openid-configuration")
        if not got:
            return None, ""        # never reached it: says nothing about the tenant
        try:
            j = json.loads(body or "{}")
        except ValueError:
            # ⚠ deliberate — unreadable answer is not a verdict, see NOTES.md#unguarded-json-crash
            return None, ""
        iss = j.get("issuer") or ""
        if iss:
            return (tid.lower() in iss.lower()), "tenant"
        # deliberate — ONLY the specific not-found answer counts as absent,
        # see NOTES.md#tenant-absence-specificity
        err = f"{j.get('error') or ''} {j.get('error_description') or ''}".lower()
        if "invalid_tenant" in err or "aadsts90002" in err:
            return False, "tenant"
        return None, ""
    if r["platform"] == "jira":
        # Atlassian serverInfo, no credential, echoes the site's own baseUrl.
        # ⚠ deliberate — this endpoint's unauthenticated reachability is a recorded, justified
        # exposure (standard #15), see NOTES.md#jira-serverinfo-exposure
        # ⚠ Website, NOT dns_name — see NOTES.md#jira-website-not-dns-name
        host = re.sub(r"^[a-z]+://", "", (r.get("endpoint") or "")).split("/")[0].strip()
        if not host:
            return None, ""
        # deliberate — status code requested explicitly, curl exits 0 on a 404,
        # see NOTES.md#http-code-vs-reached
        got, body = curl(f"https://{host}/rest/api/3/serverInfo", "-w", "\n%{http_code}")
        if not got:
            return None, ""        # never reached it: says nothing about the tenant
        body, _, code = body.rpartition("\n")
        if code.strip() == "404":
            # deliberate — see NOTES.md#tenant-absence-specificity
            return False, "tenant"
        try:
            j = json.loads(body or "{}")
        except ValueError:
            return None, ""
        base = (j.get("baseUrl") or "").lower()
        if base:
            # Compared, not merely present — a 200 describing somebody else's site would
            # otherwise pass while proving nothing about ours.
            return (host.lower() in base), "tenant"
        return None, ""
    if r["platform"] == "github":
        # unauthenticated account lookup — the account IS the tenant here
        who = c.get("username", "")
        if not who:
            return None, ""
        got, body = curl(f"https://api.github.com/users/{who}")
        if not got:
            return None, ""
        try:
            j = json.loads(body or "{}")
        except ValueError:
            return None, ""
        login = j.get("login") or ""
        if login:
            # Compared, not merely present — a 200 describing a different account would
            # otherwise pass while proving nothing about ours.
            return (login.lower() == who.lower()), "tenant"
        return (False, "tenant") if j.get("message") == "Not Found" else (None, "")
    return None, ""


def describe_check(r):
    """What this row's probe actually did, read back from what it recorded. Nothing recorded
    means nothing ran — "-", same dash REACH/AUTH use for untested. Table gets the PRIMARY
    operation + a count; --json gets the lot under `probe_ops`. See NOTES.md#describe-check-primary"""
    ops = PROBE_OPS.get(r["id"]) or []
    if not ops:
        return ""                      # nothing ran at all; "-" is the honest answer
    auth_ops = [o for o in ops if not o.startswith(("tcp ", "ping "))]
    primary = (auth_ops or ops)[0]
    # a URL collapses to its host; anything else is already the answer minus the remote command
    shown = (primary.split()[1].split("/")[0] if primary.startswith(("GET ", "POST "))
             else primary.split(" -- ")[0])
    return shown + (f" ({len(ops)})" if len(ops) > 1 else "")


def probe(r):
    """REACH is a heartbeat; AUTH is proof. Kept apart because health checks lie: a host can
    answer on the network and still be useless to you, and some hosts drop ICMP entirely.

    Hosts and services are measured differently because "is it there" means different things.
    A host has an address, so the heartbeat is the address answering. A service has no address
    in this lab — only a vendor's URL — so the heartbeat has to be scoped to the tenant, or
    else derived from the one call that does reach it. The vendor front door is never the
    answer for a service, which is why reach_probe() is not in that path at all."""
    # Every operation recorded from here on belongs to this member. Thread-local because the
    # probes run in a pool, and one worker handles one member at a time.
    _CUR.id = r["id"]
    host = r.get("fqdn") or r["endpoint"]
    port = r.get("port")
    hostless = r["platform"] in HOSTLESS_ROLES
    # ⚠ deliberate — DECLARED service only, never the wire's guess, see NOTES.md#declared-service-only
    service = hostless or (r["type"] == "service" and r["source"] == "tag")

    if not host and not service:
        return {**r, "reach": None, "auth": None, "auth_detail": "",
                "reach_basis": "untested", "access_unreachable": False,
                "cred_fallback": False, "check": describe_check(r), "probe_ops": []}

    if service:
        reach, basis = tenant_reach(r)
        # a tenant proven absent is not a login to attempt
        ok, detail = auth_probe(r) if reach is not False else (None, "")
        # deliberate — a completed auth attempt IS a reach test, see NOTES.md#auth-attempt-is-reach
        if reach is None and ok is not None:
            reach, basis = True, "derived"
        # ⚠ deliberate — `not detail` is load-bearing, not a tidy-up, see NOTES.md#not-detail-load-bearing
        if reach is None and host and ok is None and not detail:
            reach, basis = reach_probe(host, port), "endpoint"
    else:
        reach = reach_probe(host, port) if host else None
        basis = "endpoint" if host else "untested"
        ok, detail = auth_probe(r) if reach else (None, "")

    # ⚠ deliberate — ACCESS checked separately, reported as FAULT not REACH,
    # see NOTES.md#access-unreachable-fault
    access_bad = bool(service and host and reach is True and basis != "endpoint"
                      and not reach_probe(host, port))

    return {**r, "reach": reach, "auth": ok, "auth_detail": detail,
            "reach_basis": basis or "untested", "access_unreachable": access_bad,
            "cred_fallback": r["id"] in CRED_FALLBACK,
            "check": describe_check(r), "probe_ops": list(PROBE_OPS.get(r["id"]) or [])}


# filtered here, not at print time — `-s` was paying for five host probes to print one service row
_all = [classify(m) for m in members]
# deliberate — collision surfaced on both rows, not silently de-duplicated, see NOTES.md#name-collision
_seen = {}
for _r in _all:
    _seen.setdefault(_r["name"], []).append(_r)
for _n, _rs in _seen.items():
    if len(_rs) > 1:
        for _r in _rs:
            _r["name_collision"] = len(_rs)
# counted before the filter, a property of the directory, not of any one host
_member_macs = {r["mac"] for r in _all if r.get("mac")}
# deliberate — full detail kept, not just a tally, see NOTES.md#off-members-detail
OFF_MEMBERS = sorted(
    ({"ip": e.get("ip", ""), "mac": mac,
      "zone": e.get("intf_description") or e.get("intf") or "",
      "vendor": (e.get("manufacturer") or "").strip(),
      "hostname": (e.get("hostname") or "").strip()}
     for mac, e in arp.items()
     if mac not in _member_macs and mac not in ROUTER_MACS),
    key=lambda x: (x["zone"], x["ip"]))
OFF_DIRECTORY = len(OFF_MEMBERS)
_classified = [c for c in _all if not WANT or c["type"] in WANT]
with ThreadPoolExecutor(max_workers=6) as ex:      # independent and I/O-bound; NAS stays single
    rows = list(ex.map(probe, _classified))
rows.sort(key=lambda r: (r["type"] == "service", r["name"]))


def op_value(OP, label):
    """The fetch for a field that a 1Password LOGIN item duplicates — built-in username/password
    are EMPTY on this estate, real values live in ACCESS. Selects on HAVING A VALUE, not
    position. See NOTES.md#op-value-empty-builtin-fields

    deliberate — matches every raw label that ALIASES folds to this canonical one (e.g. a
    field literally labelled "Passwd" for "password"), not just the canonical spelling. The
    Python-side credential lookup (put(), near CREDS) already folds aliases; this printed
    recipe was the one place that didn't, so a field named by its alias showed green in the
    tool but the generated recipe fetched nothing."""
    labels = sorted({label} | {k for k, v in ALIASES.items() if v == label})
    want = " or ".join(f'(.label|ascii_downcase)=="{l}"' for l in labels)
    return (f'{OP} --format json --reveal '
            f"""| jq -r '[.fields[] | select({want}) """
            f"""| .value | select(. != null and . != "")][0] // empty'""")


def howto(r):
    """The exact call that authenticates to this member — assembled from the same constants
    and live data auth_probe uses. NOT prose: a literal invocation is a value, an instruction
    to interpret is not. UNVERIFIED marks anything inferred rather than run end to end."""
    host = re.sub(r"^[a-z]+://", "", (r.get("endpoint") or "")).split("/")[0]
    item, acct, pf = r["item"], r.get("account") or "", r["platform"]
    OP = f'op item get "{item}" --vault {VAULT}'
    out = []
    if pf == "opnsense":
        kp, sp = OPN_PREFIXES["api_key"], OPN_PREFIXES["api_secret"]
        out += [f'K=$({OP} --fields label="API Key" --reveal | sed \'s/^{kp}//\')',
                f'S=$({OP} --fields label="API Secret" --reveal | sed \'s/^{sp}//\')',
                f'curl -sk -u "$K:$S" https://{host}/api/core/firmware/status',
                f'# the {kp}/{sp} prefix is IN the field value; unstripped it is a silent 401']
    elif pf == "proxmox":
        out += [f'TID=$({OP} --fields label="API Key" --reveal)      # USER@REALM!TOKENID',
                f'UUID=$({OP} --fields label="API Secret" --reveal)',
                f'curl -sk -H "Authorization: PVEAPIToken=$TID=$UUID" \\',
                f'  https://{host}:{r.get("port") or 8006}/api2/json/version',
                '# /version proves only that the SECRET is live: it needs no privilege.',
                '#   Read /api2/json/nodes too — that needs Sys.Audit, which is what',
                '#   PVEAuditor grants. A privsep token with no ACL returns 200 and an',
                '#   EMPTY data array, which looks exactly like a cluster with no nodes.']
    elif pf == "synology":
        port = r.get("port") or 5001
        out += [f'U=$({op_value(OP, "username")})',
                f'P=$({op_value(OP, "password")})',
                f'curl -sk -G https://{host}:{port}/webapi/entry.cgi \\',
                f'  --data-urlencode api=SYNO.API.Auth --data-urlencode version={DSM_AUTH_VERSION} \\',
                f'  --data-urlencode method=login --data-urlencode session={DSM_SESSION} \\',
                f'  --data-urlencode format=sid --data-urlencode account="$U" --data-urlencode passwd="$P"',
                f'# session MUST be {DSM_SESSION} — any other name is refused 402. Log out after.',
                '# NEVER in parallel: concurrent logins race DSM and trip its auto-block.']
    elif pf == "aruba-switch":
        # --format json, never --fields — see NOTES.md#aruba-key-quoting
        out += ['K=$(mktemp -t wblv-swt); chmod 600 "$K"; trap \'rm -f "$K"\' EXIT',
                f'{OP} --format json --reveal \\',
                '  | jq -r \'.fields[] | select((.label|ascii_downcase)=="private key") | .value\' > "$K"',
                'ssh-keygen -y -f "$K" >/dev/null || { echo "key material malformed, not connecting"; exit 1; }',
                'ssh -o IdentitiesOnly=yes -o IdentityAgent=none -o PubkeyAcceptedAlgorithms=+ssh-rsa \\',
                f'    -o PasswordAuthentication=no -i "$K" {acct}@{host}',
                '# --fields would wrap this multi-line key in quotes and lead it with a newline;',
                '#   stripping the quotes alone is STILL invalid, so ssh-keygen -y is the gate.',
                '#   It parses the file offline: no auth attempt spent, and a mangled fetch stops',
                '#   looking like a bad credential.',
                '# password auth burns attempts toward brute-force lockout on a fabric device',
                '# ArubaOS accepts NO command as an SSH argument: this opens an interactive CLI',
                '#   at operator (>), behind a keypress banner. Scripted use needs pexpect.']
    elif pf == "tplink-eap":
        opts = " ".join(f"-o {o}" for o in SSH_LEGACY_OPTS)
        out += [f'P=$({op_value(OP, "password")})',
                # \\ in source = ONE literal backslash, the shell's line continuation. It was
                # \\\\ here (two literal backslashes), which the shell reads as an escaped
                # backslash and NOT a continuation — the recipe broke into two commands.
                f"ssh {opts} \\", f"    {acct}@{host} '<command>'",
                '# offers only legacy host keys and no setting to fix it; ask per-host, never globally']
    elif pf == "linux":
        out += [f'P=$({op_value(OP, "password")})',
                f"ssh -o StrictHostKeyChecking=no {acct}@{host} '<command>'   # password auth"]
    elif pf == "jira":
        out += [f'T=$({OP} --fields label="API Key" --reveal)',
                f'curl -s -u "{acct}:$T" -H "Accept: application/json" https://{host}/rest/api/3/myself',
                '# basic auth, not the SSO login: an Entra-federated account cannot present IdP creds here']
    elif pf == "github":
        out += [f'T=$({OP} --fields label="API Key" --reveal)',
                'curl -s -H "Authorization: Bearer $T" https://api.github.com/user',
                '# falls back to `gh auth token` if the vault field is empty — check which one answered']
    elif pf == "microsoft-graph":
        out += [f'# tenant_id/client_id/client_secret from: {OP}',
                'curl -s -X POST https://login.microsoftonline.com/$TID/oauth2/v2.0/token \\',
                '  -d "client_id=$CID&client_secret=$CSEC&grant_type=client_credentials" \\',
                '  -d "scope=https://graph.microsoft.com/.default"']
    elif pf == "tailscale":
        out += [f'# client_id/client_secret from: {OP}',
                'curl -s -X POST https://api.tailscale.com/api/v2/oauth/token \\',
                '  -d "client_id=$CID&client_secret=$CSEC"   # then Bearer the access_token']
    elif pf == "1password":
        out += [f'export OP_SERVICE_ACCOUNT_TOKEN="$(cat {TOKEN_PATH.replace(os.path.expanduser("~"), "~")})"',
                'op whoami']
    else:
        out += [f'# no recipe for platform {pf!r} — read the probe in wblv_lab.py before guessing']
    return out


def faults_of(r):
    """The FAULT column, as data. One implementation because two would drift: --brief once
    tested a key that did not exist, so its fault branch could never fire -- a check that
    cannot trigger is indistinguishable from a clean estate."""
    return [f for f, bad in (("url", r.get("endpoint_malformed")),
                             ("ip", r.get("ip_drift")),
                             ("tag", r.get("type_drift")),
                             ("name", r.get("name_mismatch")),
                             ("access", r.get("access_unreachable")),
                             ("cred", r.get("cred_fallback")),
                             # negative days (already expired) must still fault, not go quiet
                             ("expiry", r.get("cred_expiry") is not None
                              and r["cred_expiry"] <= EXPIRY_WARN_DAYS),
                             ("dup", r.get("name_collision"))) if bad]


def render(rows, meta):
    """A table for humans. Colour encodes STATE only — green up, red down, dim untested; every
    glyph maps to a measured value, none of it is commentary. Counts sit ABOVE the table since
    they answer "is the lab healthy"; the table is the detail you read when a count is wrong."""
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

    # deliberate — Time leads, everything below it is a measurement (#14), see NOTES.md#time-leads
    _utc = time.gmtime(); _loc = time.localtime()
    field("Time", time.strftime("%Y-%m-%d %H:%M:%S UTC", _utc)
                  + f"  [dim](local {time.strftime('%H:%M %Z', _loc)})[/]")
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
    _faulted = sum(1 for r in rows if faults_of(r))
    field("Faults", _faulted, "red" if _faulted else "")
    field("Non-members", meta["off_directory"])
    con.print()

    def _howto_block():
        con.print()
        con.print("[bold]How to authenticate[/] — exact calls, generated from the probes. "
                  "Read before connecting.")
        want = ONLY_ID
        for r in rows:
            if want and r["name"] != want:
                continue
            con.print(f"\n[bold]{r['name']}[/]  [dim]{r['platform']}  {r.get('access') or '-'}[/]")
            # deliberate — soft_wrap, commands are PASTED not laid out, see NOTES.md#howto-soft-wrap
            for l in howto(r):
                con.print("  " + ("[dim]" + l + "[/]" if l.lstrip().startswith("#") else l),
                          soft_wrap=True)

    if SHOW_OTHERS:
        if not OFF_MEMBERS:
            con.print("[dim]nothing on the wire that the directory does not claim[/]")
            return
        t = Table(box=box.SIMPLE, show_edge=False, header_style="bold",
                  border_style="grey35", pad_edge=False, padding=(0, 1))
        t.add_column("ADDRESS", style="bold", no_wrap=True)
        t.add_column("MAC", style="grey50", no_wrap=True)
        t.add_column("ZONE", no_wrap=True)
        t.add_column("VENDOR", no_wrap=True)
        t.add_column("HOSTNAME")
        DASH = "[grey35]-[/]"
        for o in OFF_MEMBERS:
            t.add_row(o["ip"] or DASH, o["mac"], o["zone"] or DASH,
                      o["vendor"] or DASH, o["hostname"] or DASH)
        probe = Console(width=10_000, no_color=True)
        natural = Measurement.get(probe, probe.options, t).maximum
        out = con if natural <= con.width else Console(width=natural, highlight=False)
        rule = "[grey35]" + "─" * natural + "[/]"
        out.print(rule); out.print(t); out.print(rule)
        con.print("[dim]Not a fault: these are addresses OPNsense can see that no vault item "
                  "claims. Onboarding is data — add an item and it becomes a member.[/]")
        return

    if SHOW_HOWTO and not SHOW_BRIEF:
        _howto_block()
        return

    if SHOW_BRIEF:
        # named explicitly, not scraped from a rendered column — a hook consumer must not parse a table
        field("Members", " ".join(r["name"] for r in rows))
        bad = [r for r in rows
               if r["reach"] is not True or r["auth"] is not True or faults_of(r)]
        if not bad:
            if SHOW_HOWTO: _howto_block()
            return          # already stated above, measured
        con.print()
        # one line per exception, impossible to miss
        con.print(f"[bold]NOT NORMAL — {len(bad)} of {len(rows)}[/]")
        for r in bad:
            state = ("[red]down[/]" if r["reach"] is False else
                     "[grey35]reach untested[/]" if r["reach"] is None else "up")
            a = ("[bold red]auth fail[/]" if r["auth"] is False else
                 "[grey35]auth untested[/]" if r["auth"] is None else "auth ok")
            fl = faults_of(r)
            con.print(f"  [bold]{r['name']:<8}[/]{r.get('zone') or '-':<5} {state}, {a}"
                      + (f", [red]fault {','.join(fl)}[/]" if fl else "")
                      + f"   {r.get('access') or '-'}   {r['item']}")
        if SHOW_HOWTO: _howto_block()
        return

    # deliberate — SIMPLE/no-edge is the only box starting at column 0, see NOTES.md#table-box-choice
    t = Table(box=box.SIMPLE, show_edge=False, header_style="bold", border_style="grey35",
              pad_edge=False, padding=(0, 1))
    # atomic values no_wrap; narrowing lands on CREDENTIAL (has wrap points), not the state columns
    t.add_column("HOST", style="bold", no_wrap=True)
    t.add_column("TYPE", no_wrap=True)
    t.add_column("ADDRESS", no_wrap=True)
    # zone qualifies address — an unreachable PLY host may be the firewall working, not a fault
    t.add_column("ZONE", no_wrap=True)
    if SHOW_MAC:
        t.add_column("MAC", style="grey50", no_wrap=True)
    t.add_column("REACH", justify="center", no_wrap=True, min_width=5)
    t.add_column("AUTH", justify="center", no_wrap=True, min_width=4)
    # ACCESS is the connectable URI and must never be mangled. CHECK takes the same slot under
    # --check: what the probe actually did, which for a service is not the URI at all.
    t.add_column("CHECK" if SHOW_CHECK else "ACCESS",
                 style="magenta" if SHOW_CHECK else "cyan", no_wrap=True)
    t.add_column("CREDENTIAL", style="grey50")
    # blank on a healthy row; names the field only, the sentence lives in --json — a vault-entry
    # defect, never a host defect
    t.add_column("FAULT", style="red", no_wrap=True)

    TYPE = {"physical": "default", "virtual": "cyan", "service": "magenta",
            "unclassified": "yellow"}
    DASH = "[grey35]-[/]"
    for r in rows:
        # built as a list so the MAC cell can be left out entirely, not added blank
        cells = [r["name"],
                 f"[{TYPE.get(r['type'], 'yellow')}]{r['type']}[/]",
                 r.get("ip") or DASH,
                 r.get("zone") or DASH]
        if SHOW_MAC:
            cells.append(r.get("mac") or DASH)
        cells += ["[green]up[/]" if r["reach"] is True else
                  "[red]down[/]" if r["reach"] is False else DASH,
                  "[green]ok[/]" if r["auth"] is True else
                  "[bold red]fail[/]" if r["auth"] is False else DASH,
                  (r.get("check") if SHOW_CHECK else r.get("access")) or DASH,
                  r["item"],
                  ",".join(faults_of(r))]
        t.add_row(*cells)

    # deliberate — rendered at NATURAL width, narrow terminals soft-wrap rather than mangle,
    # see NOTES.md#natural-width-render
    probe = Console(width=10_000, no_color=True)
    natural = Measurement.get(probe, probe.options, t).maximum
    out = con if natural <= con.width else Console(width=natural, highlight=False)
    rule = "[grey35]" + "─" * natural + "[/]"
    out.print(rule)
    out.print(t)
    out.print(rule)


if __name__ == "__main__":
    shown = rows                       # WANT was applied before the probes, not after them

    # token_file_age_days: age of the FILE, not time-to-expiry — 1Password exposes no expiry to read
    meta = {"vault": VAULT, "ipam_source": opn["endpoint"],
            "prober": PROBER, "prober_zone": PROBER_ZONE,
            "runtime_s": round(time.time() - _T0, 1), "off_directory": OFF_DIRECTORY,
            "off_directory_members": OFF_MEMBERS,
            "token_file_age_days": TOKEN_FILE_AGE_DAYS}
    if "--json" in sys.argv:
        print(json.dumps({**meta, "members": [{k: r.get(k) for k in KEEP_JSON} for r in shown]},
                         indent=2))
    elif SHOW_TEST:
        # deliberate — one probe pass, nine renders; running the CLI nine times would trip
        # SSH brute-force lockout, see NOTES.md#show-test-one-pass
        VIEWS = [
            ("wblv-lab",               set(),          False, False),
            ("wblv-lab -p",            {"physical"},   False, False),
            ("wblv-lab -v",            {"virtual"},    False, False),
            ("wblv-lab -s",            {"service"},    False, False),
            ("wblv-lab --mac",         set(),          True,  False),
            ("wblv-lab --check",       set(),          False, True),
            ("wblv-lab --check --mac", set(),          True,  True),
            ("wblv-lab -p --check",    {"physical"},   False, True),
            ("wblv-lab -s --check",    {"service"},    False, True),
        ]
        for label, want, mac, chk in VIEWS:
            SHOW_MAC, SHOW_CHECK = mac, chk
            print(f"\n{'=' * 78}\n$ {label}\n{'=' * 78}")
            render([r for r in shown if not want or r["type"] in want], meta)
        # these vary what the table IS, not which members show — can't ride the loop above
        SHOW_MAC = SHOW_CHECK = False
        # --brief FIRST — the view the session hook actually reads
        SHOW_BRIEF = True
        print(f"\n{'=' * 78}\n$ wblv-lab --brief\n{'=' * 78}")
        render(shown, meta)
        SHOW_BRIEF = False
        print(f"\n{'=' * 78}\n$ wblv-lab --json\n{'=' * 78}")
        print(json.dumps({**meta, "members": [{k: r.get(k) for k in KEEP_JSON}
                                              for r in shown]}, indent=2))
        print(f"\n{'=' * 78}\n$ wblv-lab -h\n{'=' * 78}")
        print(HELP)
    else:
        render(shown, meta)
