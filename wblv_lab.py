#!/usr/bin/env -S uv run --with pexpect<5 --with rich<16 --quiet --script
"""wblv-lab — what is alive in the lab, and how to reach it.

A directory, not a broker. It reports members, their state and their access route, then
gets out of the way: you connect to the host yourself using the credential it names.

Authorities, in order of use:
  1Password   membership. A vault item IS what makes something a lab member — so onboarding
              is data, not code, and non-members (workstation, control node) never appear.
  OPNsense    detail. Dnsmasq reservations are the IPAM; ARP supplies the live vendor string.
  the network everything else: reachability and a real login are measured, never recorded.

Nothing here is cached, and nothing about THIS lab is written down: no address, no hostname,
no naming convention. Every member, and the router that supplies the inventory, is found by
what its vault item declares it is. What remains in code is knowledge of vendors' APIs — the
dialect each platform speaks, and where its endpoint lives — which changes when a vendor
changes, not when Harry renames a box.
"""
import os, sys, json, re, socket, subprocess, tempfile, threading, time, datetime
try:
    import pexpect
except ImportError:
    pexpect = None   # SSH probes report this rather than failing silently
from concurrent.futures import ThreadPoolExecutor

_T0 = time.time()          # for the Runtime stat: measured, not estimated

TOKEN_PATH = os.path.expanduser("~/.config/wblv/op-token")

# Platforms whose API can serve the lab's IPAM. This is a VENDOR fact — "can I read Dnsmasq
# reservations from this dialect" — not a fact about Harry's lab, which is why it survives him
# renaming or replacing the box. The router used to be found by a three-character hostname
# prefix, which meant a rename or a swap to pfSense did not degrade the tool, it killed it,
# and the assumption was invisible: buried in a next() rather than declared.
#
# Everything else a member needs — its role, its API dialect, its scheme and port — now comes
# from its own vault item. There is no prefix table any more, so onboarding any device of any
# type is entirely data: create the item, and it appears.
IPAM_PLATFORMS = ("opnsense",)

# Credentials are held OUT of the member records so they cannot reach stdout. Output rows are
# built from an explicit whitelist below; a secret must never be one accidental print away.
CREDS = {}

# Item ids whose probe authenticated with a credential this MACHINE holds rather than the one
# the vault item carries. The row's whole claim is "this item opens it", so a green AUTH that
# actually proves `gh`'s local token works is the row asserting something untested. Surfaced
# as a fault, because the qualifier in auth_detail never reaches the table.
CRED_FALLBACK = set()

# Vendor strings OPNsense resolves from the OUI. Matched on the NAME the router reports, not
# on a local OUI table — the lookup is the device's, we only classify the answer.
# Roles whose auth probe talks to no host, so neither an endpoint nor a successful REACH is a
# precondition for testing them. Kept explicit: the default stays "do not attempt a login
# against something that did not answer", which is what stops repeated probes tripping lockouts.
# github belongs here for the same reason: its probe hardcodes api.github.com, so an item
# carrying only a token — or one whose URL slot holds labelled data rather than a link, the
# shape the M365 item already had — needs no endpoint to be testable. Without this it was
# dropped before any probe ran and read as permanently untested.
HOSTLESS_ROLES = ("1password", "github")

# OAuth's own names for "this is us, not you" (RFC 6749 §5.2 plus Azure's spelling). A token
# endpoint that answers with one of these has NOT rejected the credential, so the probe must
# report untested rather than failed — otherwise a provider-side wobble reads as a dead secret
# and the fix looks like "rotate the credential", which is both wrong and destructive.
TRANSIENT_OAUTH = ("temporarily_unavailable", "server_error", "slow_down")

# What each probe actually DID. ACCESS answers "how do I get in" and is the URI you connect
# to; for a service that is the admin console, which is deliberately NOT what the probe talks
# to — nobody logs in to api.github.com. Sitting next to REACH and AUTH, ACCESS reads as the
# thing those columns measured, and for a service it never was. `--check` swaps the column so
# the mechanism is legible instead of implied.
#
# RECORDED, not described. A hand-written table of what each probe does is a fact that goes
# stale silently: add an omada probe and it says "no probe"; 1Password changes its verb and
# it still claims the old one. Same failure as writing a device's address into a note.
#
# So the probe helpers append what they ACTUALLY did, keyed by the member being probed, and
# CHECK is read back from that. A member with nothing recorded gets "" -> "-", which is the
# truth: nothing was checked. Adding a probe makes its row describe itself with no second
# place to update.
#
# Only the operation is recorded, never its credentials — the URL without its query string,
# the command without its arguments. Same rule as the output whitelist.
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

    Day-first, because that is how the vault's dates are written (23/07/2028) and how Harry
    types them. Guessing month-first would silently move a date by up to eleven months and
    still look like a valid answer -- so an unrecognised string returns None and says nothing,
    rather than inventing a deadline. ISO is accepted too, being unambiguous."""
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

# Explicit whitelist for --json: credentials live in CREDS and must never be one careless
# print away. reach_basis says WHICH measurement produced REACH — "endpoint" (the address
# answered), "tenant" (a tenant-scoped call answered), "derived" (the auth probe reached it,
# and nothing weaker could) or "untested" (nothing could be measured). Two rows both reading
# reach:true are not making the same claim, and a machine consuming this should be able to
# tell. It is never absent and never empty: a consumer branching on the set would otherwise
# default an unmeasured member into whichever bucket it happened to fall through to.
KEEP_JSON = ("name", "type", "source", "type_drift", "fqdn", "ip", "mac", "vendor", "role",
             "access", "check", "probe_ops", "reach", "reach_basis", "auth", "auth_detail",
             "item", "account", "endpoint", "endpoint_malformed", "access_unreachable",
             # arp_seen says whether the router could see this member at all. Without it,
             # ip_drift:null and zone:"" are ambiguous — a service legitimately has neither,
             # and a machine whose ARP entry aged out has neither for a very different reason.
             "cred_fallback", "zone", "arp_seen", "live_ip", "ip_drift", "platform",
             "name_collision",
             # Both spellings are kept, not just the winner: a `name` fault says the two
             # disagree, and the consumer cannot act on that without seeing each of them.
             # cred_expiry is days remaining — negative means already expired.
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
  wblv-lab --brief      counts + Members + only what is NOT normal (what the hook reads)
  wblv-lab --tasks      swap the member table for open work (jsm-01)
  wblv-lab --tasks 1a.5 resolve one task by its Lab ID
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

# Both are read before any work is done. Printing help used to cost a full probe run, and a
# filtered view used to probe every host and then throw most of the results away — the flags
# were parsed in __main__, which runs last.
if {"-h", "--help", "help"} & set(sys.argv[1:]):
    print(HELP); sys.exit(0)

# An unrecognised flag used to be IGNORED, so `wblv-lab --breif` printed the full table and
# said nothing -- you asked for one view and silently got another. That is the same defect the
# whole tool is built against, sitting in its own argument parsing. Typos are the common case
# and they are exactly when a confident wrong answer does the most damage.
KNOWN = {"-p", "-v", "-s", "--mac", "--check", "--json", "--test", "--brief", "--tasks", "-j",
         "-h", "--help", "help"}
_bad = [a for a in sys.argv[1:] if a.startswith("-") and a not in KNOWN]
if _bad:
    die(f"unknown option: {', '.join(_bad)}",
        hint=f"known options: {' '.join(sorted(KNOWN - {'help'}))}   (wblv-lab -h)")

WANT = ({"physical"} if "-p" in sys.argv else set()) | \
       ({"virtual"} if "-v" in sys.argv else set()) | \
       ({"service"} if "-s" in sys.argv else set())

# MAC is the widest column that answers a question nobody asks at a glance: it identifies a
# NIC, where every other column answers "is the lab healthy and how do I get in". It cost 20
# columns and pushed the table past the ~120 the comment below the table warns about — three
# additions (FAULT, ZONE, services-as-members) took the natural width from 119 to 138, so a
# terminal that used to fit stopped fitting without changing size. Hidden here, never dropped:
# --json still carries it, because a machine has no width limit.
SHOW_MAC = "--mac" in sys.argv

# Swaps the ACCESS column for CHECK rather than adding one — same slot, so the table stays at
# its width. The two answer different questions and only a machine wants both at once, which
# is what --json is for.
SHOW_CHECK = "--check" in sys.argv

# Every view from one probe pass, so a whole-surface check can be pasted into a conversation
# without running the probes nine times.
SHOW_TEST = "--test" in sys.argv

# Swaps the member table for the task table — same slot, same reasoning as --check. "What is
# alive" and "what should I do next" are different questions; the default answers the first.
# An argument after the flag resolves ONE Lab ID, which is the lookup that would otherwise be
# six lines of curl assembled by hand every time.
# Exceptions only. Ten rows that all say "fine" carry one bit between them, and a wall of
# green teaches the reader to skim -- which is how a silently truncated session hook went
# unnoticed for days. The counts still ASSERT health positively, so "all fine" and "the probe
# never ran" stay distinguishable; health is never implied by the absence of rows.
SHOW_BRIEF = "--brief" in sys.argv

SHOW_TASKS = bool({"--tasks", "-j"} & set(sys.argv[1:]))
TASK_ID = next((a for a in sys.argv[1:] if not a.startswith("-")), None) if SHOW_TASKS else None


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
    # The URL is also kept WHOLE, not just parsed for scheme/host/port. Rebuilding it from
    # those three threw the path away, so an item saying https://github.com/wblv-dev was
    # reported as https://github.com:443 — a connect target less useful than the field it
    # came from, and a port number nobody typed. A host's URI is still rebuilt from the IPAM
    # (which is authoritative for its name); a service has no IPAM, so the vault URL as
    # written is the only truth there is.
    website = next((s.strip() for s in slots if "://" in s), "")
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
    #
    # ⚠ This looked only at `urls`, and every item in the vault has an EMPTY urls array — the
    # Website is a labelled FIELD. So `intended` was always False and the 'url' fault could not
    # fire on any member that exists: a malformed Website would have rendered exactly like a
    # service that legitimately has none. A check that cannot fail and a check that passes are
    # the same silence, which is the failure mode this tool exists to refuse. Both slots now count.
    intended = any(("://" in (u.get("href") or "")) or
                   _fold(u.get("label")) in ("website", "url")
                   for u in (full.get("urls") or [])) or \
               bool(_field(full, "website", "url", "endpoint"))
    junk = intended and not endpoint
    # A service has no meaningful hostname prefix — a SaaS tenant is not identified by the
    # first three letters of its portal's DNS name — so the URL is the only thing that states
    # how to reach it. Read the scheme and port from it rather than inferring them.
    scheme = (m.group(1).lower() if endpoint else "")
    DEFAULT_PORT = {"https": 443, "http": 80, "ssh": 22}
    url_port = (int(m.group(3)) if (endpoint and m.group(3))
                else DEFAULT_PORT.get(scheme) if endpoint else None)
    # A set value never loses to an empty one — the same rule the credential map applies below.
    # 1Password's built-in username field exists whether or not it is filled, so an item that
    # carries its account in a named section would show a blank ACCOUNT purely because the empty
    # built-in comes first in the array. That is luck, not design, and it made the one migrated
    # item look accountless next to the seven that had not been touched yet.
    user = next((f.get("value") for f in (full.get("fields") or [])
                 if (f.get("label") or "").lower() == "username" and f.get("value")), "")
    # IDENTITY IS DECLARED, NOT DERIVED. The item states its name in `DNS Name`, and that is
    # authoritative. Derivation stays only as the fallback for an item that has not declared one.
    #
    # Why it matters: derived identity MOVES when something else changes. A name taken from the
    # endpoint follows the URL, so repointing a host at a different interface renamed it; a name
    # taken from the title followed a rename of the credential. Neither edit is about identity,
    # and both silently made the member look like a different member — including to the ip_drift
    # and name_collision checks, which key off it.
    #
    # The declared name also unifies the two cases that used to need separate rules. A machine's
    # DNS name is its identity, but a service's URL is the VENDOR's domain and names nothing
    # useful — portal.azure.com would be "portal", login.tailscale.com "login". The vault answers
    # both the same way, because every item declares a short canonical name (365-01, nas-01).
    is_service = any(t.lower() == "service" for t in (full.get("tags") or []))
    declared = _field(full, "dns name").lower()
    # ⚠ This used to end `.removeprefix("wblv-")`, which was the last fact about THIS lab left in
    # the code — a naming convention ("credential titles are prefixed wblv-") that the tool would
    # have carried into any estate it was pointed at. Removed 2026-08-06.
    #
    # Nothing depends on it: `DNS Name` is authoritative and every item declares one, so this
    # feeds only the fallback. Removing it also improves how the fallback FAILS. Before, an item
    # with no declared name was silently corrected into something that happened to match the
    # IPAM; now it derives the title as written, finds no IPAM entry, and says so. A member that
    # cannot be identified should be visibly unidentified, not quietly guessed into place.
    from_title = title.split("/")[0].strip().lower()
    derived = from_title if (is_service or not endpoint) else endpoint.split(".")[0].lower()
    # Tolerated rather than required: someone may reasonably write the FQDN here. The short name
    # is the identity either way, so both spellings resolve to the same member.
    name = declared.split(".")[0] if declared else derived
    # A declared name that disagrees with the endpoint means one of the two fields is stale, and
    # there is no way to tell WHICH from inside the tool — so it is reported, not resolved.
    #
    # Services are exempt BY DESIGN, not overlooked: their endpoint is the vendor's domain, so
    # 365-01 vs portal.azure.com is the correct state of a healthy item. Faulting on it would
    # light up every service permanently, and a fault that is always on is one nobody reads.
    name_mismatch = bool(declared and endpoint and not is_service
                         and declared.split(".")[0] != endpoint.split(".")[0].lower())
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
    for e in json.loads(_arp.result()[1] or "[]"):
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
    # Two attributes, deliberately separate. PLATFORM is the API dialect and selects the auth
    # probe — it changes entirely if OPNsense becomes pfSense. ROLE is what the thing is for and
    # survives that swap untouched. Collapsing them made "role" mean two things at once.
    # While items are being migrated, a lone `role` is still accepted as the platform.
    _c = CREDS.get(m["id"], {})
    platform = (_c.get("platform") or _c.get("role") or "").strip().lower()
    role = (_c.get("role") if _c.get("platform") else "").strip().lower()
    # The item states how it is reached, so the tool no longer infers it from a naming
    # convention. This used to come from a prefix table that named the MANAGEMENT port —
    # necessary while items carried a bare browser URL, and wrong the moment one didn't. Every
    # item now carries a real scheme, with an explicit port wherever it is not the default, so
    # the table had nothing left to add and a rename can no longer change how a host is read.
    proto, port = (m.get("scheme") or ""), m.get("url_port")
    _a = arp.get(inv.get("mac", ""), {})
    # Did the router see this member at all. EVERYTHING below that reads from the ARP entry —
    # zone, vendor, live_ip, ip_drift and the type-drift check — is UNMEASURED when this is
    # false, which is a different statement from "measured and clean". Kept as its own field
    # because that distinction is invisible in the values themselves: a blank zone and an
    # absent ARP entry render identically, and so did a skipped drift check.
    arp_seen = bool(_a)
    vendor = _a.get("manufacturer", "")
    zone = _a.get("intf_description", "")      # LAN / ADM / PLY, straight off the interface
    # The reservation says where it should be; ARP says where it is. Disagreement is the
    # lease that outlived the misconfig which created it — silent until someone looks.
    #
    # ⚠ TRI-STATE, for exactly the reason REACH and AUTH are: with no ARP entry there is nothing
    # to compare against, and a flat False asserted "checked, and no drift" about a host whose
    # drift was never examined. That is the one claim this tool may not make.
    #
    # It is not a hypothetical. An ARP entry ages out on a QUIET host, and after a VLAN change
    # the affected host is precisely the quiet one — so the check went silent exactly when it was
    # load-bearing, and the lesson it exists to automate ("DHCP leases outlive the misconfig that
    # created them") is the one it stopped enforcing. opn-01 is worse: it has no reservation of
    # its own, so it has no MAC here and could never be checked at all, while reading clean.
    #
    # None = untested. The FAULT column treats it as falsy so a healthy table is unchanged, but
    # --json can now tell "no drift" apart from "never looked".
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

    # ⚠ Same untested-vs-clean trap as ip_drift, and it shares the cause: with no ARP entry
    # `observed` is "", so this reports no drift about a comparison that never happened. Left as
    # a string rather than made tri-state — an empty drift string is already "nothing to say" —
    # but `arp_seen` is what distinguishes the two, so a consumer can tell. Do not read a blank
    # here as corroboration that the tag is right.
    drift = (f"tagged {declared}, but the wire says {observed}"
             if declared and observed and declared != observed else "")
    # A machine gets its URI rebuilt from the IPAM name, which is authoritative and may differ
    # from whatever the vault item was typed with. A service has no IPAM entry, so its own URL
    # is all there is — shown as written, path and all.
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
    return subprocess.run(["nc", "-z", "-G", str(t), "-w", str(t), host, str(port)],
                          capture_output=True).returncode == 0

def ping_ok(host, t=2):
    return subprocess.run(["ping", "-c", "1", "-t", str(t), host], capture_output=True).returncode == 0

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
        # Appliances whose SSH predates current defaults. Modern OpenSSH refuses to negotiate
        # with them at all, and it fails BEFORE the password prompt — so without this the probe
        # reports "SSH refused before auth" for a device that is perfectly healthy, a false
        # negative indistinguishable from a real fault. Asked for explicitly, per platform,
        # rather than globally: weakening the client for every host to suit the worst one is
        # how a workaround becomes the standard.
        args += ["-o", "HostKeyAlgorithms=+ssh-rsa",
                 "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
                 "-o", "KexAlgorithms=+diffie-hellman-group14-sha1",
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
            return True, "login ok"
        return False, ("credential rejected" if i in (1, 2) else
                       "connected but no expected response")
    finally:
        try: c.close(force=True)
        except Exception: pass

def aruba_probe(user, host, pw, private_key=None):
    """ArubaOS does not accept a command as an SSH argument — it opens an interactive session
    with a banner and a keypress gate. Reaching the prompt IS the proof of login, so the probe
    stops there rather than running anything.

    The prompt character is the useful part: '>' is operator (show-only), '#' is manager. That
    reports the PRIVILEGE LEVEL as observed on the device, which is the read-only guarantee
    demonstrated rather than assumed — and it would catch the account being promoted.

    A key is used when the item carries one, because the switch may be set
    `aaa authentication ssh login public-key`, under which passwords are refused outright.
    The two paths are kept separate rather than blended: WHICH mechanism succeeded is part of
    what is being reported, and a client left free to fall back would report a key login that
    never happened. The detail line says which was exercised."""
    if pexpect is None:
        return None, "pexpect unavailable (run via uv, not bare python3)"
    if not private_key and not pw:
        return None, "no private key or password on the 1Password item"
    base = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=12 ")
    keyfile = None
    if private_key:
        # ssh reads identities from a file, so the key cannot be handed over any other way.
        # The exposure is bounded instead of avoided: 0600, private temp dir, one probe's
        # lifetime, removed in the finally even when the probe raises.
        fd, keyfile = tempfile.mkstemp(prefix="wblv-probe-", suffix=".key")
        os.write(fd, (private_key if private_key.endswith("\n") else private_key + "\n").encode())
        os.close(fd)
        os.chmod(keyfile, 0o600)
        # IdentitiesOnly and IdentityAgent=none force THIS key. With an agent in reach ssh can
        # authenticate on a different identity and the probe would report success for a
        # credential it never tested — the same reason the password path pins
        # PubkeyAuthentication=no.
        #
        # PubkeyAcceptedAlgorithms=+ssh-rsa is asked for HERE, per platform, never globally.
        # Mocana SSH 6.3 does not send the server-sig-algs extension, so a modern client cannot
        # learn that SHA-2 RSA signatures are acceptable and silently declines to OFFER an RSA
        # key at all ("no mutual signature algorithm"). The key is never SENT rather than
        # rejected — which looks identical to a bad credential from the far end.
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
            got, body = curl(f"https://{host}/api/core/firmware/status", "-u", f"{k}:{sec}")
            if not got:
                return None, "no answer from the API"
            j = json.loads(body or "{}")
            v = j.get("product_version")
            return (bool(v), f"OPNsense {v}" if v else "API rejected the credential")
        if r["platform"] == "synology":
            u = c.get("username", ""); pw = c.get("password") or c.get("confirmpassword", "")
            # The port comes from the member, not from a literal. It was written here AND in
            # the prefix table, so the two could disagree with nothing to catch it.
            dsm = r.get("port") or 5001
            base = f"https://{host}:{dsm}/webapi/entry.cgi"
            # Recorded here because this probe drives curl directly rather than through
            # curl(), for the logout it has to issue. A call that skips the helper skips the
            # recorder too, and the row would claim nothing was checked.
            note_op(f"GET {host}:{dsm}/webapi/entry.cgi")
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
        if r["platform"] in ("aruba-switch", "linux", "tplink-eap"):
            u = c.get("username", "").removeprefix("username=") or r.get("account") or ""
            pw = (c.get("password") or c.get("confirmpassword")
                  or c.get("operator password", "")).removeprefix("password=")
            if not u:
                return None, "no username field on the 1Password item"
            # Prove the session is really established, not merely connected: the switch echoes
            # its own name, the shell echoes a token we chose.
            if r["platform"] == "aruba-switch":
                # An SSH-key item carries no password at all, so the key is not an override of
                # the password — it is the only credential the item has. Both are passed and
                # the probe picks: a Login item still probes by password unchanged, which is
                # what lets the two item formats coexist during a migration.
                return aruba_probe(u, host, pw, c.get("private_key") or "")
            # A standalone TP-Link EAP answers SSH with an unprivileged BusyBox ash shell
            # (uid 1, cannot even write /dev/null), not the restricted CLI its GUI implies, so
            # the same echo test proves the session for real. Its host keys are ssh-rsa/ssh-dss
            # only, hence legacy.
            return ssh_probe(u, host, pw, r"wblv-ok", "echo wblv-ok",
                             legacy=r["platform"] == "tplink-eap")
        if r["platform"] == "microsoft-graph":
            # Client-credentials against the tenant. A token issued is proof the app
            # registration, the secret and the tenant are all live — which is what "is M365
            # reachable" actually means. TLS to a Microsoft endpoint only proves Microsoft is up.
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
                return True, "Graph token issued"
            # An answer that is not a token is not automatically a rejection. OAuth names its
            # server-side transients, and reading one as "your credential is bad" sends Harry
            # to rotate a working secret during someone else's outage — the same mistake as
            # deriving reach from a transport failure, one layer up.
            if (j.get("error") or "") in TRANSIENT_OAUTH:
                return None, f"token endpoint unavailable ({j['error']})"
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
        if r["platform"] == "jira":
            # Basic auth with email:token — Atlassian's documented REST scheme, and the ONLY
            # one that survives SSO. An account federated to Entra cannot present its IdP
            # credentials to the API at all, which is precisely why the token exists and why
            # mac-01 can reach Jira with no browser and no human in front of it. It also means
            # a Conditional Access misfire that locks the browser out does NOT lock this out —
            # worth knowing, not worth relying on.
            #
            # /myself is the cheapest READ that proves a token is live: it mutates nothing and
            # returns the identity the token is acting as.
            user, k = c.get("username") or "", c.get("api_key") or c.get("password") or ""
            # Website, not DNS Name — see the reach branch. DNS Name is the canonical short
            # name for a service; the API host is the Website URL.
            host = re.sub(r"^[a-z]+://", "", (r.get("endpoint") or "")).split("/")[0].strip()
            if not (user and k and host):
                return None, "item needs username, API Key and a Website URL"
            # Credentials go in on STDIN via --config, never in argv: an argument is readable
            # by any local process from `ps` and lands verbatim in any spindump swept into a
            # diagnostic bundle. Same invariant ssh_probe and the github branch state.
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
            # Report the AUTHORITY the credential carries, not merely that it works — the same
            # reason the github branch reads x-oauth-scopes. On the Free plan every account
            # with product access is an admin, so a read-only credential is not achievable and
            # this WILL read "admin". That is the point: the accepted gap stays visible every
            # session instead of living only in the register. If it ever stops saying admin,
            # something real changed.
            #
            # Best-effort and deliberately non-fatal: a working token whose permission lookup
            # failed is still a working token, and must not be downgraded to a red AUTH.
            # Enumerate what the credential can DO, not a single word for it. Reporting
            # "ADMIN" collapsed a set into a label and overstated it: this token holds
            # ADMINISTER and EDIT and CREATE but NOT DELETE, so "ADMIN" read as "can do
            # anything" while a delete was refused. A credential description that is wider
            # than the credential is the same defect as one that is narrower.
            #
            # Best-effort and deliberately non-fatal: a working token whose permission lookup
            # failed is still a working token and must not be downgraded to a red AUTH.
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
        if r["platform"] == "github":
            # A PAT authenticates as a bearer token, and /user is the cheapest READ that proves
            # one is live: it mutates nothing and costs one of 5,000 hourly calls. The item's
            # Website stays the human URL, as it does for the tenant and the tailnet — the API
            # host is the probe's business, not something to make Harry type.
            # The vault first, then gh's own store. `gh` already holds a working token and is
            # the tool that owns it, so copying it into 1Password would create a second copy
            # that goes stale the moment gh re-authenticates — the same reason ops-01 carries
            # no secret and is probed via the local op token. Which source was used is REPORTED
            # rather than silently resolved: a probe that quietly falls back to a local
            # credential would show green while the vault entry it claims to test is wrong.
            k, src = (c.get("api_key") or c.get("password") or ""), "vault"
            if not k:
                # Bounded like every other probe. Unbounded, a gh that blocks on a Keychain
                # prompt with no human present never returns, and because probe() runs in a
                # thread pool the WHOLE directory hangs — the session hook dies at 60s with no
                # lab state, the MCP server at 120s. One row's credential is not worth that.
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
            # Headers as well as body. GitHub returns the token's own grants in x-oauth-scopes,
            # so the probe can report the AUTHORITY it is carrying rather than merely that it
            # works — a credential wider than its job is a finding, and this surfaces it every
            # session instead of during an incident. Fine-grained PATs send no such header,
            # which is itself the answer.
            #
            # Headers go to stderr and the body to stdout, so the two are separated by the OS
            # rather than by parsing. `-D -` interleaves them on one stream with no reliable
            # blank line between: curl emits CRLF per header but no CRLFCRLF terminator, so
            # splitting on it silently yields an empty body and reads as a rejected token.
            #
            # The token goes in on STDIN, never in argv. ssh_probe's docstring already states
            # the invariant — a secret passed as an argument is readable by any local process
            # from `ps`, and lands verbatim in any sample or spindump swept into a diagnostic
            # bundle. The KEEP whitelist guards the output path; argv was leaking out the side.
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
            # A header that is PRESENT but empty is a classic PAT with no scopes ticked, which
            # is not the same thing as an absent header (a fine-grained PAT). Collapsing them
            # reported a legacy full-account token as the modern narrowly-scoped kind — the
            # exact inversion this branch exists to prevent. Split on the comma and strip,
            # since the separator is ", " only by convention.
            scoped = next((l.split(":", 1)[1].strip() for l in head.splitlines()
                           if l.lower().startswith("x-oauth-scopes:")), None)
            grants = [s.strip() for s in (scoped or "").split(",") if s.strip()]
            admin = [s for s in grants if s.startswith("admin:")]
            kind = (f"{len(grants)} scopes" + (f" incl. {len(admin)} admin" if admin else "")
                    if grants else "classic, no scopes" if scoped is not None
                    else "fine-grained")
            return True, f"{login}, {kind}, via {src}"
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
        # Entra publishes per-tenant OIDC discovery with no credential. A live tenant answers
        # 200 and echoes its own id in `issuer`; one that does not exist answers 400
        # AADSTS90002. The id is CHECKED, not merely the status — a 200 describing somebody
        # else's tenant would be a pass proving nothing about ours.
        got, body = curl(f"https://login.microsoftonline.com/{tid}"
                         "/v2.0/.well-known/openid-configuration")
        if not got:
            return None, ""        # never reached it: says nothing about the tenant
        try:
            j = json.loads(body or "{}")
        except ValueError:
            # A captive portal, a proxy error page or an HTML 5xx is an answer we cannot read,
            # which is not a verdict. Unguarded this raised inside a thread pool and took the
            # WHOLE directory down with a traceback — every healthy host with it.
            return None, ""
        iss = j.get("issuer") or ""
        if iss:
            return (tid.lower() in iss.lower()), "tenant"
        # ONLY the specific tenant-not-found answer counts as absent. Anything else Entra says
        # — throttling, temporarily_unavailable, an interstitial — must stay None, because a
        # False here also suppresses the auth probe, and that is the signal actually trusted.
        # Reporting a live tenant as gone while silently skipping the login is the worst of
        # both: it looks like a deleted tenant and proves nothing.
        err = f"{j.get('error') or ''} {j.get('error_description') or ''}".lower()
        if "invalid_tenant" in err or "aadsts90002" in err:
            return False, "tenant"
        return None, ""
    if r["platform"] == "jira":
        # Atlassian Cloud publishes serverInfo with no credential, and it ECHOES the site's own
        # baseUrl. Same shape as the Entra discovery document and the GitHub account probe: it
        # needs no secret, it names OUR tenant rather than the vendor, and it discriminates.
        # That keeps this row off "derived", so REACH stops depending on the token being valid.
        #
        # ⚠ That this endpoint answers at all is itself a standard #15 declared-exposure
        # finding — "reachable without authenticating" is exactly what #15 asks to be
        # enumerated and justified. It is Atlassian's default rather than a misconfiguration,
        # and it is recorded in the jsm-01 runbook rather than silently relied upon here.
        # ⚠ NOT dns_name. For a service, "DNS Name" carries the SHORT CANONICAL NAME
        # (jsm-01, 365-01, git-01) — the vault's answer to "what is this called" — while the
        # API host lives in the item's Website URL. Reading dns_name here builds
        # https://jsm-01/... and fails in a way that looks like an unreachable tenant.
        host = re.sub(r"^[a-z]+://", "", (r.get("endpoint") or "")).split("/")[0].strip()
        if not host:
            return None, ""
        # The status code is requested explicitly because an HTTP error is a COMPLETED
        # transfer: curl exits 0 on a 404, so REACHED alone cannot separate "this site does
        # not exist" from "the answer was unreadable". Atlassian's 404 is an HTML page, not
        # JSON, so without the code both collapse into a ValueError and a live-but-renamed
        # site would report as untested forever.
        got, body = curl(f"https://{host}/rest/api/3/serverInfo", "-w", "\n%{http_code}")
        if not got:
            return None, ""        # never reached it: says nothing about the tenant
        body, _, code = body.rpartition("\n")
        if code.strip() == "404":
            # ONLY the specific site-not-found answer counts as absent. Throttling, a captive
            # portal or a 5xx must stay None — a False here also suppresses the auth probe,
            # and reporting a live site as gone while skipping the login proves nothing.
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
        # GitHub publishes an account unauthenticated, and the account IS the tenant here.
        # Same shape as the Entra discovery document: it needs no credential, it names the
        # thing we care about rather than the vendor, and it discriminates — a real account
        # answers 200 echoing its own login, one that does not exist answers 404. That takes
        # this row off "derived", so REACH stops depending on the PAT being valid.
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
    """What this row's probe actually did, read back from what it recorded.

    Nothing recorded means nothing ran, and the honest answer is "-" — the same dash REACH
    and AUTH use for untested, meaning the same thing. It is not a claim that no probe could
    exist; it is the absence of one, which is what you want to see for a platform whose probe
    has not been written yet.

    The table gets the PRIMARY operation and a count of everything else; --json gets the lot
    under `probe_ops`. Primary means the one that produced AUTH, falling back to the reach
    test when no login was attempted — so a member whose platform has no probe written still
    says what was tried rather than going blank. The full M365 form carries a tenant GUID twice and runs
    past 150 characters, which is why the detail belongs where there is no width to spend."""
    ops = PROBE_OPS.get(r["id"]) or []
    if not ops:
        return ""                      # nothing ran at all; "-" is the honest answer
    auth_ops = [o for o in ops if not o.startswith(("tcp ", "ping "))]
    primary = (auth_ops or ops)[0]
    # A URL collapses to its host: the path is the least surprising part and the longest.
    # Anything else — ssh, op, gh — is already the answer, minus the remote command, which is
    # how the login is proven rather than what was contacted.
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
    # A DECLARED service only. classify() also INFERS "service" from the wire, for any member
    # with no IPAM entry — and an untagged host that has fallen out of Dnsmasq, or whose item
    # hostname stopped matching its reservation, looks exactly like that. Routing it here
    # would drop the reach gate and fire repeated password logins at a box that never
    # answered, which is the DSM auto-block the synology branch warns about. The tag is Harry
    # stating what a thing is; the wire is a guess, and a guess must never change how a member
    # is measured. Hostless members take this path whatever they are tagged, because there is
    # no address to measure either way.
    service = hostless or (r["type"] == "service" and r["source"] == "tag")

    if not host and not service:
        return {**r, "reach": None, "auth": None, "auth_detail": "",
                "reach_basis": "untested", "access_unreachable": False,
                "cred_fallback": False, "check": describe_check(r), "probe_ops": []}

    if service:
        reach, basis = tenant_reach(r)
        # A tenant proven absent is not a login to attempt — the same restraint that stops a
        # dead host being probed, and the reason auth stays "-" rather than "fail".
        ok, detail = auth_probe(r) if reach is not False else (None, "")
        # A completed auth attempt IS a reach test: you cannot be rejected by something you
        # did not reach. But that only holds for a verdict the far end actually gave us —
        # which is why every probe now returns None, not False, when the transfer never
        # completed. Deriving from False was reporting a total outage as REACH up.
        if reach is None and ok is not None:
            reach, basis = True, "derived"
        # Still nothing, and NOTHING WAS ATTEMPTED: fall back to the endpoint so a member
        # onboarded the way the design intends — vault item first, probe later — reports a
        # measured heartbeat rather than a row of dashes indistinguishable from a broken
        # vault entry.
        #
        # The `not detail` is load-bearing, not a tidy-up. Every probe that RAN and failed to
        # reach says so ("no answer from the API"); only the fallthrough for a platform with
        # no probe written returns None with nothing to say. Falling back on the noisy case
        # too would put the vendor's front door back into REACH by the side door — an outage
        # would show the tenant as up because portal.azure.com still accepts TCP, which is
        # the exact green-light-wired-to-the-wrong-thing this rework existed to remove.
        if reach is None and host and ok is None and not detail:
            reach, basis = reach_probe(host, port), "endpoint"
    else:
        reach = reach_probe(host, port) if host else None
        basis = "endpoint" if host else "untested"
        ok, detail = auth_probe(r) if reach else (None, "")

    # The ACCESS column is the one thing this tool exists to hand you, and once services
    # stopped being measured by their own URL nothing checked it at all: a mistyped vendor
    # hostname is still syntactically valid, so `url` never fires, and the row went fully
    # green while the URI in it was dead. Checked separately and reported as a FAULT, so it
    # cannot leak back into REACH and start meaning "the vendor is up" again.
    access_bad = bool(service and host and reach is True and basis != "endpoint"
                      and not reach_probe(host, port))

    return {**r, "reach": reach, "auth": ok, "auth_detail": detail,
            "reach_basis": basis or "untested", "access_unreachable": access_bad,
            "cred_fallback": r["id"] in CRED_FALLBACK,
            "check": describe_check(r), "probe_ops": list(PROBE_OPS.get(r["id"]) or [])}


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

# ---------------------------------------------------------------- Jira task snapshot -----
# jsm-01 is a member like any other, and its task state is member DETAIL in the same way
# auth_detail is: a fact about that member, read live, stored nowhere. The default view shows
# only the counts, because "is the lab healthy" and "what should I do next" are different
# questions and the second one is asked with --tasks.
#
# ⚠ Returns None for UNTESTED and never a zeroed dict. A Jira outage that reported "0 open"
# would read as "all work is done", which is the worst possible lie this tool could tell.
LAB_PROJECT = "LAB"

def jira_snapshot(rows):
    """One call, everything computed here. Returns None if there is no jira member or the
    API did not answer; a dict otherwise. Blocked-ness is derived from real issue links, not
    from prose, which is the whole reason task state left markdown."""
    m = next((r for r in rows if r["platform"] == "jira"), None)
    if not m:
        return None
    c = CREDS.get(m["id"], {})
    user, k = c.get("username") or "", c.get("api_key") or c.get("password") or ""
    host = re.sub(r"^[a-z]+://", "", (m.get("endpoint") or "")).split("/")[0].strip()
    if not (user and k and host):
        return None
    # maxResults is bounded: a runaway project must not turn a session hook into a paginator.
    # If it is ever hit the count is a floor, and truncated says so rather than lying quietly.
    # WORK is hierarchyLevel 0. Epics (1) are containers and sub-tasks (-1) would double-count
    # their parent. Filtered by TYPE ID, not by name: "issuetype != Epic" silently starts
    # counting epics as work the day somebody renames the type, and nothing would say so.
    got, body = curl(f"https://{host}/rest/api/3/project/{LAB_PROJECT}",
                     "--config", "-", stdin=f'user = "{user}:{k}"\n')
    if not got:
        return None
    try:
        work_ids = [t["id"] for t in json.loads(body or "{}").get("issueTypes", [])
                    if t.get("hierarchyLevel") == 0]
    except ValueError:
        return None
    if not work_ids:
        return None                      # no work types is not the same as no work
    only = f"issuetype in ({', '.join(work_ids)})"

    # Fetch OPEN work only. Done issues never leave a project, so a whole-project fetch is
    # bounded by HISTORY rather than by outstanding work — it would have crossed any cap on
    # completed tasks alone, and the counts would then have quietly meant "open among the
    # first N". Open work is the thing that is actually bounded.
    got, body = curl(f"https://{host}/rest/api/3/search/jql", "-G",
                     "--data-urlencode",
                     f"jql=project = {LAB_PROJECT} AND {only} AND statusCategory != Done"
                     " ORDER BY created ASC",
                     "--data-urlencode", "maxResults=200",
                     "--data-urlencode", "fields=summary,status,issuetype,issuelinks,parent,"
                                         "fixVersions,customfield_10042,customfield_10045,"
                                         "customfield_10046",
                     "--config", "-", stdin=f'user = "{user}:{k}"\n')
    if not got:
        return None
    try:
        j = json.loads(body or "{}")
    except ValueError:
        return None
    issues = j.get("issues")
    if issues is None:
        return None                      # the API answered, but not with a result set

    # Done is counted, never listed: the number is the only part anyone reads, and counting it
    # costs one call instead of paging through every task ever finished.
    dgot, dbody = curl(f"https://{host}/rest/api/3/search/approximate-count",
                       "-X", "POST", "-H", "Content-Type: application/json",
                       "-d", json.dumps({"jql": f"project = {LAB_PROJECT} AND {only}"
                                                " AND statusCategory = Done"}),
                       "--config", "-", stdin=f'user = "{user}:{k}"\n')
    try:
        done_n = json.loads(dbody or "{}").get("count") if dgot else None
    except ValueError:
        done_n = None                    # untested, and it says so rather than showing 0

    out = {"open": 0, "prog": 0, "done": done_n, "ready": [], "blocked": [], "mine": [],
           "truncated": len(issues) >= 200, "host": host}
    for i in issues:
        f = i["fields"]
        cat = f["status"]["statusCategory"]["key"]
        labid = f.get("customfield_10042") or i["key"]
        hands = (f.get("customfield_10045") or {}).get("value") or "-"
        out["prog" if cat == "indeterminate" else "open"] += 1
        # "is blocked by" pointing at something not yet done. A link to a CLOSED blocker is
        # not a blocker, which is the difference between a dependency graph and a list of
        # references — and the reason this is computed rather than stored.
        waits = [l["outwardIssue"] for l in (f.get("issuelinks") or [])
                 if l["type"]["inward"] == "is blocked by" and l.get("outwardIssue")
                 and l["outwardIssue"]["fields"]["status"]["statusCategory"]["key"] != "done"]
        row = {"id": labid, "key": i["key"], "hands": hands,
               "scope": ((f.get("parent") or {}).get("fields") or {}).get("summary", "").split(" —")[0],
               "phase": ((f.get("fixVersions") or [{}])[0] or {}).get("name", "")[:2],
               "summary": f["summary"].split("— ", 1)[-1],
               "waits": [w["key"] for w in waits]}
        if waits:
            out["blocked"].append(row)
        else:
            out["ready"].append(row)
            if hands == "Claude":
                out["mine"].append(row)
    # Blocked rows name Jira keys; the vault speaks Lab IDs. Translate, because a runbook that
    # says "1e.1" and a hook that says "LAB-6" do not obviously refer to the same thing.
    key2id = {i["key"]: (i["fields"].get("customfield_10042") or i["key"]) for i in issues}
    for r in out["blocked"]:
        r["waits"] = [key2id.get(k, k) for k in r["waits"]]
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
                             # A recorded expiry is only worth a column once it is near -- or
                             # already past, which reads as negative days and must still fault
                             # rather than going quiet.
                             ("expiry", r.get("cred_expiry") is not None
                              and r["cred_expiry"] <= EXPIRY_WARN_DAYS),
                             ("dup", r.get("name_collision"))) if bad]


TASKS = jira_snapshot(rows)


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

    # Time leads because everything under it is a measurement, and a measurement without a
    # timestamp is a claim (#14). It is also the answer to "what is now" for anything reading
    # this output — a session hook that has to guess the date will fabricate one, and a
    # fabricated timestamp is indistinguishable from a measured one once written down.
    # UTC first because the estate standard is UTC; local in brackets because Harry is not.
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
    # UNTESTED prints a dash, exactly as REACH and AUTH do, and means the same thing. A Jira
    # outage must never render as "0 open" — that reads as "all work is done".
    if TASKS is None:
        field("Tasks", "-", "dim")
    else:
        _done = TASKS["done"]
        field("Tasks", f"{TASKS['open']} open · {TASKS['prog']} in progress · "
                       + (f"{_done} done" if _done is not None else "[dim]- done[/]")
                       + ("  [yellow](truncated at 200)[/]" if TASKS["truncated"] else ""))
    con.print()

    if SHOW_BRIEF:
        # Named explicitly rather than scraped from a column: the hook hands this list to the
        # to-do generator so it does not make its own probe, and a consumer that has to parse
        # a rendered table breaks the moment the table changes shape.
        field("Members", " ".join(r["name"] for r in rows))
        bad = [r for r in rows
               if r["reach"] is not True or r["auth"] is not True or faults_of(r)]
        if not bad:
            return          # Faults/Reachable/Authenticated above already state it, measured
        con.print()
        # Only what is not normal, with why. One line each: the full row is one command away
        # and the point here is that the exception is impossible to miss.
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
        return

    if SHOW_TASKS:
        if TASKS is None:
            con.print("[dim]tasks UNTESTED — jsm-01 did not answer. Not the same as no tasks.[/]")
            return
        DASH = "[grey35]-[/]"
        if TASK_ID:
            # One record reads as fields, not as a one-row table — the same shape the header
            # uses, for the same reason: there is nothing to compare it against.
            hit = [r for r in TASKS["ready"] + TASKS["blocked"]
                   if r["id"].lower() == TASK_ID.lower()]
            if not hit:
                con.print(f"[dim]no OPEN task with Lab ID {TASK_ID}. It may be done, or the id may be"
                          f" wrong — those are different, so check before assuming.[/]")
                return
            for r in hit:
                con.print(f"[bold]{r['id']}[/]  {r['summary']}")
                field("Scope", r["scope"] or DASH)
                field("Phase", r["phase"] or DASH)
                field("Hands", r["hands"])
                field("Jira", r["key"])
                field("Waits on", ", ".join(r["waits"]) if r["waits"] else DASH,
                      "yellow" if r["waits"] else "")
            return
        # One table, state in a column — the member table's shape. Splitting ready and blocked
        # into separate blocks made STATE invisible as a value you can scan and compare, and
        # DELEGABLE was a third rendering of rows already on screen. HANDS answers it instead.
        t = Table(box=box.SIMPLE, show_edge=False, header_style="bold", border_style="grey35",
                  pad_edge=False, padding=(0, 1))
        t.add_column("TASK", style="bold", no_wrap=True)
        t.add_column("PH", no_wrap=True)
        t.add_column("SCOPE", no_wrap=True)
        t.add_column("HANDS", no_wrap=True)
        t.add_column("STATE", justify="center", no_wrap=True, min_width=7)
        # Blank unless something is actually holding this up, so the absence of a blocker is as
        # visible as its presence — the same reasoning as FAULT.
        t.add_column("WAITS ON", style="yellow", no_wrap=True)
        t.add_column("SUMMARY", style="cyan")
        HANDS = {"Claude": "cyan", "Harry": "default", "Either": "magenta"}
        for r in sorted(TASKS["ready"], key=lambda x: (x["phase"], x["id"])) + \
                 sorted(TASKS["blocked"], key=lambda x: (x["phase"], x["id"])):
            t.add_row(r["id"], r["phase"] or DASH, r["scope"] or DASH,
                      f"[{HANDS.get(r['hands'],'yellow')}]{r['hands']}[/]",
                      "[green]ready[/]" if not r["waits"] else "[yellow]blocked[/]",
                      ", ".join(r["waits"]) or "",
                      r["summary"])
        probe = Console(width=10_000, no_color=True)
        natural = Measurement.get(probe, probe.options, t).maximum
        out = con if natural <= con.width else Console(width=natural, highlight=False)
        rule = "[grey35]" + "─" * natural + "[/]"
        out.print(rule); out.print(t); out.print(rule)
        return

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
    if SHOW_MAC:
        t.add_column("MAC", style="grey50", no_wrap=True)
    t.add_column("REACH", justify="center", no_wrap=True, min_width=5)
    t.add_column("AUTH", justify="center", no_wrap=True, min_width=4)
    # ACCESS is the connectable URI and must never be mangled. CHECK takes the same slot under
    # --check: what the probe actually did, which for a service is not the URI at all.
    t.add_column("CHECK" if SHOW_CHECK else "ACCESS",
                 style="magenta" if SHOW_CHECK else "cyan", no_wrap=True)
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
        # Built as a list, not positional arguments, so the MAC cell can be left out entirely
        # rather than added as a blank one — a blank column still costs its header width.
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
        print(json.dumps({**meta, "members": [{k: r.get(k) for k in KEEP_JSON} for r in shown]},
                         indent=2))
    elif SHOW_TEST:
        # Every view, from ONE probe pass. Running the CLI nine times would be the obvious
        # implementation and the wrong one: it would take nine times as long, and it would
        # fire nine rounds of SSH logins at rpi-01 and swt-01, which is how you trip the
        # brute-force lockout that standard #13 exists to enable. Probing is the expensive and
        # risky part; rendering is free, so it is the only part repeated.
        #
        # A consequence worth knowing when reading the output: every view below is the SAME
        # measurement, so the rows agree with each other by construction. This shows what each
        # flag renders, not that nine separate runs would agree.
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
        # --tasks swaps the table, so it cannot ride the loop above: the loop varies which
        # MEMBERS are shown, and this varies what the table IS. Same single probe pass.
        SHOW_MAC = SHOW_CHECK = False
        SHOW_TASKS = True
        print(f"\n{'=' * 78}\n$ wblv-lab --tasks\n{'=' * 78}")
        render(shown, meta)
        SHOW_TASKS = False
        print(f"\n{'=' * 78}\n$ wblv-lab --json\n{'=' * 78}")
        print(json.dumps({**meta, "members": [{k: r.get(k) for k in KEEP_JSON}
                                              for r in shown]}, indent=2))
        print(f"\n{'=' * 78}\n$ wblv-lab -h\n{'=' * 78}")
        print(HELP)
    else:
        render(shown, meta)
