# wblv-lab — design rationale and incident history

This is where the "why" lives that used to sit inline in `wblv_lab.py`. Every entry below is
referenced from a `# deliberate — ... see NOTES.md#anchor` comment on the exact line it
protects. If you're about to "simplify" something in the code and there's a pointer to this
file on it, read the entry first — most of these exist because the simpler version was tried
and broke, sometimes across multiple sessions before the cause was found.

General design philosophy (why the tool exists at all, its zone/reach/auth vocabulary) lives
in README.md, not here. This file is specifically the incident-level "here's the bug this
prevents" material.

## ipam-platform-prefix-table
`IPAM_PLATFORMS` used to be found by a three-character hostname prefix. A rename or a swap to
pfSense didn't degrade the tool — it killed it, and the assumption was invisible, buried in a
`next()` rather than declared. Every member's role/dialect/scheme/port now comes from its own
vault item; there's no prefix table left to break.

## transient-oauth
OAuth's own names for "this is us, not you" (RFC 6749 §5.2, plus Azure's spelling):
`temporarily_unavailable`, `server_error`, `slow_down`. A token endpoint answering with one of
these has NOT rejected the credential. Misreading it as failed sends Harry rotating a live
secret during someone else's outage — the same mistake as deriving reach from a transport
failure, one layer up. Applies identically to the Microsoft Graph and Tailscale OAuth probes.

## probe-ops-recorded-not-described
`PROBE_OPS`/CHECK is what each probe actually DID, recorded live rather than hand-described in
a table. A hand-written description goes stale silently — add a probe and it still says "no
probe"; a vendor changes their verb and the table still claims the old one. The probe helpers
append what they ACTUALLY did, keyed by member; CHECK is read back from that. Only the
operation is recorded, never its credentials — the URL without its query string, the command
without its arguments.

## hostless-roles
Roles whose auth probe talks to no host (`1password`, `github`), so neither an endpoint nor a
successful REACH is a precondition for testing them. The default is "do not attempt a login
against something that did not answer" — this stops repeated probes tripping lockouts. github
belongs here because its probe hardcodes `api.github.com`; an item carrying only a token (or
whose URL slot holds labelled data rather than a link, the shape the M365 item already had)
needs no endpoint to be testable. Without this exemption it was dropped before any probe ran
and read as permanently untested.

## day-first-dates
`_expiry_days` parses dates day-first because that's how the vault's dates are written
(23/07/2028) and how Harry types them. Guessing month-first would silently move a date by up
to eleven months and still look like a valid answer — so an unrecognised string returns `None`
and says nothing, rather than inventing a deadline. ISO is also accepted, being unambiguous.

## reach-basis
`reach_basis` in `--json` says WHICH measurement produced REACH: `"endpoint"` (the address
answered), `"tenant"` (a tenant-scoped call answered), `"derived"` (the auth probe reached it
and nothing weaker could), or `"untested"` (nothing could be measured). Two rows both reading
`reach: true` are not making the same claim, and a consumer should be able to tell. Never
absent or empty — a consumer branching on the set would otherwise default an unmeasured member
into whichever bucket it happened to fall through to.

## arp-seen
`arp_seen` says whether the router could see this member at all. Everything downstream that
reads from the ARP entry — zone, vendor, live_ip, ip_drift, the type-drift check — is
UNMEASURED when this is false, a different statement from "measured and clean". Kept as its
own field because the distinction is invisible in the values themselves: a blank zone and an
absent ARP entry render identically, and so did a skipped drift check.

## url-kept-whole
A member's URL is kept WHOLE, not rebuilt from parsed scheme/host/port. Rebuilding from those
three threw the path away — an item saying `https://github.com/wblv-dev` was reported as
`https://github.com:443`, a connect target less useful than the field it came from, with a port
number nobody typed. A host's URI is still rebuilt from the IPAM (authoritative for its name);
a service has no IPAM, so the vault URL as written is the only truth there is.

## url-fault-could-never-fire
⚠ The `intended`/`url` fault used to check only the `urls` array — and every item in the vault
has an EMPTY `urls` array, since the Website lives in a labelled FIELD. So `intended` was
always `False` and the `'url'` fault could never fire on any member that exists: a malformed
Website rendered exactly like a service that legitimately has none. A check that cannot fail
and a check that passes are the same silence — the failure mode this tool exists to refuse.
Both slots (urls array and labelled fields) now count.

## set-value-wins-empty
A set value never loses to an empty one. 1Password's built-in `username`/`password` fields
exist on every item whether or not they're filled. An item carrying its account in a named
section would show a blank ACCOUNT purely because the empty built-in comes first in the
array — luck, not design. It made the one migrated item look accountless next to the seven
that hadn't been touched yet. Same rule applies in `put()` for the general field/credential map.

## declared-vs-derived-name
IDENTITY IS DECLARED, NOT DERIVED. The item states its name in `DNS Name`; that's
authoritative. Derivation is fallback only, for an item that hasn't declared one. Derived
identity MOVES when something else changes — a name taken from the endpoint follows the URL,
so repointing a host at a different interface silently renamed it; a name taken from the title
followed a rename of the credential. Neither edit is about identity, and both made the member
look like a different member, including to `ip_drift` and `name_collision`, which key off it.
The declared name also unifies machine and service identity: a machine's DNS name is its
identity, but a service's URL is the VENDOR's domain and names nothing useful —
`portal.azure.com` would derive to "portal", `login.tailscale.com` to "login". The vault
answers both the same way, since every item declares a short canonical name (365-01, nas-01).

## wblv-prefix-removed
⚠ `derived` used to end `.removeprefix("wblv-")` — the last fact about THIS lab left in the
code, a naming convention the tool would have carried into any estate it was pointed at.
Removed 2026-08-06. Nothing depends on it: `DNS Name` is authoritative and every item declares
one, so this only fed the fallback. Removing it also improved how the fallback FAILS — before,
an item with no declared name was silently corrected into something matching the IPAM; now it
derives the title as written, finds no IPAM entry, and says so. A member that cannot be
identified should be visibly unidentified, not quietly guessed into place.

## field-label-matching
1Password's Login item offers custom fields and labelled website entries, and Harry uses
both — the M365 `tenant_id`/`client_id` live as LABELLED URLS because that's the slot the UI
made easy. Reading only `fields` threw those labels away and made the data look like a
malformed endpoint. Both are read; `fields` wins a clash, being the more deliberate slot.
Labels are typed by hand in a GUI, so they're matched forgivingly — stored under both the
plain lowercase form and one with spaces/hyphens folded to underscores, so "Client ID",
"client-id" and "client_id" all resolve. A label that silently fails to match looks exactly
like a field that was never filled in.

## creds-keyed-by-id
`CREDS` is keyed by the ITEM's id, never by the resolved name. Two items can resolve to the
same name — a duplicate made while migrating a format, say — and a name-keyed store lets one
silently overwrite the other, so a member gets probed with a different member's credentials
and the result still reads "ok". Which one wins would be decided by thread scheduling, and
invisible.

## scheme-from-item
`classify()`'s PLATFORM/port logic used to come from a prefix table that named the management
port — necessary while items carried a bare browser URL, wrong the moment one didn't. Every
item now carries a real scheme, with an explicit port wherever it isn't the default, so the
table had nothing left to add — a rename can no longer change how a host is read.

## ip-drift-tri-state
⚠ `ip_drift` is TRI-STATE, for the same reason REACH and AUTH are. With no ARP entry there's
nothing to compare against, and a flat `False` would assert "checked, and no drift" about a
host whose drift was never examined — the one claim this tool may not make. Not a
hypothetical: an ARP entry ages out on a QUIET host, and after a VLAN change the affected host
is precisely the quiet one — so the check goes silent exactly when it's load-bearing, and the
lesson it exists to automate ("DHCP leases outlive the misconfig that created them") is the one
it stopped enforcing. `opn-01` is worse: it has no reservation of its own, so it has no MAC
here and could never be checked at all, while reading clean. `None` = untested; the FAULT
column treats it as falsy so a healthy table is unchanged, but `--json` can tell "no drift"
apart from "never looked".

## type-drift-trap
Same untested-vs-clean trap as `ip_drift`, and shares the cause: with no ARP entry `observed`
is `""`, so `drift` reports no drift about a comparison that never happened. Left as a string
rather than made tri-state — an empty drift string is already "nothing to say" — but
`arp_seen` is what distinguishes the two, so a consumer can tell. Do not read a blank here as
corroboration that the tag is right.

## ssh-legacy-opts
Legacy SSH options (`SSH_LEGACY_OPTS`) are asked for explicitly, per platform, never globally.
Appliances (aruba-switch, tplink-eap) whose SSH predates current defaults get refused by
modern OpenSSH before the password prompt even appears — without this the probe reports "SSH
refused before auth" for a device that's perfectly healthy, a false negative indistinguishable
from a real fault. Weakening the client for every host to suit the worst one is how a
workaround becomes the standard.

## aruba-key-quoting
`op item get --fields <label> --reveal` renders a multi-line SSHKEY value wrapped in literal
double quotes AND led by a newline; ssh rejects that file outright. Stripping the quotes alone
leaves the leading blank line and it's STILL invalid — the obvious one-line repair reproduces
the identical symptom. Read the whole item as JSON instead (as `CREDS` does). A malformed key
file and a rejected credential are INDISTINGUISHABLE from the far end (both answer "Permission
denied"); `ssh-keygen -y` parses the file offline first, so mangled key material is caught as
what it is, costs no authentication attempt, and doesn't trip the switch's brute-force lockout.
UNTESTED, not failed — nothing was ever sent, so the far end never said no.

## aruba-rsa-sig-algs
`IdentitiesOnly=yes`/`IdentityAgent=none` force THIS key — with an agent in reach, ssh can
authenticate on a different identity and the probe would report success for a credential it
never tested. `PubkeyAcceptedAlgorithms=+ssh-rsa` is asked for HERE, per platform, never
globally: Mocana SSH 6.3 (the switch's SSH stack) doesn't send the server-sig-algs extension,
so a modern client can't learn SHA-2 RSA signatures are acceptable and silently declines to
OFFER an RSA key at all ("no mutual signature algorithm"). The key is never SENT rather than
rejected — which looks identical to a bad credential from the far end.

## aruba-probe-shape
A key is used when the item carries one, because the switch may be set `aaa authentication
ssh login public-key`, under which passwords are refused outright. Key and password paths are
kept separate rather than blended: WHICH mechanism succeeded is part of what's reported, and a
client left free to fall back would report a key login that never happened. The detail line
says which was exercised.

## undecorate-history
`_undecorate` strips surrounding whitespace and ONE matching pair of wrapping quotes — nothing
else, so it can never become a place where a wrong value is massaged into a plausible one. It
exists because the estate has produced three credentials that were correct and unusable: the
OPNsense `key=`/`secret=` prefix, the Aruba key rendered quoted and newline-led by `--fields`,
and a PVE token id stored as `'" user@pve!tokenid"'`. Every one of them failed as a 401 or a
Permission denied — the far end saying no to something it was never sent properly. The PVE
token's SHAPE (`USER@REALM!TOKENID`, and a UUID) is checked offline before spending an auth
attempt, for the same reason.

## opnsense-schema-move
⚠ Assert on the REJECTION, not on a version string at one fixed path. OPNsense says 401 /
"Authentication Failed" in the body when it refuses — that's the only thing that means the
credential is bad. Inferring failure from a missing field made a SCHEMA MOVE indistinguishable
from a rejected login: firmware 26.7 nested `product_version` inside `"product"`, so a 200
carrying a valid payload rendered as "auth fail" three times across three separate sessions
and sent us looking at a credential that was never involved. Both paths are read now; a
version we cannot name is a gap in this tool's knowledge, not a gap in the login.

## pve-two-call-auth
`/version` needs only a valid token, so a 200 proves the SECRET and nothing about the ACL. A
privsep token with no `pveum acl modify` is the likeliest way to get this wrong, and it fails
exactly like Jira's search endpoint: authorised, permission-filtered, and empty — which reads
as a healthy but idle cluster. `/nodes` needs `Sys.Audit` on `/nodes`, which is what
`PVEAuditor` actually grants, so the two calls together separate "the secret works" from "it
can read anything".

## dsm-note-op
Synology's probe drives curl directly rather than through the shared `curl()` helper, because
it needs to issue a logout too. A call that skips the helper skips the operation recorder too,
so it's noted manually. Every DSM call goes to `entry.cgi`, so naming only the path would
collapse three operations into one (`note_op` dedupes identical text by design) — the `api=`
label is named explicitly instead, or `--check` reports one call on a run that made three. The
label is constructed here, not lifted from the query string, since the query string is where
the password rides and must never reach the recorder.

## dsm-order-load-bearing
⚠ ORDER IS LOAD-BEARING. The Core.System capability read must happen while the session is
still valid — written the other way round (logout first), a dead session returns an error
indistinguishable from a permissions refusal, and the probe would report "insufficient
permission" about a session it had just closed itself. Right answer, wrong reason, nothing in
the output would have said so. A bare "DSM login ok" reads as full access to the box holding
the backups; one representative READ turns that into a measurement. 105 is "insufficient
permission", a different answer from the API not existing.

## echo-proves-session
Proves the session is really established, not merely connected: the switch/shell echoes a
token we chose. An SSH-key item carries no password at all, so the key isn't an override of
the password — it's the only credential the item has; both are passed and the probe picks,
which is what lets old (password) and new (key) item formats coexist during migration.

## graph-roles-claim
The Graph token carries its own grants in the `roles` claim, so what the credential can DO
costs nothing extra to report — it's already in hand. "Graph token issued" only ever said the
secret was live; whether those grants are read-only is the fact the estate's read-only
doctrine actually turns on, and it was previously invisible.

## jira-basic-auth-survives-sso
Basic auth with email:token is Atlassian's documented REST scheme, and the ONLY one that
survives SSO. An account federated to Entra cannot present its IdP credentials to the API at
all — precisely why the token exists, and why mac-01 can reach Jira with no browser and no
human in front of it. It also means a Conditional Access misfire that locks the browser out
does NOT lock this out — worth knowing, not worth relying on.

## creds-never-in-argv
Credentials go in on STDIN via `--config`/piped input, never in argv. An argument is readable
by any local process from `ps` and lands verbatim in any spindump swept into a diagnostic
bundle. Applies identically to the github branch's token and ssh_probe's password (sent at the
interactive prompt, never as a command argument).

## jira-permission-enumeration
Report the AUTHORITY the credential carries, not merely that it works. On the Free plan every
account with product access is an admin, so a read-only credential isn't achievable and this
WILL read "admin" — the point is that the accepted gap stays visible every session instead of
living only in the register. Enumerate what the credential can DO rather than a single word
for it: reporting "ADMIN" collapsed a set into a label and overstated it — a token can hold
ADMINISTER, EDIT and CREATE but NOT DELETE, so "ADMIN" read as "can do anything" while a
delete was actually refused. A description wider than the credential is the same defect as one
that's narrower. Best-effort and deliberately non-fatal: a working token whose permission
lookup failed is still a working token, and must not be downgraded to a red AUTH.

## github-vault-then-gh
The vault is tried first, then `gh`'s own token store. `gh` already holds a working token and
is the tool that owns it, so copying it into 1Password would create a second copy that goes
stale the moment `gh` re-authenticates — the same reason `ops-01` carries no secret and is
probed via the local `op` token. Which source was used is REPORTED (`src`), not silently
resolved: a probe that quietly falls back to a local credential would show green while the
vault entry it claims to test is actually wrong.

## github-header-body-split
Headers go to stderr and the body to stdout, so the two are separated by the OS rather than by
parsing. `-D -` interleaves them on one stream with no reliable blank line between: curl emits
CRLF per header but no CRLFCRLF terminator, so splitting on it silently yields an empty body
and reads as a rejected token.

## github-scopes-header
A header that's PRESENT but empty is a classic PAT with no scopes ticked — not the same thing
as an ABSENT header (a fine-grained PAT). Collapsing them reported a legacy full-account token
as the modern narrowly-scoped kind, the exact inversion this branch exists to prevent. Split
on comma and strip, since the separator is `", "` only by convention.

## unguarded-json-crash
A captive portal, a proxy error page, or an HTML 5xx is an answer that can't be parsed as
JSON, which is not a verdict. Unguarded, this raised inside a thread pool and took the WHOLE
directory down with a traceback — every healthy host's result lost with it.

## tenant-absence-specificity
ONLY the specific tenant/site-not-found answer counts as absent (Entra's AADSTS90002, Jira's
404). Anything else — throttling, `temporarily_unavailable`, an interstitial, a captive
portal, a 5xx — must stay `None`, because a `False` here also suppresses the auth probe, and
that's the signal actually trusted. Reporting a live tenant/site as gone while silently
skipping the login is the worst of both: it looks like a deleted tenant and proves nothing.

## jira-serverinfo-exposure
⚠ That Jira's `serverInfo` endpoint answers without a credential is itself a recorded, standard
#15 declared-exposure finding — "reachable without authenticating" is exactly what #15 asks to
be enumerated and justified. It's Atlassian's default rather than a misconfiguration, and it's
recorded in the jsm-01 runbook rather than silently relied upon here.

## jira-website-not-dns-name
⚠ For a service, `DNS Name` carries the SHORT CANONICAL NAME (jsm-01, 365-01, git-01) — the
vault's answer to "what is this called" — while the API host lives in the item's Website URL.
Reading `dns_name` here builds `https://jsm-01/...` and fails in a way that looks like an
unreachable tenant.

## http-code-vs-reached
The status code is requested explicitly because an HTTP error is a COMPLETED transfer: curl
exits 0 on a 404, so REACHED alone can't separate "this site doesn't exist" from "the answer
was unreadable". Atlassian's 404 is an HTML page, not JSON, so without the code both collapse
into a `ValueError` and a live-but-renamed site would report as untested forever.

## describe-check-primary
The table gets the PRIMARY operation (the one that produced AUTH, falling back to the reach
test when no login was attempted) plus a count of everything else; `--json` gets the lot under
`probe_ops`. A member whose platform has no probe written still says what was tried rather
than going blank. The full M365 form carries a tenant GUID twice and runs past 150 characters,
which is why the detail lives where there's no width to spend.

## declared-service-only
`probe()`'s `service` flag is a DECLARED service only. `classify()` also INFERS "service" from
the wire for any member with no IPAM entry — and an untagged host that's fallen out of Dnsmasq,
or whose item hostname stopped matching its reservation, looks exactly like that. Routing it
here would drop the reach gate and fire repeated password logins at a box that never answered —
the DSM auto-block the synology branch guards against. The tag is Harry stating what a thing
is; the wire is a guess, and a guess must never change how a member is measured. Hostless
members take this path regardless of tag, since there's no address to measure either way.

## auth-attempt-is-reach
A completed auth attempt IS a reach test — you cannot be rejected by something you didn't
reach. That only holds for a verdict the far end actually gave, which is why every probe
returns `None`, not `False`, when the transfer never completed. Deriving reach from `False`
was reporting a total outage as REACH up.

## not-detail-load-bearing
⚠ The `not detail` check in `probe()`'s service fallback is load-bearing, not a tidy-up. Every
probe that RAN and failed to reach says so (`"no answer from the API"`); only the fallthrough
for a platform with no probe written returns `None` with nothing to say. Falling back to the
endpoint on the noisy case too would put the vendor's front door back into REACH by the side
door — an outage would show the tenant as up because `portal.azure.com` still accepts TCP,
exactly the green-light-wired-to-the-wrong-thing this design exists to prevent.

## access-unreachable-fault
The ACCESS column is the one thing this tool exists to hand you, and once services stopped
being measured by their own URL, nothing checked it at all — a mistyped vendor hostname is
still syntactically valid, so the `url` fault never fires, and the row went fully green while
the URI in it was dead. Checked separately and reported as a FAULT, so it can't leak back into
REACH and start meaning "the vendor is up" again.

## name-collision
Two vault items resolving to one name is a data fault: whichever the eye lands on, the other
is a member you're not seeing. Surfaced on both rows rather than silently de-duplicated.

## off-members-detail
A COUNT can't tell you a device appeared. "14 things on your wire that no vault item claims"
answers "how much of the wire is accounted for" but not "what is alive", which is the question
this tool exists for — so the detail is kept, not just the tally. It's also what a
since-last-session diff needs: you cannot diff a number into "this is new".

## tasks-plane-removed
Jira was retired as the lab's task tracker, so `--tasks`, `jira_snapshot`, `tasks_snapshot`,
`TASKS_WHY` and the `Tasks:` summary line were removed — 272 lines. The flag now dies loud as
an unknown option, which is the point of the KNOWN set: a retired flag must not read as a
silent no-op.

**`jsm-01` stays a member.** Membership is decided by 1Password, not by code, so the platform,
the auth probe and the `--howto` recipe all stay and the row still reads `auth: ok`. Removing
the task plane is not the same act as removing the member, and only the second one is a vault
edit. The shared positional was renamed `TASK_ID` → `ONLY_ID`, because it now narrows `--howto`
to one member and nothing else — a name that says "task" would be the same word meaning two
things.

The eight `jira-snapshot-*`, `jira-page-bound`, `jira-project-discovery`,
`jira-pagination-truncation`, `jira-link-direction` and `jira-probe-ops-reread` sections below
describe code that no longer exists. They are kept as history, not as description. The four
anchors the auth probe still cites — `jira-basic-auth-survives-sso`,
`jira-permission-enumeration`, `jira-serverinfo-exposure`, `jira-website-not-dns-name` — are
live.

Verified by diffing a full run against one captured before the cut: the only intended change
was the `Tasks:` line disappearing. A `swt-01` ZONE that also changed was proved environmental
by re-running the PRE-removal code, which showed the same thing — ZONE comes from the router's
ARP entry, and a quiet switch ages out of it.

## jira-snapshot-design
⚠ `jira_snapshot` returns `None` for UNTESTED and never a zeroed dict — a Jira outage that
reported "0 open" would read as "all work is done", the worst possible lie this tool could
tell. The project key and custom-field IDs are facts about THIS lab and THIS Jira site; they
used to be hardcoded, the precise thing `wblv-prefix-removed` records as deliberately removed
elsewhere. Both are now DISCOVERED — the key from the site, the field ids by NAME. A raw
`customfield_10042` is meaningless on any other tenant and would silently read as empty rather
than failing.

## jira-page-bound
Page size is asked for, and how many pages before the count becomes an admitted floor. The
server trims by response size and hands back fewer than asked with a token, so the real bound
is PAGES, not `maxResults` — 8 × 100 is ~4x the current board and still a fixed stop.

## jira-snapshot-unfiltered
`jira_snapshot` is deliberately given the UNFILTERED member list. Fed the `-p`/`-v` view's
rows, `jsm-01` simply isn't there, and the tool would report "jsm-01 did not answer" — stating
as measured fact that a probe failed when it was never sent. `off_directory` is computed
before the filter for exactly this reason.

## jira-snapshot-note-op
`note_op` attributes to `_CUR.id`, which `probe()` sets on its pool workers. `jira_snapshot`
runs on the main thread after the pool has joined, so without setting `_CUR.id = m["id"]`
itself, its calls record NOTHING and `--check`/`probe_ops` under-report what the run actually
contacted — in a tool whose stated contract is that `probe_ops` describes what happened, not
what the code intends to do.

## jira-project-discovery
`maxResults` is bounded so a runaway project can't turn a session hook into a paginator; if
ever hit, the count is a floor and `truncated` says so. WORK is `hierarchyLevel 0` — Epics (1)
are containers and sub-tasks (-1) would double-count their parent — filtered by TYPE ID, not
name, since `"issuetype != Epic"` silently starts counting epics as work the day someone
renames the type. Which project is DISCOVERED, not named: one project on the site is
unambiguous; more than one and the tool must be TOLD which, via a `Project` field on the vault
item — guessing would silently report another project's backlog as the lab's.

## jira-pagination-truncation
⚠ Done issues never leave a project, so a whole-project fetch is bounded by HISTORY rather
than outstanding work. `maxResults` is a CEILING the server may ignore — it trims pages by
response size. Asking for 200 returned 100 and a `nextPageToken`, so `len(first page)` was
reported as the open count and under-read 135 open items as 100, a third of the board missing,
rendered as confidently as any other number. The cap was never the bound that mattered — so
the loop pages until the token runs out, still bounded (a session hook must not become an
unbounded paginator, but stopping at the first page isn't a counter at all). A later page that
fails is NOT a failed probe — the earlier pages were really measured; it degrades to the floor
the cap always promised, and `truncated` says so. Absence of a token is the ONLY evidence of a
complete set — reading completeness off `len()` is what hid 35 open items in the first place.

## jira-link-direction
⚠ An issue carries `inwardIssue` for the end it IS BLOCKED BY, and `outwardIssue` for the end
it blocks. `type["inward"]` is the same string on BOTH directions, so testing it alone keeps
every Blocks link; the side that's *present* (`inwardIssue` vs `outwardIssue`) is what carries
the direction. Read the wrong side and the graph inverts — and it inverts into something
plausible, which is why it survived a review of the rendered output before being caught.
Verified against raw links. A link to a CLOSED blocker is not a blocker, which is the
difference between a dependency graph and a list of references, and the reason `waits` is
computed rather than stored.

## op-value-empty-builtin-fields
Every 1Password login item carries built-in `username`/`password` fields, and on this estate
they're EMPTY on all of them — the real values live in the item's ACCESS section as
`Username`/`Password`. `--fields label=password` matches case-insensitively and returns the
FIRST match, so it hands back the empty built-in and the recipe fails at the far end: DSM
answers 400, ssh prompts — both look exactly like a wrong password, sending you to rotate a
credential that was never broken. Select on HAVING A VALUE, not position — the duplicate is
the item's shape (nas-01, rpi-01, wap-01 all carry it), not one bad entry, so the recipe must
survive it whether or not the vault is ever tidied.

## unknown-flag-dies
An unrecognised flag used to be IGNORED, so `wblv-lab --breif` printed the full table and said
nothing — you asked for one view and silently got another. Same defect the whole tool is built
against, sitting in its own argument parsing. Typos are the common case, and exactly when a
confident wrong answer does the most damage.

## show-mac-width
MAC identifies a NIC, where every other column answers "is the lab healthy and how do I get
in" — it cost 20 columns and pushed the table past the ~120-column comfortable width. Three
additions (FAULT, ZONE, services-as-members) took the natural width from 119 to 138, so a
terminal that used to fit stopped fitting without changing size. Hidden by default; `--json`
always carries it, since a machine has no width limit.

## show-brief-exceptions
Ten rows that all say "fine" carry one bit between them, and a wall of green teaches the
reader to skim — which is how a silently truncated session hook went unnoticed for days. The
counts above still ASSERT health positively, so "all fine" and "the probe never ran" stay
distinguishable; health is never implied by the absence of rows.

## howto-always-shown
The recipes go in the session brief rather than behind a flag, because the evidence is that a
flag you've been told about is still a flag you don't reach for: every one of these logins was
got wrong by hand while the ACCESS URI and credential item were already in context. Knowing
WHERE was never the problem.

## howto-soft-wrap
These are commands to be PASTED, not prose to be laid out. With a non-tty console the width is
`COLUMNS` (the session hook sets 150), and rich was wrapping the longest recipe mid-argument —
`--vault \n <vault-name>` — so the one line most likely to be copied verbatim was the one line
that couldn't be. A wrapped recipe fails as a shell error attributable to the host, sending the
reader to debug a login that was never actually attempted.

## time-leads
Time leads the output because everything under it is a measurement, and a measurement without
a timestamp is a claim (see standard #14). It's also the answer to "what is now" for anything
reading this output — a session hook that has to guess the date will fabricate one, and a
fabricated timestamp is indistinguishable from a measured one once written down. UTC first
because the estate standard is UTC; local in brackets because Harry is not.

## jira-probe-ops-reread
`probe()` copies `check`/`probe_ops` out of `PROBE_OPS` when its worker finishes, and the Jira
task-snapshot calls happen later on the main thread — so the row as originally built still
describes the run as it was BEFORE those calls. Re-reading it here is necessary, or `--check`
reports five operations on a run that actually made eight. Symptom of the task snapshot living
outside the probe pool; the structural fix would be making it part of jsm-01's own probe.

## show-test-one-pass
`--test` runs every view from ONE probe pass. Running the CLI nine times would be the obvious
implementation and the wrong one — nine times the wall-clock, and nine rounds of SSH logins at
rpi-01 and swt-01, which is how you trip the brute-force lockout that standard #13 exists to
guard against. Probing is the expensive and risky part; rendering is free, so it's the only
part repeated. Consequence worth knowing when reading the `--test` output: every view is the
SAME measurement, so the rows agree with each other by construction — this shows what each
flag renders, not that nine separate runs would agree with each other.

## table-box-choice
`box.SIMPLE` without an edge is the only Rich box style that starts at column 0 — every
bordered style reserves a blank edge column and indents the whole block by one. The rule under
the header comes from the box; the rules above and below are drawn separately, at the table's
measured width.

## natural-width-render
Rich compresses columns to fit the terminal, and under real pressure will squeeze a column
down to a single character — a stack of ellipses that looks like output while carrying
nothing. `min_width` doesn't hold at that point. For a directory tool, a mangled value is worse
than an ugly one, so the table renders at its NATURAL width and a narrow terminal is left to
soft-wrap: every value survives, legibly, at the cost of looking untidy below about 120
columns.

## m365-host-named-23
A URL field holding something that isn't a hostname is a data fault in the vault, not
something to coerce. Reported as such rather than silently parsed into nonsense — the M365
item holds an expiry date and two GUIDs in its URL slots, which once parsed as a host named
"23".

## empty-ipam-dies
Empty inventory is not "no reservations" — it's a read that failed without raising. Left
alone, it yields a full table with every address/MAC/zone blank and every host flagged as
type-drifted because the wire appears to say nothing. Confident and wrong is the one outcome
this tool may not produce, so it dies loudly instead.

## reach-probe-timeouts
The TCP and ping tests in `reach_probe` are raced, not tried in turn — either one answering is
proof of life, so waiting for the first to time out before starting the second simply adds one
timeout to the other, and that only ever happens on a host that's down, precisely the host
that sets the wall-clock for the whole run. The timeouts themselves are deliberately NOT
reduced: they're what stops a slow-but-alive host being reported as down, and a false "down"
is the failure this tool exists to avoid.

## nc-ignores-its-own-timeouts
macOS 26.3.1 `nc` does not honour `-G`, `-w` or `--apple-tcp-timeout`. Against a host that
DROPS the SYN the socket stays in SYN_SENT indefinitely — measured with `lsof`, reproduced
3/3. An open port returns instantly and an address with no ARP entry fails instantly, so the
flags look like they work right up until a member is firewalled or off.

`nc_open` had no caller-side bound, and `reach_probe` joins its futures, so ONE such member
wedged the whole run: four `pve` nodes held it for 579.8s and it only finished when the stuck
`nc` processes were killed by hand. Orphans from earlier runs were still alive 17 days later.

The bound is now `subprocess.run(timeout=t + 1)`, which also reaps the child. The flags stay
in the command in case Apple honours them later. Runtime went 579.8s → 11.1s with the table
unchanged. **A timeout an external tool promises is not a timeout** — bound it where the
promise cannot be broken.

## tasks-one-table
`--tasks` renders ready and blocked work as one table with STATE as a column, the same shape
the member table uses. Splitting ready and blocked into separate blocks made STATE invisible
as a value you can scan and compare, and a separate DELEGABLE column would have been a third
rendering of rows already on screen — HANDS already answers that question.

## router-macs-derived
The router doesn't hold a DHCP reservation for itself — it IS the DHCP server — so its own
interfaces carry no MAC in the IPAM, and every one of them used to count as an address "no
vault item claims". Three of fourteen non-members were `opn-01` talking to itself, and the
count had been overstating since it existed, because a bare number can't be inspected. Derived
from the router's own interface list, not declared, so nothing goes in a vault item that would
then need maintaining by hand.
