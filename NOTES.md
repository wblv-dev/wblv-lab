# wblv-lab (rebuild) — design rationale

Rationale for decisions made in the rebuild. Entries inherited from the original tool live in
`legacy/NOTES.md` and are cited as `legacy NOTES.md#anchor`; they still apply.

## config-pointers-not-facts
The config exists so things can move without a code change: a vault renamed, a token file
relocated, the IPAM served by a different backend. It may therefore name WHERE each authority
is, and never WHAT the authority says. The moment a config holds an address it becomes the
note-written-last-week this tool was built to replace — a value that moves while the file
does not. The loader refuses any string that parses as an IP address or network, so the
easiest version of that mistake cannot be made by accident. Hostnames are not policed (too
many false positives), which is why this is also stated here.

## config-no-fallback-location
The config is read from exactly one place: `--config`, else `$WBLV_LAB_CONFIG`, else the XDG
default. Whichever applies first is the answer; if that file does not exist it is an error.
Falling through to "the next file that exists" would let a typo in `--config` silently load a
different lab's settings and report on it confidently — the same defect as an ignored unknown
flag (legacy NOTES.md#unknown-flag-dies), one layer down.

## config-empty-is-not-a-value
`vault = ""` is refused rather than treated as "use the default" or "no vault". An empty
string in a hand-edited file is almost always a half-finished edit, and accepting it means the
file says one thing while the tool does another. To take a default, remove the line. Same
family as legacy NOTES.md#set-value-wins-empty: a blank must never win over a real value, and
must never pass for one.

## config-unimplemented-backends-rejected
`ipam.hosts = "kea"` is refused until a Kea backend exists in code. Accepting a value that
nothing reads would render a table built from the wrong source — or from none — with no sign
that the setting was ignored. Choices are the backends that exist, and grow as they are
written.

## config-all-problems-at-once
Validation collects every problem in the file and reports them together. Config errors are
fixed by a human editing a file; one-problem-per-run turns a four-line fix into four runs. This
is not in tension with "one clean root cause" — the root cause is the file, and the list is
its content.

## cli-unconfigured-is-not-empty
With no config at the default location the tool prints its normal header with every value
as a dash, says "Not configured. Nothing was probed.", and exits 2. It does NOT print an empty
table or `Hosts: 0`: a zero is a measurement ("I looked and found nothing"), and the whole
tool is built on keeping "not measured" and "measured, nothing there" apart (legacy
NOTES.md#empty-ipam-dies, #show-brief-exceptions). `--json` returns an `error` object, never
`"members": []`, so a hook or an MCP client cannot mistake a fresh install for an empty lab.

Only the DEFAULT location being empty is "not configured". A path someone named — `--config`
or `$WBLV_LAB_CONFIG` — that does not exist is a typo, and is a fault (exit 1). A config that
exists but is invalid is also a fault: someone meant to set it up, and a welcome screen would
hide what they got wrong.

## cli-init-never-overwrites
`--init` writes the shipped example to wherever the config would be read from, creating the
directory 0700 and the file 0600, with `O_EXCL` so it fails rather than overwrite something
that appeared in the meantime. It refuses outright if a config exists. The example ships with
`vault` commented out, so a fresh install cannot run until someone names a vault: a
placeholder that loads would probe a vault nobody chose. It never creates or asks for a token.

## cli-exit-codes
0 a run completed; 1 a fault; 2 not configured. A script, hook or MCP wrapper cannot read a
table, so "not set up yet" must be distinguishable from "broken" by the exit code alone.

## provider-shape-not-meaning
A secrets provider returns shapes — items, fields, labelled URLs — and nothing else. What a
field MEANS (DNS Name is the identity, Platform selects the probe, a "/BACKUP" title is not
the read-only identity) is decided once, in `members.py`. That split is what lets someone add
Bitwarden or HashiCorp Vault as one module without re-deriving every rule the vault layer
learned the hard way.

## item-read-failure-is-not-empty
An item that is listed but whose `op item get` timed out, was refused, or answered with
something unparseable becomes a `ReadFailure`, reported by name and reason. The legacy tool
parsed a failed read as `{}`, which produced a member with no endpoint — indistinguishable
from an item that genuinely has none. One bad item does not sink the others, and it is never
silently dropped.

## token-never-at-rest
The default token source is the Linux kernel keyring (`@u`, per user): `wblv-lab --unlock`
reads the token with input hidden, and keyctl receives it on STDIN — never argv, never a temp
file. It lives in kernel memory only, expires after `unlock_hours`, and is gone after a
restart. The kernel enforces per-user isolation: another account cannot even find the key.
That is the property that matters with an AI assistant on the same machine — the token must
be held by a DIFFERENT user from the one the assistant runs as, because anything running as
the same user can read the same keyring. `.env` files were considered and rejected: they are
plain text on disk under a friendlier name. `token_source = "file"` remains for systems with
no kernel keyring, and is refused unless its settings match (a `token_file` next to a keyring
source is an error, not ignored).

## unlock-verifies-before-storing
`--unlock` checks the token's SHAPE offline (starts `ops_`, no whitespace, one pair of paste
quotes stripped) and then proves it with `op whoami` BEFORE storing it. A token that fails
either check is never kept, so the keyring can only ever hold a credential that worked at the
moment it was put there. The expiry is set as part of storing; if it cannot be set, the token
is taken back out — a token that would never expire is not what was asked for.

## token-file-mode
The token file must be mode 600 (no group/other bits) or the tool refuses before the token is
used. It is a read credential for every member in the vault; a world-readable copy is the
kind of exposure that goes unnoticed until it matters. The fix is named in the error.

## vault-exact-match
`[secrets].vault` matches a vault's exact name or id. The legacy tool picked the first vault
whose name CONTAINED a word, so adding a second vault with a similar name could silently
switch the whole directory to it. Two vaults with the same name are an error that asks for the
id. "Cannot see the vault" lists what the token CAN see, because a mis-scoped token and a
misspelt name look identical otherwise.

## cli-vault-view-is-incomplete
Until the IPAM and probes exist, a configured run shows the VAULT VIEW: what the vault
declares, with every measured column as a dash, the words "nothing was probed", and exit 1.
`--json` returns it under an `error` key with `vault_members`, never `members`, so no consumer
can mistake a declaration for a measurement. Credentials are out of scope in this view — it
is built from Member fields only.

## config-identity-suffixes
The legacy tool accepted only titles ending `/CLAUDE` as the read-only identity, which put an
assistant's name into the vault's naming convention. The suffix is now configured
(`membership.identity_suffixes`, default `/READONLY`) and may list several, so items can be
renamed one at a time during a migration without the tool losing sight of any of them.
