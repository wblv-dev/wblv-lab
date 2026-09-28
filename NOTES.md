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

## config-identity-suffixes
The legacy tool accepted only titles ending `/CLAUDE` as the read-only identity, which put an
assistant's name into the vault's naming convention. The suffix is now configured
(`membership.identity_suffixes`, default `/READONLY`) and may list several, so items can be
renamed one at a time during a migration without the tool losing sight of any of them.
