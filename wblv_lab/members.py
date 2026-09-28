"""Membership: the vault decides what is a lab member, and what each item's fields MEAN.

Provider-agnostic — it reads the Item/Field/Url shapes from wblv_lab.secrets, so the same
rules apply whichever provider filled them in. Ported from the legacy `_member()`; every
`legacy NOTES.md#...` pointer marks behaviour kept on purpose.
"""
from __future__ import annotations

import datetime
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .secrets import Item, ItemRef, ReadFailure

# 1Password/autofill label variants, folded to one canonical name. ADDITIVE — the original
# label is kept too. Vendor knowledge (how password managers name fields), so it lives in code.
ALIASES = {
    "newusername": "username", "user": "username", "login": "username",
    "pass": "password", "passwd": "password",
    "key": "api_key", "secret": "api_secret",
    "apikey": "api_key", "apisecret": "api_secret",
    "clientid": "client_id", "clientsecret": "client_secret", "tenantid": "tenant_id",
    "url": "website", "endpoint": "website",
}

DEFAULT_PORT = {"https": 443, "http": 80, "ssh": 22}

# Any scheme, not just http(s): an SSH-managed host should be able to say so.
_URL = re.compile(r"([a-z][a-z0-9+.\-]*)://([A-Za-z0-9.\-]+)(?::(\d+))?", re.I)

# Day-first, because that is how the vault's dates are written; ISO too, being unambiguous.
# Month-first is never guessed (legacy NOTES.md#day-first-dates).
_DATE_FORMATS = ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%y")


def fold(label: str | None) -> str:
    """One spelling for a hand-typed GUI label: lowercased, spaces/hyphens to underscores
    (legacy NOTES.md#field-label-matching)."""
    return re.sub(r"[\s\-]+", "_", (label or "").strip().lower())


def _norm_title(s: str) -> str:
    return s.upper().replace(" ", "")


def is_identity(title: str, suffixes) -> bool:
    """An unqualified title is a member. A title qualified with "/" names one specific
    credential, and only the configured read-only suffixes count — so a write-capable twin
    ("NAS-01 / BACKUP") can never be reported as the identity."""
    t = _norm_title(title)
    if "/" not in t:
        return True
    return any(t.endswith(_norm_title(s)) for s in suffixes)


def select(refs: list[ItemRef], cfg) -> tuple[list[ItemRef], list[ItemRef]]:
    """(keep, skipped). Decided from the listing alone, BEFORE any item is read — a skipped
    item's fields are never fetched."""
    keep, skipped = [], []
    for r in refs:
        (keep if is_identity(r.title, cfg.membership.identity_suffixes) else skipped).append(r)
    return keep, skipped


class Credentials(Mapping):
    """An item's fields, by folded label. Held apart from Member so output built from Members
    can never carry a secret; its repr says how many values it holds, never what they are."""

    def __init__(self, data: dict[str, str]):
        self._d = dict(data)

    def __getitem__(self, k):
        return self._d[k]

    def __iter__(self):
        return iter(self._d)

    def __len__(self):
        return len(self._d)

    def __repr__(self):
        return f"<Credentials: {len(self._d)} keys, values hidden>"

    __str__ = __repr__


@dataclass(frozen=True)
class Member:
    id: str
    item: str                 # the vault item's title — where the credential lives
    name: str                 # identity: declared, else derived (see declared-vs-derived-name)
    endpoint: str
    account: str
    scheme: str
    url_port: int | None
    website: str
    endpoint_malformed: bool
    tags: tuple[str, ...]
    declared_name: str
    derived_name: str
    name_mismatch: bool
    cred_expiry: int | None   # days until the recorded expiry; None = none recorded/unparseable
    platform: str             # API dialect — selects the auth probe
    role: str                 # what it is for — survives a product swap


@dataclass(frozen=True)
class Directory:
    members: tuple[Member, ...]
    skipped: tuple[ItemRef, ...]          # qualified titles that are not the read-only identity
    unreadable: tuple[ReadFailure, ...]   # in the vault, but their fields could not be read
    creds: Mapping[str, Credentials] = field(repr=False, default_factory=dict)

    def collisions(self) -> dict[str, int]:
        """Names claimed by more than one item (legacy NOTES.md#name-collision)."""
        seen: dict[str, int] = {}
        for m in self.members:
            seen[m.name] = seen.get(m.name, 0) + 1
        return {n: c for n, c in seen.items() if c > 1}


def expiry_days(value: str, today: datetime.date | None = None) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    today = today or datetime.date.today()
    for fmt in _DATE_FORMATS:
        try:
            return (datetime.datetime.strptime(value, fmt).date() - today).days
        except ValueError:
            continue
    return None


def _field(item: Item, *labels: str) -> str:
    """First non-empty value among the given labels, matched forgivingly. Reads FIELDS only:
    the vault keeps real values there, and its `urls` arrays are often empty."""
    want = {fold(x) for x in labels}
    return next((f.value.strip() for f in item.fields
                 if fold(f.label) in want and f.value.strip()), "")


def _cred_map(item: Item) -> dict[str, str]:
    """Every label -> value, under both its lowercase and folded spellings plus any alias.
    A set value never loses to an empty one (legacy NOTES.md#set-value-wins-empty); labelled
    URLs are read too, and fields win a clash, being the more deliberate slot
    (legacy NOTES.md#field-label-matching)."""
    c: dict[str, str] = {}

    def keys(label):
        low = (label or "").strip().lower()
        return {low, re.sub(r"[\s\-]+", "_", low)} - {""}

    def put(label, value):
        for k in keys(label):
            for k2 in {k, ALIASES.get(k, k)}:
                if value or k2 not in c:
                    c[k2] = value

    for u in item.urls:
        put(u.label, u.href)
    for f in item.fields:
        put(f.label, f.value)
    return c


def member_of(item: Item, cfg, today: datetime.date | None = None) -> tuple[Member, Credentials]:
    F = cfg.fields
    # Any slot may carry the URL — the built-in website entry, or a custom field.
    slots = [u.href for u in item.urls] + [f.value for f in item.fields if "://" in f.value]
    href = ";".join(slots)
    # URL kept WHOLE, not rebuilt from parts (legacy NOTES.md#url-kept-whole)
    website = next((s.strip() for s in slots if "://" in s), "")
    m = _URL.search(href)
    # a malformed URL is reported, never coerced (legacy NOTES.md#m365-host-named-23)
    endpoint = m.group(2) if (m and "." in m.group(2)) else ""
    # both slots count, or the fault can never fire (legacy NOTES.md#url-fault-could-never-fire)
    website_labels = {fold(F.website), "website", "url"}
    intended = (any("://" in u.href or fold(u.label) in website_labels for u in item.urls)
                or bool(_field(item, F.website, "website", "url", "endpoint")))
    scheme = m.group(1).lower() if endpoint else ""
    url_port = (int(m.group(3)) if (endpoint and m.group(3))
                else DEFAULT_PORT.get(scheme) if endpoint else None)
    # a set value never loses to an empty built-in (legacy NOTES.md#set-value-wins-empty)
    account = next((f.value for f in item.fields
                    if f.label.strip().lower() == "username" and f.value), "")

    # IDENTITY IS DECLARED, NOT DERIVED (legacy NOTES.md#declared-vs-derived-name)
    service_tag = cfg.membership.type_tags.service.lower()
    is_service = any(t.lower() == service_tag for t in item.tags)
    declared = _field(item, F.dns_name).lower()
    from_title = item.title.split("/")[0].strip().lower()
    derived = from_title if (is_service or not endpoint) else endpoint.split(".")[0].lower()
    # tolerated: someone may write the FQDN; the short name is the identity either way
    name = declared.split(".")[0] if declared else derived
    # reported, not resolved — services exempt BY DESIGN (their endpoint is a vendor domain)
    name_mismatch = bool(declared and endpoint and not is_service
                         and declared.split(".")[0] != endpoint.split(".")[0].lower())

    c = _cred_map(item)
    kp, kr = fold(F.platform), fold(F.role)
    # PLATFORM is the API dialect, ROLE what it is for. A lone Role is still accepted.
    platform = (c.get(kp) or c.get(kr) or "").strip().lower()
    # `or ""`: an item with a Platform but NO Role field at all crashed the legacy line this
    # came from — items built from the template always carried an empty Role, so it never fired
    role = ((c.get(kr) or "") if c.get(kp) else "").strip().lower()

    member = Member(
        id=item.id, item=item.title, name=name, endpoint=endpoint, account=account,
        scheme=scheme, url_port=url_port, website=website,
        endpoint_malformed=intended and not endpoint, tags=tuple(item.tags),
        declared_name=declared, derived_name=derived, name_mismatch=name_mismatch,
        cred_expiry=expiry_days(_field(item, F.expiry, "expiry date", "expiry"), today),
        platform=platform, role=role)
    return member, Credentials(c)


def build(read: list[Item | ReadFailure], skipped: list[ItemRef], cfg,
          today: datetime.date | None = None) -> Directory:
    members, creds, unreadable = [], {}, []
    for r in read:
        if isinstance(r, ReadFailure):
            unreadable.append(r)
            continue
        m, c = member_of(r, cfg, today)
        members.append(m)
        # keyed by ITEM ID, never by name (legacy NOTES.md#creds-keyed-by-id)
        creds[m.id] = c
    return Directory(members=tuple(members), skipped=tuple(skipped),
                     unreadable=tuple(unreadable), creds=creds)
