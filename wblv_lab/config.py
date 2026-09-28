"""Configuration: where the authorities are — never what they say.

The config file names POINTERS: which vault, which token file, which platform serves the
IPAM, which field labels the vault uses. It never holds a FACT about the lab — no address, no
hostname, no member list. Those are asked for on every run. See NOTES.md#config-pointers-not-facts.

Everything here fails loud and all at once: every problem in the file is reported together,
so fixing a config is one edit, not one edit per run.
"""
from __future__ import annotations

import difflib
import ipaddress
import os
import re
import tomllib
import typing
from dataclasses import MISSING, dataclass, field, fields, is_dataclass
from pathlib import Path

ENV_VAR = "WBLV_LAB_CONFIG"
APP_DIR = "wblv-lab"
FILE_NAME = "config.toml"

# Backends that exist in code today. A value naming one that does not is refused rather than
# accepted and ignored — see NOTES.md#config-unimplemented-backends-rejected.
SECRET_PROVIDERS = ("1password",)
IPAM_PLATFORMS = ("opnsense",)
IPAM_HOST_BACKENDS = ("dnsmasq",)


class ConfigError(Exception):
    """Every problem found in one pass. `problems` is the list; str() is one line per problem."""

    def __init__(self, problems: list[str], source: Path | str | None = None):
        self.problems = list(problems)
        self.source = str(source) if source else None
        head = f"invalid config {self.source}" if self.source else "invalid config"
        n = len(self.problems)
        super().__init__(f"{head} ({n} problem{'s' if n != 1 else ''}):\n  "
                         + "\n  ".join(self.problems))


class ConfigNotFound(ConfigError):
    """No file where the config was looked for. `why` says which rule chose `path`, because
    "nothing at the default location" (not set up yet) and "nothing at the path you named"
    (a typo) are different situations — see NOTES.md#cli-unconfigured-is-not-empty."""

    DEFAULT = "default location"

    def __init__(self, path: Path, why: str):
        self.path, self.why = path, why
        super().__init__([f"no config file at {path} (from {why})"])


# --- schema ---------------------------------------------------------------------------------
# Constraints ride in field metadata: choices, pattern, min, max. `internal` fields are set by
# the loader and may not appear in the file.

@dataclass(frozen=True)
class Secrets:
    vault: str                                   # exact name or id — required, never guessed
    provider: str = field(default="1password", metadata={"choices": SECRET_PROVIDERS})
    token_file: Path = Path("op-token")          # relative paths resolve against the config dir


@dataclass(frozen=True)
class TypeTags:
    physical: str = "physical"
    virtual: str = "virtual"
    service: str = "service"


@dataclass(frozen=True)
class Membership:
    # A title with a "/" qualifier (e.g. "NAS-01 / BACKUP") names a specific credential. Only
    # these qualifiers are the read-only identity; any other qualifier is skipped so a
    # write-capable twin can never be reported as the identity. Compared case- and
    # space-insensitively. Unqualified titles are always members.
    identity_suffixes: tuple[str, ...] = ("/READONLY",)
    type_tags: TypeTags = field(default_factory=TypeTags)


@dataclass(frozen=True)
class Fields:
    """1Password field labels the tool keys off. Matched forgivingly at read time
    (legacy NOTES.md#field-label-matching) — these are the canonical spellings."""
    dns_name: str = "DNS Name"
    website: str = "Website"
    platform: str = "Platform"
    role: str = "Role"
    expiry: str = "Expiry Date"


@dataclass(frozen=True)
class Ipam:
    # Found by the platform a member DECLARES, never by its name
    # (legacy NOTES.md#ipam-platform-prefix-table).
    source: str = field(default="platform:opnsense",
                        metadata={"pattern": r"platform:[a-z0-9][a-z0-9-]*",
                                  "platform_choices": IPAM_PLATFORMS})
    hosts: str = field(default="dnsmasq", metadata={"choices": IPAM_HOST_BACKENDS})
    arp: bool = True
    router_interfaces: bool = True               # legacy NOTES.md#router-macs-derived


@dataclass(frozen=True)
class Probing:
    concurrency: int = field(default=6, metadata={"min": 1, "max": 64})
    item_read_concurrency: int = field(default=8, metadata={"min": 1, "max": 64})
    # Not reduced to speed things up: a false "down" is the failure this tool exists to avoid
    # (legacy NOTES.md#reach-probe-timeouts).
    timeout_s: int = field(default=10, metadata={"min": 1, "max": 300})
    # Echoed over SSH to prove a real session, not merely a connection
    # (legacy NOTES.md#echo-proves-session).
    session_token: str = field(default="lab-ok", metadata={"pattern": r"[A-Za-z0-9_-]{4,64}"})
    # Platforms whose logins must never run concurrently (DSM auto-block).
    serial_platforms: tuple[str, ...] = ("synology",)


@dataclass(frozen=True)
class Faults:
    expiry_warn_days: int = field(default=45, metadata={"min": 0, "max": 3650})


@dataclass(frozen=True)
class Classify:
    # Vendor strings (from the router's OUI lookup) that mean "this NIC is virtual".
    hypervisor_vendors: tuple[str, ...] = ("proxmox", "vmware", "qemu", "kvm", "xen",
                                           "microsoft corporation", "oracle virtualbox",
                                           "nutanix", "parallels", "red hat")


@dataclass(frozen=True)
class Output:
    # Width used when stdout is not a terminal (a hook, a pipe); COLUMNS still wins if set.
    non_tty_columns: int = field(default=200, metadata={"min": 40, "max": 10000})


@dataclass(frozen=True)
class Config:
    secrets: Secrets
    membership: Membership = field(default_factory=Membership)
    fields: Fields = field(default_factory=Fields)
    ipam: Ipam = field(default_factory=Ipam)
    probing: Probing = field(default_factory=Probing)
    faults: Faults = field(default_factory=Faults)
    classify: Classify = field(default_factory=Classify)
    output: Output = field(default_factory=Output)
    source: Path | None = field(default=None, metadata={"internal": True})

    @property
    def ipam_platform(self) -> str:
        return self.ipam.source.split(":", 1)[1]


# --- location -------------------------------------------------------------------------------

def resolve(explicit: str | os.PathLike | None = None,
            env: typing.Mapping[str, str] | None = None) -> tuple[Path, str]:
    """Where the config IS, by rule — whether or not a file exists there yet. Precedence:
    explicit path, then $WBLV_LAB_CONFIG, then $XDG_CONFIG_HOME (or ~/.config)/wblv-lab/config.toml.
    Returns (path, which rule chose it)."""
    env = os.environ if env is None else env
    if explicit:
        return Path(explicit).expanduser(), "--config"
    if env.get(ENV_VAR):
        return Path(env[ENV_VAR]).expanduser(), f"${ENV_VAR}"
    base = Path(env["XDG_CONFIG_HOME"]).expanduser() if env.get("XDG_CONFIG_HOME") \
        else Path.home() / ".config"
    return base / APP_DIR / FILE_NAME, ConfigNotFound.DEFAULT


def locate(explicit: str | os.PathLike | None = None,
           env: typing.Mapping[str, str] | None = None) -> Path:
    """The ONE place the config is read from (see resolve()). Whichever rule applies first is
    the answer — if that file does not exist, it is an error. It never falls through to the next
    candidate. See NOTES.md#config-no-fallback-location."""
    p, why = resolve(explicit, env)
    if not p.is_file():
        raise ConfigNotFound(p, why)
    return p


def load(explicit: str | os.PathLike | None = None,
         env: typing.Mapping[str, str] | None = None) -> Config:
    path = locate(explicit, env)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ConfigError([f"not valid TOML: {e}"], path) from None
    except OSError as e:
        raise ConfigError([f"unreadable: {type(e).__name__}: {e}"], path) from None
    return parse(data, base_dir=path.parent, source=path)


def parse(data: dict, base_dir: Path, source: Path | None = None) -> Config:
    """Validate a decoded TOML document into a Config. Collects every problem, then raises."""
    problems: list[str] = []
    kwargs = _build(Config, data, "", problems, base_dir)
    if problems:
        raise ConfigError(problems, source)
    cfg = Config(**kwargs, source=source)
    return cfg


# --- validation -----------------------------------------------------------------------------

def _build(cls, data, where: str, problems: list[str], base_dir: Path) -> dict | None:
    if not isinstance(data, dict):
        problems.append(f"{where.rstrip('.') or '(root)'}: expected a table, got {_kind(data)}")
        return None
    hints = typing.get_type_hints(cls)
    schema = [f for f in fields(cls) if not f.metadata.get("internal")]
    known = [f.name for f in schema]
    for key in data:
        if key not in known:
            near = difflib.get_close_matches(key, known, n=1)
            problems.append(f"{where}{key}: unknown key"
                            + (f" — did you mean '{where}{near[0]}'?" if near
                               else f" (known: {', '.join(known)})"))
    out = {}
    for f in schema:
        name = f"{where}{f.name}"
        if f.name in data:
            ok, value = _coerce(hints[f.name], data[f.name], name, f.metadata, problems, base_dir)
            if ok:
                out[f.name] = value
        elif f.default is MISSING and f.default_factory is MISSING:
            problems.append(f"{name}: required key is missing")
        elif hints[f.name] is Path and f.default is not MISSING:
            out[f.name] = _resolve_path(f.default, base_dir)
    return out


def _coerce(tp, value, name, meta, problems, base_dir):
    """Return (ok, value). Appends to `problems` and returns (False, None) on any defect."""
    if is_dataclass(tp):
        before = len(problems)
        kw = _build(tp, value, f"{name}.", problems, base_dir)
        return (kw is not None and len(problems) == before), (tp(**kw) if kw is not None
                                                               and len(problems) == before else None)
    if tp is bool:
        if not isinstance(value, bool):
            problems.append(f"{name}: expected true/false, got {_kind(value)}")
            return False, None
        return True, value
    if tp is int:
        # bool is a subclass of int in Python; `true` must not pass as 1
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(f"{name}: expected an integer, got {_kind(value)}")
            return False, None
        lo, hi = meta.get("min"), meta.get("max")
        if (lo is not None and value < lo) or (hi is not None and value > hi):
            problems.append(f"{name}: {value} is outside {lo}..{hi}")
            return False, None
        return True, value
    if tp is str:
        return _check_str(value, name, meta, problems)
    if tp is Path:
        ok, s = _check_str(value, name, meta, problems)
        return (True, _resolve_path(s, base_dir)) if ok else (False, None)
    if typing.get_origin(tp) is tuple:
        if not isinstance(value, list):
            problems.append(f"{name}: expected a list of strings, got {_kind(value)}")
            return False, None
        items, ok = [], True
        for i, v in enumerate(value):
            good, s = _check_str(v, f"{name}[{i}]", {}, problems)
            ok &= good
            items.append(s)
        return (True, tuple(items)) if ok else (False, None)
    raise TypeError(f"schema type {tp!r} for {name} has no validator")   # programming error


def _check_str(value, name, meta, problems):
    if not isinstance(value, str):
        problems.append(f"{name}: expected a string, got {_kind(value)}")
        return False, None
    if not value.strip():
        # An empty value is not a setting — see NOTES.md#config-empty-is-not-a-value
        problems.append(f"{name}: is empty — remove the line to use the default")
        return False, None
    if value != value.strip():
        problems.append(f"{name}: has leading/trailing whitespace")
        return False, None
    if _looks_like_address(value):
        problems.append(f"{name}: {value!r} contains a network address — the config names "
                        "where to ask, never what the answer is (NOTES.md#config-pointers-not-facts)")
        return False, None
    if "choices" in meta and value not in meta["choices"]:
        problems.append(f"{name}: {value!r} is not supported (supported: "
                        f"{', '.join(meta['choices'])})")
        return False, None
    if "pattern" in meta and not re.fullmatch(meta["pattern"], value):
        problems.append(f"{name}: {value!r} does not match the expected form {meta['pattern']}")
        return False, None
    if "platform_choices" in meta:
        plat = value.split(":", 1)[1]
        if plat not in meta["platform_choices"]:
            problems.append(f"{name}: platform {plat!r} cannot serve this (supported: "
                            f"{', '.join(meta['platform_choices'])})")
            return False, None
    return True, value


_ADDR_TOKEN = re.compile(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?")


def _looks_like_address(s: str) -> bool:
    """True if any token in s parses as an IPv4/IPv6 address or network."""
    for tok in _ADDR_TOKEN.findall(s):
        if tok.count(".") < 3 and tok.count(":") < 2:
            continue
        try:
            ipaddress.ip_network(tok, strict=False)
            return True
        except ValueError:
            continue
    return False


def _resolve_path(p, base_dir: Path) -> Path:
    p = Path(p).expanduser()
    return p if p.is_absolute() else (base_dir / p)


def _kind(v) -> str:
    return {bool: "a boolean", int: "an integer", float: "a number", str: "a string",
            list: "a list", dict: "a table"}.get(type(v), type(v).__name__)
