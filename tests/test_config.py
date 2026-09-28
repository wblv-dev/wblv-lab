import dataclasses
import re
from pathlib import Path

import pytest

from wblv_lab import config as C

REPO = Path(__file__).resolve().parent.parent
MINIMAL = '[secrets]\nvault = "Lab Directory"\n'


def write(tmp_path, text, name="config.toml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def problems_of(tmp_path, text):
    with pytest.raises(C.ConfigError) as e:
        C.load(write(tmp_path, text))
    return e.value.problems


# --- happy path -----------------------------------------------------------------------------

def test_minimal_config_takes_defaults(tmp_path):
    cfg = C.load(write(tmp_path, MINIMAL))
    assert cfg.secrets.vault == "Lab Directory"
    assert cfg.secrets.provider == "1password"
    assert cfg.ipam_platform == "opnsense"
    assert cfg.ipam.hosts == "dnsmasq"
    assert cfg.probing.timeout_s == 10
    assert cfg.membership.type_tags.service == "service"
    assert cfg.source == tmp_path / "config.toml"


def test_relative_token_file_resolves_against_config_dir(tmp_path):
    cfg = C.load(write(tmp_path, MINIMAL))
    assert cfg.secrets.token_file == tmp_path / "op-token"
    cfg = C.load(write(tmp_path, MINIMAL + 'token_file = "sub/tok"\n'))
    assert cfg.secrets.token_file == tmp_path / "sub" / "tok"


def test_tilde_and_absolute_token_file(tmp_path):
    cfg = C.load(write(tmp_path, MINIMAL + 'token_file = "~/x/tok"\n'))
    assert cfg.secrets.token_file == Path.home() / "x" / "tok"
    cfg = C.load(write(tmp_path, MINIMAL + 'token_file = "/opt/tok"\n'))
    assert cfg.secrets.token_file == Path("/opt/tok")


def test_config_is_immutable(tmp_path):
    cfg = C.load(write(tmp_path, MINIMAL))
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.secrets.vault = "other"


def test_overrides_are_applied(tmp_path):
    cfg = C.load(write(tmp_path, MINIMAL + """
[membership]
identity_suffixes = ["/READONLY", "/LEGACY"]
[membership.type_tags]
service = "saas"
[probing]
concurrency = 2
serial_platforms = []
"""))
    assert cfg.membership.identity_suffixes == ("/READONLY", "/LEGACY")
    assert cfg.membership.type_tags.service == "saas"
    assert cfg.membership.type_tags.physical == "physical"      # untouched sibling keeps default
    assert cfg.probing.concurrency == 2
    assert cfg.probing.serial_platforms == ()


# --- fails loud -----------------------------------------------------------------------------

def test_unknown_top_level_key_suggests(tmp_path):
    p = problems_of(tmp_path, MINIMAL + "[secret]\nx = 1\n")
    assert any("secret: unknown key" in x and "did you mean 'secrets'" in x for x in p)


def test_unknown_nested_key_suggests(tmp_path):
    p = problems_of(tmp_path, MINIMAL + "[probing]\ntimeout = 5\n")
    assert any("probing.timeout: unknown key" in x and "probing.timeout_s" in x for x in p)


def test_missing_vault_is_required(tmp_path):
    p = problems_of(tmp_path, "[secrets]\nprovider = \"1password\"\n")
    assert p == ["secrets.vault: required key is missing"]


def test_missing_secrets_section(tmp_path):
    assert problems_of(tmp_path, "[probing]\nconcurrency = 2\n") == \
        ["secrets: required key is missing"]


@pytest.mark.parametrize("line,expect", [
    ('concurrency = "6"', "expected an integer, got a string"),
    ("concurrency = true", "expected an integer, got a boolean"),     # bool is not an int
    ("concurrency = 6.0", "expected an integer, got a number"),
    ("concurrency = 0", "outside 1..64"),
    ("timeout_s = 301", "outside 1..300"),
])
def test_probing_types_and_ranges(tmp_path, line, expect):
    p = problems_of(tmp_path, MINIMAL + f"[probing]\n{line}\n")
    assert len(p) == 1 and expect in p[0]


def test_bool_must_be_bool(tmp_path):
    p = problems_of(tmp_path, MINIMAL + "[ipam]\narp = 1\n")
    assert p == ["ipam.arp: expected true/false, got an integer"]


def test_empty_string_is_not_a_value(tmp_path):
    p = problems_of(tmp_path, '[secrets]\nvault = ""\n')
    assert "is empty" in p[0]
    p = problems_of(tmp_path, MINIMAL + '[fields]\ndns_name = "   "\n')
    assert "is empty" in p[0]


def test_whitespace_padding_rejected(tmp_path):
    p = problems_of(tmp_path, '[secrets]\nvault = " Lab Directory"\n')
    assert "leading/trailing whitespace" in p[0]


def test_list_items_validated(tmp_path):
    p = problems_of(tmp_path, MINIMAL + '[membership]\nidentity_suffixes = ["/READONLY", 3]\n')
    assert p == ["membership.identity_suffixes[1]: expected a string, got an integer"]


def test_section_must_be_a_table(tmp_path):
    # top-level keys must precede the first [table] header, or TOML files them under it
    p = problems_of(tmp_path, 'probing = 5\n' + MINIMAL)
    assert p == ["probing: expected a table, got an integer"]


@pytest.mark.parametrize("section,line", [
    ("secrets", 'vault = "vault at 192.0.2.10"'),
    ("classify", 'hypervisor_vendors = ["qemu", "2001:db8::1"]'),
    ("fields", 'dns_name = "198.51.100.0/24"'),
])
def test_addresses_are_refused(tmp_path, section, line):
    text = (f"[secrets]\n{line}\n" if section == "secrets"
            else MINIMAL + f"[{section}]\n{line}\n")
    p = problems_of(tmp_path, text)
    assert len(p) == 1 and "pointers-not-facts" in p[0]


def test_unimplemented_backend_refused(tmp_path):
    p = problems_of(tmp_path, MINIMAL + '[ipam]\nhosts = "kea"\n')
    assert p == ["ipam.hosts: 'kea' is not supported (supported: dnsmasq)"]
    p = problems_of(tmp_path, MINIMAL + '[ipam]\nsource = "platform:pfsense"\n')
    assert "platform 'pfsense' cannot serve this" in p[0]
    p = problems_of(tmp_path, MINIMAL + '[ipam]\nsource = "opn-01"\n')
    assert "does not match the expected form" in p[0]


def test_all_problems_reported_in_one_pass(tmp_path):
    p = problems_of(tmp_path, """
[secrets]
vault = ""
[probing]
concurrency = "x"
timeot_s = 3
[ipam]
hosts = "kea"
""")
    assert len(p) == 4


def test_internal_field_cannot_be_set(tmp_path):
    p = problems_of(tmp_path, 'source = "/etc/other.toml"\n' + MINIMAL)
    assert p[0].startswith("source: unknown key")


def test_bad_toml_names_the_file(tmp_path):
    path = write(tmp_path, "[secrets\nvault = 1\n")
    with pytest.raises(C.ConfigError) as e:
        C.load(path)
    assert "not valid TOML" in e.value.problems[0] and str(path) in str(e.value)


# --- location: one answer, no fall-through --------------------------------------------------

def test_explicit_path_wins(tmp_path):
    p = write(tmp_path, MINIMAL, "mine.toml")
    assert C.locate(p, env={}) == p


def test_explicit_missing_does_not_fall_back(tmp_path):
    xdg = tmp_path / "xdg"
    (xdg / "wblv-lab").mkdir(parents=True)
    write(xdg / "wblv-lab", MINIMAL)                       # a valid default EXISTS ...
    with pytest.raises(C.ConfigError) as e:                # ... and is still not used
        C.locate(tmp_path / "missing.toml", env={"XDG_CONFIG_HOME": str(xdg)})
    assert "from --config" in e.value.problems[0]


def test_env_var_then_xdg(tmp_path):
    envfile = write(tmp_path, MINIMAL, "env.toml")
    xdg = tmp_path / "xdg"
    (xdg / "wblv-lab").mkdir(parents=True)
    default = write(xdg / "wblv-lab", MINIMAL)
    assert C.locate(None, env={"WBLV_LAB_CONFIG": str(envfile),
                               "XDG_CONFIG_HOME": str(xdg)}) == envfile
    assert C.locate(None, env={"XDG_CONFIG_HOME": str(xdg)}) == default


def test_env_var_missing_does_not_fall_back(tmp_path):
    xdg = tmp_path / "xdg"
    (xdg / "wblv-lab").mkdir(parents=True)
    write(xdg / "wblv-lab", MINIMAL)
    with pytest.raises(C.ConfigError) as e:
        C.locate(None, env={"WBLV_LAB_CONFIG": str(tmp_path / "nope.toml"),
                            "XDG_CONFIG_HOME": str(xdg)})
    assert "$WBLV_LAB_CONFIG" in e.value.problems[0]


# --- the shipped example stays valid and neutral --------------------------------------------

def test_example_config_is_valid_and_matches_defaults(tmp_path):
    text = (REPO / "config.example.toml").read_text(encoding="utf-8")
    cfg = C.load(write(tmp_path, text))
    ref = C.load(write(tmp_path, MINIMAL, "ref.toml"))
    for section in ("membership", "fields", "ipam", "probing", "faults", "classify", "output"):
        assert getattr(cfg, section) == getattr(ref, section), section


def test_no_assistant_names_in_defaults_or_example():
    """AI-agnostic: no assistant or vendor-of-assistant names baked into conventions."""
    banned = re.compile(r"claude|anthropic|openai|chatgpt|gpt-|qwen|deepseek|copilot|gemini",
                        re.I)
    blob = repr(C.Config(secrets=C.Secrets(vault="x"))) + \
        (REPO / "config.example.toml").read_text(encoding="utf-8")
    assert not banned.search(blob), banned.search(blob).group(0)
