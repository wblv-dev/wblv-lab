import datetime

import pytest

from conftest import SECRET_VALUES
from wblv_lab import config as C
from wblv_lab import members as M
from wblv_lab.secrets import Field, Item, ItemRef, Url

TODAY = datetime.date(2026, 9, 28)


@pytest.fixture
def directory(provider, cfg):
    provider.check(); provider.resolve_vault()
    keep, skipped = M.select(provider.list_items(), cfg)
    return M.build(provider.get_items(keep), skipped, cfg, today=TODAY)


def by_name(d):
    return {m.name: m for m in d.members}


# --- membership: which items count ----------------------------------------------------------

@pytest.mark.parametrize("title,suffixes,expect", [
    ("NAS-01", ("/READONLY",), True),                       # unqualified: always a member
    ("NAS-01 / READONLY", ("/READONLY",), True),
    ("nas-01/readonly", ("/READONLY",), True),               # case and spaces ignored
    ("NAS-01 / BACKUP", ("/READONLY",), False),              # a write-capable twin
    ("NAS-01 / LEGACY", ("/READONLY",), False),
    ("NAS-01 / LEGACY", ("/READONLY", "/LEGACY"), True),     # migration: both accepted
])
def test_is_identity(title, suffixes, expect):
    assert M.is_identity(title, suffixes) is expect


def test_skipped_items_are_never_read(provider, cfg, fake_op):
    provider.check(); provider.resolve_vault()
    keep, skipped = M.select(provider.list_items(), cfg)
    provider.get_items(keep)
    assert [s.title for s in skipped] == ["TEST-HOST-01 / BACKUP"]
    got = [c[2] for c in fake_op.calls if c[1:3] == ["item", "get"]]
    assert "itmhost01b" not in got


def test_directory_contents(directory):
    names = sorted(m.name for m in directory.members)
    assert names == ["bad-01", "host-01", "mis-01", "nas-01", "old-01", "svc-01"]
    assert [u.title for u in directory.unreadable] == ["TEST-FAIL-01"]
    assert directory.collisions() == {}


# --- what the fields mean -------------------------------------------------------------------

def test_host_member(directory):
    h = by_name(directory)["host-01"]
    assert (h.endpoint, h.scheme, h.url_port) == ("host-01.example.test", "ssh", 22)
    assert h.website == "ssh://host-01.example.test:22"
    assert (h.platform, h.role) == ("linux", "compute")
    # the built-in username is EMPTY; the section's Username must win
    assert h.account == "lab-ro"
    assert not h.endpoint_malformed and not h.name_mismatch
    assert h.cred_expiry is None


def test_service_member_keeps_url_whole(directory):
    s = by_name(directory)["svc-01"]
    assert s.website == "https://login.example.test/admin"      # path kept, not rebuilt
    assert s.url_port == 443
    assert not s.name_mismatch                                  # services exempt by design
    creds = directory.creds[s.id]
    assert creds["client_id"] == "fake-client-id"
    assert creds["tenant_id"] == "00000000-0000-0000-0000-000000000000"   # from a labelled URL


def test_port_and_day_first_expiry(directory):
    n = by_name(directory)["nas-01"]
    assert n.url_port == 5001
    assert n.cred_expiry == (datetime.date(2028, 7, 23) - TODAY).days


def test_malformed_url_is_reported_not_coerced(directory):
    b = by_name(directory)["bad-01"]
    assert b.endpoint_malformed and b.endpoint == "" and b.url_port is None


def test_declared_name_wins_and_mismatch_is_reported(directory):
    m = by_name(directory)["mis-01"]
    assert m.name == "mis-01" and m.derived_name == "other-01" and m.name_mismatch


def test_legacy_suffix_member_present(directory):
    assert by_name(directory)["old-01"].item == "TEST-OLD-01 / LEGACY"


# --- secrets stay out of member records -----------------------------------------------------

def test_no_secret_in_members_or_directory_repr(directory):
    blob = repr(directory.members) + repr(directory)
    for s in SECRET_VALUES:
        assert s not in blob, s


def test_credentials_repr_hides_values(directory):
    c = directory.creds[by_name(directory)["host-01"].id]
    assert c["password"] == "fake-pass-1"
    assert "fake-pass-1" not in repr(c) and "values hidden" in repr(c)


def test_creds_keyed_by_item_id_not_name(cfg):
    a = Item("id-a", "DUP / READONLY", ("physical",), (Field("DNS Name", "dup-01"),
                                                        Field("Password", "one")))
    b = Item("id-b", "DUP2 / READONLY", ("physical",), (Field("DNS Name", "dup-01"),
                                                         Field("Password", "two")))
    d = M.build([a, b], [], cfg, today=TODAY)
    assert d.collisions() == {"dup-01": 2}
    assert d.creds["id-a"]["password"] == "one" and d.creds["id-b"]["password"] == "two"


# --- field reading rules --------------------------------------------------------------------

def test_set_value_wins_empty_in_creds(cfg):
    it = Item("i", "X", (), (Field("password", ""), Field("Password", "real")))
    _, c = M.member_of(it, cfg, TODAY)
    assert c["password"] == "real"


def test_fields_win_over_labelled_urls(cfg):
    it = Item("i", "X", (), (Field("Client ID", "from-field"),),
              (Url("Client ID", "from-url"),))
    _, c = M.member_of(it, cfg, TODAY)
    assert c["client_id"] == "from-field"


def test_labels_match_forgivingly(cfg):
    it = Item("i", "X", ("physical",), (Field("dns-name", "fold-01"),
                                        Field("PLATFORM", "linux")))
    m, _ = M.member_of(it, cfg, TODAY)
    assert m.name == "fold-01" and m.platform == "linux"


def test_platform_without_any_role_field(cfg):
    """Regression: legacy crashed here; template-built items always had an empty Role."""
    it = Item("i", "X", (), (Field("Platform", "linux"),))
    m, _ = M.member_of(it, cfg, TODAY)
    assert (m.platform, m.role) == ("linux", "")


def test_lone_role_still_selects_platform(cfg):
    it = Item("i", "X", (), (Field("Role", "Synology"),))
    m, _ = M.member_of(it, cfg, TODAY)
    assert (m.platform, m.role) == ("synology", "")


def test_configured_labels_are_used(tmp_path, token_file):
    cfg = C.parse({"secrets": {"vault": "v", "token_file": str(token_file)},
                   "fields": {"dns_name": "Hostname", "platform": "Kind"}}, tmp_path)
    it = Item("i", "X", (), (Field("Hostname", "cfg-01"), Field("Kind", "linux"),
                             Field("DNS Name", "ignored-01")))
    m, _ = M.member_of(it, cfg, TODAY)
    assert m.name == "cfg-01" and m.platform == "linux"


@pytest.mark.parametrize("value,expect", [
    ("23/07/2028", 664), ("2028-07-23", 664), ("23-07-2028", 664), ("23/07/28", 664),
    ("07/23/2028", None),        # month-first is never guessed
    ("next year", None), ("", None),
])
def test_expiry_parsing(value, expect):
    assert M.expiry_days(value, TODAY) == expect
