import pytest

from conftest import FakeKeyctl
from wblv_lab import config as C
from wblv_lab.secrets import SecretsError
from wblv_lab.secrets.tokens import FileToken, KernelKeyring, store_for, undecorate

TOK = "ops_FAKE_keyring_token"


def ring(fk=None, ttl=3600):
    fk = fk or FakeKeyctl()
    return KernelKeyring("wblv-lab:1password", ttl, runner=fk, which=lambda _: "/usr/bin/keyctl"), fk


def test_locked_keyring_says_how_to_unlock():
    r, _ = ring()
    with pytest.raises(SecretsError, match="the token is locked") as e:
        r.get()
    assert "wblv-lab --unlock" in e.value.detail["hint"]


def test_put_then_get_roundtrip_via_stdin_only():
    r, fk = ring(ttl=7200)
    r.put(TOK)
    assert r.get() == (TOK, None)
    assert not any(TOK in a for argv in fk.calls for a in argv)       # never in argv
    assert TOK in fk.inputs                                            # only ever on stdin
    (kid,) = fk.keys
    assert fk.timeouts[kid] == 7200                                    # always expires


def test_put_replaces_rather_than_accumulates():
    r, fk = ring()
    r.put("ops_first")
    r.put("ops_second")
    assert [v for _, v in fk.keys.values()] == ["ops_second"]


def test_expiry_failure_takes_the_token_back_out():
    r, fk = ring(FakeKeyctl(fail={"timeout"}))
    with pytest.raises(SecretsError, match="not kept"):
        r.put(TOK)
    assert fk.keys == {}


def test_store_failure():
    r, _ = ring(FakeKeyctl(fail={"padd"}))
    with pytest.raises(SecretsError, match="could not store"):
        r.put(TOK)


def test_clear():
    r, fk = ring()
    assert r.clear() is False
    r.put(TOK)
    assert r.clear() is True and fk.keys == {}


def test_keyctl_missing():
    r = KernelKeyring("x", 60, runner=FakeKeyctl(), which=lambda _: None)
    with pytest.raises(SecretsError, match="keyctl") as e:
        r.get()
    assert "keyutils" in e.value.detail["hint"] and 'token_source = "file"' in e.value.detail["hint"]


def test_file_store_cannot_be_unlocked(tmp_path):
    with pytest.raises(SecretsError, match="edit the file yourself"):
        FileToken(tmp_path / "t").put(TOK)


def test_store_for_follows_config(tmp_path):
    k = C.parse({"secrets": {"vault": "v", "unlock_hours": 2}}, tmp_path)
    s = store_for(k, which=lambda _: "/usr/bin/keyctl")
    assert isinstance(s, KernelKeyring) and s.ttl_s == 7200
    f = C.parse({"secrets": {"vault": "v", "token_source": "file"}}, tmp_path)
    assert isinstance(store_for(f), FileToken)


@pytest.mark.parametrize("raw,expect", [
    ("  ops_abc \n", "ops_abc"), ('"ops_abc"', "ops_abc"), ("' ops_abc '", "ops_abc"),
    ('"ops_abc', '"ops_abc'),            # unmatched quote is left alone, never "repaired"
    ('""ops_abc""', '"ops_abc"'),        # ONE pair only
])
def test_undecorate(raw, expect):
    assert undecorate(raw) == expect
