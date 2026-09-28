import pytest

from conftest import TOKEN, VAULT, FakeOp
from wblv_lab.secrets import ItemRef, ReadFailure, SecretsError
from wblv_lab.secrets.onepassword import OnePassword


def op_with(cfg, **fake):
    f = FakeOp(**fake)
    return OnePassword(cfg, runner=f, which=lambda _: "/usr/bin/op"), f


# --- token ----------------------------------------------------------------------------------

def test_token_goes_in_env_never_argv(provider, fake_op):
    provider.check()
    provider.resolve_vault()
    refs = provider.list_items()
    provider.get_items(refs)
    assert fake_op.calls, "no op calls recorded"
    for argv in fake_op.calls:
        assert not any(TOKEN in a for a in argv), argv
    assert all(e.get("OP_SERVICE_ACCOUNT_TOKEN") == TOKEN for e in fake_op.envs)


def test_token_missing(cfg, token_file):
    token_file.unlink()
    p, _ = op_with(cfg)
    with pytest.raises(SecretsError, match="token file not found"):
        p.check()


def test_token_empty(cfg, token_file):
    token_file.write_text("  \n")
    p, _ = op_with(cfg)
    with pytest.raises(SecretsError, match="token file is empty"):
        p.check()


def test_token_readable_by_others_is_refused(cfg, token_file):
    token_file.chmod(0o644)
    p, f = op_with(cfg)
    with pytest.raises(SecretsError, match="readable by other users") as e:
        p.check()
    assert "chmod 600" in e.value.detail["hint"]
    assert f.calls == []                          # refused before the token was ever used


def test_op_not_installed(cfg):
    p = OnePassword(cfg, runner=FakeOp(), which=lambda _: None)
    with pytest.raises(SecretsError, match="not on PATH"):
        p.check()


# --- whoami: one root cause, classified ------------------------------------------------------

@pytest.mark.parametrize("fail,cause", [
    ("timeout", "1Password unreachable (no answer)"),
    (("refuse", "dial tcp: lookup example.1password.com: no such host"),
     "1Password unreachable (network)"),
    (("refuse", "[ERROR] 401: Unauthorized: token expired"), "token invalid or expired"),
    (("refuse", "something odd"), "op whoami failed"),
])
def test_whoami_failures_are_classified(cfg, fail, cause):
    p, _ = op_with(cfg, fail={("whoami",): fail})
    with pytest.raises(SecretsError) as e:
        p.check()
    assert e.value.cause == cause
    assert "token_file_age_days" in e.value.detail


def test_whoami_without_identity(cfg):
    p, _ = op_with(cfg, whoami={"url": "https://example.1password.com"})
    with pytest.raises(SecretsError, match="named no identity"):
        p.check()


def test_whoami_ok(provider):
    ident = provider.check()
    assert ident.account == "example.1password.com"
    assert provider.token_file_age_days is not None


# --- vault: exact, never substring ----------------------------------------------------------

def test_vault_by_exact_name(provider):
    provider.check()
    assert provider.resolve_vault() == VAULT["name"]
    assert provider.vault_id == VAULT["id"]


def test_vault_by_id(tmp_path, token_file):
    from wblv_lab import config as C
    cfg = C.parse({"secrets": {"vault": VAULT["id"], "token_file": str(token_file)}}, tmp_path)
    p, _ = op_with(cfg)
    p.check()
    assert p.resolve_vault() == VAULT["name"]


def test_vault_substring_does_not_match(tmp_path, token_file):
    from wblv_lab import config as C
    cfg = C.parse({"secrets": {"vault": "Lab Directory", "token_file": str(token_file)}}, tmp_path)
    p, _ = op_with(cfg)
    p.check()
    with pytest.raises(SecretsError, match="cannot see a vault named 'Lab Directory'") as e:
        p.resolve_vault()
    assert e.value.detail["visible"] == VAULT["name"]


def test_vault_ambiguous_name(cfg):
    twin = {"id": "vlt0000000000000000000002", "name": VAULT["name"]}
    p, _ = op_with(cfg, vaults=[VAULT, twin])
    p.check()
    with pytest.raises(SecretsError, match="2 vaults are named"):
        p.resolve_vault()


def test_no_vaults_visible(cfg):
    p, _ = op_with(cfg, vaults=[])
    p.check()
    with pytest.raises(SecretsError) as e:
        p.resolve_vault()
    assert "mis-scoped" in e.value.detail["visible"]


# --- items ----------------------------------------------------------------------------------

def test_empty_vault_dies(cfg):
    p, _ = op_with(cfg, items={})
    p.check(); p.resolve_vault()
    with pytest.raises(SecretsError, match="returned no items"):
        p.list_items()


def test_item_list_garbage_dies(cfg):
    p, _ = op_with(cfg, fail={("item", "list"): "garbage"})
    p.check(); p.resolve_vault()
    with pytest.raises(SecretsError, match="unreadable"):
        p.list_items()


def test_one_unreadable_item_does_not_sink_the_rest(provider):
    provider.check(); provider.resolve_vault()
    got = provider.get_items(provider.list_items())
    fails = [g for g in got if isinstance(g, ReadFailure)]
    assert [f.title for f in fails] == ["TEST-FAIL-01"]
    assert fails[0].reason == "no answer (timed out)"
    assert len(got) - len(fails) == 7


def test_refused_and_garbage_items_are_read_failures(cfg):
    p, _ = op_with(cfg, fail={("item", "get", "itmhost01"): ("refuse", "[ERROR] denied\nmore"),
                              ("item", "get", "itmnas01"): "garbage"})
    p.check(); p.resolve_vault()
    got = {g.id: g for g in p.get_items([ItemRef("itmhost01", "a"), ItemRef("itmnas01", "b")])}
    assert got["itmhost01"].reason == "refused: [ERROR] denied"
    assert got["itmnas01"].reason == "unreadable answer"


def test_field_values_never_in_repr(provider):
    provider.check(); provider.resolve_vault()
    items = provider.get_items([ItemRef("itmhost01", "x")])
    assert "fake-pass-1" not in repr(items)
