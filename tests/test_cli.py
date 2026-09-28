import json
import stat

import pytest

from wblv_lab import cli
from wblv_lab import config as C


@pytest.fixture
def env(tmp_path):
    """An isolated environment: XDG points into tmp, no WBLV_LAB_CONFIG."""
    return {"XDG_CONFIG_HOME": str(tmp_path / "xdg")}


def default_path(env):
    from pathlib import Path
    return Path(env["XDG_CONFIG_HOME"]) / "wblv-lab" / "config.toml"


def run(argv, env, capsys):
    code = cli.main(argv, env)
    out = capsys.readouterr()
    return code, out.out, out.err


# --- not configured: dashes, not zeros ------------------------------------------------------

def test_unconfigured_screen(env, capsys):
    code, out, err = run([], env, capsys)
    assert code == cli.EXIT_UNCONFIGURED == 2
    assert "Not configured. Nothing was probed." in out
    assert str(default_path(env)) in out
    assert "wblv-lab --init" in out
    for label in ("Hosts:", "Reachable:", "Authenticated:"):
        line = next(l for l in out.splitlines() if l.startswith(label))
        assert line.split(":", 1)[1].strip() == "-", line     # a dash, never 0
    assert " 0" not in out.split("Hosts:")[1].split("Not configured")[0]


def test_unconfigured_json_is_an_error_not_an_empty_directory(env, capsys):
    code, out, _ = run(["--json"], env, capsys)
    assert code == 2
    j = json.loads(out)
    assert j["error"] == "not configured"
    assert "members" not in j
    assert j["config_path"] == str(default_path(env))
    assert j["config_from"] == "default location"


def test_named_config_missing_is_a_fault_not_a_first_run(env, tmp_path, capsys):
    code, _, err = run(["--config", str(tmp_path / "typo.toml")], env, capsys)
    assert code == cli.EXIT_FAULT
    assert "from --config" in err and "Not configured" not in err


def test_env_config_missing_is_a_fault(tmp_path, capsys):
    env = {"WBLV_LAB_CONFIG": str(tmp_path / "nope.toml"), "XDG_CONFIG_HOME": str(tmp_path)}
    code, _, err = run([], env, capsys)
    assert code == 1 and "$WBLV_LAB_CONFIG" in err


# --- --init ---------------------------------------------------------------------------------

def test_init_writes_example_then_refuses_to_overwrite(env, capsys):
    code, out, _ = run(["--init"], env, capsys)
    p = default_path(env)
    assert code == 0 and p.is_file() and str(p) in out
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    shipped = (__import__("importlib").resources.files("wblv_lab")
               .joinpath("config.example.toml").read_text(encoding="utf-8"))
    assert p.read_text(encoding="utf-8") == shipped

    p.write_text("# my edits\n", encoding="utf-8")
    code, _, err = run(["--init"], env, capsys)
    assert code == 1 and "refusing to overwrite" in err
    assert p.read_text(encoding="utf-8") == "# my edits\n"     # untouched


def test_init_honours_config_path(env, tmp_path, capsys):
    target = tmp_path / "elsewhere" / "lab.toml"
    code, out, _ = run(["--init", "--config", str(target), "--json"], env, capsys)
    assert code == 0 and json.loads(out)["created"] == str(target) and target.is_file()


def test_init_output_is_not_yet_a_valid_config(env, capsys):
    """The starter file must force a real choice of vault — a placeholder that loads would let
    a fresh install probe a vault nobody chose."""
    run(["--init"], env, capsys)
    code, _, err = run([], env, capsys)
    assert code == 1
    assert "secrets.vault: required key is missing" in err


def test_init_rejects_view_flags(env, capsys):
    code, _, err = run(["--init", "--brief"], env, capsys)
    assert code == 1 and "--init takes only" in err


# --- configured -----------------------------------------------------------------------------

def test_broken_config_lists_every_problem(env, capsys):
    p = default_path(env)
    p.parent.mkdir(parents=True)
    p.write_text('[secrets]\nvault = ""\n[probing]\ntimeout = 5\n', encoding="utf-8")
    code, _, err = run([], env, capsys)
    assert code == 1
    assert "secrets.vault: is empty" in err and "did you mean 'probing.timeout_s'" in err
    assert "Traceback" not in err


def test_broken_config_json(env, capsys):
    p = default_path(env)
    p.parent.mkdir(parents=True)
    p.write_text("[secrets]\n", encoding="utf-8")
    code, out, _ = run(["--json"], env, capsys)
    j = json.loads(out)
    assert code == 1 and j["problems"] == ["secrets.vault: required key is missing"]


def test_valid_config_without_token_is_one_root_cause(env, capsys):
    p = default_path(env)
    p.parent.mkdir(parents=True)
    p.write_text('[secrets]\nvault = "Lab Directory"\ntoken_source = "file"\n', encoding="utf-8")
    code, out, err = run([], env, capsys)
    assert code == 1 and out == ""
    assert "secrets substrate check failed: token file not found" in err


# --- --unlock / --lock (kernel keyring, offline) --------------------------------------------

class Stdin:
    """A piped stdin: not a TTY, one line."""
    def __init__(self, text):
        self._t = text

    def isatty(self):
        return False

    def readline(self):
        return self._t


def _keyring_setup(env, whoami_fail=None):
    from conftest import VAULT, FakeKeyctl, FakeOp
    from wblv_lab.secrets.onepassword import OnePassword
    from wblv_lab.secrets.tokens import KernelKeyring
    p = default_path(env)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f'[secrets]\nvault = "{VAULT["name"]}"\nunlock_hours = 6\n'
                 '[membership]\nidentity_suffixes = ["/READONLY", "/LEGACY"]\n', encoding="utf-8")
    fk = FakeKeyctl()
    store = KernelKeyring("wblv-lab:1password", 6 * 3600, runner=fk,
                          which=lambda _: "/usr/bin/keyctl")
    fail = {("whoami",): whoami_fail} if whoami_fail else None
    factory = lambda cfg: OnePassword(cfg, runner=FakeOp(fail=fail), token_store=store,
                                      which=lambda _: "/usr/bin/op")
    return fk, store, factory


def test_unlock_verifies_then_holds_in_keyring(env, capsys):
    fk, store, factory = _keyring_setup(env)
    code = cli.main(["--unlock"], env, provider_factory=factory, stdin=Stdin('"ops_REAL_ish"\n'),
                    token_store=store)
    out = capsys.readouterr().out
    assert code == 0 and "unlocked for 6h" in out and "never written to disk" in out
    assert [v for _, v in fk.keys.values()] == ["ops_REAL_ish"]       # quotes undecorated
    assert "ops_REAL_ish" not in out


@pytest.mark.parametrize("given", ["hello", "ops_has space", "", "   \n"])
def test_unlock_refuses_wrong_shape_without_storing(env, capsys, given):
    fk, store, factory = _keyring_setup(env)
    code = cli.main(["--unlock"], env, provider_factory=factory, stdin=Stdin(given),
                    token_store=store)
    err = capsys.readouterr().err
    assert code == 1 and "nothing stored" in err and fk.keys == {}


def test_unlock_rejected_token_is_not_stored(env, capsys):
    fk, store, factory = _keyring_setup(env, whoami_fail=("refuse", "401 Unauthorized"))
    code = cli.main(["--unlock"], env, provider_factory=factory, stdin=Stdin("ops_bad\n"),
                    token_store=store)
    err = capsys.readouterr().err
    assert code == 1 and "not stored: token invalid or expired" in err and fk.keys == {}


def test_run_after_unlock_then_lock(env, capsys):
    fk, store, factory = _keyring_setup(env)
    cli.main(["--unlock"], env, provider_factory=factory, stdin=Stdin("ops_ok\n"), token_store=store)
    capsys.readouterr()
    assert cli.main([], env, provider_factory=factory) == 1        # vault view (incomplete)
    assert "Vault view only." in capsys.readouterr().out
    assert cli.main(["--lock"], env, token_store=store) == 0
    assert "locked — token removed" in capsys.readouterr().out and fk.keys == {}
    assert cli.main(["--lock"], env, token_store=store) == 0
    assert "already locked" in capsys.readouterr().out
    assert cli.main([], env, provider_factory=factory) == 1
    assert "the token is locked" in capsys.readouterr().err


def test_unlock_with_file_source_is_refused(env, token_file, capsys):
    p = default_path(env)
    p.parent.mkdir(parents=True)
    p.write_text(f'[secrets]\nvault = "v"\ntoken_source = "file"\ntoken_file = "{token_file}"\n',
                 encoding="utf-8")
    code, _, err = run(["--unlock"], env, capsys)
    assert code == 1 and 'applies to token_source = "keyring"' in err


def test_unlock_unconfigured(env, capsys):
    code, _, err = run(["--unlock"], env, capsys)
    assert code == 2 and "wblv-lab --init" in err


@pytest.mark.parametrize("argv", [["--unlock", "--brief"], ["--unlock", "--lock"],
                                  ["--init", "--unlock"]])
def test_actions_are_exclusive(env, capsys, argv):
    code, _, err = run(argv, env, capsys)
    assert code == 1 and ("takes only" in err or "choose one of" in err)


# --- vault view (1Password layer, offline) --------------------------------------------------

def _configured(env, token_file):
    from conftest import VAULT
    p = default_path(env)
    p.parent.mkdir(parents=True)
    p.write_text(f'[secrets]\nvault = "{VAULT["name"]}"\ntoken_source = "file"\n'
                 f'token_file = "{token_file}"\n'
                 '[membership]\nidentity_suffixes = ["/READONLY", "/LEGACY"]\n',
                 encoding="utf-8")


def _fake_factory(cfg):
    from conftest import FakeOp
    from wblv_lab.secrets.onepassword import OnePassword
    return OnePassword(cfg, runner=FakeOp(), which=lambda _: "/usr/bin/op")


def test_vault_view_lists_members_and_says_nothing_was_probed(env, token_file, capsys):
    from conftest import SECRET_VALUES
    _configured(env, token_file)
    code = cli.main([], env, provider_factory=_fake_factory)
    out = capsys.readouterr().out
    assert code == 1
    for name in ("host-01", "svc-01", "nas-01", "bad-01", "mis-01", "old-01"):
        assert name in out
    assert "skipped (not the read-only identity): TEST-HOST-01 / BACKUP" in out
    assert "unreadable: TEST-FAIL-01" in out
    assert "Vault view only." in out and "nothing was probed" in out
    bad = next(l for l in out.splitlines() if l.startswith("bad-01"))
    assert bad.rstrip().endswith("url")
    for s in SECRET_VALUES:
        assert s not in out, s


def test_vault_view_json_is_an_error_with_no_secrets(env, token_file, capsys):
    from conftest import SECRET_VALUES
    _configured(env, token_file)
    code = cli.main(["--json"], env, provider_factory=_fake_factory)
    out = capsys.readouterr().out
    j = json.loads(out)
    assert code == 1 and j["error"].startswith("incomplete")
    assert "members" not in j                     # never mistakable for a directory
    faults = {m["name"]: m["faults"] for m in j["vault_members"]}
    assert faults["bad-01"] == ["url"] and faults["mis-01"] == ["name"]
    for s in SECRET_VALUES:
        assert s not in out, s


# --- flags ----------------------------------------------------------------------------------

def test_help_answers_without_config(env, capsys):
    code, out, _ = run(["-h"], env, capsys)
    assert code == 0 and "wblv-lab --init" in out and "Exit codes" in out


def test_help_mentions_no_retired_or_assistant_features(env, capsys):
    _, out, _ = run(["--help"], env, capsys)
    for word in ("jira", "task", "claude"):
        assert word not in out.lower(), word


@pytest.mark.parametrize("argv,expect", [
    (["--breif"], "did you mean --brief?"),
    (["--tasks"], "unknown option: --tasks"),               # retired flag stays dead
    (["nas-01"], "unexpected argument: nas-01"),            # bare word is never a filter
    (["--config"], "--config needs a path"),
    (["--config="], "--config needs a path"),
])
def test_bad_arguments_die_loud(env, capsys, argv, expect):
    code, _, err = run(argv, env, capsys)
    assert code == 1 and expect in err


def test_howto_takes_one_positional(env, capsys):
    assert cli.parse_args(["--howto", "nas-01"])["only"] == "nas-01"
    with pytest.raises(cli.Usage):
        cli.parse_args(["--howto", "a", "b"])


def test_config_equals_form(tmp_path):
    assert cli.parse_args([f"--config={tmp_path}/x.toml"])["config"] == f"{tmp_path}/x.toml"
