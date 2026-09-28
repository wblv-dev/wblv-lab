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


def test_valid_config_does_not_pretend_to_have_results(env, capsys):
    p = default_path(env)
    p.parent.mkdir(parents=True)
    p.write_text('[secrets]\nvault = "Lab Directory"\n', encoding="utf-8")
    code, out, err = run([], env, capsys)
    assert code == 1 and out == "" and "cannot read the lab yet" in err


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
