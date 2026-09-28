"""Offline 1Password: a fake `op` that answers from made-up items shaped like `op --format json`.

All data here is fictional (example.test names, fake-* secrets). Real captures from a TEST
vault, redacted, can be added alongside and must pass the same tests.
"""
import json
import subprocess

import pytest

from wblv_lab import config as C
from wblv_lab.secrets.onepassword import OnePassword

TOKEN = "ops_FAKE_TOKEN_for_tests_only"
VAULT = {"id": "vlt0000000000000000000001", "name": "Lab Directory TEST"}
WHOAMI = {"url": "https://example.1password.com", "user_uuid": "FAKEUSERUUID00000000000001",
          "user_type": "SERVICE_ACCOUNT"}
SECRET_VALUES = ("fake-pass-1", "fake-pass-backup", "fake-client-secret", "fake-pass-nas",
                 "fake-pass-old", TOKEN)


def _f(label, value, section="WBLV", type_="STRING"):
    d = {"id": label.lower().replace(" ", "_"), "type": type_, "label": label, "value": value}
    if section:
        d["section"] = {"id": section.lower(), "label": section}
    return d


def _builtin(username="", password=""):
    # every login item carries these, and on the reference estate they are EMPTY
    # (legacy NOTES.md#op-value-empty-builtin-fields)
    return [{"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username",
             "value": username},
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password",
             "value": password}]


def _item(id_, title, tags, fields, urls=()):
    return {"id": id_, "title": title, "category": "LOGIN", "tags": list(tags),
            "vault": VAULT, "sections": [{"id": "wblv", "label": "WBLV"}],
            "fields": _builtin() + fields, "urls": list(urls)}


ITEMS = {
    "itmhost01": _item("itmhost01", "TEST-HOST-01 / READONLY", ["physical"], [
        _f("DNS Name", "host-01"), _f("Website", "ssh://host-01.example.test:22"),
        _f("Platform", "linux"), _f("Role", "compute"),
        _f("Username", "lab-ro"), _f("Password", "fake-pass-1", type_="CONCEALED")]),
    "itmhost01b": _item("itmhost01b", "TEST-HOST-01 / BACKUP", ["physical"], [
        _f("DNS Name", "host-01"), _f("Website", "ssh://host-01.example.test:22"),
        _f("Platform", "linux"), _f("Password", "fake-pass-backup", type_="CONCEALED")]),
    "itmsvc01": _item("itmsvc01", "TEST-SVC-01 / READONLY", ["service"], [
        _f("DNS Name", "svc-01"), _f("Website", "https://login.example.test/admin"),
        _f("Platform", "tailscale"), _f("Client ID", "fake-client-id"),
        _f("Client Secret", "fake-client-secret", type_="CONCEALED")],
        urls=[{"label": "Tenant ID", "href": "00000000-0000-0000-0000-000000000000"}]),
    "itmnas01": _item("itmnas01", "TEST-NAS-01 / READONLY", ["physical"], [
        _f("DNS Name", "nas-01"), _f("Website", "https://nas-01.example.test:5001"),
        _f("Platform", "synology"), _f("Username", "lab-ro"),
        _f("Password", "fake-pass-nas", type_="CONCEALED"), _f("Expiry Date", "23/07/2028")]),
    "itmbad01": _item("itmbad01", "TEST-BAD-01 / READONLY", ["physical"], [
        _f("DNS Name", "bad-01"), _f("Website", "a1b2c3d4-not-a-url"),
        _f("Platform", "linux")]),
    "itmold01": _item("itmold01", "TEST-OLD-01 / LEGACY", ["physical"], [
        _f("DNS Name", "old-01"), _f("Website", "ssh://old-01.example.test"),
        _f("Platform", "linux"), _f("Password", "fake-pass-old", type_="CONCEALED")]),
    "itmmis01": _item("itmmis01", "TEST-MIS-01 / READONLY", ["physical"], [
        _f("DNS Name", "mis-01"), _f("Website", "https://other-01.example.test"),
        _f("Platform", "linux")]),
    "itmfail01": _item("itmfail01", "TEST-FAIL-01", ["physical"], []),
}


class FakeOp:
    """Stands in for subprocess.run(['op', ...]). `fail` maps a call key to a failure mode:
    'timeout', 'garbage', or ('refuse', stderr)."""

    def __init__(self, items=None, vaults=None, whoami=None, fail=None):
        self.items = ITEMS if items is None else items
        self.vaults = [VAULT] if vaults is None else vaults
        self.whoami = WHOAMI if whoami is None else whoami
        self.fail = {("item", "get", "itmfail01"): "timeout"} if fail is None else fail
        self.calls, self.envs = [], []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        self.envs.append(dict(kw.get("env") or {}))
        a = argv[1:]
        key = ("whoami",) if a[0] == "whoami" else \
            ("item", "get", a[2]) if a[:2] == ["item", "get"] else tuple(a[:2])
        mode = self.fail.get(key)
        if mode == "timeout":
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        if mode == "garbage":
            return subprocess.CompletedProcess(argv, 0, "<html>captive portal</html>", "")
        if isinstance(mode, tuple) and mode[0] == "refuse":
            return subprocess.CompletedProcess(argv, 1, "", mode[1])
        if key == ("whoami",):
            out = self.whoami
        elif key == ("vault", "list"):
            out = self.vaults
        elif key == ("item", "list"):
            out = [{"id": i["id"], "title": i["title"], "tags": i["tags"]}
                   for i in self.items.values()]
        elif key[:2] == ("item", "get"):
            if key[2] not in self.items:
                return subprocess.CompletedProcess(argv, 1, "", f'"{key[2]}" isn\'t an item')
            out = self.items[key[2]]
        else:
            raise AssertionError(f"unexpected op call: {argv}")
        return subprocess.CompletedProcess(argv, 0, json.dumps(out), "")


@pytest.fixture
def token_file(tmp_path):
    p = tmp_path / "op-token"
    p.write_text(TOKEN + "\n", encoding="utf-8")
    p.chmod(0o600)
    return p


@pytest.fixture
def cfg(tmp_path, token_file):
    return C.parse({"secrets": {"vault": VAULT["name"], "token_file": str(token_file)},
                    "membership": {"identity_suffixes": ["/READONLY", "/LEGACY"]}},
                   base_dir=tmp_path)


@pytest.fixture
def fake_op():
    return FakeOp()


@pytest.fixture
def provider(cfg, fake_op):
    return OnePassword(cfg, runner=fake_op, which=lambda _: "/usr/bin/op")
