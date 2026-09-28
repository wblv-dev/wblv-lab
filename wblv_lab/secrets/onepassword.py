"""1Password, via the `op` CLI and a read-only service-account token.

The token goes to `op` in its ENVIRONMENT, never in argv (legacy NOTES.md#creds-never-in-argv).
Every call is bounded by our own timeout, not op's. Each call returns a tri-state:
True (answered yes), False (answered no), None (no answer) — and the callers keep those apart.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import Field, Identity, Item, ItemRef, ReadFailure, SecretsError, Url

TOKEN_ENV = "OP_SERVICE_ACCOUNT_TOKEN"
INSTALL_HINT = "install the 1Password CLI: https://developer.1password.com/docs/cli/get-started/"

# How `op` phrases a transport problem vs a credential problem. Vendor strings, so they live
# here; matched loosely because op's wording is not a contract.
_NETWORK_WORDS = ("network", "timeout", "timed out", "connection", "lookup", "no such host",
                  "dial tcp", "unreachable")
_AUTH_WORDS = ("unauthor", "invalid", "401", "403", "expired", "token", "not authenticated")


class OnePassword:
    name = "1password"

    def __init__(self, cfg, runner=None, which=shutil.which):
        self.cfg = cfg
        self._run_proc = runner or subprocess.run
        self._op = which("op")
        self._token: str | None = None
        self.token_file_age_days: float | None = None
        self.vault_id: str | None = None
        self.vault_name: str | None = None

    # --- plumbing ---------------------------------------------------------------------------

    def _run(self, *args, timeout=None):
        """(True|False|None, stdout, stderr). None = no answer — never conflated with False."""
        if not self._op:
            raise SecretsError("the 1Password CLI `op` is not on PATH", hint=INSTALL_HINT)
        env = {**os.environ, TOKEN_ENV: self._token or ""}
        try:
            r = self._run_proc([self._op, *args], capture_output=True, text=True, env=env,
                               stdin=subprocess.DEVNULL,
                               timeout=timeout or self.cfg.secrets.timeout_s)
        except subprocess.TimeoutExpired:
            return None, "", "timed out"
        except OSError as e:
            raise SecretsError(f"cannot execute {self._op}: {e.strerror or e}") from None
        return r.returncode == 0, r.stdout or "", r.stderr or ""

    def _json(self, text):
        try:
            return json.loads(text or "")
        except ValueError:
            return None

    # --- substrate --------------------------------------------------------------------------

    def _load_token(self):
        p = self.cfg.secrets.token_file
        try:
            st = p.stat()
            raw = p.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise SecretsError(f"token file not found at {p}",
                               hint="put the service-account token there, mode 600") from None
        except OSError as e:
            raise SecretsError(f"token file unreadable at {p} ({type(e).__name__})") from None
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            # see NOTES.md#token-file-mode
            raise SecretsError(f"token file {p} is readable by other users (mode {mode:o})",
                               hint=f"chmod 600 {p}")
        tok = raw.strip()
        if not tok:
            raise SecretsError(f"token file is empty at {p}")
        self._token = tok
        self.token_file_age_days = round((time.time() - st.st_mtime) / 86400, 1)

    def check(self) -> Identity:
        """Prove the substrate ONCE, up front: token readable, account answering, identity
        real. Anything wrong here is one root cause, not a table full of failures."""
        self._load_token()
        age = {"token_file_age_days": self.token_file_age_days}
        ok, out, err = self._run("whoami", "--format", "json",
                                 timeout=max(self.cfg.secrets.timeout_s, 20))
        if ok is None:
            raise SecretsError("1Password unreachable (no answer)", **age)
        if not ok:
            e = err.lower()
            cause = ("1Password unreachable (network)" if any(k in e for k in _NETWORK_WORDS)
                     else "token invalid or expired" if any(k in e for k in _AUTH_WORDS)
                     else "op whoami failed")
            raise SecretsError(cause, detail=err.strip()[:200], **age)
        w = self._json(out) or {}
        if not w.get("user_uuid"):
            raise SecretsError("op whoami answered but named no identity", **age)
        host = (w.get("url") or "?").split("//")[-1].rstrip("/")
        return Identity(account=host, detail=f"service account on {host}")

    def resolve_vault(self) -> str:
        """The vault named in the config, by EXACT name or id — never by substring (the legacy
        tool took the first vault whose name contained a word). Returns the vault's name."""
        ok, out, err = self._run("vault", "list", "--format", "json")
        if ok is None:
            raise SecretsError("1Password did not answer the vault list")
        if not ok:
            raise SecretsError("1Password refused the vault list", detail=err.strip()[:200])
        vaults = self._json(out)
        if not isinstance(vaults, list):
            raise SecretsError("1Password answered the vault list with something unreadable")
        want = self.cfg.secrets.vault
        hits = [v for v in vaults if want in (v.get("id"), v.get("name"))]
        if not hits:
            seen = sorted(v.get("name", "?") for v in vaults)
            raise SecretsError(f"the service account cannot see a vault named {want!r}",
                               visible=", ".join(seen) or "(no vaults at all — mis-scoped token?)")
        if len(hits) > 1:
            raise SecretsError(f"{len(hits)} vaults are named {want!r}",
                               hint="set [secrets].vault to the id of the one you mean",
                               ids=", ".join(v.get("id", "?") for v in hits))
        self.vault_id, self.vault_name = hits[0]["id"], hits[0].get("name", want)
        return self.vault_name

    # --- membership -------------------------------------------------------------------------

    def list_items(self) -> list[ItemRef]:
        ok, out, err = self._run("item", "list", "--vault", self.vault_id, "--format", "json")
        if ok is None:
            raise SecretsError(f"1Password did not answer the item list for {self.vault_name!r}")
        if not ok:
            raise SecretsError(f"1Password refused the item list for {self.vault_name!r}",
                               detail=err.strip()[:200])
        items = self._json(out)
        if not isinstance(items, list):
            raise SecretsError("1Password answered the item list with something unreadable")
        if not items:
            # empty is a failed read or an unregistered lab — either way not "zero members"
            # (legacy NOTES.md#empty-ipam-dies, same reasoning one layer up)
            raise SecretsError(f"vault {self.vault_name!r} returned no items",
                               hint="a 1Password read hiccup, or nothing is registered yet")
        return [ItemRef(id=i["id"], title=i.get("title") or "",
                        tags=tuple(i.get("tags") or ())) for i in items if i.get("id")]

    def get_items(self, refs: list[ItemRef]) -> list[Item | ReadFailure]:
        def one(ref: ItemRef):
            ok, out, err = self._run("item", "get", ref.id, "--vault", self.vault_id,
                                     "--format", "json")
            if ok is None:
                return ReadFailure(ref.id, ref.title, "no answer (timed out)")
            if not ok:
                return ReadFailure(ref.id, ref.title,
                                   "refused: " + (err.strip().splitlines() or ["?"])[0][:120])
            j = self._json(out)
            if not isinstance(j, dict):
                return ReadFailure(ref.id, ref.title, "unreadable answer")
            return _to_item(j, ref)

        with ThreadPoolExecutor(max_workers=self.cfg.probing.item_read_concurrency) as ex:
            return list(ex.map(one, refs))


def _to_item(j: dict, ref: ItemRef) -> Item:
    def text(v):
        return v if isinstance(v, str) else ("" if v is None else str(v))

    fields = tuple(Field(label=text(f.get("label")), value=text(f.get("value")),
                         section=text((f.get("section") or {}).get("label")),
                         concealed=f.get("type") == "CONCEALED")
                   for f in (j.get("fields") or []))
    urls = tuple(Url(label=text(u.get("label")), href=text(u.get("href")))
                 for u in (j.get("urls") or []))
    return Item(id=j.get("id") or ref.id, title=text(j.get("title")) or ref.title,
                tags=tuple(j.get("tags") or ref.tags), fields=fields, urls=urls)
