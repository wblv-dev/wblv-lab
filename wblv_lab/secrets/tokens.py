"""Where a provider's token is held — see NOTES.md#token-never-at-rest.

KernelKeyring keeps it in the Linux kernel's per-user keyring (@u): memory only, never on
disk, expiring on its own, and invisible to every other user including the one an AI
assistant runs as. FileToken reads a mode-600 file, for systems without a kernel keyring or
people who prefer it.

Every store answers get() with (token, age_days|None) or raises SecretsError with the fix.
"""
from __future__ import annotations

import shutil
import stat
import subprocess
import time

from . import SecretsError


class FileToken:
    kind = "file"

    def __init__(self, path):
        self.path = path

    def describe(self) -> str:
        return f"file {self.path}"

    def get(self) -> tuple[str, float | None]:
        p = self.path
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
            # legacy-style refusal before use — see NOTES.md#token-file-mode
            raise SecretsError(f"token file {p} is readable by other users (mode {mode:o})",
                               hint=f"chmod 600 {p}")
        tok = raw.strip()
        if not tok:
            raise SecretsError(f"token file is empty at {p}")
        return tok, round((time.time() - st.st_mtime) / 86400, 1)

    def put(self, token):
        raise SecretsError('token_source is "file" — edit the file yourself (mode 600)')

    def clear(self):
        raise SecretsError('token_source is "file" — delete the file yourself')


class KernelKeyring:
    """keyctl, with the token always on STDIN — never argv, never a temp file."""
    kind = "keyring"

    def __init__(self, name: str, ttl_s: int, runner=None, which=shutil.which):
        self.name, self.ttl_s = name, ttl_s
        self._run = runner or subprocess.run
        self._bin = which("keyctl")

    def describe(self) -> str:
        return f"kernel keyring (@u) '{self.name}'"

    def _k(self, *args, input=None):
        if not self._bin:
            raise SecretsError("`keyctl` is not installed, so the kernel keyring is unavailable",
                               hint='install keyutils, or set [secrets].token_source = "file"')
        try:
            return self._run([self._bin, *args], capture_output=True, text=True, input=input,
                             timeout=10)
        except subprocess.TimeoutExpired:
            raise SecretsError("keyctl did not answer") from None

    def _find(self) -> str | None:
        r = self._k("search", "@u", "user", self.name)
        kid = (r.stdout or "").strip()
        return kid if r.returncode == 0 and kid else None

    def get(self) -> tuple[str, float | None]:
        kid = self._find()
        if not kid:
            # absent and expired look the same from here, and have the same fix
            raise SecretsError("the token is locked (not in the kernel keyring, or it expired)",
                               hint="run `wblv-lab --unlock`")
        r = self._k("pipe", kid)
        if r.returncode != 0 or not r.stdout:
            raise SecretsError("the keyring entry exists but could not be read",
                               hint="run `wblv-lab --unlock` again")
        return r.stdout.strip(), None

    def put(self, token: str) -> None:
        self.clear()
        r = self._k("padd", "user", self.name, "@u", input=token)
        kid = (r.stdout or "").strip()
        if r.returncode != 0 or not kid:
            raise SecretsError("could not store the token in the kernel keyring",
                               detail=(r.stderr or "").strip()[:200])
        t = self._k("timeout", kid, str(self.ttl_s))
        if t.returncode != 0:
            # a token that would never expire is not what was asked for — take it back out
            self._k("unlink", kid, "@u")
            raise SecretsError("could not set the token's expiry, so it was not kept",
                               detail=(t.stderr or "").strip()[:200])

    def clear(self) -> bool:
        kid = self._find()
        if not kid:
            return False
        self._k("unlink", kid, "@u")
        return True


def store_for(cfg, runner=None, which=shutil.which):
    s = cfg.secrets
    if s.token_source == "file":
        return FileToken(s.token_file)
    return KernelKeyring(s.keyring_name, s.unlock_hours * 3600, runner=runner, which=which)


def undecorate(v: str) -> str:
    """Strip what a paste adds and a credential never contains: surrounding whitespace and ONE
    matching pair of wrapping quotes. Nothing else (legacy NOTES.md#undecorate-history)."""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v
