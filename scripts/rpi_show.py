#!/usr/bin/env -S uv run --with pexpect --quiet --script
"""Read-only SSH command runner for Linux hosts (password auth via env RPI_PW).
Mirrors switch_show.py but for a plain OpenSSH/Linux shell (no Aruba paging/prompts).
Runs a single non-interactive command and prints its stdout.
Usage: rpi_show.py <host> <user> "<command>"
Exit: 0 ok · 2 no password prompt · 3 auth failed."""
import pexpect, sys, os

host = sys.argv[1]
user = sys.argv[2]
cmd = sys.argv[3] if len(sys.argv) > 3 else "true"
pw = os.environ.get("RPI_PW", "")

args = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=password",
        f"{user}@{host}", cmd]
c = pexpect.spawn("ssh", args, encoding="utf-8", timeout=20)

if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) != 0:
    print("ERR: no password prompt", file=sys.stderr); sys.exit(2)
c.sendline(pw)
# after the password: a re-prompt means auth failed; EOF means the command ran and ssh exited
if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) == 0:
    print("ERR: auth failed", file=sys.stderr); sys.exit(3)
print((c.before or "").replace("\r", "").strip())
c.close()
