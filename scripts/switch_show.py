#!/usr/bin/env -S uv run --with pexpect --quiet --script
"""Read-only Aruba operator 'show' driver. Password via env SWT_PW.
Usage: switch_show.py <host> <user> "<show cmd>" ["<show cmd>" ...]"""
import pexpect, sys, os, re

host, user = sys.argv[1], sys.argv[2]
cmds = sys.argv[3:] or ["show system"]
pw = os.environ.get("SWT_PW", "")
opts = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=12 -o PubkeyAuthentication=no "
        "-o PreferredAuthentications=password,keyboard-interactive")
c = pexpect.spawn(f"ssh {opts} {user}@{host}", encoding="utf-8", timeout=25, dimensions=(200, 400))
if c.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT]) != 0:
    print("ERR: no password prompt", file=sys.stderr); sys.exit(2)
c.sendline(pw)
i = c.expect([r"[Pp]ress any key to continue", r"[Pp]assword:", r"[A-Za-z0-9._\-]+[>#]",
              r"nvalid", pexpect.EOF, pexpect.TIMEOUT])
if i in (1, 3):
    print("ERR: auth failed", file=sys.stderr); sys.exit(3)
if i == 0:
    c.send("\r"); c.expect([r"[A-Za-z0-9._\-]+[>#]", pexpect.TIMEOUT], 15)
prompt = (c.after or "").strip()
if prompt.endswith("#"):
    print(f"WARN: landed at MANAGER level ({prompt}) — expected operator", file=sys.stderr)
pchar = prompt[-1] if prompt else ">"

def run(cmd):
    c.sendline(cmd); buf = ""
    while True:
        j = c.expect([r"-- MORE --[^\n]*", re.escape(prompt), rf"[A-Za-z0-9._\-]+{re.escape(pchar)}",
                      pexpect.TIMEOUT], timeout=25)
        buf += c.before or ""
        if j == 0:
            c.send(" "); continue
        break
    buf = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", buf)      # strip ANSI
    buf = re.sub(r"\x1b[=>]", "", buf).replace("\r", "")
    return "\n".join(l for l in buf.splitlines() if l.strip() and not l.strip().startswith(cmd)).strip()

for cmd in cmds:
    print(f"----- {cmd} -----")
    print(run(cmd))
c.sendline("exit"); c.close()
