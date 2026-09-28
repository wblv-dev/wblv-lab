#!/usr/bin/env bash
# wblv-lab installer — puts the `wblv-lab` command on this machine. That is all it does.
#
#   curl -fsSL https://raw.githubusercontent.com/wblv-dev/wblv-lab/main/install.sh | bash
#   # or, to read it first:
#   curl -fsSLO https://raw.githubusercontent.com/wblv-dev/wblv-lab/main/install.sh
#   less install.sh && bash install.sh
#
# Installs for the CURRENT USER (no root) into ~/.local/share/wblv-lab and links
# ~/.local/bin/wblv-lab. Uses sudo only to install missing system packages, and only after
# asking. Never touches secrets: you add the token yourself with `wblv-lab --unlock`.
#
# Options:
#   --from SRC     install from a local checkout or a pip URL instead of GitHub
#   --ref REF      git tag/branch/commit to install (default: main)
#   --system       install for all users into /opt/wblv-lab + /usr/local/bin (run as root)
#   --no-deps      never install system packages; just report what is missing
#   --yes          answer yes to prompts (package installs)
#   --dry-run      print every change without making it
#   --uninstall    remove the installed program (never your config or a stored token)
set -euo pipefail

REPO="https://github.com/wblv-dev/wblv-lab"
REF="main"
SRC=""
SYSTEM=0 NO_DEPS=0 YES=0 DRY=0 UNINSTALL=0
MIN_PY="3.10"
# 1Password's published signing key (their docs, and the debsig policy directory name)
OP_KEY_FPR="3FEF9748469ADBE15DA7CA80AC2D62742012EA22"

say()  { printf '%s\n' "$*"; }
step() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mwblv-lab install:\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }
CLEAN=()
trap '[ ${#CLEAN[@]} -eq 0 ] || rm -rf "${CLEAN[@]}"' EXIT
# apt is quiet unless it fails: its output goes to a log that is shown only on failure
apt_q() {
  if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; return 0; fi
  local log; log="$(mktemp)"; CLEAN+=("$log")
  if ! "$@" >"$log" 2>&1; then
    tail -n 25 "$log" >&2
    die "package step failed: $*"
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --from)      [ $# -ge 2 ] || die "--from needs a path or URL"; SRC="$2"; shift ;;
    --ref)       [ $# -ge 2 ] || die "--ref needs a value"; REF="$2"; shift ;;
    --system)    SYSTEM=1 ;;
    --no-deps)   NO_DEPS=1 ;;
    --yes|-y)    YES=1 ;;
    --dry-run)   DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)   cat <<'H'
wblv-lab installer — puts the `wblv-lab` command on this machine.

  bash install.sh [--from SRC] [--ref REF] [--system] [--no-deps] [--yes] [--dry-run]
  bash install.sh --uninstall [--system]

  --from SRC   install from a local checkout or pip URL instead of GitHub
  --ref REF    git tag/branch/commit to install (default: main)
  --system     all users: /opt/wblv-lab + /usr/local/bin (run as root)
  --no-deps    never install system packages; report what is missing
  --yes        answer yes to package-install prompts
  --dry-run    print every change without making it
  --uninstall  remove the program (never your config or a stored token)
H
                 exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

if [ "$SYSTEM" = 1 ]; then
  [ "$(id -u)" = 0 ] || die "--system installs for every user and must run as root"
  PREFIX="/opt/wblv-lab"; BIN_DIR="/usr/local/bin"
else
  if [ "$(id -u)" = 0 ]; then
    # Running as root without --system would install into ROOT's home, invisible to you.
    die "running as root, so this would install into root's home, not yours.
  For yourself (recommended; it asks for sudo only if a package is missing):
    curl -fsSL https://raw.githubusercontent.com/wblv-dev/wblv-lab/main/install.sh | bash
  For every user on this machine:
    curl -fsSL https://raw.githubusercontent.com/wblv-dev/wblv-lab/main/install.sh | sudo bash -s -- --system"
  fi
  PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/wblv-lab"; BIN_DIR="$HOME/.local/bin"
fi
VENV="$PREFIX/venv"
LINK="$BIN_DIR/wblv-lab"

# --- uninstall ------------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  step "removing $VENV and $LINK"
  run rm -rf "$VENV"
  [ -L "$LINK" ] && run rm -f "$LINK"
  say "done. Kept on purpose: your config (~/.config/wblv-lab) and any unlocked token."
  say "      Drop the token now with \`wblv-lab --lock\` before uninstalling, or it expires by itself."
  exit 0
fi

# --- what is this machine -------------------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
  Linux|Darwin) ;;
  *) die "unsupported OS: $OS (Linux and macOS only)" ;;
esac
APT=0; command -v apt-get >/dev/null 2>&1 && APT=1

py_ok() {  # is python3 new enough, with a working venv module?
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -c "import sys; sys.exit(0 if sys.version_info >= tuple(map(int, '$MIN_PY'.split('.'))) else 1)" || return 1
  python3 -c "import venv, ensurepip" 2>/dev/null || return 2
}

missing_pkgs=()
set +e; py_ok; pyrc=$?; set -e
case $pyrc in
  0) ;;
  1) if command -v python3 >/dev/null 2>&1; then
       die "python3 is $(python3 -V 2>&1 | cut -d' ' -f2); wblv-lab needs $MIN_PY or newer"
     fi
     missing_pkgs+=(python3 python3-venv) ;;
  2) missing_pkgs+=(python3-venv) ;;
esac
if [ -z "$SRC" ] || [[ "$SRC" == git+* ]]; then
  command -v git >/dev/null 2>&1 || missing_pkgs+=(git)
fi
# kernel keyring tools: the default token store on Linux
if [ "$OS" = Linux ] && ! command -v keyctl >/dev/null 2>&1; then missing_pkgs+=(keyutils); fi

ask() {  # ask "question" -> 0 yes / 1 no ; --yes answers yes; no TTY answers no
  [ "$YES" = 1 ] && return 0
  [ -r /dev/tty ] || return 1
  printf '%s [y/N] ' "$1" > /dev/tty; read -r a < /dev/tty || return 1
  [[ "$a" =~ ^[Yy] ]]
}

SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
sudo_ready() {  # ask for the password once, in plain sight, before apt output goes to a log
  [ -z "$SUDO" ] || [ "$DRY" = 1 ] || $SUDO -v || die "sudo is needed to install packages"
}

if [ ${#missing_pkgs[@]} -gt 0 ]; then
  if [ "$NO_DEPS" = 1 ] || [ "$APT" = 0 ]; then
    die "missing: ${missing_pkgs[*]} — install them, then re-run$([ "$APT" = 0 ] && [ "$OS" = Darwin ] && echo " (e.g. brew install python git)")"
  fi
  if ask "Install missing packages with apt: ${missing_pkgs[*]}?"; then
    step "installing ${missing_pkgs[*]}"
    sudo_ready
    apt_q $SUDO apt-get update
    apt_q $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing_pkgs[@]}"
    say "    done"
  else
    die "missing: ${missing_pkgs[*]} — not installed (re-run with --yes, or install them yourself)"
  fi
fi

# --- 1Password CLI (needed at run time, not to install) -------------------------------------
if ! command -v op >/dev/null 2>&1; then
  if [ "$APT" = 1 ] && [ "$NO_DEPS" = 0 ] && [ "$(uname -m)" = x86_64 ] \
     && ask "The 1Password CLI (op) is not installed. Add 1Password's official apt repo and install it?"; then
    step "installing the 1Password CLI from 1Password's signed apt repository"
    sudo_ready
    command -v gpg >/dev/null 2>&1 \
      || apt_q $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gnupg
    if [ "$DRY" = 0 ]; then
      tmp="$(mktemp)"; CLEAN+=("$tmp")
      curl -fsSL https://downloads.1password.com/linux/keys/1password.asc -o "$tmp"
      fpr="$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')"
      [ "$fpr" = "$OP_KEY_FPR" ] || die "1Password signing key fingerprint mismatch ($fpr) — not installing"
      $SUDO gpg --dearmor --yes --output /usr/share/keyrings/1password-archive-keyring.gpg "$tmp"
      echo "deb [arch=amd64 signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/amd64 stable main" \
        | $SUDO tee /etc/apt/sources.list.d/1password.list >/dev/null
      apt_q $SUDO apt-get update
      apt_q $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y 1password-cli
      say "    done: $(op --version 2>/dev/null || echo 'op installed')"
    else
      say "  [dry-run] fetch 1password.asc, verify fingerprint $OP_KEY_FPR, add repo, apt-get install 1password-cli"
    fi
  else
    warn "the 1Password CLI (op) is not installed — wblv-lab needs it to read the vault:"
    warn "  https://developer.1password.com/docs/cli/get-started/"
  fi
fi

# --- the program ----------------------------------------------------------------------------
PKG="${SRC:-git+$REPO@$REF}"
step "installing wblv-lab from $PKG"
# A local checkout is built from a private copy: the build writes into its source tree, and a
# checkout the installer can read but not write (or one shared between users) must still work.
if [ -n "$SRC" ] && [ -d "$SRC" ]; then
  [ -f "$SRC/pyproject.toml" ] || die "$SRC is a directory but not a wblv-lab checkout (no pyproject.toml)"
  if [ "$DRY" = 0 ]; then
    build="$(mktemp -d)"; CLEAN+=("$build")
    tar -C "$SRC" --exclude=.git --exclude=.venv --exclude='*.egg-info' --exclude=build \
        -cf - . | tar -C "$build" -xf -
    PKG="$build"
  else
    say "  [dry-run] copy $SRC to a temporary build directory"
  fi
fi
run mkdir -p "$PREFIX" "$BIN_DIR"
if [ ! -x "$VENV/bin/python" ]; then
  run python3 -m venv "$VENV"
fi
run "$VENV/bin/python" -m pip install -q --upgrade pip
run "$VENV/bin/python" -m pip install -q --upgrade --force-reinstall "$PKG"
run ln -sf "$VENV/bin/wblv-lab" "$LINK"

if [ "$DRY" = 1 ]; then
  say "dry run — nothing was changed."
  exit 0
fi
"$LINK" -h >/dev/null || die "installed, but $LINK does not run"
say "installed: $LINK"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on this shell's PATH yet. On Ubuntu a new login adds it"
     warn "automatically; otherwise add it to PATH, or run $LINK directly." ;;
esac

# --- first-run config (per-user installs only) ----------------------------------------------
if [ "$SYSTEM" = 1 ]; then
  say
  say "next, as each user who will run it:   wblv-lab --init"
else
  cfg="${WBLV_LAB_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/wblv-lab/config.toml}"
  if [ -f "$cfg" ]; then
    say "config already present: $cfg (left untouched)"
  else
    say; "$LINK" --init
  fi
fi
