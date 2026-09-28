"""Secrets providers: where membership and credentials come from.

A provider answers four questions and nothing else — who am I (the substrate check), which
vault, which items are in it, and what fields each item carries. What those fields MEAN is
decided in members.py, so a new provider (Bitwarden, HashiCorp Vault, ...) is one module that
fills in these same shapes. See NOTES.md#provider-shape-not-meaning.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class SecretsError(Exception):
    """The substrate itself failed — one root cause, reported once, never as N member faults
    (legacy: "one substrate fault must not read as N cascading host failures")."""

    def __init__(self, cause: str, **detail):
        self.cause, self.detail = cause, detail
        super().__init__(cause)


@dataclass(frozen=True)
class Field:
    label: str
    value: str = field(repr=False)        # never in a repr, so never one accidental print away
    section: str = ""
    concealed: bool = False


@dataclass(frozen=True)
class Url:
    label: str
    href: str


@dataclass(frozen=True)
class ItemRef:
    """What a listing says about an item, before its fields are read."""
    id: str
    title: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Item:
    id: str
    title: str
    tags: tuple[str, ...] = ()
    fields: tuple[Field, ...] = ()
    urls: tuple[Url, ...] = ()


@dataclass(frozen=True)
class ReadFailure:
    """An item that is IN the vault but whose fields could not be read. Kept as its own thing
    so a failed read can never look like an item with nothing in it —
    see NOTES.md#item-read-failure-is-not-empty."""
    id: str
    title: str
    reason: str


@dataclass(frozen=True)
class Identity:
    account: str        # where the credential authenticates, e.g. my.1password.com
    detail: str         # one line for humans


def open_provider(cfg, **kw):
    """The provider named in the config. Only implemented providers are accepted by the config
    loader, so reaching the error below is a programming fault, not a user one."""
    if cfg.secrets.provider == "1password":
        from .onepassword import OnePassword
        return OnePassword(cfg, **kw)
    raise SecretsError(f"no provider implementation for {cfg.secrets.provider!r}")
