"""Hostname helpers shared by the entity extractor, the URL detector and the research step."""

from __future__ import annotations

import functools
import re

import tldextract

# Use the Public Suffix List snapshot bundled with tldextract; never fetch at runtime.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# RBI reserves *.bank.in for regulated Indian banks (migration deadline 31 Oct 2025).
# The bundled PSL snapshot predates it, so the suffix is handled here explicitly.
BANK_IN = "bank.in"


def is_ip(host: str) -> bool:
    return bool(_IP_RE.match(host))


@functools.lru_cache(maxsize=4096)
def split_host(host: str) -> tuple[str, str, str]:
    """(subdomain, registrable name, public suffix): netbanking.hdfc.bank.in -> (netbanking, hdfc, bank.in)."""
    host = host.lower().rstrip(".")
    if host.endswith("." + BANK_IN):
        labels = host[: -len(BANK_IN) - 1].split(".")
        return ".".join(labels[:-1]), labels[-1], BANK_IN
    parts = _EXTRACT(host)
    return parts.subdomain, parts.domain, parts.suffix


def registrable_domain(host: str) -> str:
    """paypal.com for login.paypal.com, sbi.co.in for www.sbi.co.in (not co.in)."""
    if is_ip(host):
        return host
    _, name, suffix = split_host(host)
    return f"{name}.{suffix}" if name and suffix else host.lower()


def has_public_suffix(host: str) -> bool:
    return is_ip(host) or bool(split_host(host)[2])


def is_bank_in(host: str) -> bool:
    return split_host(host)[2] == BANK_IN


def host_tokens(host: str) -> list[str]:
    """Labels left of the public suffix, split on dots, hyphens and underscores."""
    sub, name, _ = split_host(host)
    return [t for t in re.split(r"[.\-_]", f"{sub}.{name}") if t]
