"""Loads the curated knowledge base and exposes it as typed, cached lookups.

The YAML under data/ is the source of truth. Everything here is read once at
import time. It's small, static and reviewed by hand, so there's no reason to
reload it per request.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DATA_DIR = Path(__file__).parent / "data"


def _load_yaml(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# --------------------------------------------------------------------------- #
#  Archetypes
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Archetype:
    id: str
    name: str
    aliases: list[str]
    how_it_works: str
    signature_tells: list[str]
    channels: list[str]
    payment_rails: list[str]
    regions: object  # "global" or a list of ISO-2 codes
    refs: list[dict] = field(default_factory=list)


@functools.lru_cache
def archetypes() -> dict[str, Archetype]:
    raw = _load_yaml("archetypes.yaml")["archetypes"]
    out: dict[str, Archetype] = {}
    for a in raw:
        out[a["id"]] = Archetype(
            id=a["id"],
            name=a["name"],
            aliases=[str(x) for x in a.get("aliases", [])],
            how_it_works=" ".join(a["how_it_works"].split()),
            signature_tells=a.get("signature_tells", []),
            channels=a.get("channels", []),
            payment_rails=a.get("payment_rails", []),
            regions=a.get("regions", "global"),
            refs=a.get("refs", []),
        )
    return out


def archetype(archetype_id: str) -> Archetype | None:
    return archetypes().get(archetype_id)


def archetype_ids() -> list[str]:
    return list(archetypes().keys())


def archetype_menu() -> str:
    """Compact catalogue the classifier prompt shows the model."""
    lines = []
    for a in archetypes().values():
        alias = f" (aka {', '.join(a.aliases[:3])})" if a.aliases else ""
        lines.append(f"- {a.id}: {a.name}{alias}. {a.how_it_works}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Reporting channels
# --------------------------------------------------------------------------- #
@functools.lru_cache
def _reporting_raw() -> dict:
    return _load_yaml("reporting.yaml")


def reporting_channels(region: str | None) -> list[dict]:
    """Country-specific channels first (if we know the region), then the
    universal ones. Region is an ISO-2 code like 'IN'."""
    data = _reporting_raw()
    channels: list[dict] = []
    if region:
        channels.extend(data.get("regions", {}).get(region.upper(), []))
    channels.extend(data.get("global", []))
    # Tag each with a region label for display.
    out = []
    for c in channels:
        c = dict(c)
        c.setdefault("region", region.upper() if region else "Global")
        # note text in YAML is folded; collapse whitespace for clean display
        if c.get("note"):
            c["note"] = " ".join(c["note"].split())
        out.append(c)
    return out


# --------------------------------------------------------------------------- #
#  Brands + link heuristics
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Brand:
    name: str
    domains: list[str]
    keywords: list[str]
    indian_bank: bool = False  # any *.bank.in link counts as the brand's own


@functools.lru_cache
def brands() -> list[Brand]:
    raw = _load_yaml("brands.yaml")
    return [
        Brand(
            name=b["name"],
            domains=[d.lower() for d in b.get("domains", [])],
            keywords=[k.lower() for k in b.get("keywords", [])],
            indian_bank=bool(b.get("indian_bank", False)),
        )
        for b in raw["brands"]
    ]


def brand_by_name(name: str) -> Brand | None:
    return next((b for b in brands() if b.name == name), None)


@functools.lru_cache
def suspicious_tlds() -> tuple[str, ...]:
    return tuple(_load_yaml("brands.yaml").get("suspicious_tlds", []))


@functools.lru_cache
def url_shorteners() -> tuple[str, ...]:
    return tuple(_load_yaml("brands.yaml").get("url_shorteners", []))


@functools.lru_cache
def genuine_domains() -> set[str]:
    out: set[str] = set()
    for b in brands():
        out.update(d.lower() for d in b.domains)
    return out


# --------------------------------------------------------------------------- #
#  Lexicons
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Lexicon:
    id: str
    label: str
    severity: int
    terms: list[str]
    patterns: list[str] = field(default_factory=list)
    advisory_sensitive: bool = False


@functools.lru_cache
def lexicons() -> list[Lexicon]:
    raw = _load_yaml("lexicons.yaml")["lexicons"]
    return [
        Lexicon(
            id=lex["id"],
            label=lex["label"],
            severity=int(lex["severity"]),
            terms=[str(x) for x in lex.get("terms", [])],
            patterns=[str(x) for x in lex.get("patterns", [])],
            advisory_sensitive=bool(lex.get("advisory_sensitive", False)),
        )
        for lex in raw
    ]
