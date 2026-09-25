"""Runs every deterministic detector over a message and collects the signals.

Order doesn't matter to correctness, but we extract entities first because the
URL / payment / contact detectors all reason about them.
"""

from __future__ import annotations

from backend.knowledge import lexicons
from backend.schemas import Entities, Signal

from .contacts import analyze_contacts
from .entities import extract_entities
from .injection import analyze_injection
from .language import analyze_language
from .payments import PAYMENT_SIGNAL_IDS, analyze_payments
from .urls import URL_SIGNAL_IDS, analyze_urls


def run_detectors(text: str) -> tuple[Entities, list[Signal]]:
    entities = extract_entities(text)
    signals: list[Signal] = []
    signals += analyze_urls(text, entities)
    signals += analyze_payments(text, entities)
    signals += analyze_language(text)
    signals += analyze_contacts(text, entities)
    signals += analyze_injection(text)
    return entities, signals


def signal_score(signals: list[Signal]) -> int:
    """A transparent 0-100 floor from the deterministic signals alone.

    Not the verdict: the model can raise the risk after reasoning and research, but it
    can't go below this. The weights (6, 16, 30 for severity 1-3) are hand-set so that one
    severe signal plus one moderate one reaches the medium band; they are not fitted to
    data. The hard negatives and eval/external.py are how changes to them get checked.
    """
    if not signals:
        return 0
    weight = {0: 0, 1: 6, 2: 16, 3: 30}
    # Diminishing returns so ten weak signals don't outrank one severe one.
    total, seen_ids = 0, set()
    for s in sorted(signals, key=lambda x: -x.severity):
        if s.id in seen_ids:
            continue
        seen_ids.add(s.id)
        total += weight.get(s.severity, 0)
    return min(total, 100)


def signal_vocabulary() -> list[str]:
    """Every signal id a detector can emit. The evidence benchmark draws plausible
    fabricated citations from it; a test keeps it complete."""
    ids = set(URL_SIGNAL_IDS) | set(PAYMENT_SIGNAL_IDS) | {lex.id for lex in lexicons()}
    ids |= {"contact.freemail_impersonation", "language.prompt_injection"}
    return sorted(ids)
