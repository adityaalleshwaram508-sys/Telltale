"""Phrase-level signals from the curated lexicons.

Deliberately a dumb substring matcher, not a classifier: a hit is a checkable
fact ("this exact phrase is in the text"). The model interprets; this only
reports what's literally there.
"""
from __future__ import annotations

from backend.knowledge import lexicons
from backend.schemas import Signal


def analyze_language(text: str) -> list[Signal]:
    lower = text.lower()
    signals: list[Signal] = []
    for lex in lexicons():
        hits = [t for t in lex.terms if t in lower]
        if hits:
            # Keep the evidence short but show a couple of the actual phrases.
            shown = ", ".join(f'"{h}"' for h in hits[:3])
            signals.append(Signal(
                id=lex.id, category="language",
                label=lex.label,
                detail=f"Found {shown} in the message.",
                severity=lex.severity,
                evidence_text=hits[0],
            ))
    return signals
