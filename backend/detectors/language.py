"""Phrase-level signals from the curated lexicons.

A hit is a checkable fact (this phrase is in the text), not a classification. Terms match as
whole words, so "fine" doesn't fire on "finance"; common inflections count (arrest matches
arrested) and a space matches a hyphen (part time matches part-time).
"""

from __future__ import annotations

import functools
import re

from backend.knowledge import lexicons
from backend.schemas import Signal

_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|\n+")

# Protective advice mentions the same words as the scam it warns about: "HDFC Bank will
# never ask for your UPI PIN". Lexicons marked advisory_sensitive skip such sentences.
_PROTECTIVE = re.compile(
    r"\bnever\b"
    r"|\b(?:do|does|did|will|would|should|must|can|could)\s+not\s+"
    r"(?:share|ask|disclose|reveal|give|send|call|request|install)\b"
    r"|\b(?:don't|doesn't|won't|cannot|can't)\s+"
    r"(?:share|ask|disclose|reveal|give|send|call|request|install)\b"
)


@functools.cache
def _term_pattern(term: str) -> re.Pattern[str]:
    body = r"[\s\-]+".join(re.escape(part) for part in term.lower().split())
    return re.compile(rf"(?<![a-z0-9]){body}(?:s|es|ed|ing)?(?![a-z0-9])")


@functools.cache
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


def _first_match(rx: re.Pattern[str], sentences: list[str]) -> str | None:
    for sentence in sentences:
        m = rx.search(sentence)
        if m:
            return m.group(0)
    return None


def analyze_language(text: str) -> list[Signal]:
    lower = text.lower().replace("\u2019", "'")
    sentences = [s for s in _SENTENCE_BREAK.split(lower) if s.strip()]
    signals: list[Signal] = []
    for lex in lexicons():
        pool = (
            [s for s in sentences if not _PROTECTIVE.search(s)]
            if lex.advisory_sensitive
            else sentences
        )
        hits = [h for t in lex.terms if (h := _first_match(_term_pattern(t), pool))]
        hits += [h for p in lex.patterns if (h := _first_match(_compiled(p), pool))]
        if hits:
            shown = ", ".join(f'"{h}"' for h in hits[:3])
            signals.append(
                Signal(
                    id=lex.id,
                    category="language",
                    label=lex.label,
                    detail=f"Found {shown} in the message.",
                    severity=lex.severity,
                    evidence_text=hits[0],
                )
            )
    return signals
