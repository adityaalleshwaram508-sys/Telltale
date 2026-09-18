"""Post-hoc verification of what the model produced.

This is the layer that makes Telltale trustworthy rather than merely fluent.
Nothing the model says about evidence is taken on faith:

  * A tell citing a signal must cite a signal id we actually computed.
  * A tell citing a source must cite a source id Tavily actually returned.
  * A tell quoting the message must quote text that is really in the message.

Anything that fails is dropped. We also reconcile the score so a message full of
severe signals can never come back rated "safe" because the model got talked
around.
"""
from __future__ import annotations

import re

from backend.knowledge import archetype_ids
from backend.schemas import (
    ArchetypeMatch, RejectedClaim, RiskLevel, Signal, Source, Tell, Verdict,
)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _why_rejected(t: Tell) -> str:
    """A short, human explanation of why a tell didn't survive verification."""
    ev = t.evidence_type
    if ev == "signal":
        return f"cited a detector signal ('{t.evidence_ref}') that was never produced"
    if ev == "source":
        return f"cited a live source ('{t.evidence_ref}') that research didn't return"
    if ev == "quote":
        return "quoted wording that doesn't appear in the original message"
    return f"used an unrecognised evidence type ('{ev}')"


def verify_tells(
    tells: list[Tell], signals: list[Signal], sources: list[Source], message: str
) -> tuple[list[Tell], list[RejectedClaim]]:
    """Split the model's tells into the ones we can back and the ones we can't.

    A surviving tell must point at evidence that independently checks out — a
    signal the detectors really produced, a source research really returned, or a
    quote that really appears in the message. Everything else comes back as a
    RejectedClaim with a plain reason. We return the rejects rather than silently
    swallowing them: "the model proposed this, the evidence couldn't back it" is
    the honest part of the story, and worth showing.
    """
    signal_ids = {s.id for s in signals}
    source_ids = {s.id for s in sources}
    msg = _norm(message)

    kept: list[Tell] = []
    rejected: list[RejectedClaim] = []
    for t in tells:
        ev = t.evidence_type
        if ev == "signal" and t.evidence_ref in signal_ids:
            kept.append(t)
        elif ev == "source" and t.evidence_ref in source_ids:
            kept.append(t)
        elif ev == "quote" and t.quote and _norm(t.quote) in msg:
            kept.append(t)
        else:
            rejected.append(RejectedClaim(
                title=t.title, evidence_type=ev,
                evidence_ref=t.evidence_ref, reason=_why_rejected(t),
            ))
    return kept, rejected


def verify_archetype(match: ArchetypeMatch) -> ArchetypeMatch:
    if match.archetype_id not in archetype_ids() and match.archetype_id != "none":
        # Model named an archetype we don't have — don't let it through.
        return ArchetypeMatch(
            archetype_id="none", name="Unclassified",
            confidence=match.confidence, rationale=match.rationale,
            matched_tells=match.matched_tells,
        )
    return match


def _band(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.critical
    if score >= 60:
        return RiskLevel.high
    if score >= 35:
        return RiskLevel.medium
    if score >= 15:
        return RiskLevel.low
    return RiskLevel.info


_ORDER = {RiskLevel.info: 0, RiskLevel.low: 1, RiskLevel.medium: 2,
          RiskLevel.high: 3, RiskLevel.critical: 4}


def reconcile_verdict(verdict: Verdict, kept_tells: list[Tell], floor: int) -> Verdict:
    """Clamp the score to the deterministic floor and keep risk_level consistent."""
    score = max(min(verdict.score, 100), 0)
    score = max(score, floor)

    # Never let risk_level sit below what the (clamped) score implies.
    implied = _band(score)
    risk = verdict.risk_level
    if _ORDER[implied] > _ORDER[risk]:
        risk = implied

    return Verdict(
        risk_level=risk,
        score=score,
        headline=verdict.headline,
        tells=kept_tells,
        reasoning=verdict.reasoning,
    )
