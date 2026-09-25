"""Checks every finding the model proposes against evidence the model didn't write.

A tell survives only if the thing it points at exists and says what the tell says.

  signal  the detectors produced that id, and the tell doesn't use it to claim outside
          confirmation ("has been reported", "RBI has warned"), which a detector can't give
  quote   the words appear in the message as whole words, at least two of them, and the
          message doesn't only use them in the negative ("do not share it with anyone")
  source  research returned that id, the tell carries a verbatim excerpt from that source,
          and a claim naming a specific link or number cites a source that mentions it

Not checked, because string matching can't: whether the tell's own explanation follows
from the evidence. The UI shows the excerpt or detector detail beside each tell so a
person can judge that part.
"""

from __future__ import annotations

import re

from backend.detectors.entities import entities_mentioned, extract_entities
from backend.knowledge import archetype_ids
from backend.schemas import (
    ArchetypeMatch,
    Entities,
    RejectedClaim,
    RiskLevel,
    Signal,
    Source,
    Tell,
    Verdict,
)

MIN_QUOTE_WORDS = 2
MIN_QUOTE_CHARS = 6
MIN_EXCERPT_WORDS = 4

_EDGE = " .,;:!?\"'()[]"
# Quotes are compared word by word, so a model that drops a comma or a bracket still
# matches, while a changed or invented word does not.
_TOKEN = re.compile(r"[a-z0-9@'\u20b9$\u00a3\u20ac]+")
_NEGATORS = {"not", "never", "no", "don't", "dont", "doesn't", "won't", "cannot", "can't", "nor"}
_CONDITIONALS = {"if", "unless"}
_CLAUSE_BREAK = re.compile(r"[.,;:!?\n()]")

# Wording that asserts someone outside the message confirmed something. A detector signal
# can't back that; only a returned source can.
_OUTSIDE_CONFIRMATION = re.compile(
    r"\b(?:has|have|had) been (?:reported|flagged|blacklisted|confirmed|verified|listed|identified)\b"
    r"|\b(?:is|was|are|were) (?:reported|flagged|blacklisted|listed|confirmed|known) (?:as|by|for|on|in)\b"
    r"|\b(?:reported|flagged|blacklisted|confirmed) by\b"
    r"|\b(?:police|rbi|cert-in|government|regulator|authorities|ftc|fbi|trai|npci|sebi|the bank)"
    r" (?:has|have) (?:confirmed|warned|flagged|reported|listed|verified)\b"
    r"|\bknown (?:scam|fraud|phishing) (?:site|domain|number|link|website|account)\b"
    r"|\bvictims (?:have )?reported\b|\breported online\b|\bonline reports?\b"
)

# "this domain", "the same number": a claim about a specific thing without naming it.
_DEICTIC = re.compile(
    r"\b(?:this|that|the same) (?:exact |specific |particular )?"
    r"(?:domain|link|url|website|site|web address|number|phone number|mobile number"
    r"|upi(?: id| handle)?|account|wallet|address|email(?: address)?|sender id)\b"
)

REASONS = {
    "bad_type": "used an unrecognised evidence type",
    "unknown_signal": "cited a detector signal that was never produced",
    "overreach": (
        "claimed outside confirmation (reported, blacklisted, an agency warning) "
        "but cited only an internal detector signal"
    ),
    "quote_too_short": "quoted too little of the message to count as evidence",
    "quote_not_found": "quoted wording that doesn't appear in the original message",
    "quote_negated": "quoted words the message only uses in the negative, such as 'do not share'",
    "unknown_source": "cited a live source that research didn't return",
    "no_excerpt": "cited a live source without quoting the passage that supports the claim",
    "excerpt_not_in_source": "quoted a passage that isn't in the cited source",
    "source_off_topic": (
        "claimed a specific link or number was reported, but the cited source never mentions it"
    ),
}


def normalize(s: str) -> str:
    s = (
        s.replace("\u2019", "'")
        .replace("\u2018", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
    )
    return re.sub(r"\s+", " ", s).strip().lower()


def tokenize(text: str) -> list[tuple[str, int]]:
    """Lower-cased words, each tagged with the clause it sits in."""
    text = normalize(text)
    out: list[tuple[str, int]] = []
    clause, pos = 0, 0
    for m in _TOKEN.finditer(text):
        if _CLAUSE_BREAK.search(text[pos : m.start()]):
            clause += 1
        word = m.group(0).strip("'")
        if word:
            out.append((word, clause))
        pos = m.end()
    return out


def _negated_at(tokens: list[tuple[str, int]], i: int) -> bool:
    """True if a negator is among the three words before position i in the same clause.
    "if you don't pay" is a condition, not a prohibition, so it doesn't count."""
    clause = tokens[i][1]
    before = [w for w, c in tokens[max(0, i - 4) : i] if c == clause]
    if _CONDITIONALS & set(before):
        return False
    return bool(_NEGATORS & set(before[-3:]))


def _check_signal(t: Tell, signal_ids: set[str]) -> str | None:
    if t.evidence_ref not in signal_ids:
        return "unknown_signal"
    if _OUTSIDE_CONFIRMATION.search(normalize(f"{t.title} {t.explanation}")):
        return "overreach"
    return None


def _check_quote(t: Tell, msg_tokens: list[tuple[str, int]]) -> str | None:
    q = [w for w, _ in tokenize(t.quote)]
    if len(q) < MIN_QUOTE_WORDS or sum(map(len, q)) < MIN_QUOTE_CHARS:
        return "quote_too_short"
    words = [w for w, _ in msg_tokens]
    starts = [i for i in range(len(words) - len(q) + 1) if words[i : i + len(q)] == q]
    if not starts:
        return "quote_not_found"
    if q[0] not in _NEGATORS and all(_negated_at(msg_tokens, i) for i in starts):
        return "quote_negated"
    return None


def _check_source(t: Tell, by_id: dict[str, Source], entities: Entities) -> str | None:
    src = by_id.get(t.evidence_ref)
    if src is None:
        return "unknown_source"
    excerpt = normalize(t.support).strip(_EDGE)
    if len(excerpt.split()) < MIN_EXCERPT_WORDS:
        return "no_excerpt"
    if excerpt not in normalize(f"{src.title} {src.snippet}"):
        return "excerpt_not_in_source"
    claim = f"{t.title} {t.explanation} {t.support}"
    named = entities_mentioned(claim, entities)
    if named and not set(named) <= set(src.mentions):
        return "source_off_topic"
    if not named and _DEICTIC.search(normalize(claim)) and not src.mentions:
        return "source_off_topic"
    return None


def check_tell(
    t: Tell,
    signal_ids: set[str],
    sources: dict[str, Source],
    msg_tokens: list[tuple[str, int]],
    entities: Entities,
) -> str | None:
    """None if the tell stands, otherwise the rejection code."""
    if t.evidence_type == "signal":
        return _check_signal(t, signal_ids)
    if t.evidence_type == "quote":
        return _check_quote(t, msg_tokens)
    if t.evidence_type == "source":
        return _check_source(t, sources, entities)
    return "bad_type"


def verify_tells(
    tells: list[Tell],
    signals: list[Signal],
    sources: list[Source],
    message: str,
    entities: Entities | None = None,
) -> tuple[list[Tell], list[RejectedClaim]]:
    """Split the model's tells into the ones the evidence backs and the ones it doesn't."""
    entities = entities or extract_entities(message)
    signal_ids = {s.id for s in signals}
    by_id = {s.id: s for s in sources}
    msg_tokens = tokenize(message)

    kept: list[Tell] = []
    rejected: list[RejectedClaim] = []
    for t in tells:
        code = check_tell(t, signal_ids, by_id, msg_tokens, entities)
        if code is None:
            kept.append(t)
        else:
            rejected.append(
                RejectedClaim(
                    title=t.title,
                    evidence_type=t.evidence_type,
                    evidence_ref=t.evidence_ref,
                    code=code,
                    reason=REASONS[code],
                )
            )
    return kept, rejected


def verify_archetype(match: ArchetypeMatch) -> ArchetypeMatch:
    """An archetype the catalogue doesn't have becomes "none"."""
    if match.archetype_id not in archetype_ids() and match.archetype_id != "none":
        return ArchetypeMatch(
            archetype_id="none",
            name="Unclassified",
            confidence=match.confidence,
            rationale=match.rationale,
            matched_tells=match.matched_tells,
        )
    return match


def risk_band(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.critical
    if score >= 60:
        return RiskLevel.high
    if score >= 35:
        return RiskLevel.medium
    if score >= 15:
        return RiskLevel.low
    return RiskLevel.info


BAND_ORDER = {
    RiskLevel.info: 0,
    RiskLevel.low: 1,
    RiskLevel.medium: 2,
    RiskLevel.high: 3,
    RiskLevel.critical: 4,
}


def reconcile_verdict(verdict: Verdict, kept_tells: list[Tell], floor: int) -> Verdict:
    """Clamp the score into [floor, 100] and never leave the band below what the score implies."""
    score = max(min(verdict.score, 100), 0, floor)
    risk = verdict.risk_level
    if BAND_ORDER[risk_band(score)] > BAND_ORDER[risk]:
        risk = risk_band(score)
    return Verdict(
        risk_level=risk,
        score=score,
        headline=verdict.headline,
        tells=kept_tells,
        reasoning=verdict.reasoning,
    )
