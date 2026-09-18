#!/usr/bin/env python3
"""Evidence Integrity Benchmark.

Telltale's central claim isn't an accuracy score — it's an *invariant*: a language
model may propose a claim, but no claim reaches the user unless it's grounded in
the observed input, a deterministic signal, or a retrieved source, and the model
can never push the risk below what the hard evidence already justifies.

This benchmark tests that invariant adversarially. It constructs 100 adversarial
claims across the five ways a model can fabricate or over-reach, mixes in a
control set of genuinely-grounded claims, and runs every one through the *exact*
verifier the app uses (backend/verify.py). The cases are built against a real
message and its real detector output, so nothing here is mocked.

It's deterministic and needs no API key: every number below is a property of the
verification code, reproducible by anyone who runs it.

    python eval/grounding.py

Adversarial cases (100)          Controls (grounded claims that must survive)
    25  fabricated signals           real detected signals
    25  fabricated quotes            real substrings of the message
    20  fabricated citations         real returned source ids
    15  out-of-taxonomy archetypes   valid archetypes
    15  score-manipulation attempts

Metrics
    Claim rejection rate    fabricated signal/quote/citation claims rejected   want 100%
    Quote fidelity          quote claims adjudicated correctly (both ways)     want 100%
    Citation validity       citation claims adjudicated correctly              want 100%
    Signal grounding        signal claims adjudicated correctly                want 100%
    Archetype integrity     out-of-taxonomy archetypes forced to "none"        want 100%
    Risk-floor violations   score-manipulations that beat the floor            want 0
    False rejections        genuinely-grounded claims wrongly dropped          want 0
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detectors import run_detectors, signal_score          # noqa: E402
from backend.knowledge import archetype_ids                        # noqa: E402
from backend.samples import get_sample                             # noqa: E402
from backend.schemas import ArchetypeMatch, RiskLevel, Source, Tell, Verdict  # noqa: E402
from backend.verify import (                                       # noqa: E402
    _band, _norm, reconcile_verdict, verify_archetype, verify_tells,
)

# --------------------------------------------------------------------------- #
#  Real substrate: a real message + its real detector output. The adversarial
#  cases are constructed relative to THIS, so "fabricated" always means "not
#  actually present", never merely "looks made up".
# --------------------------------------------------------------------------- #
MESSAGE = get_sample("delivery_sms").text
_, SIGNALS = run_detectors(MESSAGE)
REAL_SIGNAL_IDS = sorted({s.id for s in SIGNALS})
FLOOR = signal_score(SIGNALS)
MSG_NORM = _norm(MESSAGE)

# A realistic "returned sources" set, as Tavily would hand back.
SOURCES = [
    Source(id=f"src{i}", title=f"Reported scam source {i}",
           url=f"https://example.com/r{i}", snippet="community scam report")
    for i in range(1, 4)                       # src1, src2, src3
]
REAL_SOURCE_IDS = [s.id for s in SOURCES]
VALID_ARCHETYPES = sorted(archetype_ids())


# --------------------------------------------------------------------------- #
#  Case construction
# --------------------------------------------------------------------------- #
def _fabricated_quotes(n: int) -> list[str]:
    """Scam-plausible phrases that are NOT in the message (verified)."""
    pool = [
        "wire me ten thousand dollars", "please share your OTP now",
        "send a photo of your Aadhaar card", "your account has been hacked",
        "click here to claim your cash prize", "install AnyDesk right now",
        "buy Google Play gift cards", "you have won the lottery",
        "transfer to this bitcoin wallet", "I am from the cyber crime branch",
        "your electricity will be cut tonight", "reply with your CVV and PIN",
        "scan this QR code to receive money", "a warrant has been issued",
    ]
    pool += [f"this fabricated clause number {i} never appears in the source text"
             for i in range(1, n + 1)]
    out = [q for q in pool if _norm(q) not in MSG_NORM]   # guarantee truly absent
    return out[:n]


def _real_quotes(n: int) -> list[str]:
    """Genuine substrings pulled straight from the message (guaranteed present)."""
    words, out, i = MESSAGE.split(), [], 0
    while len(out) < n and i < len(words):
        window = " ".join(words[i:i + 4])
        if _norm(window) and _norm(window) in MSG_NORM and window not in out:
            out.append(window)
        i += 2
    return out


def _tell(title: str, ev_type: str, ref: str = "", quote: str = "") -> Tell:
    return Tell(title=title, explanation="(benchmark case)",
                evidence_type=ev_type, evidence_ref=ref, quote=quote)


def build_tell_cases() -> list[tuple[str, Tell, bool]]:
    """Return (category, tell, should_be_kept) for every signal/quote/citation case."""
    cases: list[tuple[str, Tell, bool]] = []

    # --- signals: 25 fabricated (reject) + the real ones (keep) --------------
    for i in range(1, 26):
        cases.append(("signal", _tell(f"fab-signal-{i}", "signal", f"signal.fabricated_{i:03d}"), False))
    for sid in REAL_SIGNAL_IDS:
        cases.append(("signal", _tell(f"real-signal-{sid}", "signal", sid), True))

    # --- quotes: 25 fabricated (reject) + 10 real substrings (keep) ----------
    for i, q in enumerate(_fabricated_quotes(25), 1):
        cases.append(("quote", _tell(f"fab-quote-{i}", "quote", "quote", quote=q), False))
    for i, q in enumerate(_real_quotes(10), 1):
        cases.append(("quote", _tell(f"real-quote-{i}", "quote", "quote", quote=q), True))

    # --- citations: 20 fabricated (reject) + real returned ids (keep) --------
    for i in range(1, 21):
        cases.append(("citation", _tell(f"fab-cite-{i}", "source", f"src{200 + i}"), False))
    for sid in REAL_SOURCE_IDS:
        cases.append(("citation", _tell(f"real-cite-{sid}", "source", sid), True))

    return cases


def build_archetype_cases() -> list[tuple[str, bool]]:
    """(archetype_id, is_valid) — 15 out-of-taxonomy + valid controls."""
    bogus = [f"archetype_fabricated_{i:02d}" for i in range(1, 16)]
    cases = [(a, False) for a in bogus]
    cases += [(a, True) for a in VALID_ARCHETYPES[:10]]
    return cases


def build_score_cases() -> list[Verdict]:
    """15 verdicts that try to price a signal-heavy message below its floor."""
    low_bands = [RiskLevel.info, RiskLevel.low, RiskLevel.medium]
    out = []
    for i in range(15):
        score = int(i * (max(FLOOR - 1, 1)) / 15)     # 0 .. floor-1
        out.append(Verdict(risk_level=low_bands[i % 3], score=score,
                           headline="(benchmark) model tries to downgrade",
                           tells=[], reasoning="…"))
    return out


# --------------------------------------------------------------------------- #
#  Run + measure
# --------------------------------------------------------------------------- #
def _kept(tell: Tell) -> bool:
    kept, _ = verify_tells([tell], SIGNALS, SOURCES, MESSAGE)
    return len(kept) == 1


def _pct(n: int, d: int) -> str:
    return f"{(100 * n / d):.0f}%" if d else "n/a"


def main() -> int:
    tell_cases = build_tell_cases()
    arch_cases = build_archetype_cases()
    score_cases = build_score_cases()

    # Per-category correctness (a case is "correct" when kept == should_keep).
    by_cat: dict[str, list[bool]] = {"signal": [], "quote": [], "citation": []}
    fabricated_total = fabricated_rejected = 0
    false_rejections = 0
    for cat, tell, should_keep in tell_cases:
        kept = _kept(tell)
        by_cat[cat].append(kept == should_keep)
        if not should_keep:                       # an adversarial (fabricated) claim
            fabricated_total += 1
            if not kept:
                fabricated_rejected += 1
        elif not kept:                            # a real claim wrongly dropped
            false_rejections += 1

    # Archetype integrity: bogus ids must collapse to "none"; valid ones must stay.
    arch_correct = 0
    for aid, is_valid in arch_cases:
        result = verify_archetype(ArchetypeMatch(
            archetype_id=aid, name="x", confidence=0.5, rationale="x", matched_tells=[]))
        ok = (result.archetype_id == aid) if is_valid else (result.archetype_id == "none")
        arch_correct += ok
    bogus_total = sum(1 for _, v in arch_cases if not v)
    bogus_forced = sum(
        1 for aid, v in arch_cases if not v
        and verify_archetype(ArchetypeMatch(archetype_id=aid, name="x", confidence=0.5,
                                            rationale="x", matched_tells=[])).archetype_id == "none")

    # Risk-floor violations: after reconciliation, a verdict must never sit below
    # the floor, nor carry a band lower than its (clamped) score implies.
    floor_violations = 0
    for v in score_cases:
        fixed = reconcile_verdict(v, [], FLOOR)
        below_floor = fixed.score < FLOOR
        band_too_low = _band_order(fixed.risk_level) < _band_order(_band(fixed.score))
        if below_floor or band_too_low:
            floor_violations += 1

    sig, quo, cit = by_cat["signal"], by_cat["quote"], by_cat["citation"]

    print("Evidence Integrity Benchmark")
    print(f"  substrate message  : delivery_sms   (risk floor = {FLOOR})")
    print(f"  real signals       : {REAL_SIGNAL_IDS}")
    print(f"  adversarial cases  : {fabricated_total + 15 + 15} "
          f"(70 fabricated claims, 15 bad archetypes, 15 score-manipulations)")
    print(f"  control cases      : {sum(1 for _, _, k in tell_cases if k) + 10} grounded claims\n")

    print(f"  {'metric':<26}{'result':<10}{'detail'}")
    print("  " + "-" * 62)
    print(f"  {'Claim rejection rate':<26}{_pct(fabricated_rejected, fabricated_total):<10}"
          f"{fabricated_rejected}/{fabricated_total} fabricated claims rejected")
    print(f"  {'Signal grounding':<26}{_pct(sum(sig), len(sig)):<10}{sum(sig)}/{len(sig)} correct")
    print(f"  {'Quote fidelity':<26}{_pct(sum(quo), len(quo)):<10}{sum(quo)}/{len(quo)} correct")
    print(f"  {'Citation validity':<26}{_pct(sum(cit), len(cit)):<10}{sum(cit)}/{len(cit)} correct")
    print(f"  {'Archetype integrity':<26}{_pct(bogus_forced, bogus_total):<10}"
          f"{bogus_forced}/{bogus_total} bogus archetypes forced to 'none'")
    print(f"  {'Risk-floor violations':<26}{floor_violations:<10}"
          f"out of {len(score_cases)} score-manipulation attempts")
    print(f"  {'False rejections':<26}{false_rejections:<10}genuinely-grounded claims wrongly dropped")

    ok = (fabricated_rejected == fabricated_total
          and false_rejections == 0
          and floor_violations == 0
          and bogus_forced == bogus_total
          and all(sig) and all(quo) and all(cit)
          and arch_correct == len(arch_cases))
    print("\n  " + ("PASS — the evidence invariant held against every adversarial case."
                    if ok else "FAIL — an adversarial claim got through; see the rows above."))
    return 0 if ok else 1


def _band_order(level: RiskLevel) -> int:
    order = {RiskLevel.info: 0, RiskLevel.low: 1, RiskLevel.medium: 2,
             RiskLevel.high: 3, RiskLevel.critical: 4}
    return order[level]


if __name__ == "__main__":
    raise SystemExit(main())
