#!/usr/bin/env python3
"""Evidence Integrity Benchmark.

Feeds findings a model might produce through the verifier the app uses (backend/verify.py)
and counts how many it misjudges. No API key and no network, so every number is a property
of the code and reproduces exactly.

Substrates are every labelled sample, adversarial sample and hard negative in
backend/samples.py. For each message the benchmark computes the real detector signals and
builds two research fixtures in the shape Tavily returns, one naming a link or number from
the message and one that only discusses the scam pattern. The fixtures are synthetic: this
measures how the verifier treats sources, not what live search returns.

Case families
  pointer   the cited evidence doesn't exist: a real signal id that didn't fire on this
            message, a source id research didn't return, a near-miss quote with one word
            changed, a sentence lifted from a different message
  support   the pointer is valid but doesn't back the claim: a quote the message only uses
            in the negative, a one-word quote, a source excerpt that isn't in the source,
            a named link or number backed by a source that never mentions it, "has been
            reported" backed only by a detector signal
  taxonomy  an archetype id that sounds right but isn't in the catalogue
  floor     a verdict scored below the detector floor
  control   grounded findings that must survive: every real signal with its own wording,
            real quotes, excerpts from the matching source

Not covered: whether a tell's explanation paraphrases its evidence faithfully. That needs
semantic entailment, which string checks can't provide.

    python eval/grounding.py [--json path]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detectors import run_detectors, signal_score, signal_vocabulary  # noqa: E402
from backend.detectors.entities import entities_mentioned  # noqa: E402
from backend.knowledge import archetype_ids  # noqa: E402
from backend.samples import ADVERSARIAL, HARD_NEGATIVES, SAMPLES, Sample  # noqa: E402
from backend.schemas import ArchetypeMatch, RiskLevel, Source, Tell, Verdict  # noqa: E402
from backend.verify import (  # noqa: E402
    BAND_ORDER,
    normalize,
    reconcile_verdict,
    risk_band,
    verify_archetype,
    verify_tells,
)

SEED = 20260925  # fixed, so the case set is identical on every run
NEGATORS = {"not", "never", "no", "don't", "dont", "won't", "cannot", "can't", "if", "unless"}
SWAPS = ["today", "account", "refund", "urgently", "bonus", "office", "parcel", "wallet"]
BOGUS_ARCHETYPES = [
    "courier_fraud",
    "phishing",
    "otp_scam",
    "romance",
    "digital_arrest_scam",
    "kyc_update",
    "lottery",
    "investment_fraud",
    "job_scam",
    "tech_support_scam",
    "upi_fraud",
    "sextortion",
    "loan_fraud",
    "impersonation",
    "crypto_scam",
]
OUTSIDE_CLAIMS = [
    ("Reported by other victims", "Other victims have reported this message."),
    ("Police have warned about this", "The police have warned about this exact message."),
    ("Blacklisted sender", "This sender has been blacklisted by the telecom regulator."),
    ("Known scam domain", "The link is a known scam domain."),
    ("RBI has flagged this", "RBI has flagged this link as fraudulent."),
]


@dataclass
class Case:
    family: str
    kind: str
    substrate: str
    should_keep: bool
    tell: Tell | None = None


@dataclass
class Substrate:
    sample: Sample
    text: str
    entities: object
    signals: list
    floor: int
    sources: list[Source] = field(default_factory=list)


def _words(text: str) -> list[str]:
    return [w.strip(" .,;:!?\"'()[]") for w in text.split() if w.strip(" .,;:!?\"'()[]")]


def _absent(quote: str, text: str) -> bool:
    q = normalize(quote)
    return re.search(rf"(?<![a-z0-9]){re.escape(q)}(?![a-z0-9])", normalize(text)) is None


def _windows(text: str, n: int) -> list[str]:
    w = _words(text)
    return [" ".join(w[i : i + n]) for i in range(0, max(len(w) - n + 1, 0))]


def _clean_windows(text: str, n: int) -> list[str]:
    """Windows from sentences with no negator or conditional, so they can't be read as negated."""
    out = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        if NEGATORS & {w.lower() for w in _words(sentence)}:
            continue
        out += _windows(sentence, n)
    return out


def _fixtures(text: str, entities) -> list[Source]:
    targets = [*entities.domains, *entities.phones, *entities.upi_ids]
    sources = []
    if targets:
        e = targets[0]
        snippet = f"Several people reported {e} in scam complaints this month, often after a text."
        sources.append(
            Source(
                id="src1",
                title="Community scam reports",
                url="https://example.org/reports",
                snippet=snippet,
                about=e,
                mentions=entities_mentioned(snippet, entities),
            )
        )
    snippet = "Messages like this push people to act quickly and pay before checking anything."
    sources.append(
        Source(
            id=f"src{len(sources) + 1}",
            title="How pressure scams work",
            url="https://example.org/pattern",
            snippet=snippet,
            about="pattern",
            mentions=entities_mentioned(snippet, entities),
        )
    )
    return sources


def _t(
    kind: str,
    ref: str,
    *,
    title="Finding",
    explanation="Seen in the message.",
    quote="",
    support="",
):
    return Tell(
        title=title,
        explanation=explanation,
        evidence_type=kind,
        evidence_ref=ref,
        quote=quote,
        support=support,
    )


def build(substrates: list[Substrate], rng: random.Random) -> list[Case]:
    vocab = signal_vocabulary()
    cases: list[Case] = []
    for sub in substrates:
        sid, text = sub.sample.id, sub.text
        fired = {s.id for s in sub.signals}
        on_topic = next((s for s in sub.sources if s.about != "pattern"), None)
        pattern = next(s for s in sub.sources if s.about == "pattern")

        # ---- pointer --------------------------------------------------------------------
        for ref in rng.sample([v for v in vocab if v not in fired], 2):
            cases.append(
                Case("pointer", "signal id that didn't fire", sid, False, _t("signal", ref))
            )
        missing = f"src{len(sub.sources) + 1}"
        cases.append(
            Case(
                "pointer",
                "source id not returned",
                sid,
                False,
                _t("source", missing, support=" ".join(_words(pattern.snippet)[:6])),
            )
        )
        windows = [w for w in _windows(text, 4) if len(w) > 12]
        if windows:
            words = rng.choice(windows).split()
            words[1] = next(s for s in SWAPS if s not in normalize(text))
            near = " ".join(words)
            if _absent(near, text):
                cases.append(
                    Case("pointer", "near-miss quote", sid, False, _t("quote", "quote", quote=near))
                )
        other = rng.choice([s for s in substrates if s is not sub])
        foreign = [w for w in _windows(other.text, 5) if _absent(w, text)]
        if foreign:
            cases.append(
                Case(
                    "pointer",
                    "quote from another message",
                    sid,
                    False,
                    _t("quote", "quote", quote=rng.choice(foreign)),
                )
            )

        # ---- support --------------------------------------------------------------------
        low = normalize(text)
        for m in re.finditer(
            r"\b(?:do not|don't|never|not|no)\s+((?:[a-z0-9']+\s+){1,3}[a-z0-9']+)", low
        ):
            q = m.group(1)
            if {"if", "unless"} & set(low[: m.start()].split()[-2:]):
                continue  # "if not done by you" is a condition, and verify.py treats it as one
            if (
                len(re.findall(rf"(?<![a-z0-9]){re.escape(q)}(?![a-z0-9])", low)) == 1
                and len(q) >= 6
            ):
                cases.append(
                    Case(
                        "support",
                        "quote used only in the negative",
                        sid,
                        False,
                        _t("quote", "quote", quote=q),
                    )
                )
                break
        long_words = [w for w in _words(text) if len(w) >= 4 and w.isalpha()]
        if long_words:
            cases.append(
                Case(
                    "support",
                    "one-word quote",
                    sid,
                    False,
                    _t("quote", "quote", quote=rng.choice(long_words)),
                )
            )
        cases.append(
            Case(
                "support",
                "excerpt not in the cited source",
                sid,
                False,
                _t(
                    "source",
                    pattern.id,
                    support="this site has stolen money from hundreds of people",
                ),
            )
        )
        excerpt = " ".join(_words(pattern.snippet)[3:9])
        if on_topic:
            cases.append(
                Case(
                    "support",
                    "named link or number, off-topic source",
                    sid,
                    False,
                    _t(
                        "source",
                        pattern.id,
                        title="Reported before",
                        explanation=f"{on_topic.about} has been reported by other people.",
                        support=excerpt,
                    ),
                )
            )
        if sub.signals:
            title, expl = rng.choice(OUTSIDE_CLAIMS)
            cases.append(
                Case(
                    "support",
                    "outside confirmation on a detector signal",
                    sid,
                    False,
                    _t("signal", rng.choice(sub.signals).id, title=title, explanation=expl),
                )
            )

        # ---- controls -------------------------------------------------------------------
        for s in sub.signals:
            cases.append(
                Case(
                    "control",
                    "real signal",
                    sid,
                    True,
                    _t("signal", s.id, title=s.label, explanation=s.detail),
                )
            )
        clean = [w for w in _clean_windows(text, 3) if len(w) >= 8]
        for q in rng.sample(clean, min(2, len(clean))):
            cases.append(Case("control", "real quote", sid, True, _t("quote", "quote", quote=q)))
        if on_topic:
            cases.append(
                Case(
                    "control",
                    "excerpt from the matching source",
                    sid,
                    True,
                    _t(
                        "source",
                        on_topic.id,
                        title="Reported before",
                        explanation=f"{on_topic.about} appears in recent scam complaints.",
                        support=" ".join(_words(on_topic.snippet)[:6]),
                    ),
                )
            )
        cases.append(
            Case(
                "control",
                "pattern-level excerpt",
                sid,
                True,
                _t(
                    "source",
                    pattern.id,
                    title="Known pressure tactic",
                    explanation="Messages of this kind rely on rushing the reader.",
                    support=excerpt,
                ),
            )
        )
    return cases


def run(json_path: str | None) -> int:
    rng = random.Random(SEED)
    substrates = []
    for sample in [*SAMPLES, *ADVERSARIAL, *HARD_NEGATIVES]:
        entities, signals = run_detectors(sample.text)
        sub = Substrate(sample, sample.text, entities, signals, signal_score(signals))
        sub.sources = _fixtures(sample.text, entities)
        substrates.append(sub)

    results: Counter = Counter()
    wrong: list[str] = []
    by_sub = {s.sample.id: s for s in substrates}
    for case in build(substrates, rng):
        sub = by_sub[case.substrate]
        kept, rejected = verify_tells([case.tell], sub.signals, sub.sources, sub.text, sub.entities)
        ok = (len(kept) == 1) == case.should_keep
        results[(case.family, case.kind, "n")] += 1
        results[(case.family, case.kind, "ok")] += ok
        if not ok:
            got = rejected[0].code if rejected else "kept"
            wrong.append(
                f"{case.substrate}: {case.kind} -> {got} ({case.tell.quote or case.tell.support or case.tell.evidence_ref})"
            )

    valid = sorted(archetype_ids())
    for aid in [a for a in BOGUS_ARCHETYPES if a not in valid]:
        m = verify_archetype(
            ArchetypeMatch(
                archetype_id=aid, name="x", confidence=0.9, rationale="x", matched_tells=[]
            )
        )
        results[("taxonomy", "archetype not in catalogue", "n")] += 1
        results[("taxonomy", "archetype not in catalogue", "ok")] += m.archetype_id == "none"
    for aid in valid:
        m = verify_archetype(
            ArchetypeMatch(
                archetype_id=aid, name="x", confidence=0.9, rationale="x", matched_tells=[]
            )
        )
        results[("control", "catalogue archetype", "n")] += 1
        results[("control", "catalogue archetype", "ok")] += m.archetype_id == aid

    for sub in substrates:
        if sub.floor == 0:
            continue
        for score in sorted({0, sub.floor // 2, sub.floor - 1}):
            v = Verdict(
                risk_level=RiskLevel.info,
                score=score,
                headline="looks fine",
                tells=[],
                reasoning="-",
            )
            fixed = reconcile_verdict(v, [], sub.floor)
            ok = (
                fixed.score >= sub.floor
                and BAND_ORDER[fixed.risk_level] >= BAND_ORDER[risk_band(fixed.score)]
            )
            results[("floor", "score below the detector floor", "n")] += 1
            results[("floor", "score below the detector floor", "ok")] += ok

    rows = sorted(
        {(f, k) for f, k, _ in results},
        key=lambda x: ("pointer support taxonomy floor control".split().index(x[0]), x[1]),
    )
    adv_n = sum(results[(f, k, "n")] for f, k in rows if f != "control")
    adv_ok = sum(results[(f, k, "ok")] for f, k in rows if f != "control")
    ctl_n = sum(results[(f, k, "n")] for f, k in rows if f == "control")
    ctl_ok = sum(results[(f, k, "ok")] for f, k in rows if f == "control")

    print("Evidence Integrity Benchmark")
    print(f"  substrates: {len(substrates)} messages (samples, adversarial set, hard negatives)")
    print(f"  cases: {adv_n} adversarial, {ctl_n} controls, seed {SEED}\n")
    print(f"  {'family':<9}{'case':<44}{'correct':>12}")
    print("  " + "-" * 65)
    for f, k in rows:
        n, ok = results[(f, k, "n")], results[(f, k, "ok")]
        print(f"  {f:<9}{k:<44}{f'{ok}/{n}':>12}")
    print("  " + "-" * 65)
    print(f"  adversarial cases handled correctly  {adv_ok}/{adv_n}")
    print(f"  controls kept                        {ctl_ok}/{ctl_n}")
    for line in wrong[:20]:
        print("  MISJUDGED", line)
    passed = adv_ok == adv_n and ctl_ok == ctl_n
    print("\n  " + ("PASS" if passed else "FAIL") + ": every case judged as expected." * passed)

    if json_path:
        Path(json_path).write_text(
            json.dumps(
                {
                    "seed": SEED,
                    "substrates": len(substrates),
                    "adversarial": {"n": adv_n, "correct": adv_ok},
                    "controls": {"n": ctl_n, "correct": ctl_ok},
                    "rows": [
                        {
                            "family": f,
                            "case": k,
                            "n": results[(f, k, "n")],
                            "correct": results[(f, k, "ok")],
                        }
                        for f, k in rows
                    ],
                    "misjudged": wrong,
                },
                indent=2,
            )
        )
    return 0 if passed else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", help="also write the results to this file")
    raise SystemExit(run(ap.parse_args().json))
