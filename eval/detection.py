#!/usr/bin/env python3
"""Detection metrics on the examples in backend/samples.py.

  labelled        16 scams and 8 legitimate controls written for this project
  hard negatives  legitimate messages that use scam vocabulary: bank advisories, OTPs,
                  promo codes, news links, genuine bank and .bank.in links

A message counts as flagged at medium risk or above (score 35+). Without NEBIUS_API_KEY this
measures the deterministic detectors, which is what CI runs and what docs/EVALUATION.md
reports; with a key it runs the full pipeline. Both sets were written by the author, so read
the numbers as regression checks. eval/external.py measures on independent data.

    python eval/detection.py [--json path]

Exits non-zero on any false positive in either set.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import get_settings  # noqa: E402
from backend.pipeline import analyze  # noqa: E402
from backend.samples import HARD_NEGATIVES, SAMPLES, Sample  # noqa: E402
from backend.schemas import AnalysisResult  # noqa: E402

FLAGGED = {"medium", "high", "critical"}


async def _run(sample: Sample) -> AnalysisResult:
    result = None
    async for item in analyze(
        text=sample.text, region_hint=sample.region_hint, input_kind="sample"
    ):
        if isinstance(item, AnalysisResult):
            result = item
    return result


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "n/a"


async def main(json_path: str | None) -> int:
    mode = (
        "full pipeline" if get_settings().has_llm else "deterministic detectors (no NEBIUS_API_KEY)"
    )
    print(f"Telltale detection eval, mode: {mode}\n")

    tp = fp = tn = fn = arch_ok = 0
    print(f"{'sample':<20}{'label':<7}{'risk':<9}{'score':>5}  result")
    print("-" * 56)
    for s in SAMPLES:
        r = await _run(s)
        flagged = r.verdict.risk_level.value in FLAGGED
        mark = {
            (True, True): "TP",
            (True, False): "FN  missed",
            (False, True): "FP  false alarm",
        }.get((s.expect_scam, flagged), "TN")
        tp += mark == "TP"
        fn += mark.startswith("FN")
        fp += mark.startswith("FP")
        tn += mark == "TN"
        arch_ok += r.archetype.archetype_id == s.expect_archetype
        label = "scam" if s.expect_scam else "legit"
        print(f"{s.id:<20}{label:<7}{r.verdict.risk_level.value:<9}{r.verdict.score:>5}  {mark}")

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print("-" * 56)
    print(f"confusion  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(
        f"precision {precision:.1%}   recall {recall:.1%}   F1 {f1:.1%}   FPR {_pct(fp, fp + tn)}"
    )
    print(f"archetype accuracy {_pct(arch_ok, len(SAMPLES))}")

    hn_scores = []
    for s in HARD_NEGATIVES:
        hn_scores.append((s.id, (await _run(s)).verdict.score))
    hn_flagged = [sid for sid, score in hn_scores if score >= 35]
    top = max(hn_scores, key=lambda x: x[1])
    print(f"\nhard negatives  {len(HARD_NEGATIVES)} legitimate messages, flagged {len(hn_flagged)}")
    print(f"highest score   {top[1]} ({top[0]})")
    for sid in hn_flagged:
        print(f"  FALSE ALARM {sid}")

    if json_path:
        Path(json_path).write_text(
            json.dumps(
                {
                    "mode": mode,
                    "labelled": {
                        "tp": tp,
                        "fp": fp,
                        "tn": tn,
                        "fn": fn,
                        "precision": precision,
                        "recall": recall,
                        "f1": f1,
                        "archetype_accuracy": arch_ok / len(SAMPLES),
                    },
                    "hard_negatives": {
                        "n": len(HARD_NEGATIVES),
                        "flagged": hn_flagged,
                        "max_score": top[1],
                    },
                },
                indent=2,
            )
        )
    return 0 if fp == 0 and not hn_flagged else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Detection metrics on the built-in examples.")
    ap.add_argument("--json", help="also write the results to this file")
    raise SystemExit(asyncio.run(main(ap.parse_args().json)))
