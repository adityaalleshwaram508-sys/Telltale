#!/usr/bin/env python3
"""Detection evaluation over the labelled examples in backend/samples.py.

Reports a confusion matrix and the standard metrics (precision / recall / F1 /
false-positive rate), plus archetype-classification accuracy. Runs in whatever
mode the environment allows: with NEBIUS_API_KEY set it exercises the full
Nemotron pipeline; without it, the deterministic detectors only (which is what
the committed numbers in docs/evaluation.md are measured on, so they're
reproducible by anyone without a key).

    python eval/detection.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import get_settings          # noqa: E402
from backend.pipeline import analyze              # noqa: E402
from backend.samples import SAMPLES               # noqa: E402
from backend.schemas import AnalysisResult        # noqa: E402

FLAGGED = {"medium", "high", "critical"}


async def _run(sample) -> AnalysisResult:
    result = None
    async for item in analyze(text=sample.text, region_hint=sample.region_hint,
                              input_kind="sample"):
        if isinstance(item, AnalysisResult):
            result = item
    return result


def _pct(n: int, d: int) -> str:
    return f"{(100 * n / d):.1f}%" if d else "n/a"


async def main() -> int:
    s = get_settings()
    mode = "full pipeline (Nemotron + live research)" if s.has_llm \
        else "deterministic detectors only (no NEBIUS_API_KEY)"
    print(f"Telltale detection eval — mode: {mode}")
    print(f"{len(SAMPLES)} labelled examples "
          f"({sum(x.expect_scam for x in SAMPLES)} scam / "
          f"{sum(not x.expect_scam for x in SAMPLES)} legitimate)\n")

    tp = fp = tn = fn = arch_ok = 0
    rows = []
    for sample in SAMPLES:
        r = await _run(sample)
        flagged = r.verdict.risk_level.value in FLAGGED
        if sample.expect_scam and flagged:
            tp += 1; mark = "TP"
        elif sample.expect_scam and not flagged:
            fn += 1; mark = "FN  <- missed"
        elif not sample.expect_scam and flagged:
            fp += 1; mark = "FP  <- false alarm"
        else:
            tn += 1; mark = "TN"
        if r.archetype.archetype_id == sample.expect_archetype:
            arch_ok += 1
        rows.append((sample.id, "scam" if sample.expect_scam else "legit",
                     r.verdict.risk_level.value, r.verdict.score, mark))

    print(f"{'sample':<18}{'label':<7}{'risk':<9}{'score':<6}{'result'}")
    print("-" * 68)
    for sid, lab, risk, score, mark in rows:
        print(f"{sid:<18}{lab:<7}{risk:<9}{score:<6}{mark}")
    print("-" * 68)

    n = len(SAMPLES)
    print(f"\nConfusion matrix:  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Detection accuracy : {_pct(tp + tn, n)}")
    print(f"Precision          : {_pct(tp, tp + fp)}")
    print(f"Recall             : {_pct(tp, tp + fn)}")
    print(f"False-positive rate: {_pct(fp, fp + tn)}")
    print(f"Archetype accuracy : {_pct(arch_ok, n)}"
          + ("" if s.has_llm else "   (weak without the model — needs NEBIUS_API_KEY)"))

    # The hard invariant is "never falsely flag a legitimate message." Recall is
    # a reported metric, not a gate: the deterministic layer intentionally leaves
    # the subtle, semantic cases to the model.
    return 0 if fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
