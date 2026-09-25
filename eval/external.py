#!/usr/bin/env python3
"""Detection on independent data: the SMS Phishing Dataset of Mishra and Soni (2022).

5,971 real SMS labelled ham, spam or smishing by other researchers. Telltale's rules were not
written from it. It was run as a regression check after the detector precision pass, and two
detections that pass had dropped (verifyapple.uk, "bequest") were restored after it showed
them. Most of its smishing is older UK and Nigerian SMS, while the detectors target
Indian scams, so detector-only recall here is expected to be low.

The dataset is not redistributed. Download it from Mendeley Data
(https://data.mendeley.com/datasets/f45bkkt8pr/1, DOI 10.17632/f45bkkt8pr.1) and pass the CSV:

    python eval/external.py Dataset_5971.csv
    python eval/external.py Dataset_5971.csv --with-model --limit 100 --no-research

The default runs the deterministic detectors over every message, free. --with-model runs the
full pipeline on a stratified sample and spends Token Factory credits; --no-research skips
Tavily. Spam is reported on its own line: marketing spam isn't a scam, so it counts as neither.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import os
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import get_settings  # noqa: E402
from backend.detectors import run_detectors, signal_score  # noqa: E402

FLAG_AT = 35


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def load(path: str) -> list[tuple[str, str]]:
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [(r["LABEL"].strip().lower(), r["TEXT"]) for r in csv.DictReader(fh)]


async def _model_score(text: str) -> int:
    from backend.pipeline import analyze
    from backend.schemas import AnalysisResult

    score = 0
    async for item in analyze(text=text, input_kind="text"):
        if isinstance(item, AnalysisResult):
            score = item.verdict.score
    return score


def report(rows: list[tuple[str, int, list[str]]]) -> dict:
    out = {}
    for label in ("ham", "smishing", "spam"):
        scores = [s for lab, s, _ in rows if lab == label]
        k = sum(s >= FLAG_AT for s in scores)
        lo, hi = wilson(k, len(scores))
        out[label] = {
            "n": len(scores),
            "flagged": k,
            "rate": k / len(scores) if scores else 0,
            "ci95": [lo, hi],
        }
        print(
            f"{label:<9} n={len(scores):<5} flagged={k:<5} {100 * k / max(len(scores), 1):6.2f}%"
            f"   95% CI {100 * lo:.2f}-{100 * hi:.2f}%"
        )
    noise = Counter(sig for lab, _, sigs in rows if lab == "ham" for sig in sigs)
    print(
        "\nsignals raised on legitimate messages (below the flag threshold unless counted above):"
    )
    for sig, n in noise.most_common(6):
        print(f"  {sig:<32}{n}")
    out["ham_signal_counts"] = dict(noise)
    return out


async def main() -> int:
    ap = argparse.ArgumentParser(description="Detection on the Mishra and Soni SMS dataset.")
    ap.add_argument("csv")
    ap.add_argument(
        "--with-model", action="store_true", help="run the full pipeline (costs credits)"
    )
    ap.add_argument(
        "--limit", type=int, default=100, help="messages to sample in --with-model mode"
    )
    ap.add_argument("--no-research", action="store_true", help="skip Tavily in --with-model mode")
    ap.add_argument("--json", help="also write the results to this file")
    args = ap.parse_args()

    data = load(args.csv)
    print(f"{len(data)} messages: {dict(Counter(lab for lab, _ in data))}\n")
    rows = []
    if not args.with_model:
        print("mode: deterministic detectors only\n")
        for label, text in data:
            _, signals = run_detectors(text)
            rows.append((label, signal_score(signals), sorted({s.id for s in signals})))
    else:
        if args.no_research:
            os.environ["TAVILY_API_KEY"] = ""
        get_settings.cache_clear()
        if not get_settings().has_llm:
            sys.exit("--with-model needs NEBIUS_API_KEY")
        rng = random.Random(7)
        half = args.limit // 2
        sample = [
            (lab, t)
            for lab in ("ham", "smishing")
            for lab, t in rng.sample(
                [x for x in data if x[0] == lab], min(half, sum(1 for x in data if x[0] == lab))
            )
        ]
        print(f"mode: full pipeline on {len(sample)} messages (stratified, seed 7)\n")
        for i, (label, text) in enumerate(sample, 1):
            rows.append((label, await _model_score(text), []))
            print(f"\r  {i}/{len(sample)}", end="", flush=True)
        print("\n")
    result = report(rows)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
