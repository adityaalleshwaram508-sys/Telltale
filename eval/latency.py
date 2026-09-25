#!/usr/bin/env python3
"""Per-step latency and tokens against the live Token Factory API.

Runs built-in samples through the full pipeline and reports the median latency and tokens
for each step from the run trace. With --compare-reasoning it runs the same samples a second
time with Nemotron reasoning switched on for every step, which shows what the per-step
reasoning settings save. Spends Token Factory credits; Tavily is skipped.

    python eval/latency.py --runs 2
    python eval/latency.py --runs 2 --compare-reasoning
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.llm as llm_mod  # noqa: E402
from backend.config import get_settings  # noqa: E402
from backend.pipeline import analyze  # noqa: E402
from backend.samples import get_sample  # noqa: E402
from backend.schemas import AnalysisResult  # noqa: E402

SAMPLE_IDS = ["delivery_sms", "upi_refund", "task_job", "legit_otp"]
STEPS = ["context", "classify", "verdict", "action"]


async def measure(runs: int) -> dict[str, dict[str, list[int]]]:
    llm_mod._llm = None  # rebuild the client with the current settings
    stats: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for _ in range(runs):
        for sid in SAMPLE_IDS:
            s = get_sample(sid)
            result = None
            async for item in analyze(text=s.text, region_hint=s.region_hint):
                if isinstance(item, AnalysisResult):
                    result = item
            for e in result.run_trace:
                if e.kind == "model" and e.ok:
                    stats[e.stage]["ms"].append(e.ms)
                    stats[e.stage]["out"].append(e.tokens_out)
                    stats[e.stage]["mode"] = [e.detail]
                    stats[e.stage]["model"] = [e.name.split("/")[-1]]
            stats["total"]["ms"].append(result.duration_ms)
    return stats


def show(title: str, stats) -> None:
    print(f"\n{title}")
    print(f"  {'step':<10}{'model':<34}{'mode':<16}{'median ms':>10}{'median out tok':>16}")
    for step in [*STEPS, "total"]:
        st = stats.get(step)
        if not st or not st["ms"]:
            continue
        out = int(statistics.median(st["out"])) if st.get("out") else ""
        model = st.get("model", [""])[0]
        mode = st.get("mode", [""])[0]
        print(f"  {step:<10}{model:<34}{mode:<16}{int(statistics.median(st['ms'])):>10}{out:>16}")


async def main() -> int:
    ap = argparse.ArgumentParser(description="Per-step latency and tokens on Token Factory.")
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--compare-reasoning", action="store_true")
    args = ap.parse_args()
    os.environ["TAVILY_API_KEY"] = ""
    get_settings.cache_clear()
    if not get_settings().has_llm:
        sys.exit("needs NEBIUS_API_KEY")
    show("configured reasoning modes", await measure(args.runs))
    if args.compare_reasoning:
        for step in STEPS:
            os.environ[f"TELLTALE_THINKING_{step.upper()}"] = "on"
        get_settings.cache_clear()
        show("reasoning on for every step", await measure(args.runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
