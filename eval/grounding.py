#!/usr/bin/env python3
"""Evidence-grounding evaluation.

Telltale's core claim is that the model's output is *verified*: a "tell" only
survives if it maps to a real detected signal, a real returned source, or a
verbatim quote from the message. This script measures that directly.

It builds a labelled set of tells against a real message and its real computed
signals — some genuinely supported, some fabricated the way a model sometimes
hallucinates — runs them through the exact verifier the app uses, and reports:

  * unsupported-claim rejection rate  (fabricated tells that were dropped)
  * supported-claim retention rate    (real tells that were kept)

    python eval/grounding.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detectors import run_detectors       # noqa: E402
from backend.samples import get_sample            # noqa: E402
from backend.schemas import Source, Tell          # noqa: E402
from backend.verify import verify_tells           # noqa: E402

MESSAGE = get_sample("delivery_sms").text
_, SIGNALS = run_detectors(MESSAGE)
SIGNAL_IDS = sorted(s.id for s in SIGNALS)
# One real live source, as if Tavily had returned it.
SOURCES = [Source(id="src1", title="Reported courier phishing domain",
                  url="https://example.com/report", snippet="users report this domain")]

# (tell, is_actually_supported)
CASES: list[tuple[Tell, bool]] = [
    # --- genuinely supported: should be KEPT ---
    (Tell(title="Look-alike/brand-in-link", explanation="…",
          evidence_type="signal", evidence_ref="url.brand_in_subdomain"), True),
    (Tell(title="Cheap throwaway TLD", explanation="…",
          evidence_type="signal", evidence_ref="url.suspicious_tld"), True),
    (Tell(title="Manufactured urgency", explanation="…",
          evidence_type="quote", evidence_ref="quote", quote="within 24 hours"), True),
    (Tell(title="Small fee to release parcel", explanation="…",
          evidence_type="quote", evidence_ref="quote", quote="redelivery fee"), True),
    (Tell(title="Reported online", explanation="…",
          evidence_type="source", evidence_ref="src1"), True),

    # --- fabricated: should be DROPPED ---
    (Tell(title="Invented signal id", explanation="…",
          evidence_type="signal", evidence_ref="url.totally_made_up"), False),
    (Tell(title="Signal not present here", explanation="…",
          evidence_type="signal", evidence_ref="payment.gift_card"), False),
    (Tell(title="Cites a source that wasn't returned", explanation="…",
          evidence_type="source", evidence_ref="src9"), False),
    (Tell(title="Fabricated quote", explanation="…",
          evidence_type="quote", evidence_ref="quote",
          quote="wire me ten thousand dollars"), False),
    (Tell(title="Another fabricated quote", explanation="…",
          evidence_type="quote", evidence_ref="quote",
          quote="please share your OTP now"), False),
    (Tell(title="Plausible but absent claim", explanation="…",
          evidence_type="signal", evidence_ref="language.threat"), False),
]


def main() -> int:
    tells = [t for t, _ in CASES]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    kept_titles = {t.title for t in kept}

    supported = [t for t, ok in CASES if ok]
    fabricated = [t for t, ok in CASES if not ok]
    supported_kept = sum(t.title in kept_titles for t in supported)
    fabricated_dropped = sum(t.title not in kept_titles for t in fabricated)

    print("Evidence-grounding eval")
    print(f"  message           : delivery_sms")
    print(f"  real signals       : {SIGNAL_IDS}")
    print(f"  tells evaluated    : {len(CASES)} "
          f"({len(supported)} supported, {len(fabricated)} fabricated)")
    print(f"  verifier rejected  : {len(rejected)}\n")
    print(f"  unsupported-claim rejection : {fabricated_dropped}/{len(fabricated)} "
          f"({100*fabricated_dropped/len(fabricated):.0f}%)")
    print(f"  supported-claim retention   : {supported_kept}/{len(supported)} "
          f"({100*supported_kept/len(supported):.0f}%)")

    # Show the working: exactly what the verifier threw out, and why. This is the
    # same reason text the app surfaces in its "Evidence check" panel.
    if rejected:
        print("\n  rejected (model proposed it → evidence couldn't back it):")
        for rc in rejected:
            print(f"    ✗ {rc.title} — {rc.reason}")

    ok = (fabricated_dropped == len(fabricated)) and (supported_kept == len(supported))
    print("\n" + ("PASS — every fabricated claim was rejected, every real one kept."
                  if ok else "FAIL — verifier did not behave as expected."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
