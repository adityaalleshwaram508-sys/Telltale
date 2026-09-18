# Evaluation

Two things are measured here, both reproducible from the repo with no API key:

1. **Detection** — does it catch scams without flagging legitimate messages?
2. **Evidence grounding** — does the verifier actually reject model claims that
   aren't supported by evidence? (This is the property the whole design exists for.)

The dataset is a small, **hand-authored** labelled set in
[`backend/samples.py`](../backend/samples.py) — 24 examples (16 scams across the
common archetypes, 8 legitimate controls, including cases naive keyword filters
get wrong: a real bank OTP alert, a genuine payment reminder, a real transaction
alert, a legitimate job invite). It is **not** a production benchmark, and the
numbers below shouldn't be read as real-world accuracy — the set is small and
written by one person. Its purpose is to keep the detection and grounding
behaviour honest and regression-checked.

## Reproduce

```bash
python eval/detection.py    # detection metrics
python eval/grounding.py    # evidence integrity benchmark
```

Both run in **deterministic mode** by default (no `NEBIUS_API_KEY`), so anyone can
reproduce the exact numbers below. With a key set, `detection.py` exercises the
full Nemotron pipeline and recall/archetype accuracy improve; the integrity
benchmark is verifier-only and identical either way.

## Detection results (deterministic detectors only)

```
24 labelled examples (16 scam / 8 legitimate)

Confusion matrix:  TP=12  FP=0  TN=8  FN=4
Detection accuracy : 83.3%
Precision          : 100.0%
Recall             : 75.0%
False-positive rate: 0.0%
Archetype accuracy : 75.0%
```

What this says, honestly:

* **Zero false positives.** Every legitimate control — including the tricky ones
  — was left clean. The deterministic layer never cries wolf, which is the
  invariant the eval gates on.
* **75% recall with the model off.** The 4 misses (a family-emergency text, a
  predatory-loan SMS, a business-email-compromise invoice, a Hinglish job scam)
  are the subtle, semantic cases that have few mechanical tells. They're what the
  Nemotron reasoning step is *for*; deterministic mode intentionally under-flags
  rather than guess.
* **Archetype accuracy is heuristic here (75%)** — real classification is the
  model's job and improves with `NEBIUS_API_KEY` set.

The takeaway is the split: code gives a high-precision floor you can trust; the
model lifts recall on the cases that need interpretation.

## Evidence Integrity Benchmark

This is the benchmark that measures Telltale's actual contribution. Detection
accuracy is a table stakes; the question that matters is whether the verifier
holds the invariant *the model proposes, evidence decides* under adversarial
pressure.

`eval/grounding.py` constructs **100 adversarial claims** against a real message
and its real computed signals — 25 fabricated signal references, 25 fabricated
quotes, 20 fabricated citations, 15 out-of-taxonomy archetypes, and 15
score-manipulation attempts — plus a **control set of 27 genuinely-grounded
claims** that must survive. Every case runs through the exact functions the app
uses (`verify_tells`, `verify_archetype`, `reconcile_verdict`). "Fabricated" is
computed relative to the real substrate, so it always means *not actually
present*, never merely *looks made up*.

```
adversarial cases : 100 (70 fabricated claims, 15 bad archetypes, 15 score-manipulations)
control cases     : 27 grounded claims

Claim rejection rate    100%   70/70 fabricated claims rejected
Signal grounding        100%   29/29 correct
Quote fidelity          100%   35/35 correct
Citation validity       100%   23/23 correct
Archetype integrity     100%   15/15 bogus archetypes forced to 'none'
Risk-floor violations   0      out of 15 score-manipulation attempts
False rejections        0      genuinely-grounded claims wrongly dropped
```

These numbers are a property of the verification code, not a model run, so they're
fully reproducible. If a future change weakens the verifier, this benchmark fails
loudly rather than silently.

## Unit tests

```bash
python -m pytest -q        # 40 tests
```

[`tests/test_verify.py`](../tests/test_verify.py) covers the same grounding
guarantee at the unit level, and [`tests/test_pipeline.py`](../tests/test_pipeline.py)
checks that a strong scam is never returned as "safe" and a control is never
over-flagged.

## Limitations

* The set is small and hand-authored; treat the percentages as regression signals,
  not real-world accuracy.
* Deterministic-mode recall is a floor; the reported number will differ (higher)
  with the model enabled.
* A larger, independently-sourced, anonymised dataset is the clear next step (see
  the roadmap in the README).
