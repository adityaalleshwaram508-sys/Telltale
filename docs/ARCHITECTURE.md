# Architecture

Telltale is a small pipeline built around one rule: **the model reasons, but
evidence decides.** Every stage is separable and testable, and no claim reaches
the user unless it can be traced to a real signal, a returned source, or a
verbatim quote from the input.

## Pipeline

```
        ┌── screenshot ──► MiniCPM-V (transcribe) ──┐
input ──┤── link ───────────────────────────────────►│
        └── text ───────────────────────────────────►│  message text
                                                      ▼
                                  ┌───────────────────────────────────┐
                                  │ deterministic detectors (code)     │
                                  │  entities · urls · payments ·      │
                                  │  language · contacts               │
                                  └───────────────┬───────────────────┘
                                      signals + a transparent risk FLOOR
                                                  │
                  Nemotron Nano ── context ───────┤
                  Nemotron Super ── classify ─────┤ (archetype ∈ curated catalogue)
                                                  │
                                  Tavily ── live research (year-aware) ──► sources
                                                  │
                  Nemotron Super ── verdict (tells bound to signal / source / quote)
                                                  │
                              verify.py ── drop unsupported tells · clamp score to floor
                                                  │
                  Nemotron Super ── action plan + safe reply   report channels ◄─ curated KB
                                                  ▼
                                          AnalysisResult
```

Each stage emits a server-sent event so the UI can narrate the work as it happens.
Every model stage is wrapped: if the model or network is unavailable, that stage
degrades to a deterministic path and records a coverage note instead of failing —
the app **fails closed**, never inventing to fill a gap.

## The evidence contract

Three kinds of evidence exist, and a *tell* in the final verdict must reference
exactly one of them:

| Kind     | Produced by        | Referenced as              | Verified by                          |
| -------- | ------------------ | -------------------------- | ------------------------------------ |
| `signal` | the code detectors | a `Signal.id`              | id must exist in the computed set    |
| `source` | Tavily             | a `Source.id`              | id must exist in the returned set    |
| `quote`  | the message itself | the verbatim substring     | must actually appear in the input    |

[`backend/verify.py`](../backend/verify.py) enforces the right-hand column and
discards anything that fails. This is what stops the classic LLM failure — a
fluent, well-cited-looking claim that is actually fabricated.

## Scoring

`detectors.signal_score()` turns the deterministic signals into a 0–100 floor
(severity weights, de-duplicated by id, with diminishing returns so one severe
tell outweighs a pile of weak ones). The model proposes its own score;
`verify.reconcile_verdict()` clamps it into `[floor, 100]` and raises the risk
band if the clamped score implies a higher one. So a message full of severe
signals can never come back "safe," regardless of what the model says.

## Models

| Stage                 | Model                                   | Why                              |
| --------------------- | --------------------------------------- | -------------------------------- |
| Screenshot OCR        | `openbmb/MiniCPM-V-4_5`                 | vision-language transcription    |
| Message understanding | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | fast, cheap structured extraction|
| Classification/verdict/actions | `nvidia/nemotron-3-super-120b-a12b` | reasoning + long context   |

All reasoning runs on NVIDIA Nemotron via Nebius Token Factory's OpenAI-compatible
endpoint. Token Factory has no Nemotron vision model, so screenshot transcription
uses MiniCPM-V; nothing that decides the verdict runs on a non-Nemotron model.
IDs are configurable in [`backend/config.py`](../backend/config.py).

## Knowledge base

Everything citable is data, under [`backend/knowledge/data`](../backend/knowledge/data):
scam archetypes, reporting channels (by ISO-2 region + a global fallback),
impersonated brands, and the language lexicons. **Adding a scam type or a country's
reporting info is a YAML edit, not a code change** — which keeps coverage easy to
extend and every cited fact reviewable in one place.

## Failure behaviour

* No `NEBIUS_API_KEY` → deterministic mode: detectors + knowledge base only, every
  step labelled as heuristic in the UI.
* No `TAVILY_API_KEY` → the research step is skipped and said so; the verdict simply
  has no `source`-backed tells.
* A single model step failing → that step falls back; the rest continues.
* The SSE stream is wrapped so it always closes cleanly.

Structured output everywhere: each model call requests `response_format=json_schema`
(schema also placed in the prompt) and validates against a Pydantic model, with a
`json_object` + repair fallback — so a caller always gets a typed object or a clean
error, never half-parsed prose.
