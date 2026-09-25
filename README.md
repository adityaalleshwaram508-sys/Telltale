  # Telltale

[![CI](https://github.com/adityaalleshwaram508-sys/Telltale/actions/workflows/ci.yml/badge.svg)](https://github.com/adityaalleshwaram508-sys/Telltale/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)

Telltale checks whether a message is a scam and shows the proof. Paste a text, email,
WhatsApp message, call transcript or link, or share it straight from your phone, and you get
a risk score, the specific tells behind it, what to do next and where to report it.

NVIDIA Nemotron on Nebius Token Factory does the reasoning. Code outside the model decides
what counts as evidence. A finding reaches you only if it points at something checkable (a
detector signal, a passage from a live Tavily source, or the message's own words), and the
score can never drop below what the detectors found.

**Live demo** https://telltale-jawt.onrender.com
**Architecture** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) &nbsp; **Evaluation** [docs/EVALUATION.md](docs/EVALUATION.md) &nbsp; **Threat model** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

Built for the 2026 Nebius x NVIDIA Global AI Hackathon (Best Apps and Agents track). The
first commit is from 18 September 2026, inside the submission period.

![Result](docs/shot-2-evidence.png)

## Why

People in the US reported losing $12.5 billion to fraud in 2024, 25% more than the year
before ([FTC](https://www.ftc.gov/news-events/news/press-releases/2025/03/new-ftc-data-show-big-jump-reported-losses-fraud-125-billion-2024)).
In India the same scams arrive as fake KYC alerts, courier fees, UPI "refunds" and "digital
arrest" calls. Asking a chatbot is the obvious fix and a risky one, because a confident wrong
answer gets acted on. A model can invent a helpline number, call a real bank's site
dangerous, or quote a rule that doesn't exist. Telltale lets the model reason but not decide.

## How it works

```text
 text / link / screenshot ─► MiniCPM-V (screenshots only) ─► message text
                                                              │
                 deterministic detectors ─► signals + risk floor
                                                              │
   Nemotron Nano   read the message        (reasoning off)    │
   Nemotron Super  match a scam pattern    (reasoning off)    │
   Tavily          exact-match searches for the message's own link, number, UPI id
   Nemotron Super  verdict, every tell bound to evidence (reasoning low)
                                                              │
         verify.py  drop tells the evidence doesn't back, clamp the score to the floor
                                                              │
   Nemotron Super  action plan (reasoning off) + reporting channels from the knowledge base
```

Each step has a deterministic fallback. If a model or search call fails, the answer gets
narrower instead of breaking, the result says which step fell back, and it isn't cached.

## What the verifier checks

| A tell that cites | survives only if |
| --- | --- |
| a detector **signal** | the detectors produced that id for this message, and the tell doesn't use it to claim outside confirmation ("has been reported", "RBI has warned") |
| the message (**quote**) | the words appear in the message, at least two of them, and the message doesn't only use them in the negative ("do not share it with anyone") |
| a live **source** | research returned that id, the tell carries a verbatim excerpt from it, and a claim about a specific link or number cites a source that mentions it |

Rejected tells are shown to the user with the reason. What string checks can't establish is
whether a tell's explanation follows from its evidence, so the UI puts the excerpt or the
detector's finding next to every tell.

## Nemotron on Token Factory

| Step | Model | Reasoning | Why |
| --- | --- | --- | --- |
| Read the message | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | off | short structured extraction, the cheapest call |
| Match the scam pattern | `nvidia/nemotron-3-super-120b-a12b` | off | pick one id from a closed list |
| Verdict | `nvidia/nemotron-3-super-120b-a12b` | low effort | the only step that weighs evidence |
| Action plan | `nvidia/nemotron-3-super-120b-a12b` | off | writing, not judging |
| Second opinion (optional) | Nemotron 3 Ultra, set `TELLTALE_ESCALATION_MODEL` | on | medium-risk verdicts, or when two or more claims were rejected |
| Screenshot | `openbmb/MiniCPM-V-4_5` | n/a | Token Factory has no Nemotron vision model |

Nemotron 3 reasons before answering unless told otherwise, so each step sets its mode through
`chat_template_kwargs`. Every call has a token cap, only transient errors are retried, and a
reply cut off at the cap is never parsed. Every result includes a "How this run worked"
panel with the model, reasoning mode, latency and tokens of each call. `python eval/latency.py
--compare-reasoning` measures the per-step settings against reasoning everywhere.

## Live research with Tavily

- **Entity searches** use `exact_match`, so a result only comes back if it names the message's
  own link, phone number or UPI id.
- The suspect domain goes in `exclude_domains`, so the scam site is never cited as evidence
  about itself.
- When there's nothing specific to look up, one pattern search on the claimed sender runs
  instead, and the verifier lets those results back general claims only.
- Searches run concurrently, boost the user's country, and report credits used.

## Evaluation

All of this runs without API keys and in CI. Details in [docs/EVALUATION.md](docs/EVALUATION.md).

| Check | Result |
| --- | --- |
| Unit and integration tests | 120 passing |
| Evidence Integrity Benchmark, 52 messages | 501 of 501 adversarial cases rejected, 251 of 251 grounded controls kept |
| Labelled examples (16 scam, 8 legitimate), detectors only | precision 100%, recall 75%, F1 85.7% |
| Hard negatives (24 legitimate messages that use scam words) | 0 flagged, highest score 16 of 100 |
| [SMS Phishing Dataset](https://data.mendeley.com/datasets/f45bkkt8pr/1), 4,844 real legitimate SMS | 0 flagged by the detectors (95% CI 0 to 0.08%) |
| Same dataset, 638 real smishing SMS, detectors only | 4 flagged (0.6%) |

The last row is the honest shape of the design. The detectors are a floor built for
precision, because the model can't argue that floor down, and they were written for Indian
scam formats while that dataset is mostly older UK and Nigerian SMS. Recall on real-world
messages comes from Nemotron, which `eval/external.py --with-model` measures on a sample.

## Run it

```bash
pip install -r requirements-dev.txt
cp .env.example .env            # NEBIUS_API_KEY for the model, TAVILY_API_KEY for live checks
./scripts/run-dev.sh            # http://127.0.0.1:8000

python -m pytest -q             # tests
python eval/grounding.py        # Evidence Integrity Benchmark
python eval/detection.py        # detection metrics
```

Without keys Telltale runs in deterministic mode and says so on every result. Docker:
`docker build -t telltale . && docker run -p 8000:8000 --env-file .env telltale`. The live
demo runs that container on Render ([render.yaml](render.yaml)). Every setting is listed in
[.env.example](.env.example).

On Android, open the demo in Chrome and choose "Add to Home screen". Telltale then shows up in
the share sheet, so a suspicious WhatsApp or SMS message can be checked without copying it.

## Project layout

```text
backend/    app.py (API, limits)   pipeline.py   llm.py (Token Factory)   tavily.py
            verify.py (evidence checks)   prompts.py   schemas.py   config.py   limits.py
            detectors/   knowledge/data/*.yaml (scam types, brands, lexicons, reporting)
            samples.py (labelled, adversarial and hard-negative messages)
frontend/   single page, no framework; installable with an Android share target
eval/       grounding.py   detection.py   external.py   latency.py
tests/      unit, API and pipeline tests
docs/       ARCHITECTURE.md   EVALUATION.md   THREAT_MODEL.md
```

## Limitations

- Deterministic recall on real-world SMS is low by design; without a model key Telltale only
  catches messages with concrete tells.
- Reporting channels cover India, the US, UK, Australia, Canada and Singapore; elsewhere it
  falls back to general advice.
- The brand list and lexicons are partial and mostly English and Hinglish.
- Live search results change and are treated as supporting evidence, never as proof.
- Telltale is a safety aid, not legal or financial advice.

## Roadmap

- Model-mode results on the external dataset and a larger, independently labelled Indian set
- WhatsApp and SMS forwarding bot, and voice-call transcription
- More countries' brands and reporting channels

## License

MIT, see [LICENSE](LICENSE).
