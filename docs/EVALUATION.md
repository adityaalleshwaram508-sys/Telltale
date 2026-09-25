# Evaluation

Four measurements, from the most controlled to the most independent. All of them except the
model-mode runs work without API keys, and the first three run in CI on every push.

## 1. Evidence Integrity Benchmark

`python eval/grounding.py` feeds findings a model might produce into the verifier the app
uses and counts how many it misjudges. It runs over all 52 messages in `backend/samples.py`
(labelled, adversarial and hard negatives). For each message it computes the real detector
signals and builds two research fixtures in the shape Tavily returns, one that names a link or
number from the message and one that only discusses the scam pattern. The case set is
generated with a fixed seed, so it is identical on every run.

| Family | What it tries | Result |
| --- | --- | --- |
| pointer | real signal ids that didn't fire on this message, source ids research didn't return, near-miss quotes with one word changed, sentences from other messages | 260 of 260 rejected |
| support | quotes the message only uses in the negative, one-word quotes, excerpts that aren't in the cited source, a named link or number backed by a source that never mentions it, "has been reported" backed by a detector signal | 160 of 160 rejected |
| taxonomy | plausible archetype ids that aren't in the catalogue | 15 of 15 mapped to "none" |
| floor | verdicts scored below the detector floor | 66 of 66 raised to the floor |
| control | every real signal with its own wording, real quotes, excerpts from the matching source, every catalogue archetype | 251 of 251 kept |

**What this shows.** Given the evidence a run actually produced, the verifier doesn't let a
finding through unless its evidence exists and says what the finding says, and it doesn't
drop grounded findings.

**What it doesn't show.** The research fixtures are synthetic, so this says nothing about
what live search returns. It also can't test whether an explanation paraphrases its evidence
faithfully, which needs semantic entailment rather than string checks.

## 2. Labelled examples

`python eval/detection.py` runs the full pipeline over 24 labelled examples (16 scams across
the catalogue's scam types, 8 legitimate controls) and 24 hard negatives. A message counts
as flagged at medium risk or above (score 35+). Without a model key it measures the
deterministic detectors, which is what these numbers are.

| Set | Result |
| --- | --- |
| Labelled | TP 12, FP 0, TN 8, FN 4. Precision 100%, recall 75%, F1 85.7%, archetype accuracy 75% |
| Hard negatives | 0 of 24 flagged, highest score 16 (a fraud-awareness message) |

The hard negatives are legitimate messages that use scam vocabulary. Before the precision
pass the detectors flagged a genuine `sbi.co.in` link as SBI impersonation, scored a genuine
`amazon.co.uk` order at 46, read `firstpost.com` as the IRS and `purchase.stripe.com` as
Chase, and treated "Never share your OTP" and "use voucher code SAVE20" as scam demands.
Those messages are now regression tests.

Both sets were written by the author, so treat them as regression checks rather than a
measure of real-world accuracy. That is what the next section is for.

## 3. External dataset

`python eval/external.py Dataset_5971.csv` runs the detectors over the SMS Phishing Dataset
of Mishra and Soni (2022, [Mendeley Data](https://data.mendeley.com/datasets/f45bkkt8pr/1),
DOI 10.17632/f45bkkt8pr.1). It holds 5,971 real SMS labelled by other researchers. The
dataset isn't redistributed here; download it and pass the CSV.

| Label | Messages | Flagged by the detectors | Rate (95% Wilson interval) |
| --- | --- | --- | --- |
| legitimate (ham) | 4,844 | 0 | 0% (0 to 0.08%) |
| smishing | 638 | 4 | 0.6% (0.24 to 1.6%) |
| spam | 489 | 0 | counted as neither, since marketing isn't a scam |

The precision pass also cut the detector signals raised on those legitimate messages from 140
to 69, all of them below the flag threshold.

**Reading the recall.** The detectors are a floor that the model can't lower, so they are
built never to fire on legitimate messages, and they were written for Indian scam formats
(UPI, KYC, courier fees, `.bank.in`) while this dataset's smishing is mostly older UK and
Nigerian SMS. Recall on this kind of data has to come from Nemotron. `--with-model --limit
100` runs the full pipeline on a stratified sample and reports the same table.

**Tuning disclosure.** The detector rules were not written from this dataset. It was run as a
regression check after the precision pass, and it showed two real smishing messages that pass
had stopped catching (`verifyapple.uk` and an "unclaimed bequest" message). Both were
restored with general rules, a phishing-word-plus-brand host check and the term "bequest".

## 4. Latency and tokens

`python eval/latency.py --compare-reasoning` runs samples through Token Factory twice, once
with the configured reasoning modes and once with reasoning on for every step, and prints the
median latency and output tokens per step. It needs a key and spends credits. Every live
result also carries the same per-call data in its "How this run worked" panel.

## Reproduce

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python eval/grounding.py --json grounding.json
python eval/detection.py --json detection.json
python eval/external.py path/to/Dataset_5971.csv
```
