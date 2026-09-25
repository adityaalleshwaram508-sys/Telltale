# Architecture

Telltale is a FastAPI service with a single-page frontend. One request runs a fixed pipeline
and streams progress to the browser as server-sent events.

```text
POST /api/analyze/stream  (text, link or screenshot)
  │
  ├─ ingest        screenshot → MiniCPM-V transcription; a link is analysed as text, never fetched
  ├─ detect        entities + deterministic signals + risk floor            detectors/
  ├─ context       Nemotron Nano, reasoning off                               MessageContext
  ├─ classify      Nemotron Super, reasoning off, closed list of scam types   ArchetypeMatch
  ├─ research      Tavily, exact-match searches on the message's entities     Source[]
  ├─ verdict       Nemotron Super, reasoning low effort                       Verdict
  │                 └─ verify.py: drop unsupported tells, clamp to the floor
  │                 └─ optional second opinion on a larger model
  ├─ action        Nemotron Super, reasoning off                              ActionDraft
  └─ result        + reporting channels, "not proven" list, run trace         AnalysisResult
```

## Detectors

`backend/detectors/` is plain Python with no model. It extracts links, phone numbers, UPI
ids, emails, wallet addresses and amounts, then raises signals, each with a severity from 0
to 3 and the exact text that triggered it.

- **Links.** Registrable domains come from the Public Suffix List (tldextract's bundled
  snapshot, no network at runtime), with RBI's `.bank.in` handled explicitly. Signals cover
  raw IPs, punycode, cheap TLDs, shorteners, hosts imitating `.bank.in`, look-alikes of real
  domains (homoglyph folding, edit distance scaled to name length) and brand names used in
  someone else's domain.
- **Payments.** Patterns for a demand, not a mention: "pay with gift cards" fires, "use
  voucher code SAVE20" doesn't; "NEFT the payment to" fires, "credited via NEFT" doesn't.
- **Language.** Curated lexicons matched as whole words with inflections. Credential and
  remote-access terms skip sentences that warn against the thing ("we will never ask for your
  UPI PIN"), which banks send constantly.
- **Contacts and injection.** A brand claimed from a free email address, and phrases aimed at
  an AI analyser.

The floor is `signal_score()`. Distinct signals add 6, 16 or 30 points for severity 1, 2 or
3, capped at 100. The weights are hand-set so that one severe signal plus one moderate one
reaches the medium band. They aren't fitted to data; the hard negatives and the external
dataset are how changes to them are checked.

## Model steps

`backend/pipeline.py` has one table, `stages()`, that sets the model, reasoning mode and
token budget of each step. `backend/llm.py` makes the calls.

- Output is requested as strict JSON schema, then plain JSON mode if the endpoint refuses it,
  and one repair round if validation fails.
- Nemotron 3's reasoning mode is set per step through `chat_template_kwargs`. If an endpoint
  refuses that field, the client retries without it and remembers.
- Only timeouts, connection errors, 429 and 5xx are retried, with `Retry-After` honoured. A
  400 falls through to the next strategy at once.
- A reply that stops at `max_tokens` is never parsed, and each step has a wall-clock budget.
- Every call is recorded in the run trace with model, mode, latency, tokens and HTTP calls.

The optional second opinion (`TELLTALE_ESCALATION_MODEL`, for example Nemotron 3 Ultra)
reruns the verdict when the first one lands in the medium band or had two or more claims
rejected. It goes through the same verifier.

## Evidence contract

`backend/verify.py` runs after the verdict. Each tell names one piece of evidence.

| Evidence | Checks |
| --- | --- |
| signal | the id was produced for this message; the tell doesn't claim outside confirmation |
| quote | at least two words, found in the message word by word (punctuation-tolerant), and not only in a negated clause; "if you don't pay" is a condition, not a negation |
| source | the id was returned; a verbatim excerpt of four or more words from that result; a named link, number or UPI id (or "this domain") must be among the entities the result mentions |

Then `reconcile_verdict()` clamps the score into [floor, 100] and raises the band if the
score implies a higher one. The archetype must come from the catalogue or becomes "none".

## Research

`backend/tavily.py` plans at most three searches. The first unfamiliar domain, the first
phone number and the first UPI id each get an exact-match search, with the suspect domain in
`exclude_domains`. Genuine domains, IPs and `.bank.in` hosts aren't searched. With no
entities, one pattern search on the claimed sender runs, unless the sender is generic
("police", "bank"). Each result records what was searched for and which of the message's
entities it mentions, which is what the verifier's source checks read.

## Failure behaviour and caching

Every model step has a heuristic fallback and every search failure becomes a coverage note.
The result's `degraded` flag is set whenever something fell back. Text and link checks are
cached in memory for `TELLTALE_CACHE_TTL_S` (15 minutes by default); screenshots and degraded
runs are never cached.

## Limits

`backend/limits.py` holds a sliding-window rate limiter per client and a daily budget of full
model runs. Past the budget the app still answers from the detectors and says so. Requests
over the size limits get 413, wrong upload types 415. State is per process, which matches
the single-instance deployment.

## Knowledge base

`backend/knowledge/data/` is hand-written YAML: 14 scam archetypes with how each one works
and its sources, brands and their genuine domains, suspicious TLDs and shorteners, phrase
lexicons, and reporting channels by country. Reporting advice always comes from here, never
from the model.

## Frontend

`frontend/` is one HTML page, one script and one stylesheet, with no build step. It renders
with `textContent` only and makes links clickable only for http(s). It is installable, and
its manifest registers an Android share target, so a message shared from WhatsApp or SMS
opens Telltale with the text filled in.
