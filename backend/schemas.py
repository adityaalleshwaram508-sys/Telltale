"""Typed contracts for the whole pipeline.

Two kinds of models live here:

  * LLM-filled schemas (MessageContext, ArchetypeMatch, Verdict, ActionDraft) —
    these are handed to Nemotron as a JSON schema. They stay deliberately flat
    and free of unions/optionals because guided decoding is happiest that way.

  * Internal schemas (Signal, Source, Entities, ...) — assembled in Python. The
    important invariant, and the thing that keeps the app honest, is that every
    Tell in the final Verdict points back to a Signal, a Source, or a verbatim
    quote from the input. Nothing the model merely asserts survives on its own.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    critical = "critical"   # almost certainly a scam
    high = "high"           # likely a scam
    medium = "medium"       # suspicious, treat with caution
    low = "low"             # probably legitimate, but worth a check
    info = "info"           # no strong scam signals found


# --------------------------------------------------------------------------- #
#  Evidence primitives (built in Python, never invented by the model)
# --------------------------------------------------------------------------- #
class Signal(BaseModel):
    """A deterministic finding from one of the code-based detectors."""

    id: str                       # stable, e.g. "payment.gift_card"
    category: str                 # url | payment | language | contact | entity
    label: str
    detail: str
    severity: int = 0             # 0-3, how much this nudges the risk score
    evidence_text: str = ""       # the exact substring that triggered it, if any


class Source(BaseModel):
    """A live-research result from Tavily, referenced by id in the verdict."""

    id: str                       # "src1", "src2", ...
    title: str
    url: str
    snippet: str
    score: float | None = None


class Entities(BaseModel):
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    phones: list[str] = Field(default_factory=list)
    upi_ids: list[str] = Field(default_factory=list)
    crypto_addresses: list[str] = Field(default_factory=list)
    amounts: list[str] = Field(default_factory=list)
    brands_mentioned: list[str] = Field(default_factory=list)


class ReportingChannel(BaseModel):
    """Where to report — pulled from the curated reporting directory, not the model."""

    region: str
    name: str
    url: str | None = None
    phone: str | None = None
    note: str | None = None
    source: str | None = None


# --------------------------------------------------------------------------- #
#  LLM-filled schemas
# --------------------------------------------------------------------------- #
class Transcription(BaseModel):
    text: str


class MessageContext(BaseModel):
    language: str
    channel: str                  # sms | email | whatsapp | call_transcript | website | social_dm | unknown
    claimed_sender: str
    summary: str
    asked_to: list[str]           # what the user is being pushed to do


class ArchetypeMatch(BaseModel):
    archetype_id: str             # must exist in the taxonomy, or "none"
    name: str
    confidence: float
    rationale: str
    matched_tells: list[str]


class Tell(BaseModel):
    title: str
    explanation: str
    evidence_type: str            # "signal" | "source" | "quote"
    evidence_ref: str             # a Signal.id, a Source.id, or "quote"
    quote: str = ""               # exact substring from the input when evidence_type == "quote"


class Verdict(BaseModel):
    risk_level: RiskLevel
    score: int                    # 0-100
    headline: str
    tells: list[Tell]
    reasoning: str


class RejectedClaim(BaseModel):
    """A tell the model proposed but the verifier threw out — the visible proof
    that model output is not taken on faith."""

    title: str
    evidence_type: str
    evidence_ref: str = ""
    reason: str


class EvidenceAudit(BaseModel):
    proposed: int = 0             # findings the model returned
    kept: int = 0                 # findings backed by real evidence
    rejected: int = 0             # findings dropped as unsupported


class ActionStep(BaseModel):
    step: str
    why: str


class ActionDraft(BaseModel):
    do_now: list[ActionStep]
    do_not: list[str]
    how_to_verify: list[str]
    safe_reply: str               # a reply the user could send, or "" if replying isn't advised


# --------------------------------------------------------------------------- #
#  API surface
# --------------------------------------------------------------------------- #
class ActionPlan(BaseModel):
    do_now: list[ActionStep] = Field(default_factory=list)
    do_not: list[str] = Field(default_factory=list)
    how_to_verify: list[str] = Field(default_factory=list)
    report_to: list[ReportingChannel] = Field(default_factory=list)
    safe_reply: str = ""


class AnalysisResult(BaseModel):
    input_kind: str               # text | image | url | sample
    extracted_text: str
    context: MessageContext
    entities: Entities
    signals: list[Signal]
    sources: list[Source]
    archetype: ArchetypeMatch
    archetype_how: str = ""                 # curated "how this con works" text
    archetype_refs: list[dict] = Field(default_factory=list)   # curated citations
    verdict: Verdict
    evidence_audit: EvidenceAudit = Field(default_factory=EvidenceAudit)
    rejected_claims: list[RejectedClaim] = Field(default_factory=list)
    not_proven: list[str] = Field(default_factory=list)   # what the analysis can't confirm on its own
    action_plan: ActionPlan
    coverage_notes: list[str] = Field(default_factory=list)
    disclaimer: str = ""


class AnalyzeRequest(BaseModel):
    text: str | None = None
    url: str | None = None
    region_hint: str | None = None   # ISO-2 like "IN", "US", "GB"; helps pick reporting channels


class StepEvent(BaseModel):
    """One server-sent event describing a pipeline step."""

    step: str
    status: str                   # started | done | skipped | error
    message: str
    data: dict | None = None
