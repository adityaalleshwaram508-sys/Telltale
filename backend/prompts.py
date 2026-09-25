"""Prompt builders for each Nemotron step. The verifier re-checks everything these ask for."""

from __future__ import annotations

import json

from backend.knowledge import archetype_ids, archetype_menu
from backend.schemas import Entities, MessageContext, Signal, Source

ANALYST_PERSONA = (
    "You are Telltale, a careful fraud analyst who helps ordinary people decide "
    "whether a message, call, or website is a scam before they act. You are calm, "
    "plain-spoken, and you never overstate certainty. You reason strictly over the "
    "evidence provided to you. You never invent facts, URLs, sources, agencies, "
    "phone numbers, or legal claims. When evidence is thin, you say so."
)


# --- Step: transcribe a screenshot -----------------------------------------
def vision_system() -> str:
    return (
        "You transcribe the text content of a screenshot of a message, email, chat, "
        "call log, or web page. Output the visible text faithfully, including sender "
        "names, phone numbers, links, and buttons. Do not summarise, translate, or "
        "add commentary. Just the text as it appears."
    )


def vision_user() -> str:
    return (
        "Transcribe all readable text in the attached image(s). Preserve links, "
        "numbers, and sender info exactly."
    )


# --- Step: read the message context ----------------------------------------
def context_system() -> str:
    return ANALYST_PERSONA


def context_user(text: str) -> str:
    return (
        "Read this message and describe it factually.\n\n"
        f'MESSAGE:\n"""\n{text.strip()}\n"""\n\n'
        "Fill in:\n"
        "- language: the language the message is written in (e.g. English, Hindi, Hinglish).\n"
        "- channel: one of sms, email, whatsapp, call_transcript, website, social_dm, unknown.\n"
        "- claimed_sender: who or what the message claims to be from (a bank, a courier, "
        "a person, a company). Use 'unknown' if it doesn't say.\n"
        "- summary: one plain sentence a normal person would understand.\n"
        "- asked_to: the specific actions it pushes the reader to take (e.g. 'click a link', "
        "'share an OTP', 'pay a fee', 'install an app', 'call a number'). Empty list if none."
    )


# --- Step: classify the archetype ------------------------------------------
def classify_system() -> str:
    return ANALYST_PERSONA


def classify_user(text: str, context: MessageContext) -> str:
    ids = ", ".join(archetype_ids())
    return (
        "Decide which known scam archetype this message best matches. If it matches "
        'none of them, or looks legitimate, use archetype_id "none".\n\n'
        f"KNOWN ARCHETYPES:\n{archetype_menu()}\n\n"
        f'You must choose archetype_id from exactly this list (or "none"): {ids}\n\n'
        f"MESSAGE CONTEXT: claimed to be from {context.claimed_sender}; "
        f"channel {context.channel}; it asks the reader to: {', '.join(context.asked_to) or 'nothing specific'}.\n\n"
        f'MESSAGE:\n"""\n{text.strip()}\n"""\n\n'
        "Give a confidence 0-1, a one-paragraph rationale, and matched_tells, meaning short "
        "phrases describing the concrete giveaways you actually see in THIS message."
    )


# --- Step: synthesise the verdict ------------------------------------------
def _signals_block(signals: list[Signal]) -> str:
    if not signals:
        return "(none)"
    rows = [
        {
            "id": s.id,
            "label": s.label,
            "detail": s.detail,
            "evidence_text": s.evidence_text,
            "severity": s.severity,
        }
        for s in signals
    ]
    return json.dumps(rows, ensure_ascii=False, indent=2)


def _sources_block(sources: list[Source]) -> str:
    if not sources:
        return "(no live sources)"
    rows = [
        {
            "id": s.id,
            "searched_for": s.about,
            "mentions": s.mentions,
            "title": s.title,
            "url": s.url,
            "snippet": s.snippet,
        }
        for s in sources
    ]
    return json.dumps(rows, ensure_ascii=False, indent=2)


def verdict_system() -> str:
    return (
        ANALYST_PERSONA + "\n\n"
        "Scale for risk_level:\n"
        "- critical: almost certainly a scam; acting on it will likely cause loss.\n"
        "- high: likely a scam; strong tells, treat as dangerous.\n"
        "- medium: suspicious; some tells, verify before doing anything.\n"
        "- low: probably legitimate, but a sensible check is still worth it.\n"
        "- info: no meaningful scam signals found.\n\n"
        "Hard rules for tells:\n"
        "- Each tell cites exactly one piece of evidence: evidence_type is 'signal', 'source' or 'quote'.\n"
        "- 'signal': evidence_ref is one of the given signal ids. A signal is something the code "
        "found in the message; never use one to say the message was reported, blacklisted or "
        "confirmed by anyone.\n"
        "- 'quote': evidence_ref is 'quote' and quote is at least two words copied exactly from the "
        "message. Never quote words the message uses in the negative, such as 'do not share'.\n"
        "- 'source': evidence_ref is one of the given source ids and support is a sentence or "
        "phrase of at least four words copied exactly from that source's title or snippet. Only "
        "say a specific link, number or account was reported if that source lists it under "
        "mentions; otherwise describe the source as evidence of the general scam pattern.\n"
        "- Set quote and support to an empty string when they don't apply.\n"
        "- Never cite an id that was not provided. Prefer 3-6 of the strongest tells; do not pad."
    )


def verdict_user(
    text: str,
    context: MessageContext,
    entities: Entities,
    signals: list[Signal],
    sources: list[Source],
    archetype_name: str,
    archetype_how: str,
    signal_floor: int,
) -> str:
    return (
        f'MESSAGE:\n"""\n{text.strip()}\n"""\n\n'
        f"WHAT IT CLAIMS TO BE: {context.claimed_sender} (channel: {context.channel})\n"
        f"BEST-MATCH ARCHETYPE: {archetype_name}\n"
        f"HOW THAT CON USUALLY WORKS: {archetype_how}\n\n"
        f"DETERMINISTIC SIGNALS (found by code, trustworthy facts):\n{_signals_block(signals)}\n\n"
        f"LIVE RESEARCH RESULTS (from web search):\n{_sources_block(sources)}\n\n"
        f"The detector signals set a floor of {signal_floor}/100 that is enforced in code, so a "
        f"lower score will be raised to it. If you think a signal is a false positive, say so in "
        f"the reasoning. Go higher when the archetype and live research warrant it.\n\n"
        "Produce the verdict: risk_level, score (0-100), a one-sentence headline in plain "
        "language, the tells (each bound to evidence per the rules), and a short reasoning "
        "paragraph tying it together."
    )


# --- Step: action plan + safe reply ----------------------------------------
def action_system() -> str:
    return (
        ANALYST_PERSONA + "\n\n"
        "Give practical, specific guidance for THIS message. Steps must be concrete "
        "('call the number on the back of your card, not the one in the message'), not "
        "generic ('be careful'). The safe_reply, if any, should be short and firm, in "
        "the same language as the original message. If replying is unwise (e.g. it would "
        'confirm the number is live), set safe_reply to "" and say so in do_not.'
    )


def action_user(text: str, context: MessageContext, risk_level: str, archetype_name: str) -> str:
    return (
        f"The message (claiming to be {context.claimed_sender}, via {context.channel}) has "
        f"been assessed as risk level '{risk_level}', best matching a {archetype_name}.\n\n"
        f'MESSAGE:\n"""\n{text.strip()}\n"""\n\n'
        "Give:\n"
        "- do_now: 3-5 concrete steps, each with a one-line 'why'.\n"
        "- do_not: short, blunt list of things NOT to do.\n"
        "- how_to_verify: concrete ways to independently confirm the truth for this specific case.\n"
        f'- safe_reply: a short reply in {context.language} the person could send, or "" if '
        "replying is unwise."
    )
