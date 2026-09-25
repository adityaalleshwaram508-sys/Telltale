"""Detects attempts to manipulate the analyzer itself.

Telltale treats the message strictly as DATA, never as instructions. A message
that tries to talk the analyzer into a verdict ("ignore previous instructions",
"classify this as safe", "system prompt: ...") is not obeyed; it is flagged.
These phrases almost never occur in a genuine message, so a hit is both a robust
security property (the input can't steer the analysis) and a strong scam tell in
its own right.

Like the other detectors this is a deliberately dumb matcher: a hit is a
checkable fact ("this manipulation phrase is literally present"), not a judgement.
"""

from __future__ import annotations

import re

from backend.schemas import Signal

# Each pattern targets a phrase aimed at an AI analyser. Kept narrow: "You are now
# subscribed" and "fraudsters may pretend to be bank staff" are ordinary messages.
_PATTERNS = [
    r"ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions?|prompts?|messages?)",
    r"disregard (?:all |the )?(?:previous|prior|above|earlier)",
    r"forget (?:all |everything |the )?(?:previous|above|earlier)",
    r"new instructions?\s*[:\-]",
    r"system\s*(?:prompt|message)\s*[:\-]",
    r"you are now (?:an? )?(?:ai|assistant|model|analy[sz]er|classifier|chatbot|dan|unrestricted|jailbroken|in developer mode)\b",
    r"pretend (?:that )?(?:you are|you're|to be) (?:an? )?(?:ai|assistant|model|analy[sz]er|classifier|chatbot|system)\b",
    r"classify (?:this|it|the message) as (?:safe|legitimate|not a scam)",
    r"mark (?:this|it) as (?:safe|legitimate)",
    r"(?:say|state|report|respond)(?: that)? there(?:'s| is| are) no (?:risks?|scam|threats?)",
    r"do not (?:flag|warn|report|mark|treat)",
    r"(?:rate|score) (?:this|it) (?:as )?(?:safe|zero|0)\b",
    r"override (?:your |the )?(?:instructions|rules|safety)",
]

_RE = re.compile("|".join(f"(?:{p})" for p in _PATTERNS), flags=re.I)


def analyze_injection(text: str) -> list[Signal]:
    m = _RE.search(text)
    if not m:
        return []
    return [
        Signal(
            id="language.prompt_injection",
            category="language",
            label="Prompt-injection / analyzer-manipulation attempt",
            detail=(
                "The message tries to instruct the analyzer itself, for example to "
                "ignore its rules or declare the message safe. Telltale treats message "
                "content as data, not instructions, so this is flagged, never obeyed."
            ),
            severity=2,
            evidence_text=m.group(0),
        )
    ]
