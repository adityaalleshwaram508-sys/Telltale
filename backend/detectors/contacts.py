"""Contact-channel mismatches.

A real bank or government office doesn't email you from a gmail address. When a
message name-drops an official brand but the actual contact address is a free
webmail account, that gap is worth flagging on its own.
"""
from __future__ import annotations

from backend.schemas import Entities, Signal

_FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "proton.me", "protonmail.com", "rediffmail.com",
    "aol.com", "icloud.com", "mail.com", "gmx.com", "zoho.com",
}


def analyze_contacts(text: str, entities: Entities) -> list[Signal]:
    signals: list[Signal] = []
    if not entities.brands_mentioned:
        return signals

    for email in entities.emails:
        domain = email.split("@")[-1].lower()
        if domain in _FREEMAIL:
            signals.append(Signal(
                id="contact.freemail_impersonation", category="contact",
                label="'Official' message sent from free webmail",
                detail=(f"The message invokes {', '.join(entities.brands_mentioned)} but the "
                        f"contact address {email} is a personal {domain} account, not a "
                        f"corporate one."),
                severity=2, evidence_text=email,
            ))
    return signals
