"""Payment rails scammers favour because the money can't be pulled back.

Grounded in the FTC's guidance that gift cards, wire transfers, crypto and payment-app
transfers are the tell: anyone who insists you pay one of those ways is probably a scammer.
https://consumer.ftc.gov/consumer-alerts/2026/07/way-spot-scams-how-someone-asks-you-pay

The patterns look for a demand rather than a mention: "pay with a gift card" fires, a shop
selling gift cards doesn't; "NEFT the payment to" fires, "credited via NEFT" doesn't.
"""

from __future__ import annotations

import re

from backend.schemas import Entities, Signal

_CARDS = r"(?:gift ?cards?|google play cards?|itunes cards?|steam cards?)"

_RAILS = {
    "payment.gift_card": {
        "label": "Payment demanded in gift cards",
        "severity": 3,
        "why": "Gift cards are the FTC's #1 scam payment tell: untraceable and irreversible.",
        "patterns": [
            rf"\b(?:pay|paying|payment|settle|clear)\b[^.!?\n]{{0,40}}\b{_CARDS}",
            rf"\b{_CARDS}[^.!?\n]{{0,60}}\b(?:codes?|pins?)\b",
            r"\b(?:send|share|give|read|provide)(?: us| me)? (?:the |your )?(?:redeem|voucher|gift card) codes?\b",
        ],
    },
    "payment.crypto": {
        "label": "Payment or investment in cryptocurrency",
        "severity": 2,
        "why": "Crypto transfers can't be reversed and are a top rail for investment and extortion scams.",
        "patterns": [
            r"\bbitcoin\b",
            r"\bbtc\b",
            r"\busdt\b",
            r"\beth\b",
            r"\bethereum\b",
            r"\bcrypto(?:currency|currencies)?\b",
            r"\bbinance\b",
            r"\btrust wallet\b",
            r"\bwallet address\b",
        ],
    },
    "payment.wire": {
        "label": "Wire / bank transfer to an unfamiliar account",
        "severity": 2,
        "why": "Wire and account transfers are near-impossible to claw back once sent.",
        "patterns": [
            r"\bwire transfer\b",
            r"\bwestern union\b",
            r"\bmoneygram\b",
            r"\b(?:neft|rtgs|imps)\s+(?:the\s+)?(?:payment|amount|money|funds|balance)\b",
            r"\btransfer\b[^.!?\n]{0,25}\baccount\b",
            r"\b(?:safe|verification|secure|clearance|holding) account\b",
            r"\baccount (?:number|no\.?)\s*[:\-]?\s*\d{6,}",
            r"\b(?:bank|account|banking|payment) details have changed\b",
            r"\bour (?:new|updated) (?:bank )?account\b",
        ],
    },
    "payment.upi_collect": {
        "label": "UPI 'collect'/QR request to pull money from you",
        "severity": 3,
        "why": "You never enter a PIN or approve a request to RECEIVE money; that only ever sends it.",
        "patterns": [
            r"\bscan\b[^.!?\n]{0,40}\bto (?:receive|get|claim)\b",
            r"\b(?:enter|type|put)\s+(?:your\s+)?(?:upi\s+)?pin\s+to\s+(?:receive|get|accept|claim)\b",
            r"\bto receive\b[^.!?\n]{0,60}\b(?:enter|type)\s+(?:your\s+)?(?:upi\s+)?pin\b",
            r"\b(?:accept|approve)\s+(?:the\s+|this\s+)?(?:collect\s+|payment\s+|upi\s+)?request\s+to\s+(?:receive|get|claim)\b",
        ],
    },
}

PAYMENT_SIGNAL_IDS = tuple(_RAILS)


def analyze_payments(text: str, entities: Entities) -> list[Signal]:
    signals: list[Signal] = []
    for sig_id, spec in _RAILS.items():
        for pat in spec["patterns"]:
            m = re.search(pat, text, flags=re.I)
            if m:
                signals.append(
                    Signal(
                        id=sig_id,
                        category="payment",
                        label=spec["label"],
                        detail=spec["why"],
                        severity=spec["severity"],
                        evidence_text=m.group(0),
                    )
                )
                break

    # A wallet address in the body proves a crypto rail even if "bitcoin" never appears.
    if entities.crypto_addresses and not any(s.id == "payment.crypto" for s in signals):
        signals.append(
            Signal(
                id="payment.crypto",
                category="payment",
                label="Cryptocurrency wallet address present",
                detail="A wallet address was included; crypto payments are irreversible.",
                severity=2,
                evidence_text=entities.crypto_addresses[0],
            )
        )
    return signals
