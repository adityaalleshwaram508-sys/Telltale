"""Detects the payment rails scammers favour because they're hard to reverse.

Grounded in the FTC's guidance that gift cards, wire transfers, crypto and
payment-app transfers are the telltale rails — "anyone who says you can only pay
in one of these ways is probably a scammer".
https://consumer.ftc.gov/consumer-alerts/2026/07/way-spot-scams-how-someone-asks-you-pay
"""
from __future__ import annotations

import re

from backend.schemas import Entities, Signal

_RAILS = {
    "payment.gift_card": {
        "label": "Payment demanded in gift cards",
        "severity": 3,
        "why": "Gift cards are the FTC's #1 scam payment tell — untraceable and irreversible.",
        "patterns": [
            r"gift ?card", r"google play card", r"itunes card", r"amazon (?:gift )?card",
            r"steam card", r"redeem code", r"voucher code",
        ],
    },
    "payment.crypto": {
        "label": "Payment or investment in cryptocurrency",
        "severity": 2,
        "why": "Crypto transfers can't be reversed and are a top rail for investment and extortion scams.",
        "patterns": [
            r"bitcoin", r"\bbtc\b", r"\busdt\b", r"\beth\b", r"ethereum",
            r"crypto", r"binance", r"trust wallet", r"wallet address",
        ],
    },
    "payment.wire": {
        "label": "Wire / bank transfer to an unfamiliar account",
        "severity": 2,
        "why": "Wire and account transfers are near-impossible to claw back once sent.",
        "patterns": [
            r"wire transfer", r"western union", r"moneygram", r"bank transfer",
            r"neft", r"\brtgs\b", r"\bimps\b",
            r"transfer .{0,25}account", r"(?:safe|verification|secure|clearance) account",
            r"account (?:number|no\.?)\s*[:\-]?\s*\d{6,}",
            r"bank details have changed", r"details have changed", r"updated account",
        ],
    },
    "payment.upi_collect": {
        "label": "UPI 'collect'/QR request to pull money from you",
        "severity": 3,
        "why": "You never enter a PIN or approve a request to RECEIVE money — that only ever sends it.",
        "patterns": [
            r"scan (?:this |the )?qr", r"collect request", r"approve the request",
            r"enter (?:your )?(?:upi )?pin to receive", r"accept the payment request",
        ],
    },
}


def analyze_payments(text: str, entities: Entities) -> list[Signal]:
    signals: list[Signal] = []
    for sig_id, spec in _RAILS.items():
        for pat in spec["patterns"]:
            m = re.search(pat, text, flags=re.I)
            if m:
                signals.append(Signal(
                    id=sig_id, category="payment",
                    label=spec["label"], detail=spec["why"],
                    severity=spec["severity"], evidence_text=m.group(0),
                ))
                break

    # A crypto address in the body is concrete proof of a crypto rail even if the
    # word "bitcoin" never appears.
    if entities.crypto_addresses and not any(s.id == "payment.crypto" for s in signals):
        signals.append(Signal(
            id="payment.crypto", category="payment",
            label="Cryptocurrency wallet address present",
            detail="A wallet address was included — crypto payments are irreversible.",
            severity=2, evidence_text=entities.crypto_addresses[0],
        ))
    return signals
