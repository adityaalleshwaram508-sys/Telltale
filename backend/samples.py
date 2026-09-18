"""Labelled examples used by the demo and the evaluation harness.

This is a small, hand-authored set — not a production benchmark. It deliberately
spans the common scam archetypes, a few multilingual/adversarial cases, and a set
of *legitimate* control messages (including ones naive keyword filters get wrong,
like a real bank OTP alert or a genuine payment reminder). `expect_archetype` is
scored by the eval; `expect_scam` drives the detection metrics.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    id: str
    label: str
    kind: str                  # sms | whatsapp | email | call_transcript | social_dm
    region_hint: str | None
    expect_archetype: str      # taxonomy id, or "none" for legitimate
    expect_scam: bool
    text: str


SAMPLES: list[Sample] = [
    # ---------------- scams ----------------
    Sample(
        id="upi_refund", label="'Refund' asking for your UPI PIN",
        kind="call_transcript", region_hint="IN",
        expect_archetype="otp_upi", expect_scam=True,
        text=("Caller: Sir I am calling from Paytm. Your KYC has expired and a refund of "
              "Rs 4,999 is pending. To receive the refund please open your UPI app and "
              "enter your UPI PIN when you get the request. Do not disconnect the call, "
              "stay on the line while I guide you. If you don't do it now the account "
              "will be blocked permanently."),
    ),
    Sample(
        id="task_job", label="WhatsApp 'part-time job' task scam",
        kind="whatsapp", region_hint="IN",
        expect_archetype="job_task", expect_scam=True,
        text=("Hello! I'm Priya from Amazon recruitment team. We offer a part time online "
              "job, just like YouTube videos and earn ₹50 per task, ₹3000-5000 daily. "
              "First 3 tasks are free and you get paid immediately. To unlock the "
              "high-commission tasks you make a small refundable deposit of ₹2000. "
              "Interested? Message me on Telegram @priya_hr_amazon to start."),
    ),
    Sample(
        id="delivery_sms", label="Delivery 'fee due' phishing SMS",
        kind="sms", region_hint=None,
        expect_archetype="delivery_package", expect_scam=True,
        text=("INDIA POST: Your parcel is on hold at our warehouse due to incomplete "
              "address. Please update and pay the ₹25 redelivery fee within 24 hours or "
              "it will be returned: https://indiapost-redelivery.top/track"),
    ),
    Sample(
        id="crypto_pig", label="Crypto 'guaranteed returns' DM",
        kind="social_dm", region_hint=None,
        expect_archetype="investment_crypto", expect_scam=True,
        text=("Hi, sorry wrong number! But since we're talking 😊 — I work in crypto and my "
              "mentor's signals make 20-30% a week, guaranteed. I've withdrawn profits "
              "twice already. You can start with just $200 on this platform (link only "
              "works through me): https://gtx-globaltrade.xyz/join. When you want to "
              "withdraw there's a small 10% tax fee first, totally normal."),
    ),
    Sample(
        id="digital_arrest", label="'Digital arrest' police impersonation",
        kind="call_transcript", region_hint="IN",
        expect_archetype="impersonation_authority", expect_scam=True,
        text=("This is Inspector Sharma, Cyber Crime Branch. A parcel in your name "
              "containing illegal items and linked to a money-laundering case has been "
              "seized. An arrest warrant is being prepared. You must stay on this video "
              "call, do not tell your family, and transfer ₹85,000 to this verification "
              "account for RBI clearance to prove your funds are clean. Failure means "
              "immediate arrest."),
    ),
    Sample(
        id="netflix_phish", label="Netflix 'payment failed' phishing",
        kind="email", region_hint=None,
        expect_archetype="phishing_account", expect_scam=True,
        text=("Netflix: We couldn't process your payment. Your account will be suspended "
              "within 24 hours. Update your billing details now to avoid interruption: "
              "http://netflix-billing.top/renew"),
    ),
    Sample(
        id="sbi_kyc", label="Bank 'KYC expired' phishing SMS",
        kind="sms", region_hint="IN",
        expect_archetype="phishing_account", expect_scam=True,
        text=("SBI Alert: Your KYC has expired and your account will be suspended within "
              "24 hours. Verify immediately to avoid blocking: "
              "https://sbi-kyc-update.xyz/login"),
    ),
    Sample(
        id="tech_support", label="Tech-support pop-up / remote access",
        kind="call_transcript", region_hint=None,
        expect_archetype="tech_support", expect_scam=True,
        text=("Microsoft Support: We detected a virus on your computer sending your bank "
              "details to hackers. Do not turn it off. Call our engineer now and install "
              "AnyDesk so we can remove the threat and secure your account."),
    ),
    Sample(
        id="lottery", label="'You won the lottery' prize scam",
        kind="sms", region_hint="IN",
        expect_archetype="prize_lottery", expect_scam=True,
        text=("Congratulations! You have won the KBC lucky lottery of ₹25,00,000. Your "
              "number was selected today. To claim your prize, pay a small refundable "
              "processing fee of ₹6,500 and share your bank details. Claim within 2 hours."),
    ),
    Sample(
        id="inheritance", label="Advance-fee inheritance email",
        kind="email", region_hint=None,
        expect_archetype="advance_fee", expect_scam=True,
        text=("Dear Friend, I am a bank manager. A client who died left $10.5 million with "
              "no next of kin. You have been chosen as the beneficiary. To release the "
              "funds I only need a small clearance fee sent by wire transfer, and your "
              "bank account details to process the transfer."),
    ),
    Sample(
        id="refund_overpay", label="Overpayment 'send it back' scam",
        kind="email", region_hint=None,
        expect_archetype="refund_overpayment", expect_scam=True,
        text=("We processed your refund but accidentally sent $500 too much — see the "
              "attached deposit confirmation. Please return the extra $500 by buying "
              "Google Play gift cards and sending us the redeem codes today, before our "
              "audit closes."),
    ),
    Sample(
        id="family_emergency", label="'Mum, new number' emergency scam",
        kind="whatsapp", region_hint=None,
        expect_archetype="family_emergency", expect_scam=True,
        text=("Hi mum, I dropped my phone in water so this is my new number. I'm fine but "
              "I urgently need to pay a bill and I'm locked out of my banking. Can you "
              "send ₹18,000 right now? I'll pay you back tonight, promise. Don't call the "
              "old number, it's dead."),
    ),
    Sample(
        id="loan_app", label="Predatory instant-loan offer",
        kind="sms", region_hint="IN",
        expect_archetype="loan_app", expect_scam=True,
        text=("Instant loan approved! ₹50,000 ready, no documents, no credit check. Just "
              "pay a ₹999 processing fee to release the amount and download our app "
              "(allow contacts and gallery access to complete verification)."),
    ),
    Sample(
        id="marketplace_qr", label="Marketplace QR 'to receive money' scam",
        kind="whatsapp", region_hint="IN",
        expect_archetype="marketplace", expect_scam=True,
        text=("Hi, I want to buy your sofa on OLX, I'm an army officer posted out of "
              "station so I'll pay in advance by UPI. I'm sending a QR code — just scan it "
              "and enter your UPI PIN to receive the ₹8,000 payment. Please do it fast, "
              "I'm on duty."),
    ),
    Sample(
        id="bec_invoice", label="Vendor 'bank details changed' (BEC)",
        kind="email", region_hint=None,
        expect_archetype="business_invoice", expect_scam=True,
        text=("Hi, regarding invoice INV-2087 — please note our bank details have changed. "
              "Kindly NEFT the payment to our updated account instead of the old one. "
              "Send it today so we can clear the order. Confirm once transferred. "
              "Regards, Accounts."),
    ),
    Sample(
        id="hinglish_job", label="Hinglish work-from-home scam",
        kind="whatsapp", region_hint="IN",
        expect_archetype="job_task", expect_scam=True,
        text=("Namaste! Ghar baithe part time job karo, ₹5000 daily kamao. Bas ek chhota "
              "registration fee ₹500 UPI pe bhejo aur aaj hi start karo. WhatsApp par "
              "reply karo, limited seats hain, jaldi karo."),
    ),

    # ---------------- legitimate controls ----------------
    Sample(
        id="legit_order", label="Order confirmation (control)",
        kind="email", region_hint=None,
        expect_archetype="none", expect_scam=False,
        text=("Your Amazon order #402-5518923-7712 has shipped. Your package with "
              "\"USB-C cable (2m)\" will arrive Thursday. Track it in the Amazon app or at "
              "amazon.in. No action is needed. If you didn't place this order, review your "
              "orders in Your Account."),
    ),
    Sample(
        id="legit_otp", label="Genuine bank OTP alert (control)",
        kind="sms", region_hint="IN",
        expect_archetype="none", expect_scam=False,
        text=("456123 is your one-time password (OTP) for logging in. It is valid for 10 "
              "minutes. Do not share it with anyone. - HDFC Bank"),
    ),
    Sample(
        id="legit_appointment", label="Appointment reminder (control)",
        kind="sms", region_hint=None,
        expect_archetype="none", expect_scam=False,
        text=("Reminder: your dentist appointment is tomorrow at 4:00 PM with Dr. Rao. "
              "Reply YES to confirm, or call the clinic to reschedule."),
    ),
    Sample(
        id="legit_bill", label="Utility bill reminder (control)",
        kind="sms", region_hint="IN",
        expect_archetype="none", expect_scam=False,
        text=("Your electricity bill of ₹1,240 is due on 25 Sep. Pay through the official "
              "BESCOM website or app. Please ignore this message if you've already paid."),
    ),
    Sample(
        id="legit_delivery", label="Genuine delivery notice (control)",
        kind="sms", region_hint=None,
        expect_archetype="none", expect_scam=False,
        text=("Your Amazon package will be delivered today between 6 and 9 PM. Track it in "
              "the Amazon app. No signature required."),
    ),
    Sample(
        id="legit_bank_debit", label="Genuine transaction alert (control)",
        kind="sms", region_hint="IN",
        expect_archetype="none", expect_scam=False,
        text=("HDFC Bank: Rs 2,500 debited from a/c XX1234 on 16-Sep for a UPI payment to "
              "Zomato. Not you? Call 18002586161."),
    ),
    Sample(
        id="legit_job", label="Genuine interview invite (control)",
        kind="email", region_hint="IN",
        expect_archetype="none", expect_scam=False,
        text=("Thank you for applying to Infosys. Your interview is scheduled for Monday "
              "at 10:00 AM. No fee is required at any stage of our hiring process. Please "
              "reply to confirm your availability."),
    ),
    Sample(
        id="legit_receipt", label="Genuine payment receipt (control)",
        kind="email", region_hint=None,
        expect_archetype="none", expect_scam=False,
        text=("Thanks for your payment of ₹499 to Spotify Premium. Your subscription is "
              "active until 16 Oct. Manage your plan anytime in the app. This is a receipt "
              "for your records; no action is needed."),
    ),
]

_BY_ID = {s.id: s for s in SAMPLES}


def get_sample(sample_id: str) -> Sample | None:
    return _BY_ID.get(sample_id)


# A curated subset shown as clickable chips in the UI (keeps the demo focused).
DEMO_IDS = ["upi_refund", "task_job", "delivery_sms", "crypto_pig",
            "digital_arrest", "legit_order"]
