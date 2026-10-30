"""
ScamShield PK — knowledge base (the "expert knowledge").

Viva: this file is DATA, not the reasoning program. The engine in engine.py
reads RULES and fires them. Adding a new scam pattern means adding a dict here;
you do not rewrite if/else in the engine.

Layers (family-tree generations):
  0 FACTS   — what the user observed (checkboxes)
  1 FLAGS   — intermediate red flags (R01–R36 plus extra R71–R100)
  2 TYPES   — which scam it looks like (R37–R50 plus extra R101–R104)
  3 RISK    — critical / high / medium / low (R51–R54, first match)
  4 ACTIONS — what to do now (R55–R70 plus extra R105–R110)
"""

# ---------------------------------------------------------------------------
# Layer 0 — user-visible facts (38). Labels are the checkbox text.
# Channel is a radio (pick one). Everything else is a checkbox.
# ---------------------------------------------------------------------------

CHANNEL_FACTS = [
    ("channel_sms", "SMS / text message"),
    ("channel_call", "Phone call"),
    ("channel_whatsapp", "WhatsApp"),
    ("channel_email", "Email"),
    ("channel_marketplace", "Marketplace (OLX, Facebook Marketplace, etc.)"),
    ("channel_social", "Social media (Facebook, Instagram, TikTok, etc.)"),
]

SENDER_FACTS = [
    ("unknown_sender", "Sender is unknown / not in my contacts"),
    ("claims_bank", "They claim to be from a bank"),
    ("claims_wallet", "They claim to be from JazzCash / Easypaisa / a wallet"),
    ("claims_govt", "They claim to be from government (BISP / Ehsaas / FIA / FBR / PTA)"),
    ("claims_courier", "They claim to be from a courier (TCS, Leopards, Pakistan Post, etc.)"),
    ("claims_relative", "They claim to be a family member or close friend"),
    ("claims_recruiter", "They claim to be a recruiter / employer"),
    ("claims_tech_support", "They claim to be tech support (Microsoft, Jazz, PTCL, etc.)"),
]

ASKS_FACTS = [
    ("asks_otp", "They ask for an OTP / one-time code"),
    ("asks_pin_password", "They ask for PIN, password, or MPIN"),
    ("asks_cnic_card", "They ask for CNIC number or a card photo"),
    ("asks_install_app", "They ask me to install an app (AnyDesk, TeamViewer, unknown APK)"),
    ("asks_click_link", "They ask me to tap / open a link"),
    ("asks_fee_upfront", "They ask for an upfront fee (registration, tax, release fee)"),
    ("asks_load_giftcard", "They ask me to load / send gift cards"),
    ("asks_personal_account", "They ask me to send money to a personal account"),
    ("asks_advance_marketplace", "They ask for advance payment before meetup / delivery"),
]

PRESSURE_FACTS = [
    ("deadline", "They give a short deadline (act now / today only)"),
    ("threat_block_arrest", "They threaten account block, FIR, or arrest"),
    ("secrecy_requested", "They say keep this secret / don't tell anyone"),
]

PROMISE_FACTS = [
    ("promises_prize", "They promise a prize, lottery, or lucky draw"),
    ("promises_govt_money", "They promise government money (BISP, Ehsaas, refund, subsidy)"),
    ("promises_easy_job", "They promise an easy / work-from-home job"),
    ("promises_loan_no_docs", "They promise a loan with almost no documents"),
    ("promises_guaranteed_returns", "They promise guaranteed / very high investment returns"),
    ("overpays_buyer", "A buyer offers to pay more than the asking price (then 'refund')"),
]

QUALITY_FACTS = [
    ("link_shortened", "The link is shortened (bit.ly, tinyurl, or similar)"),
    ("link_domain_mismatch", "The link domain does not match the real organisation"),
    ("poor_spelling", "Poor spelling / broken English or Urdu"),
    ("new_number_claim", "They say 'I lost my phone, this is my new number'"),
    ("moves_to_whatsapp", "They quickly move the chat to WhatsApp"),
    ("refuses_cod_meet", "They refuse cash-on-delivery or an in-person meeting"),
]

# Extra Pakistan-specific observations (kept as their own group so the original 38 stay intact).
EXTRA_FACTS = [
    ("claims_utility", "They claim to be from WAPDA / K-Electric / Sui Gas / a bill office"),
    ("claims_nadra", "They claim to be from NADRA / passport / ID-card office"),
    ("claims_university", "They claim to be from a university / HEC / admissions office"),
    ("claims_charity", "They claim to collect charity / flood / mosque donation"),
    ("asks_sim_puk", "They ask for SIM PUK, ICCID, or to 'move my number'"),
    ("asks_share_screen", "They ask me to share my screen / camera"),
    ("asks_qr_pay", "They ask me to scan a JazzCash/Easypaisa QR to 'receive' money"),
    ("asks_apk_file", "They sent an APK / unknown file to install"),
    ("promises_crypto", "They promise USDT / Binance / crypto profit"),
    ("promises_bill_waive", "They promise to waive or refund an electricity/gas bill"),
]

FACT_GROUPS = [
    ("Who they claim to be / sender", SENDER_FACTS),
    ("What they ask for", ASKS_FACTS),
    ("Pressure", PRESSURE_FACTS),
    ("What they promise", PROMISE_FACTS),
    ("Message quality", QUALITY_FACTS),
    ("More Pakistan-specific details", EXTRA_FACTS),
]

FACTS = (
    [f[0] for f in CHANNEL_FACTS]
    + [f[0] for f in SENDER_FACTS]
    + [f[0] for f in ASKS_FACTS]
    + [f[0] for f in PRESSURE_FACTS]
    + [f[0] for f in PROMISE_FACTS]
    + [f[0] for f in QUALITY_FACTS]
    + [f[0] for f in EXTRA_FACTS]
)

FACT_LABELS = {}
for _group in (
    CHANNEL_FACTS, SENDER_FACTS, ASKS_FACTS, PRESSURE_FACTS,
    PROMISE_FACTS, QUALITY_FACTS, EXTRA_FACTS,
):
    for _fid, _label in _group:
        FACT_LABELS[_fid] = _label

# Intermediate conclusions (layer 1) — shown as "red flags" in the UI.
FLAGS = [
    "credential_request",
    "remote_access_request",
    "urgency_pressure",
    "secrecy_isolation",
    "impersonation",
    "too_good",
    "payment_request",
    "suspicious_link",
    "unsolicited_contact",
    "fake_authority",
    "account_takeover",
    "sim_swap_pressure",
    "crypto_lure",
    "charity_pressure",
    "screen_share_request",
    "utility_impersonation",
]

FLAG_LABELS = {
    "credential_request": "Asking for secrets (OTP / PIN / CNIC)",
    "remote_access_request": "Asking to take remote control of the phone",
    "urgency_pressure": "Urgency / fear pressure",
    "secrecy_isolation": "Asked to keep it secret",
    "impersonation": "Likely impersonation",
    "too_good": "Too good to be true",
    "payment_request": "Asking you to pay or send money",
    "suspicious_link": "Suspicious link",
    "unsolicited_contact": "Unsolicited contact from a stranger",
    "fake_authority": "Fake authority / legal threat",
    "account_takeover": "Account-takeover pattern",
    "sim_swap_pressure": "SIM-swap / number-port pressure",
    "crypto_lure": "Crypto / USDT lure",
    "charity_pressure": "Urgency charity / donation ask",
    "screen_share_request": "Asked to share the screen",
    "utility_impersonation": "Fake utility / bill office",
}

# Layer 2 conclusions. Highest CF among these becomes scam_score.
SCAM_TYPES = [
    "wallet_fraud",
    "bank_phishing",
    "govt_aid_scam",
    "job_scam",
    "prize_scam",
    "marketplace_scam",
    "courier_phishing",
    "family_emergency_scam",
    "investment_scam",
    "remote_access_scam",
    "loan_scam",
    "generic_phishing",
    "utility_phishing",
    "sim_swap_scam",
    "crypto_scam",
    "charity_scam",
    "nadra_id_scam",
    "university_admission_scam",
]

SCAM_LABELS = {
    "wallet_fraud": "JazzCash / Easypaisa wallet fraud",
    "bank_phishing": "Bank phishing",
    "govt_aid_scam": "Government-aid (BISP / Ehsaas) scam",
    "job_scam": "Job / recruitment fee scam",
    "prize_scam": "Prize / lottery scam",
    "marketplace_scam": "Marketplace (OLX) scam",
    "courier_phishing": "Courier delivery-link phishing",
    "family_emergency_scam": "Family-emergency ('Mom I lost my phone') scam",
    "investment_scam": "Investment / guaranteed-returns scam",
    "remote_access_scam": "Remote-access / fake tech-support scam",
    "loan_scam": "Easy-loan scam",
    "generic_phishing": "Generic phishing",
    "utility_phishing": "Utility-bill (WAPDA / K-Electric / Sui) phishing",
    "sim_swap_scam": "SIM-swap / number-port scam",
    "crypto_scam": "Crypto / USDT investment scam",
    "charity_scam": "Fake charity / disaster-donation scam",
    "nadra_id_scam": "Fake NADRA / ID-card scam",
    "university_admission_scam": "Fake university / HEC admission-fee scam",
}

RISK_LEVELS = ["risk_critical", "risk_high", "risk_medium", "risk_low"]

RISK_LABELS = {
    "risk_critical": "Critical",
    "risk_high": "High",
    "risk_medium": "Medium",
    "risk_low": "Low",
}

# verify before submission
HELPLINES = {
    "FIA NR3C cybercrime helpline": "1991",
    "FIA cybercrime reporting": "https://complaint.fia.gov.pk/ (verify before submission)",
    "PTA complaint line": "0800-55055",
    "Easypaisa": "3737",
    "JazzCash": "4444",
    "BISP / Ehsaas": "8171",
    "NADRA": "1515",
    "K-Electric": "118",
}

# 2–4 short bullets the user should follow. Keys match layer-4 rule "then" values.
ACTIONS = {
    "act_wallet_fraud": [
        "Never share OTP/PIN with anyone, including people who say they are 'agents'.",
        "Hang up and call the wallet's official helpline from its app (JazzCash 4444 / Easypaisa 3737).",
        "If you already sent money, report it to the wallet and to FIA NR3C immediately.",
    ],
    "act_bank_phishing": [
        "Banks never ask for OTP, PIN, or full card details over call, SMS, or email.",
        "Open the official bank app yourself; do not use the sender's link.",
        "Call the number printed on your debit card if you are unsure.",
    ],
    "act_govt_aid_scam": [
        "BISP/Ehsaas will not ask you to click a random SMS link or pay a 'release fee'.",
        "Confirm only on the official portal or by calling 8171.",
        "Do not share CNIC photos with unknown numbers.",
    ],
    "act_job_scam": [
        "Real employers never charge registration, training, or 'file opening' fees.",
        "Do not pay anything to get the job.",
        "Verify the company on its official website and a real LinkedIn page.",
    ],
    "act_prize_scam": [
        "You cannot win a lottery you never entered. Do not pay tax/fee to 'release' a prize.",
        "Ignore the message and block the sender.",
    ],
    "act_marketplace_scam": [
        "Meet in person or use cash on delivery only.",
        "Never accept 'I overpaid, please refund the extra' — that is a classic OLX scam.",
        "Do not share OTPs to 'receive' money.",
    ],
    "act_courier_phishing": [
        "Do not tap the tracking link in the SMS.",
        "Track the parcel only inside the courier's official app or website.",
        "Couriers do not ask for CNIC OTP to deliver a packet.",
    ],
    "act_family_emergency_scam": [
        "Call your relative on their old number, not the new one in the chat.",
        "Never send money based on a text alone.",
        "Ask a question only they would know (a family nickname, last visit, etc.).",
    ],
    "act_investment_scam": [
        "Guaranteed high returns are a warning sign, not an opportunity.",
        "Do not send money to personal accounts or 'recovery' wallets.",
        "Check SECP / official company filings before investing.",
    ],
    "act_remote_access_scam": [
        "Do not install AnyDesk, TeamViewer, or an APK a caller sent you.",
        "Hang up. Real Microsoft / Jazz / bank staff will not ask to control your phone.",
        "If you already installed it, uninstall, change passwords, and call your bank/wallet.",
    ],
    "act_loan_scam": [
        "A real loan needs documents; 'no documents + small processing fee' is a scam.",
        "Do not pay any fee to 'unlock' a loan.",
        "Use only licensed banks / microfinance institutions.",
    ],
    "act_generic_phishing": [
        "Do not click the link. Hover or inspect the real URL if you can.",
        "Go to the organisation by typing its address yourself or using its app.",
        "When unsure, call the official helpline from their website, not the message.",
    ],
    "act_stop_and_report": [
        "Stop all contact with this sender now.",
        "Report to FIA NR3C (helpline 1991) and keep screenshots as evidence.",
        "Contact your bank/wallet to freeze or watch the account.",
    ],
    "act_block_and_report": [
        "Block the number / account.",
        "Do not click links or send money.",
        "Report the sender to PTA (0800-55055) and, if money moved, to FIA 1991.",
    ],
    "act_verify_officially": [
        "Pause. Verify through an official channel you already trust (app, printed helpline).",
        "Do not use contact details provided in the suspicious message.",
    ],
    "act_stay_cautious": [
        "No strong scam pattern was found from the details you ticked.",
        "Still verify through the official channel before acting, and stay alert.",
    ],
    "act_never_share_secrets": [
        "OTP, PIN, CNIC photos and passwords are for you only.",
        "Anyone asking for them over call/SMS/WhatsApp is not a legitimate agent.",
    ],
    "act_dont_install": [
        "Do not install remote-access apps or APKs from this contact.",
        "If already installed, uninstall now and change important passwords.",
    ],
    "act_dont_click": [
        "Do not tap the link. Links in unexpected messages are a common phishing path.",
        "Use the official app or website you type yourself.",
    ],
    "act_verify_identity": [
        "The sender may be pretending to be someone you trust.",
        "Call the real organisation or person on a number you already have.",
    ],
    "act_hang_up_unknown": [
        "This contact came from someone you do not know. Be extra careful.",
        "You can hang up / ignore and confirm via an official channel later.",
    ],
    "act_freeze_wallet": [
        "This looks like an account-takeover attempt (OTP + fake wallet/bank agent).",
        "If you shared an OTP, call JazzCash 4444 / Easypaisa 3737 / your bank immediately.",
    ],
    "act_no_matching_rule": [
        "No rule in this knowledge base classifies this combination as a scam type.",
        "That is a knowledge gap, not a certificate of safety — the engine does not invent rules.",
        "Verify through an official app or printed helpline before you send money, OTP, or CNIC details.",
    ],
    "act_utility_phishing": [
        "Pay bills only inside the official WAPDA / K-Electric / Sui app or a trusted retailer.",
        "Do not tap 'pay bill' SMS links or share a meter-photo OTP.",
        "Call the printed helpline on your last bill, not the number in the SMS.",
    ],
    "act_sim_swap_scam": [
        "Do not share PUK, ICCID, or last-recharge details. That is how a SIM swap starts.",
        "Call your operator from another phone if you lose signal suddenly.",
        "Tell JazzCash/Easypaisa/your bank to watch the account.",
    ],
    "act_crypto_scam": [
        "Guaranteed USDT/Binance profit is a scam. Do not send crypto to 'recovery' wallets.",
        "Pakistan has no official body that asks you to invest via WhatsApp.",
        "If you already sent funds, screenshot the chat and report to FIA 1991.",
    ],
    "act_charity_scam": [
        "Donate only through organisations you already know, never to a personal JazzCash number from a blast message.",
        "Scammers use floods, Gaza, and mosque appeals. Verify the NGO's official account.",
    ],
    "act_nadra_id_scam": [
        "NADRA does not ask for CNIC photos + a fee over WhatsApp to 'unblock' your ID.",
        "Use the official NADRA app/site or visit a centre. Helpline 1515.",
    ],
    "act_university_admission_scam": [
        "Universities and HEC do not collect admission fees on personal wallets.",
        "Pay only on the official campus portal you type yourself.",
    ],
    "act_qr_caution": [
        "A QR that is supposed to 'receive' money is often set to send money instead.",
        "Generate receive-QR only from inside your own wallet app.",
    ],
}


def _r(rid, layer, iff, then, cf, why):
    """Small helper so each rule stays on a few readable lines."""
    return {"id": rid, "layer": layer, "if": iff, "then": then, "cf": cf, "why": why}


# ===========================================================================
# RULES — 110 entries. Minimum required by the assignment is 50; the original
# spec listed 70 (R01–R70). Extra rules R71–R110 cover more Pakistan-specific
# combinations so the knowledge base is clearly 100+ facts-as-rules for viva.
# ===========================================================================

RULES = [
    # ----- A. Credential and access flags (layer 1) -----
    _r("R01", 1, ["asks_otp", "claims_bank"], "credential_request", 0.95,
       "Banks never ask for OTPs over call/SMS"),
    _r("R02", 1, ["asks_otp", "claims_wallet"], "credential_request", 0.95,
       "JazzCash/Easypaisa agents never ask for OTP on a call"),
    _r("R03", 1, ["asks_otp", "unknown_sender"], "credential_request", 0.90,
       "An unknown number asking for OTP is a classic takeover move"),
    _r("R04", 1, ["asks_pin_password"], "credential_request", 0.85,
       "PIN/password is never required to 'verify' you by a caller"),
    _r("R05", 1, ["asks_cnic_card", "unknown_sender"], "credential_request", 0.80,
       "Strangers asking for CNIC copies are collecting identity data"),
    _r("R06", 1, ["asks_cnic_card", "claims_govt"], "credential_request", 0.85,
       "Fake BISP/FIA messages harvest CNIC details"),
    _r("R07", 1, ["asks_install_app", "claims_tech_support"], "remote_access_request", 0.90,
       "Fake tech support wants AnyDesk/TeamViewer to empty accounts"),
    _r("R08", 1, ["asks_install_app", "claims_bank"], "remote_access_request", 0.90,
       "Banks do not ask you to install remote-control apps"),
    # ----- B. Urgency and secrecy flags (layer 1) -----
    _r("R09", 1, ["deadline", "threat_block_arrest"], "urgency_pressure", 0.85,
       "Deadline plus arrest/block threats is fear-based social engineering"),
    _r("R10", 1, ["deadline"], "urgency_pressure", 0.50,
       "A short deadline is used to stop you thinking"),
    _r("R11", 1, ["threat_block_arrest", "claims_bank"], "urgency_pressure", 0.80,
       "Fake bank 'your account will be blocked' calls"),
    _r("R12", 1, ["threat_block_arrest", "claims_govt"], "urgency_pressure", 0.85,
       "Fake FIA/FBR arrest threats are a known Pakistan scam"),
    _r("R13", 1, ["secrecy_requested"], "secrecy_isolation", 0.80,
       "Scammers isolate the victim so family cannot warn them"),
    _r("R14", 1, ["secrecy_requested", "claims_relative"], "secrecy_isolation", 0.90,
       "'Don't tell anyone' plus a fake relative is a family-emergency pattern"),
    # ----- C. Impersonation flags (layer 1) -----
    _r("R15", 1, ["claims_bank", "unknown_sender"], "impersonation", 0.80,
       "A real bank would contact you from known channels, not a random number"),
    _r("R16", 1, ["claims_wallet", "unknown_sender"], "impersonation", 0.80,
       "Wallet companies do not cold-call from unknown numbers for OTP"),
    _r("R17", 1, ["claims_govt", "unknown_sender"], "impersonation", 0.85,
       "Government offices do not send random SMS asking for data"),
    _r("R18", 1, ["claims_courier", "unknown_sender"], "impersonation", 0.70,
       "Courier 'duty unpaid' SMS often comes from spoofed senders"),
    _r("R19", 1, ["claims_relative", "new_number_claim"], "impersonation", 0.90,
       "'I lost my phone, new number' is a well-known WhatsApp scam"),
    _r("R20", 1, ["claims_recruiter", "moves_to_whatsapp"], "impersonation", 0.60,
       "Fake recruiters move you off the platform onto WhatsApp"),
    _r("R21", 1, ["claims_tech_support", "unknown_sender"], "impersonation", 0.80,
       "Microsoft/Jazz/PTCL do not cold-call from unknown numbers"),
    # ----- D. Too-good-to-be-true flags (layer 1) -----
    _r("R22", 1, ["promises_prize"], "too_good", 0.85,
       "Unexpected prizes are almost never real"),
    _r("R23", 1, ["promises_govt_money"], "too_good", 0.80,
       "Unexpected 'your BISP payment is ready' SMS is frequently fake"),
    _r("R24", 1, ["promises_easy_job"], "too_good", 0.70,
       "Easy high-pay work-from-home offers are a common job-scam hook"),
    _r("R25", 1, ["promises_loan_no_docs"], "too_good", 0.70,
       "A genuine loan always needs some documentation"),
    _r("R26", 1, ["promises_guaranteed_returns"], "too_good", 0.90,
       "Guaranteed high returns violate how real investing works"),
    _r("R27", 1, ["overpays_buyer"], "too_good", 0.80,
       "Overpaying then asking for a refund is a marketplace scam script"),
    # ----- E. Payment-request flags (layer 1) -----
    _r("R28", 1, ["asks_fee_upfront"], "payment_request", 0.80,
       "Upfront fees (registration, tax, release) are a scam cash-out"),
    _r("R29", 1, ["asks_load_giftcard"], "payment_request", 0.90,
       "Gift cards are irreversible payment — a favourite of scammers"),
    _r("R30", 1, ["asks_personal_account", "unknown_sender"], "payment_request", 0.80,
       "Sending money to a stranger's personal account is high risk"),
    _r("R31", 1, ["asks_advance_marketplace", "channel_marketplace"], "payment_request", 0.70,
       "Advance payment before seeing the item is a marketplace red flag"),
    _r("R32", 1, ["refuses_cod_meet", "channel_marketplace"], "payment_request", 0.70,
       "Refusing COD or meetup removes the safe way to trade"),
    # ----- F. Suspicious-link flags (layer 1) -----
    _r("R33", 1, ["asks_click_link", "link_shortened"], "suspicious_link", 0.75,
       "Short links hide the real destination"),
    _r("R34", 1, ["asks_click_link", "link_domain_mismatch"], "suspicious_link", 0.90,
       "A lookalike domain is classic phishing"),
    _r("R35", 1, ["asks_click_link", "poor_spelling"], "suspicious_link", 0.70,
       "Urgent link plus bad spelling is a cheap phishing kit"),
    _r("R36", 1, ["asks_click_link", "unknown_sender"], "suspicious_link", 0.60,
       "Unexpected links from unknown senders should not be tapped"),
    # ----- G. Scam-type rules (layer 2) -----
    _r("R37", 2, ["credential_request", "claims_wallet"], "wallet_fraud", 0.92,
       "Secrets requested while posing as a wallet agent → wallet fraud"),
    _r("R38", 2, ["credential_request", "claims_bank"], "bank_phishing", 0.92,
       "Secrets requested while posing as a bank → bank phishing"),
    _r("R39", 2, ["suspicious_link", "claims_bank"], "bank_phishing", 0.85,
       "Fake bank link is phishing even without an OTP request"),
    _r("R40", 2, ["impersonation", "claims_govt", "too_good"], "govt_aid_scam", 0.90,
       "Fake government identity plus a money promise → aid scam"),
    _r("R41", 2, ["too_good", "payment_request", "claims_recruiter"], "job_scam", 0.95,
       "Easy job plus a fee is the recruitment-scam pattern"),
    _r("R42", 2, ["promises_prize", "payment_request"], "prize_scam", 0.90,
       "Prize plus a fee/tax to release it is a lottery scam"),
    _r("R43", 2, ["payment_request", "channel_marketplace"], "marketplace_scam", 0.85,
       "Payment tricks on a marketplace listing"),
    _r("R44", 2, ["overpays_buyer", "channel_marketplace"], "marketplace_scam", 0.90,
       "OLX overpayment scam"),
    _r("R45", 2, ["suspicious_link", "claims_courier"], "courier_phishing", 0.85,
       "Fake tracking link from a 'courier'"),
    _r("R46", 2, ["impersonation", "secrecy_isolation", "payment_request"], "family_emergency_scam", 0.92,
       "Fake relative + secrecy + money request"),
    _r("R47", 2, ["promises_guaranteed_returns", "payment_request"], "investment_scam", 0.90,
       "Guaranteed returns plus send money now"),
    _r("R48", 2, ["remote_access_request"], "remote_access_scam", 0.95,
       "Remote-control request is itself the scam"),
    _r("R49", 2, ["promises_loan_no_docs", "payment_request"], "loan_scam", 0.88,
       "Easy loan plus processing fee"),
    _r("R50", 2, ["suspicious_link", "urgency_pressure"], "generic_phishing", 0.85,
       "Urgent 'click this link' with no clearer type → generic phishing"),
    # ----- H. Risk (layer 3). FIRST MATCH WINS. Keep this order. -----
    _r("R51", 3, ["scam_score>=0.85"], "risk_critical", 1.0,
       "Highest scam-type confidence is 0.85 or above"),
    _r("R52", 3, ["scam_score>=0.65"], "risk_high", 1.0,
       "Highest scam-type confidence is 0.65 or above"),
    _r("R53", 3, ["scam_score>=0.40"], "risk_medium", 1.0,
       "Highest scam-type confidence is 0.40 or above"),
    _r("R54", 3, ["scam_score>=0.0"], "risk_low", 1.0,
       "No strong match (or no scam type fired)"),
    # ----- I. Action rules (layer 4). ALL matches fire. -----
    _r("R55", 4, ["wallet_fraud"], "act_wallet_fraud", 1.0, "Advice for wallet fraud"),
    _r("R56", 4, ["bank_phishing"], "act_bank_phishing", 1.0, "Advice for bank phishing"),
    _r("R57", 4, ["govt_aid_scam"], "act_govt_aid_scam", 1.0, "Advice for government-aid scams"),
    _r("R58", 4, ["job_scam"], "act_job_scam", 1.0, "Advice for job-fee scams"),
    _r("R59", 4, ["prize_scam"], "act_prize_scam", 1.0, "Advice for prize scams"),
    _r("R60", 4, ["marketplace_scam"], "act_marketplace_scam", 1.0, "Advice for marketplace scams"),
    _r("R61", 4, ["courier_phishing"], "act_courier_phishing", 1.0, "Advice for courier phishing"),
    _r("R62", 4, ["family_emergency_scam"], "act_family_emergency_scam", 1.0, "Advice for family-emergency scams"),
    _r("R63", 4, ["investment_scam"], "act_investment_scam", 1.0, "Advice for investment scams"),
    _r("R64", 4, ["remote_access_scam"], "act_remote_access_scam", 1.0, "Advice for remote-access scams"),
    _r("R65", 4, ["loan_scam"], "act_loan_scam", 1.0, "Advice for loan scams"),
    _r("R66", 4, ["generic_phishing"], "act_generic_phishing", 1.0, "Advice for generic phishing"),
    _r("R67", 4, ["risk_critical"], "act_stop_and_report", 1.0, "Critical: stop and report"),
    _r("R68", 4, ["risk_high"], "act_block_and_report", 1.0, "High: block and report"),
    _r("R69", 4, ["risk_medium"], "act_verify_officially", 1.0, "Medium: verify officially"),
    _r("R70", 4, ["risk_low"], "act_stay_cautious", 1.0, "Low: stay cautious"),
    # ----- Extra layer-1 flags (R71–R100) so the KB is 100+ rules -----
    _r("R71", 1, ["asks_otp", "claims_govt"], "credential_request", 0.90,
       "Government SMS never needs your OTP"),
    _r("R72", 1, ["asks_otp", "claims_courier"], "credential_request", 0.75,
       "Couriers do not need OTP to deliver a parcel"),
    _r("R73", 1, ["asks_pin_password", "claims_wallet"], "credential_request", 0.95,
       "Wallet PIN requested by a 'agent' is a takeover attempt"),
    _r("R74", 1, ["asks_pin_password", "claims_bank"], "credential_request", 0.95,
       "Bank PIN requested by a caller is a takeover attempt"),
    _r("R75", 1, ["asks_cnic_card", "asks_click_link"], "credential_request", 0.75,
       "CNIC plus a link is identity-harvest phishing"),
    _r("R76", 1, ["asks_install_app", "unknown_sender"], "remote_access_request", 0.80,
       "A stranger sending an APK/AnyDesk link is remote-access fraud"),
    _r("R77", 1, ["asks_install_app", "channel_call"], "remote_access_request", 0.70,
       "Callers walking you through an install is a tech-support scam step"),
    _r("R78", 1, ["deadline", "claims_wallet"], "urgency_pressure", 0.70,
       "Fake wallet agents rush you so you share OTP"),
    _r("R79", 1, ["deadline", "claims_courier"], "urgency_pressure", 0.65,
       "Fake 'pay customs in 1 hour' courier SMS"),
    _r("R80", 1, ["threat_block_arrest", "unknown_sender"], "urgency_pressure", 0.75,
       "Unknown number threatening arrest/block"),
    _r("R81", 1, ["secrecy_requested", "asks_personal_account"], "secrecy_isolation", 0.85,
       "Secret money transfer is a family-emergency / romance pattern"),
    _r("R82", 1, ["claims_relative", "unknown_sender"], "impersonation", 0.70,
       "A 'relative' texting from a number you do not know"),
    _r("R83", 1, ["claims_govt", "promises_govt_money"], "impersonation", 0.75,
       "Unsolicited government payment claims are usually impersonation"),
    _r("R84", 1, ["claims_tech_support", "channel_call"], "impersonation", 0.70,
       "Unsolicited 'tech support' calls are rarely genuine"),
    _r("R85", 1, ["claims_recruiter", "promises_easy_job"], "impersonation", 0.65,
       "Recruiter plus 'easy job' is often a fake hiring page"),
    _r("R86", 1, ["asks_fee_upfront", "promises_easy_job"], "payment_request", 0.85,
       "Job fee is the cash-out of a recruitment scam"),
    _r("R87", 1, ["asks_fee_upfront", "promises_prize"], "payment_request", 0.85,
       "Prize-release fee is the cash-out of a lottery scam"),
    _r("R88", 1, ["asks_fee_upfront", "promises_guaranteed_returns"], "payment_request", 0.90,
       "Investment 'entry fee' is the cash-out of a returns scam"),
    _r("R89", 1, ["asks_click_link", "claims_govt"], "suspicious_link", 0.80,
       "Government bodies do not send random action links by SMS"),
    _r("R90", 1, ["asks_click_link", "claims_wallet"], "suspicious_link", 0.75,
       "Wallet 'KYC update' links in SMS are often fake"),
    _r("R91", 1, ["link_shortened", "claims_courier"], "suspicious_link", 0.70,
       "Short courier tracking links hide phishing sites"),
    _r("R92", 1, ["poor_spelling", "claims_courier"], "suspicious_link", 0.65,
       "Broken English 'pakage pending' SMS is a phishing kit"),
    _r("R93", 1, ["unknown_sender", "channel_call"], "unsolicited_contact", 0.70,
       "Unknown incoming call — treat as unsolicited"),
    _r("R94", 1, ["unknown_sender", "channel_sms"], "unsolicited_contact", 0.70,
       "Unknown SMS — treat as unsolicited"),
    _r("R95", 1, ["unknown_sender", "channel_whatsapp"], "unsolicited_contact", 0.60,
       "Unknown WhatsApp — treat as unsolicited"),
    _r("R96", 1, ["unknown_sender", "channel_email"], "unsolicited_contact", 0.70,
       "Unknown email — treat as unsolicited"),
    _r("R97", 1, ["threat_block_arrest", "claims_govt"], "fake_authority", 0.90,
       "Fake FIA/police legal threat"),
    _r("R98", 1, ["threat_block_arrest", "claims_bank"], "fake_authority", 0.85,
       "Fake bank legal/block threat"),
    _r("R99", 1, ["claims_wallet", "asks_otp", "channel_call"], "account_takeover", 0.90,
       "Wallet agent + OTP on a call is an account-takeover script"),
    _r("R100", 1, ["claims_bank", "asks_otp", "channel_call"], "account_takeover", 0.90,
       "Bank agent + OTP on a call is an account-takeover script"),
    # ----- Extra layer-2 types (do not disturb the 10 demo expected risks) -----
    _r("R101", 2, ["credential_request", "urgency_pressure", "claims_wallet"], "wallet_fraud", 0.95,
       "OTP pressure from a fake wallet agent (stronger wallet-fraud pattern)"),
    _r("R102", 2, ["remote_access_request", "channel_call"], "remote_access_scam", 0.92,
       "Remote-access request during a call"),
    _r("R103", 2, ["overpays_buyer", "too_good", "channel_marketplace"], "marketplace_scam", 0.92,
       "Overpay + marketplace channel (stronger OLX pattern)"),
    _r("R104", 2, ["promises_loan_no_docs", "asks_fee_upfront"], "loan_scam", 0.85,
       "No-document loan plus a processing fee"),
    # ----- Extra layer-4 actions (fire-all; extra advice, same risk) -----
    _r("R105", 4, ["credential_request"], "act_never_share_secrets", 1.0,
       "Never share OTP/PIN/CNIC regardless of scam type"),
    _r("R106", 4, ["remote_access_request"], "act_dont_install", 1.0,
       "Do not install remote-access software"),
    _r("R107", 4, ["suspicious_link"], "act_dont_click", 1.0,
       "Do not tap the unexpected link"),
    _r("R108", 4, ["impersonation"], "act_verify_identity", 1.0,
       "Verify the person/organisation on a number you already have"),
    _r("R109", 4, ["unsolicited_contact"], "act_hang_up_unknown", 1.0,
       "Unsolicited contact: you can ignore and verify later"),
    _r("R110", 4, ["account_takeover"], "act_freeze_wallet", 1.0,
       "If OTP was shared, freeze the wallet/bank account now"),
    _r("R111", 4, ["no_matching_rule"], "act_no_matching_rule", 1.0,
       "Knowledge gap: no scam-type rule matched these facts"),
    # ----- Extra realistic flags (new facts; will not fire on the original 10 demos) -----
    _r("R112", 1, ["claims_utility", "unknown_sender"], "utility_impersonation", 0.80,
       "Utility companies do not cold-SMS from random numbers"),
    _r("R113", 1, ["claims_utility", "promises_bill_waive"], "too_good", 0.85,
       "Nobody waives your electricity bill over SMS"),
    _r("R114", 1, ["claims_utility", "asks_click_link"], "suspicious_link", 0.80,
       "Pay-bill SMS links are a common WAPDA/KE phishing kit"),
    _r("R115", 1, ["claims_utility", "asks_otp"], "credential_request", 0.85,
       "A bill office never needs your wallet OTP"),
    _r("R116", 1, ["asks_sim_puk"], "sim_swap_pressure", 0.90,
       "PUK/ICCID questions are the opening of a SIM-swap"),
    _r("R117", 1, ["asks_sim_puk", "claims_govt"], "fake_authority", 0.85,
       "Fake PTA/FIA callers harvest SIM data to port the number"),
    _r("R118", 1, ["asks_sim_puk", "unknown_sender"], "impersonation", 0.80,
       "A stranger asking for PUK is not your operator"),
    _r("R119", 1, ["promises_crypto"], "crypto_lure", 0.90,
       "Guaranteed crypto profit is the hook"),
    _r("R120", 1, ["promises_crypto", "asks_fee_upfront"], "payment_request", 0.90,
       "USDT 'entry' or 'gas fee' is the cash-out"),
    _r("R121", 1, ["promises_crypto", "asks_personal_account"], "payment_request", 0.85,
       "Send-USDT-to-this-wallet is the cash-out"),
    _r("R122", 1, ["claims_charity", "asks_personal_account"], "charity_pressure", 0.85,
       "Blast charity + personal JazzCash is a donation scam"),
    _r("R123", 1, ["claims_charity", "deadline"], "urgency_pressure", 0.70,
       "Fake disaster appeals always say 'today only'"),
    _r("R124", 1, ["claims_nadra", "unknown_sender"], "impersonation", 0.85,
       "NADRA does not WhatsApp you to unblock a CNIC"),
    _r("R125", 1, ["claims_nadra", "asks_cnic_card"], "credential_request", 0.90,
       "Fake NADRA harvests CNIC photos"),
    _r("R126", 1, ["claims_nadra", "asks_fee_upfront"], "payment_request", 0.85,
       "Fake NADRA 'unblock fee'"),
    _r("R127", 1, ["claims_university", "asks_fee_upfront"], "payment_request", 0.85,
       "Admission/processing fee on WhatsApp is not how HEC works"),
    _r("R128", 1, ["claims_university", "unknown_sender"], "impersonation", 0.75,
       "Universities do not offer seats from unknown numbers"),
    _r("R129", 1, ["asks_share_screen"], "screen_share_request", 0.90,
       "Screen share lets them see OTPs as they arrive"),
    _r("R130", 1, ["asks_share_screen", "claims_tech_support"], "remote_access_request", 0.88,
       "Tech support + screen share is remote-access fraud"),
    _r("R131", 1, ["asks_apk_file"], "remote_access_request", 0.92,
       "A random APK is malware / a banking trojan"),
    _r("R132", 1, ["asks_qr_pay"], "payment_request", 0.80,
       "A 'receive' QR is often a pay-QR in disguise"),
    _r("R133", 1, ["asks_qr_pay", "claims_wallet"], "account_takeover", 0.75,
       "Wallet-agent QR tricks drain the account"),
    _r("R134", 1, ["asks_qr_pay", "overpays_buyer"], "payment_request", 0.85,
       "OLX buyer sending a QR is a payment-direction scam"),
    # ----- Extra flags on existing facts (checked not to disturb the original 10) -----
    _r("R135", 1, ["asks_load_giftcard", "claims_tech_support"], "payment_request", 0.90,
       "Tech support + gift cards is a classic cash-out"),
    _r("R136", 1, ["asks_personal_account", "claims_recruiter"], "payment_request", 0.80,
       "Salary/fee to a recruiter's personal account"),
    _r("R137", 1, ["asks_click_link", "claims_tech_support"], "suspicious_link", 0.70,
       "Support links from a cold call are phishing"),
    _r("R138", 1, ["asks_pin_password", "unknown_sender"], "credential_request", 0.90,
       "Stranger asking for PIN"),
    _r("R139", 1, ["asks_cnic_card", "claims_courier"], "credential_request", 0.75,
       "Courier does not need a CNIC selfie to deliver"),
    _r("R140", 1, ["link_domain_mismatch", "claims_wallet"], "suspicious_link", 0.85,
       "Lookalike JazzCash/Easypaisa domain"),
    _r("R141", 1, ["channel_social", "unknown_sender"], "unsolicited_contact", 0.55,
       "Unknown social-media DM"),
    # ----- Extra scam types -----
    _r("R142", 2, ["utility_impersonation", "suspicious_link"], "utility_phishing", 0.90,
       "Fake utility + bill-pay link"),
    _r("R143", 2, ["utility_impersonation", "too_good"], "utility_phishing", 0.88,
       "Fake utility + bill-waive promise"),
    _r("R144", 2, ["sim_swap_pressure"], "sim_swap_scam", 0.95,
       "Asking for PUK/porting data is itself the SIM-swap scam"),
    _r("R145", 2, ["crypto_lure", "payment_request"], "crypto_scam", 0.95,
       "USDT profit plus send money now"),
    _r("R146", 2, ["charity_pressure"], "charity_scam", 0.90,
       "Urgent charity plus a money ask is the donation-scam pattern"),
    _r("R147", 2, ["impersonation", "claims_nadra", "payment_request"], "nadra_id_scam", 0.90,
       "Fake NADRA plus a fee"),
    _r("R148", 2, ["impersonation", "claims_nadra", "credential_request"], "nadra_id_scam", 0.88,
       "Fake NADRA plus CNIC harvest"),
    _r("R149", 2, ["claims_university", "payment_request"], "university_admission_scam", 0.88,
       "Fake admissions office plus a fee"),
    _r("R150", 2, ["asks_qr_pay", "channel_marketplace"], "marketplace_scam", 0.80,
       "Marketplace QR-to-pay trick"),
    _r("R151", 2, ["screen_share_request", "credential_request"], "remote_access_scam", 0.90,
       "Screen share while they ask for OTP"),
    # ----- Extra actions -----
    _r("R152", 4, ["utility_phishing"], "act_utility_phishing", 1.0, "Advice for utility-bill phishing"),
    _r("R153", 4, ["sim_swap_scam"], "act_sim_swap_scam", 1.0, "Advice for SIM-swap"),
    _r("R154", 4, ["crypto_scam"], "act_crypto_scam", 1.0, "Advice for crypto scams"),
    _r("R155", 4, ["charity_scam"], "act_charity_scam", 1.0, "Advice for fake charity"),
    _r("R156", 4, ["nadra_id_scam"], "act_nadra_id_scam", 1.0, "Advice for fake NADRA"),
    _r("R157", 4, ["university_admission_scam"], "act_university_admission_scam", 1.0, "Advice for fake admissions"),
    _r("R158", 4, ["asks_qr_pay"], "act_qr_caution", 1.0, "QR codes can reverse the payment direction"),
    _r("R159", 4, ["sim_swap_pressure"], "act_sim_swap_scam", 1.0, "Stop sharing SIM data even before the type fires"),
    _r("R160", 4, ["crypto_lure"], "act_crypto_scam", 1.0, "Crypto lure: do not send funds"),
    _r("R161", 4, ["charity_pressure"], "act_charity_scam", 1.0, "Verify charity accounts officially"),
]

assert len(RULES) >= 100, "Knowledge base must have 100+ rules"
assert [r["id"] for r in RULES] == [f"R{i:02d}" for i in range(1, len(RULES) + 1)]


def validate_knowledge_base():
    """Catch broken rules at import time so a typo cannot silently skip in viva demos."""
    allowed_then = set(FLAGS) | set(SCAM_TYPES) | set(RISK_LEVELS) | set(ACTIONS) | {"no_matching_rule"}
    allowed_if = set(FACTS) | set(FLAGS) | set(SCAM_TYPES) | set(RISK_LEVELS) | {"no_matching_rule"}
    for r in RULES:
        if r["then"] not in allowed_then:
            raise ValueError(f"{r['id']} has unknown THEN {r['then']}")
        for cond in r["if"]:
            name = cond.split(">=")[0]
            if name not in allowed_if and name != "scam_score":
                raise ValueError(f"{r['id']} has unknown IF condition {cond}")


validate_knowledge_base()
