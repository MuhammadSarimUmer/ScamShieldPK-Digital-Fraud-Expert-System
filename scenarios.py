"""
Ten demo cases used by:
  - the Analyze tab "Load example" dropdown
  - pytest (tests/test_engine.py)

Each expected type/risk was worked by hand from the CF tables. If a test
fails by a small margin, tune the extra-rule CFs — do not silently weaken
the original R01–R70 table.
"""

SCENARIOS = [
    {
        "name": "Fake Easypaisa agent call",
        "facts": [
            "channel_call", "claims_wallet", "asks_otp",
            "unknown_sender", "deadline", "threat_block_arrest",
        ],
        "expect_type": "wallet_fraud",
        "expect_risk": "Critical",
    },
    {
        "name": "Courier SMS link",
        "facts": [
            "channel_sms", "claims_courier", "unknown_sender",
            "asks_click_link", "link_shortened", "poor_spelling",
        ],
        "expect_type": "courier_phishing",
        "expect_risk": "High",
    },
    {
        "name": "OLX overpaying buyer",
        "facts": [
            "channel_marketplace", "overpays_buyer", "moves_to_whatsapp",
        ],
        "expect_type": "marketplace_scam",
        "expect_risk": "Critical",
    },
    {
        "name": "Job offer with fee",
        "facts": [
            "channel_whatsapp", "claims_recruiter", "moves_to_whatsapp",
            "promises_easy_job", "asks_fee_upfront",
        ],
        "expect_type": "job_scam",
        "expect_risk": "High",
    },
    {
        "name": "Genuine bank balance alert (safe case)",
        "facts": ["channel_sms", "claims_bank"],
        "expect_type": None,
        "expect_risk": "Low",
    },
    {
        "name": "Mom, new number",
        "facts": [
            "channel_whatsapp", "claims_relative", "new_number_claim",
            "secrecy_requested", "asks_personal_account", "unknown_sender",
        ],
        "expect_type": "family_emergency_scam",
        "expect_risk": "High",
    },
    {
        "name": "BISP/Ehsaas money SMS",
        "facts": [
            "channel_sms", "claims_govt", "unknown_sender",
            "promises_govt_money", "asks_cnic_card", "asks_click_link",
            "link_domain_mismatch",
        ],
        "expect_type": "govt_aid_scam",
        "expect_risk": "High",
    },
    {
        "name": "Tech support remote access",
        "facts": [
            "channel_call", "claims_tech_support", "asks_install_app",
        ],
        "expect_type": "remote_access_scam",
        "expect_risk": "Critical",
    },
    {
        "name": "Guaranteed-returns investment",
        "facts": [
            "channel_social", "promises_guaranteed_returns", "asks_fee_upfront",
        ],
        "expect_type": "investment_scam",
        "expect_risk": "High",
    },
    {
        "name": "Vague urgent email with link",
        "facts": [
            "channel_email", "unknown_sender", "deadline", "asks_click_link",
        ],
        "expect_type": "generic_phishing",
        "expect_risk": "Medium",
    },
    # Extra loadable examples (not required by the original 10 tests).
    {
        "name": "Prize lottery release fee",
        "facts": [
            "channel_sms", "unknown_sender", "promises_prize", "asks_fee_upfront",
        ],
        "expect_type": "prize_scam",
        "expect_risk": "High",
    },
    {
        "name": "Easy loan processing fee",
        "facts": [
            "channel_whatsapp", "unknown_sender",
            "promises_loan_no_docs", "asks_fee_upfront",
        ],
        "expect_type": "loan_scam",
        "expect_risk": "Critical",
    },
    {
        "name": "Fake K-Electric bill link",
        "facts": [
            "channel_sms", "claims_utility", "unknown_sender",
            "asks_click_link", "promises_bill_waive",
        ],
        "expect_type": "utility_phishing",
        "expect_risk": "Critical",
    },
    {
        "name": "SIM PUK harvesting call",
        "facts": [
            "channel_call", "unknown_sender", "asks_sim_puk", "claims_govt",
        ],
        "expect_type": "sim_swap_scam",
        "expect_risk": "Critical",
    },
    {
        "name": "USDT guaranteed profit WhatsApp",
        "facts": [
            "channel_whatsapp", "unknown_sender",
            "promises_crypto", "asks_fee_upfront",
        ],
        "expect_type": "crypto_scam",
        "expect_risk": "Critical",
    },
    {
        "name": "Flood charity personal JazzCash",
        "facts": [
            "channel_sms", "unknown_sender", "claims_charity",
            "asks_personal_account", "deadline",
        ],
        "expect_type": "charity_scam",
        "expect_risk": "High",
    },
    {
        "name": "Fake NADRA CNIC unblock",
        "facts": [
            "channel_whatsapp", "claims_nadra", "unknown_sender",
            "asks_cnic_card", "asks_fee_upfront",
        ],
        "expect_type": "nadra_id_scam",
        "expect_risk": "Critical",
    },
]

# The assignment's original ten — used by pytest.
REQUIRED_SCENARIOS = SCENARIOS[:10]
