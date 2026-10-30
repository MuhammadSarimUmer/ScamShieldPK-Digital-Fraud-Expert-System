# ScamShield PK: Digital Fraud Triage Expert System

**Live link:** *(add Streamlit Community Cloud URL after you deploy — needs a public GitHub repo)*  
**Student:** Muhammad Sarim Umer, `ROLL-NO` (set the roll number in `student.py`)

### Run locally
```
pip install -r requirements.txt
streamlit run app.py
```
Tests: `pip install -r requirements-dev.txt` then `pytest`.

The knowledge base has **161 rules** and extra Pakistan-specific facts (utility bills, SIM-swap, crypto, charity, NADRA, university fees). Inference is still the same small forward-chaining engine. If no scam-type rule matches, the engine records a knowledge gap (`GAP`) instead of guessing.

**Code explanation PDF:** `ScamShield_PK_Code_Explanation.pdf` (has a blank box for the Streamlit URL). Rebuild with `python scripts/build_pdf.py`.

---

> **Instructions for the coding agent:** this README is the full spec. Build exactly what is described, in the order given in [Build Order](#build-order). Keep the code **simple and readable**, because a third-year CS student must explain every line in a viva. Do not over-engineer.

---

## 1. Project Summary

| Item | Value |
|---|---|
| Course | Artificial Intelligence (Expert Systems assignment), Week 14 deadline |
| Type | Rule-based expert system, **solo** project |
| Niche | Triage of suspicious messages, calls and offers in Pakistan (fake JazzCash/Easypaisa agents, fake BISP/Ehsaas SMS, job-fee scams, OLX overpayment scams, courier-link SMS, "mom I lost my phone" WhatsApp scams) |
| Inference | **Forward chaining** + **certainty factors (CF)** |
| UI | **Streamlit only** |
| Hosting | Streamlit Community Cloud (public URL, reachable over the internet) |
| Required rules | Minimum 50 (this spec defines **70**) |
| Required visual | A **tree diagram** (family-tree style): facts → flags → scam type → risk → action |
| Deliverables | Project zip, PDF code explanation, live Streamlit link |

**What the system does:** the user answers yes/no questions about a suspicious message or call. The system outputs:

1. **Scam type(s)** with a confidence score
2. **Risk level**: Low / Medium / High / Critical
3. **What to do right now** (block, do not click, call the official helpline, report to FIA)
4. **Why**: the exact rules that fired, shown as a list **and** as a tree diagram

**Disclaimer (show it in the UI footer):** educational project, not legal or financial advice.

---

## 2. Tech Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.10+ | |
| UI | Streamlit | Only UI framework allowed |
| Tree diagram | Graphviz DOT string via `st.graphviz_chart` | Renders in the browser, **no system Graphviz needed on the server** |
| Static tree images (for the PDF) | `graphviz` Python package + Graphviz binary | **Local only**, used by `scripts/export_trees.py`, not needed at deploy time |
| Knowledge base | Python list of dicts in `rules.py` | Data, not hardcoded `if/else` |
| Tests | `pytest` | Scenario tests |
| Hosting | Streamlit Community Cloud (from a public GitHub repo) | Fallback: `cloudflared tunnel` or `ngrok` from a laptop |
| **Do NOT use** | `experta` / `pyknow` | Broken on Python 3.10+, and the student must explain the engine themselves |
| **Do NOT use** | Any LLM/API call, ML model, database or login | The system must be fully deterministic and explainable |

`requirements.txt`:
```
streamlit>=1.30
```
(Add `graphviz` only to `requirements-dev.txt`, for the export script.)

---

## 3. Project Structure

```
scamshield/
├── app.py                  # Streamlit UI (tabs, form, results, tree)
├── engine.py               # Forward chaining + CF + two-phase logic (~60 lines)
├── rules.py                # FACTS, FLAGS, RULES (70), ACTIONS text, helplines
├── tree.py                 # Builds Graphviz DOT strings (per-case, full, per-scam-type)
├── scenarios.py            # 10 demo scenarios (also used by tests + "Load example")
├── scripts/
│   ├── export_trees.py     # Renders full-KB tree + per-scam-type trees to PNG (local)
│   └── export_rules_table.py  # Dumps all 70 rules to rules_table.csv/.md for the PDF
├── tests/
│   └── test_engine.py      # One test per scenario
├── docs/                   # Generated PNGs/CSV land here
├── requirements.txt
├── requirements-dev.txt
├── packages.txt            # Only if the Graphviz system package becomes necessary
└── README.md
```

---

## 4. Architecture

Five layers form the tree. Each layer's conclusions become the next layer's conditions.

```
Layer 0  FACTS         (user answers: asks_otp, claims_bank, deadline ...)      38 facts
   │
Layer 1  FLAGS         (credential_request, urgency_pressure, impersonation...)  rules R01-R36
   │
Layer 2  SCAM TYPES    (wallet_fraud, bank_phishing, job_scam ...)               rules R37-R50
   │
Layer 3  RISK LEVEL    (critical / high / medium / low)                          rules R51-R54
   │
Layer 4  ACTIONS       (what the user should do)                                 rules R55-R70
```

### Inference (two phases)

**Phase A: forward chaining to a fixed point** (rules R01-R50)
1. Start with working memory `known = {fact: 1.0}` for every fact the user ticked.
2. Loop: for each unfired rule, if all its conditions are in `known`, fire it.
3. `rule_cf = min(cf of conditions) × rule["cf"]`
4. If the conclusion already exists, combine: `new = old + rule_cf × (1 − old)`
5. Repeat until a full pass fires nothing new.
6. Compute `scam_score` = the highest CF among the 12 scam-type facts (0 if none).

**Phase B: risk and actions** (rules R51-R70)
1. **Risk rules use first-match conflict resolution**: evaluated in priority order (critical → high → medium → low), and the first rule whose threshold is met fires; the rest are skipped.
2. **Action rules**: all matching rules fire (an action fires if its scam type or risk fact is present).

### Condition syntax
- Plain string `"asks_otp"` is true if the fact exists in `known`.
- Threshold string `"scam_score>=0.85"` is parsed as `name`, `operator` (`>=`), `value`, and compared with `known.get(name, 0)`. Only `scam_score` is used with thresholds.

### Reference engine (implement this, tidy as needed)

```python
# engine.py
from rules import RULES

SCAM_TYPES = ["wallet_fraud", "bank_phishing", "govt_aid_scam", "job_scam", "prize_scam",
              "marketplace_scam", "courier_phishing", "family_emergency_scam",
              "investment_scam", "remote_access_scam", "loan_scam", "generic_phishing"]

def _holds(cond, known):
    if ">=" in cond:
        name, val = cond.split(">=")
        return known.get(name, 0.0) >= float(val)
    return cond in known

def _fire(rule, known, fired):
    cf = min(known.get(c, 1.0) if ">=" not in c else 1.0 for c in rule["if"]) * rule["cf"]
    old = known.get(rule["then"], 0.0)
    known[rule["then"]] = old + cf * (1 - old)
    fired.append({"id": rule["id"], "if": rule["if"], "then": rule["then"], "cf": round(cf, 3)})

def infer(facts):
    known = {f: 1.0 for f in facts}
    fired = []
    # Phase A: layers 1-2, forward chain to fixed point
    phase_a = [r for r in RULES if r["layer"] in (1, 2)]
    changed = True
    while changed:
        changed = False
        for r in phase_a:
            if r["id"] not in {x["id"] for x in fired} and all(_holds(c, known) for c in r["if"]):
                _fire(r, known, fired); changed = True
    known["scam_score"] = max([known.get(t, 0.0) for t in SCAM_TYPES], default=0.0)
    # Phase B-1: risk, first match wins
    for r in [r for r in RULES if r["layer"] == 3]:
        if all(_holds(c, known) for c in r["if"]):
            _fire(r, known, fired); break
    # Phase B-2: actions, all matches fire
    for r in [r for r in RULES if r["layer"] == 4]:
        if all(_holds(c, known) for c in r["if"]):
            _fire(r, known, fired)
    return known, fired
```
Notes for the agent: a **single pass in Phase A is not enough**, because scam-type rules depend on flags fired in the same pass, so the `while changed` loop stays. Keep `fired` in firing order, since the UI shows it as the "Why?" trace.

### Rule data format (`rules.py`)

```python
RULES = [
  {"id": "R01", "layer": 1, "if": ["asks_otp", "claims_bank"], "then": "credential_request", "cf": 0.95,
   "why": "Banks never ask for OTPs over call/SMS"},
  ...
]
```
Every rule has: `id`, `layer` (1 flags, 2 scam types, 3 risk, 4 actions), `if` (list), `then`, `cf`, `why` (one-line human reason, shown in the UI and the PDF).

---

## 5. Facts: the 38 User Inputs (Layer 0)

Group them in the UI with `st.expander`, one checkbox per fact, written in plain language.

| Group | Fact IDs |
|---|---|
| **Channel** (pick one, `st.radio`) | `channel_sms`, `channel_call`, `channel_whatsapp`, `channel_email`, `channel_marketplace`, `channel_social` |
| **Who they claim to be / sender** | `unknown_sender`, `claims_bank`, `claims_wallet` (JazzCash/Easypaisa), `claims_govt` (BISP/FIA/FBR/PTA), `claims_courier`, `claims_relative`, `claims_recruiter`, `claims_tech_support` |
| **What they ask for** | `asks_otp`, `asks_pin_password`, `asks_cnic_card`, `asks_install_app` (AnyDesk/TeamViewer/APK), `asks_click_link`, `asks_fee_upfront`, `asks_load_giftcard`, `asks_personal_account`, `asks_advance_marketplace` |
| **Pressure** | `deadline`, `threat_block_arrest`, `secrecy_requested` |
| **What they promise** | `promises_prize`, `promises_govt_money`, `promises_easy_job`, `promises_loan_no_docs`, `promises_guaranteed_returns`, `overpays_buyer` |
| **Message quality** | `link_shortened`, `link_domain_mismatch`, `poor_spelling`, `new_number_claim` ("I lost my phone, this is my new number"), `moves_to_whatsapp`, `refuses_cod_meet` |

(6 + 8 + 9 + 3 + 6 + 6 = 38)

---

## 6. The 70 Rules (Knowledge Base)

### A. Credential and access flags (Layer 1)
| ID | IF | THEN | CF |
|---|---|---|---|
| R01 | asks_otp, claims_bank | credential_request | 0.95 |
| R02 | asks_otp, claims_wallet | credential_request | 0.95 |
| R03 | asks_otp, unknown_sender | credential_request | 0.90 |
| R04 | asks_pin_password | credential_request | 0.85 |
| R05 | asks_cnic_card, unknown_sender | credential_request | 0.80 |
| R06 | asks_cnic_card, claims_govt | credential_request | 0.85 |
| R07 | asks_install_app, claims_tech_support | remote_access_request | 0.90 |
| R08 | asks_install_app, claims_bank | remote_access_request | 0.90 |

### B. Urgency and secrecy flags (Layer 1)
| ID | IF | THEN | CF |
|---|---|---|---|
| R09 | deadline, threat_block_arrest | urgency_pressure | 0.85 |
| R10 | deadline | urgency_pressure | 0.50 |
| R11 | threat_block_arrest, claims_bank | urgency_pressure | 0.80 |
| R12 | threat_block_arrest, claims_govt | urgency_pressure | 0.85 |
| R13 | secrecy_requested | secrecy_isolation | 0.80 |
| R14 | secrecy_requested, claims_relative | secrecy_isolation | 0.90 |

### C. Impersonation flags (Layer 1)
| ID | IF | THEN | CF |
|---|---|---|---|
| R15 | claims_bank, unknown_sender | impersonation | 0.80 |
| R16 | claims_wallet, unknown_sender | impersonation | 0.80 |
| R17 | claims_govt, unknown_sender | impersonation | 0.85 |
| R18 | claims_courier, unknown_sender | impersonation | 0.70 |
| R19 | claims_relative, new_number_claim | impersonation | 0.90 |
| R20 | claims_recruiter, moves_to_whatsapp | impersonation | 0.60 |
| R21 | claims_tech_support, unknown_sender | impersonation | 0.80 |

### D. Too-good-to-be-true flags (Layer 1)
| ID | IF | THEN | CF |
|---|---|---|---|
| R22 | promises_prize | too_good | 0.85 |
| R23 | promises_govt_money | too_good | 0.80 |
| R24 | promises_easy_job | too_good | 0.70 |
| R25 | promises_loan_no_docs | too_good | 0.70 |
| R26 | promises_guaranteed_returns | too_good | 0.90 |
| R27 | overpays_buyer | too_good | 0.80 |

### E. Payment-request flags (Layer 1)
| ID | IF | THEN | CF |
|---|---|---|---|
| R28 | asks_fee_upfront | payment_request | 0.80 |
| R29 | asks_load_giftcard | payment_request | 0.90 |
| R30 | asks_personal_account, unknown_sender | payment_request | 0.80 |
| R31 | asks_advance_marketplace, channel_marketplace | payment_request | 0.70 |
| R32 | refuses_cod_meet, channel_marketplace | payment_request | 0.70 |

### F. Suspicious-link flags (Layer 1)
| ID | IF | THEN | CF |
|---|---|---|---|
| R33 | asks_click_link, link_shortened | suspicious_link | 0.75 |
| R34 | asks_click_link, link_domain_mismatch | suspicious_link | 0.90 |
| R35 | asks_click_link, poor_spelling | suspicious_link | 0.70 |
| R36 | asks_click_link, unknown_sender | suspicious_link | 0.60 |

### G. Scam-type rules (Layer 2)
| ID | IF | THEN | CF |
|---|---|---|---|
| R37 | credential_request, claims_wallet | wallet_fraud | 0.92 |
| R38 | credential_request, claims_bank | bank_phishing | 0.92 |
| R39 | suspicious_link, claims_bank | bank_phishing | 0.85 |
| R40 | impersonation, claims_govt, too_good | govt_aid_scam | 0.90 |
| R41 | too_good, payment_request, claims_recruiter | job_scam | 0.95 |
| R42 | promises_prize, payment_request | prize_scam | 0.90 |
| R43 | payment_request, channel_marketplace | marketplace_scam | 0.85 |
| R44 | overpays_buyer, channel_marketplace | marketplace_scam | 0.90 |
| R45 | suspicious_link, claims_courier | courier_phishing | 0.85 |
| R46 | impersonation, secrecy_isolation, payment_request | family_emergency_scam | 0.92 |
| R47 | promises_guaranteed_returns, payment_request | investment_scam | 0.90 |
| R48 | remote_access_request | remote_access_scam | 0.95 |
| R49 | promises_loan_no_docs, payment_request | loan_scam | 0.88 |
| R50 | suspicious_link, urgency_pressure | generic_phishing | 0.85 |

### H. Risk-level rules (Layer 3, **first match wins**, in this order)
| ID | IF | THEN | CF |
|---|---|---|---|
| R51 | scam_score>=0.85 | risk_critical | 1.0 |
| R52 | scam_score>=0.65 | risk_high | 1.0 |
| R53 | scam_score>=0.40 | risk_medium | 1.0 |
| R54 | scam_score>=0.0 | risk_low | 1.0 |

### I. Action rules (Layer 4, **all matches fire**)
| ID | IF | THEN (action key) |
|---|---|---|
| R55 | wallet_fraud | act_wallet_fraud |
| R56 | bank_phishing | act_bank_phishing |
| R57 | govt_aid_scam | act_govt_aid_scam |
| R58 | job_scam | act_job_scam |
| R59 | prize_scam | act_prize_scam |
| R60 | marketplace_scam | act_marketplace_scam |
| R61 | courier_phishing | act_courier_phishing |
| R62 | family_emergency_scam | act_family_emergency_scam |
| R63 | investment_scam | act_investment_scam |
| R64 | remote_access_scam | act_remote_access_scam |
| R65 | loan_scam | act_loan_scam |
| R66 | generic_phishing | act_generic_phishing |
| R67 | risk_critical | act_stop_and_report |
| R68 | risk_high | act_block_and_report |
| R69 | risk_medium | act_verify_officially |
| R70 | risk_low | act_stay_cautious |

All action rules use `cf: 1.0`. Action text lives in `ACTIONS = {"act_wallet_fraud": [...bullets...], ...}` in `rules.py`, 2 to 4 short bullets each (examples below).

| Action key | Example bullets |
|---|---|
| act_wallet_fraud | Never share OTP/PIN with anyone, including "agents". Hang up and call the wallet's official helpline from its app. If you already sent money, report it immediately. |
| act_job_scam | Real employers never charge fees. Do not pay "registration/training" fees. Verify the company on its official website and LinkedIn. |
| act_marketplace_scam | Meet in person / cash on delivery only. Never accept "overpayment then refund". Do not share OTPs to "receive" money. |
| act_courier_phishing | Do not tap the link. Track parcels only in the courier's official app/website. |
| act_family_emergency_scam | Call your relative on their **old number**. Never send money based on a text alone. Ask a question only they can answer. |
| act_stop_and_report | Stop all contact. Report to FIA NR3C. Contact your bank/wallet to block accounts. Save screenshots as evidence. |
| act_stay_cautious | No strong scam pattern found. Verify through the official channel before acting, and stay alert. |

**Helplines/portals (put in `rules.py` as constants; the agent must tell the student to re-verify them before submission):** FIA NR3C cybercrime helpline `1991` (and the FIA cybercrime reporting portal), PTA complaint line `0800-55055`, Easypaisa `3737`, JazzCash `4444`, BISP/Ehsaas `8171`. Add the comment `# verify before submission`.

---

## 7. Streamlit UI Spec (`app.py`)

Use `st.set_page_config(page_title="ScamShield PK", page_icon="🛡️", layout="wide")`.

**Four tabs:**

1. **🔍 Analyze** (main)
   - "Load example scenario" `selectbox` (from `scenarios.py`) + **Load** button. Use an `on_click` callback that writes to `st.session_state[fact_key]` *before* widgets render, otherwise Streamlit raises a widget-state error.
   - Channel `st.radio`, then the other fact groups in `st.expander`s with checkboxes (key = fact ID).
   - **Analyze** button → calls `infer()` → shows:
     - Risk badge, colored: Low = green, Medium = yellow, High = orange, Critical = red (`st.error/warning/success` or colored markdown)
     - Top scam type(s) with CF as `st.progress` bars (show all scam types with CF > 0, sorted descending)
     - "What to do right now" bullet list from `ACTIONS`
     - Intermediate flags that fired, with CF (shows red flags even when no scam type matches)
     - Expander **"Why? (rules that fired)"**: ordered list, each line `R37: credential_request + claims_wallet → wallet_fraud (CF 0.915). <why>`
     - Header **"Reasoning tree"** → `st.graphviz_chart(case_tree_dot)`
   - If no facts are selected, show `st.info("Select at least one detail first")`.
2. **📚 Knowledge Base**: `st.dataframe` of all 70 rules (ID, layer, IF, THEN, CF, why), with a layer filter.
3. **🌳 Full Tree**: the whole knowledge base as a tree (`st.graphviz_chart`), plus a `selectbox` to view the sub-tree of one scam type.
4. **ℹ️ How it works**: 5 to 8 lines on forward chaining, CF formula, the 5 layers, and the first-match vs fire-all difference. This is the viva crib sheet, shown in-app.

Footer: disclaimer and "Made by <student name>, <roll no>".

Keep the UI free of heavy styling. Clarity beats looks.

---

## 8. Tree Diagrams (`tree.py`): the teacher's requirement

The teacher asked for a family-tree-style diagram. Layers map to generations: **facts = grandchildren → flags → scam types → risk → actions**. Use `rankdir=TB` with `rank=same` per layer so the layers line up like generations.

Three DOT builders:

1. `case_tree_dot(fired, facts)`: only the nodes and edges for the current case. Nodes: facts (light blue), flags (yellow), scam types (orange), risk (red/green by level), actions (grey box). Edge label = rule ID. Show CF on conclusion nodes (`wallet_fraud\n0.92`).
2. `full_tree_dot()`: every rule in `RULES` as edges, all nodes, color-coded by layer. This is the "whole knowledge base" figure for the PDF.
3. `scam_subtree_dot(scam_type)`: the ancestors of one scam type only (what facts and flags can lead to it). Gives 12 small readable trees for the PDF, one per scam type.

```python
def case_tree_dot(fired, facts):
    lines = ['digraph G {', 'rankdir=TB;', 'node [shape=box, style="filled,rounded", fontname="Helvetica"];']
    for r in fired:
        for c in r["if"]:
            lines.append(f'"{c}" -> "{r["then"]}" [label="{r["id"]}"];')
    lines.append('}')
    return "\n".join(lines)   # then color nodes by layer using a LAYER_OF dict
```

`scripts/export_trees.py` (run locally, needs the Graphviz binary) writes `docs/full_tree.png` and `docs/tree_<scam_type>.png`. `scripts/export_rules_table.py` writes `docs/rules_table.csv` and `.md`, so the PDF's rule table is generated, not retyped.

---

## 9. Demo Scenarios (`scenarios.py`)

Each scenario is `{"name", "facts": [...], "expect_type", "expect_risk"}`. These double as the "Load example" feature and the tests.

| # | Name | Facts | Expected scam type | Expected risk |
|---|---|---|---|---|
| 1 | Fake Easypaisa agent call | channel_call, claims_wallet, asks_otp, unknown_sender, deadline, threat_block_arrest | wallet_fraud | Critical |
| 2 | Courier SMS link | channel_sms, claims_courier, unknown_sender, asks_click_link, link_shortened, poor_spelling | courier_phishing | High |
| 3 | OLX overpaying buyer | channel_marketplace, overpays_buyer, moves_to_whatsapp | marketplace_scam | Critical |
| 4 | Job offer with fee | channel_whatsapp, claims_recruiter, moves_to_whatsapp, promises_easy_job, asks_fee_upfront | job_scam | High |
| 5 | Genuine bank balance alert (**safe case**) | channel_sms, claims_bank | none | Low |
| 6 | "Mom, new number" | channel_whatsapp, claims_relative, new_number_claim, secrecy_requested, asks_personal_account, unknown_sender | family_emergency_scam | High |
| 7 | BISP/Ehsaas money SMS | channel_sms, claims_govt, unknown_sender, promises_govt_money, asks_cnic_card, asks_click_link, link_domain_mismatch | govt_aid_scam | High |
| 8 | "Tech support" remote access | channel_call, claims_tech_support, asks_install_app | remote_access_scam | Critical |
| 9 | Guaranteed-returns investment | channel_social, promises_guaranteed_returns, asks_fee_upfront | investment_scam | High |
| 10 | Vague urgent email with link | channel_email, unknown_sender, deadline, asks_click_link | generic_phishing | Medium |

The expected values were computed by hand with the CFs above. **If a test fails by a small margin, tune the rule CF, not the test**, then document the change. Scenario 5 matters most: it proves the system does not flag everything.

---

## 10. Build Order

1. `rules.py`: FACTS list, 70 `RULES` (copy the tables above), `ACTIONS`, helplines.
2. `engine.py`: `infer()`; verify in a terminal with scenario 1.
3. `scenarios.py` and `tests/test_engine.py`: run `pytest` and tune CFs until all 10 pass.
4. `tree.py`: three DOT builders; print the DOT and paste into an online Graphviz viewer to sanity-check.
5. `app.py`: Analyze tab first, then Knowledge Base, Full Tree, How it works.
6. `scripts/`: export PNGs and the rules table into `docs/`.
7. **Deploy**: push to a public GitHub repo → [share.streamlit.io](https://share.streamlit.io) → "New app" → pick the repo, branch `main`, file `app.py` → copy the public URL → put it at the top of this README. Open the link in a private/incognito window and on a phone to confirm WAN access.
8. Final pass: comments on every function, remove dead code, make sure `streamlit run app.py` works from a clean venv.

---

## 11. Definition of Done

- [ ] 70 rules live in `rules.py` as data (≥ 50 required)
- [ ] `pytest` passes all 10 scenarios
- [ ] App runs locally with `streamlit run app.py`, no errors on empty or full input
- [ ] Per-case tree shows in the Analyze tab; full tree and per-type subtrees show in the Full Tree tab
- [ ] `docs/` contains `full_tree.png`, 12 sub-tree PNGs and `rules_table.csv`
- [ ] Public Streamlit URL works from another network or device
- [ ] No API keys, secrets or LLM calls anywhere in the repo
- [ ] README top has: live link, student name, how to run locally

---

## 12. Viva Crib Sheet (the agent should reflect these in code comments and the "How it works" tab)

| Question | Short answer |
|---|---|
| What is an expert system? | Software that encodes expert knowledge as rules and reasons over them to give advice and explain itself. |
| Parts of your system? | Knowledge base (`rules.py`), inference engine (`engine.py`), working memory (`known`), user interface (`app.py`), explanation facility (fired-rules trace + tree). |
| Why forward chaining? | Facts are known up front (what the user observed) and we discover the conclusion. Backward chaining suits "prove this goal" problems. |
| What are certainty factors? | Real-world rules are not 100% sure, so each carries a 0 to 1 confidence. Combine two supports for the same conclusion with `old + new × (1 − old)`; use `min` across the conditions of one rule. |
| Conflict resolution? | Risk rules use first-match by priority; flag, scam-type and action rules fire all. |
| Difference from plain if/else? | Rules are data separate from the engine, so adding a rule means no code change; the system can explain *why*. |
| Limitations? | Rules are hand-written and not learned; depends on honest user answers; limited to the covered scam types. |
| Future work? | Roman-Urdu keyword detection, learning CFs from reported cases, a backward-chaining "is this a wallet scam?" mode. |

---

## 13. Knowledge Sources (cite these in the PDF; student to add the exact links they read)

- FIA National Response Centre for Cyber Crime (NR3C) public awareness advisories
- PTA consumer-awareness material on SMS and call fraud
- State Bank of Pakistan / commercial bank fraud-awareness pages ("never share OTP/PIN")
- JazzCash and Easypaisa official security/awareness pages
- BISP/Ehsaas official notices on fake SMS and helpline messages
- OLX Pakistan safety tips (overpayment, advance payment scams)
