"""
ScamShield PK — inference engine.

Viva (short version):
- This is FORWARD CHAINING: start from known facts, fire rules whose IF
  conditions are all true, add the THEN conclusion, repeat.
- CERTAINTY FACTORS: each rule has cf in 0..1. One rule:
      rule_cf = min(CF of its conditions) * rule["cf"]
  Two rules supporting the same conclusion:
      new = old + rule_cf * (1 - old)
- Working memory is the dict `known` (fact/flag/type → CF).
- Rules live in rules.py; this file never hard-codes scam names into if/else
  except the list of scam-type keys used to compute scam_score.
"""

from rules import FACTS, RULES, SCAM_TYPES

VALID_FACTS = set(FACTS)
MAX_PASSES = 25  # each rule fires at most once; this is a safety cap only


def clean_facts(facts):
    """Drop blanks, duplicates, and ids that are not in the knowledge base."""
    if not facts:
        return []
    seen = set()
    out = []
    for item in facts:
        if not item or item not in VALID_FACTS or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _holds(cond, known):
    """True if a condition is satisfied in working memory.

    Plain string  → the fact/flag exists in `known`.
    'name>=0.85'  → numeric threshold (only scam_score uses this).
    """
    if not cond:
        return False
    if ">=" in cond:
        name, val = cond.split(">=", 1)
        try:
            return known.get(name, 0.0) >= float(val)
        except ValueError:
            return False
    return cond in known


def _fire(rule, known, fired):
    """Apply one rule: combine CFs and record the trace for the Why? panel."""
    cond_cfs = [
        known.get(c, 1.0) if ">=" not in c else 1.0
        for c in rule["if"]
    ]
    cf = min(cond_cfs) * rule["cf"]
    cf = max(0.0, min(cf, 1.0))
    old = known.get(rule["then"], 0.0)
    known[rule["then"]] = old + cf * (1 - old)
    fired.append({
        "id": rule["id"],
        "if": rule["if"],
        "then": rule["then"],
        "cf": round(cf, 3),
        "why": rule.get("why", ""),
        "layer": rule["layer"],
    })


def infer(facts):
    """Run the expert system.

    Phase A (layers 1–2): forward chain to a fixed point. A single pass is
    not enough, because scam-type rules need flags that fire in the same
    case.

    Phase B-1 (layer 3): risk rules, FIRST MATCH WINS (critical → low).

    Phase B-2 (layer 4): action rules, ALL matches fire.

    Returns (known, fired) where fired is in firing order (the explanation).
    """
    known = {f: 1.0 for f in clean_facts(facts)}
    fired = []

    phase_a = [r for r in RULES if r["layer"] in (1, 2)]
    changed = True
    passes = 0
    while changed and passes < MAX_PASSES:
        changed = False
        passes += 1
        already = {x["id"] for x in fired}
        for r in phase_a:
            if r["id"] not in already and all(_holds(c, known) for c in r["if"]):
                _fire(r, known, fired)
                changed = True
                already.add(r["id"])

    scores = [known.get(t, 0.0) for t in SCAM_TYPES]
    known["scam_score"] = max(scores) if scores else 0.0

    # Closed-world / incomplete KB: if no layer-2 scam-type rule fired, the
    # engine must NOT invent a type. It records a knowledge gap instead.
    if known["scam_score"] == 0.0:
        known["no_matching_rule"] = 1.0
        fired.append({
            "id": "GAP",
            "if": ["(no layer-2 scam-type rule matched)"],
            "then": "no_matching_rule",
            "cf": 1.0,
            "why": (
                "Rule-based systems only conclude what is in the knowledge base. "
                "Missing rule ⇒ no scam type, not 'therefore safe'."
            ),
            "layer": 2,
        })

    for r in [r for r in RULES if r["layer"] == 3]:
        if all(_holds(c, known) for c in r["if"]):
            _fire(r, known, fired)
            break

    for r in [r for r in RULES if r["layer"] == 4]:
        if all(_holds(c, known) for c in r["if"]):
            _fire(r, known, fired)

    return known, fired


def top_scam_types(known, min_cf=0.0):
    """Scam types with CF > min_cf, highest first. Used by the UI and tests."""
    ranked = [(t, known.get(t, 0.0)) for t in SCAM_TYPES if known.get(t, 0.0) > min_cf]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def risk_of(known):
    """Return the risk_* key that is present, or None."""
    for key in ("risk_critical", "risk_high", "risk_medium", "risk_low"):
        if key in known:
            return key
    return None


if __name__ == "__main__":
    demo = [
        "channel_call", "claims_wallet", "asks_otp",
        "unknown_sender", "deadline", "threat_block_arrest",
    ]
    mem, trace = infer(demo)
    print("scam_score", round(mem["scam_score"], 3))
    print("risk", risk_of(mem))
    print("types", top_scam_types(mem))
    print("fired", [t["id"] for t in trace])
