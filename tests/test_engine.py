"""One test per required demo scenario, plus a few engine sanity checks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from engine import clean_facts, infer, risk_of, top_scam_types
from rules import RULES, SCAM_TYPES
from scenarios import REQUIRED_SCENARIOS, SCENARIOS


def test_knowledge_base_has_100_plus_rules():
    assert len(RULES) >= 100
    ids = [r["id"] for r in RULES]
    assert ids == [f"R{i:02d}" for i in range(1, len(RULES) + 1)]
    for r in RULES:
        assert r["layer"] in (1, 2, 3, 4)
        assert r["if"] and r["then"]
        assert 0 < r["cf"] <= 1.0
        assert r["why"]


@pytest.mark.parametrize("scenario", REQUIRED_SCENARIOS, ids=[s["name"] for s in REQUIRED_SCENARIOS])
def test_required_scenario(scenario):
    known, fired = infer(scenario["facts"])
    risk_key = risk_of(known)
    assert risk_key is not None
    assert RISK_LABEL[risk_key] == scenario["expect_risk"]

    ranked = top_scam_types(known, min_cf=0.0)
    if scenario["expect_type"] is None:
        assert ranked == []
    else:
        assert ranked, "expected a scam type but none fired"
        best_type, best_cf = ranked[0]
        assert best_type == scenario["expect_type"]
        assert best_cf > 0
        # expected type is not merely present — it is the winner
        assert all(best_cf >= cf for _, cf in ranked)


def test_safe_case_does_not_flag_everything():
    """Scenario 5: a plain bank SMS must stay Low with no scam type."""
    safe = next(s for s in REQUIRED_SCENARIOS if "safe" in s["name"].lower())
    known, fired = infer(safe["facts"])
    assert top_scam_types(known) == []
    assert risk_of(known) == "risk_low"
    assert known.get("no_matching_rule") == 1.0
    # no encoded scam-type rule fired (GAP is the knowledge-gap marker)
    assert not any(t["then"] in SCAM_TYPES for t in fired)
    assert any(t["id"] == "GAP" for t in fired)


def test_missing_rule_does_not_invent_a_type():
    """Unknown combination → knowledge gap, not a made-up scam type."""
    known, fired = infer(["channel_sms"])
    assert top_scam_types(known) == []
    assert known.get("no_matching_rule") == 1.0
    assert risk_of(known) == "risk_low"
    assert any(t["then"] == "act_no_matching_rule" for t in fired)


def test_extra_examples_still_make_sense():
    for scenario in SCENARIOS[10:]:
        known, _fired = infer(scenario["facts"])
        ranked = top_scam_types(known)
        assert ranked and ranked[0][0] == scenario["expect_type"]
        assert RISK_LABEL[risk_of(known)] == scenario["expect_risk"]


def test_clean_facts_drops_unknown_and_duplicates():
    assert clean_facts(["channel_sms", "channel_sms", "not_a_fact", "", None]) == ["channel_sms"]
    known, _fired = infer(["not_a_fact", "channel_sms"])
    assert "channel_sms" in known
    assert "not_a_fact" not in known


def test_fired_trace_is_ordered_and_unique():
    known, fired = infer(REQUIRED_SCENARIOS[0]["facts"])
    ids = [t["id"] for t in fired]
    assert ids == sorted(ids, key=lambda x: ids.index(x))
    assert len(ids) == len(set(ids))
    assert known["scam_score"] == max(known.get(t, 0.0) for t in SCAM_TYPES)


RISK_LABEL = {
    "risk_critical": "Critical",
    "risk_high": "High",
    "risk_medium": "Medium",
    "risk_low": "Low",
}
