"""
ScamShield PK — Streamlit UI.

Four tabs: Analyze, Knowledge Base, Full Tree, How it works.
Keep the layout plain; the viva is about the engine, not CSS.
"""

import streamlit as st

from engine import infer, risk_of, top_scam_types
from rules import (
    ACTIONS,
    CHANNEL_FACTS,
    FACT_GROUPS,
    FACT_LABELS,
    FLAG_LABELS,
    FLAGS,
    HELPLINES,
    RISK_LABELS,
    RULES,
    SCAM_LABELS,
    SCAM_TYPES,
)
from scenarios import SCENARIOS
from student import ROLL_NO, STUDENT_NAME
from tree import case_tree_dot, full_tree_dot, scam_subtree_dot

st.set_page_config(page_title="ScamShield PK", page_icon="🛡️", layout="wide")

CHANNEL_IDS = [fid for fid, _ in CHANNEL_FACTS]
SKIP = "(not sure / skip)"
NON_CHANNEL = [fid for fid in FACT_LABELS if fid not in CHANNEL_IDS]


def _load_example():
    """Write fact widgets' session_state BEFORE they render (Streamlit rule)."""
    name = st.session_state.get("scenario_choice")
    match = next((s for s in SCENARIOS if s["name"] == name), None)
    if match is None:
        return
    factset = set(match["facts"])
    channel = next((c for c in CHANNEL_IDS if c in factset), SKIP)
    st.session_state["channel"] = channel
    for fid in NON_CHANNEL:
        st.session_state[fid] = fid in factset
    st.session_state["result"] = infer(match["facts"])
    st.session_state["result_facts"] = list(match["facts"])


def _clear_form():
    st.session_state["channel"] = SKIP
    for fid in NON_CHANNEL:
        st.session_state[fid] = False
    st.session_state.pop("result", None)
    st.session_state.pop("result_facts", None)


def _selected_facts():
    facts = []
    channel = st.session_state.get("channel", SKIP)
    if channel and channel != SKIP:
        facts.append(channel)
    for fid in NON_CHANNEL:
        if st.session_state.get(fid):
            facts.append(fid)
    return facts


def _risk_banner(risk_key, score):
    label = RISK_LABELS.get(risk_key, "Unknown")
    msg = f"**Risk: {label}**  ·  scam score {score:.2f}"
    if risk_key == "risk_critical":
        st.error(msg)
    elif risk_key == "risk_high":
        st.warning(msg)
    elif risk_key == "risk_medium":
        st.info(msg)
    else:
        st.success(msg)


def _show_results(known, fired, facts):
    """Shared result panel for Analyze (manual run or loaded example)."""
    risk_key = risk_of(known)
    score = known.get("scam_score", 0.0)
    _risk_banner(risk_key, score)
    st.caption(f"{len(fired)} rules fired · {len(facts)} facts used")

    ranked = top_scam_types(known, min_cf=0.0)
    st.markdown("### Scam type(s)")
    if known.get("no_matching_rule"):
        st.info(
            "**No matching expert rule.** Nothing in the knowledge base maps these "
            "ticks to a scam type, so the engine does **not** invent one. That is a "
            "knowledge gap (incomplete KB), not proof the message is safe. Risk "
            "falls back to Low. See flags below if any still fired."
        )
    elif not ranked:
        st.write("No specific scam type matched.")
    else:
        for name, cf in ranked:
            st.write(f"**{SCAM_LABELS.get(name, name)}**  ({cf:.2f})")
            st.progress(min(max(cf, 0.0), 1.0))

    st.markdown("### What to do right now")
    seen = set()
    bullets = []
    for step in fired:
        key = step["then"]
        if key in ACTIONS and key not in seen:
            seen.add(key)
            bullets.extend(ACTIONS[key])
    if bullets:
        for b in bullets:
            st.markdown(f"- {b}")
    else:
        st.write("No specific action fired.")

    st.markdown("### Intermediate flags")
    flag_hits = [(f, known[f]) for f in FLAGS if f in known]
    if not flag_hits:
        st.write("No red flags fired.")
    else:
        for name, cf in sorted(flag_hits, key=lambda x: -x[1]):
            st.write(f"- {FLAG_LABELS.get(name, name)}  ·  CF {cf:.2f}")

    with st.expander("Why? (rules that fired)", expanded=True):
        if not fired:
            st.write("Nothing fired.")
        for step in fired:
            conds = " + ".join(step["if"])
            why = step.get("why") or ""
            st.markdown(
                f"- `{step['id']}`: {conds} → **{step['then']}** "
                f"(CF {step['cf']:.3f}). {why}"
            )

    st.markdown("### Reasoning tree")
    st.caption("Facts (blue) → flags (yellow) → scam type (orange) → risk → action (grey). Edge labels are rule IDs.")
    try:
        st.graphviz_chart(case_tree_dot(fired, facts, known))
    except Exception:
        st.warning("Tree could not be drawn in this browser. The Why? list above is the same explanation.")


def tab_analyze():
    st.subheader("Analyze a suspicious message or call")
    st.caption("Tick what you observed. The system will classify the scam type, risk, and next steps.")

    names = [s["name"] for s in SCENARIOS]
    cols = st.columns([3, 1, 1])
    with cols[0]:
        st.selectbox("Load example scenario", names, key="scenario_choice")
    with cols[1]:
        st.write("")
        st.button("Load", on_click=_load_example, use_container_width=True)
    with cols[2]:
        st.write("")
        st.button("Clear", on_click=_clear_form, use_container_width=True)

    channel_map = {fid: lab for fid, lab in CHANNEL_FACTS}
    if "channel" not in st.session_state:
        st.session_state["channel"] = SKIP
    st.radio(
        "How did they contact you?",
        [SKIP] + CHANNEL_IDS,
        format_func=lambda x: x if x == SKIP else channel_map[x],
        key="channel",
    )

    for group_name, items in FACT_GROUPS:
        with st.expander(group_name, expanded=False):
            for fid, label in items:
                st.checkbox(label, key=fid)

    facts = _selected_facts()
    clicked = st.button("Analyze", type="primary")
    if clicked:
        if not facts:
            st.info("Select at least one detail first")
            st.session_state.pop("result", None)
        else:
            st.session_state["result"] = infer(facts)
            st.session_state["result_facts"] = facts

    if "result" in st.session_state:
        known, fired = st.session_state["result"]
        _show_results(known, fired, st.session_state.get("result_facts", facts))


def tab_knowledge_base():
    st.subheader("Knowledge base")
    st.caption(
        f"{len(RULES)} rules and {len(FACT_LABELS)} facts in `rules.py`. "
        "Filter by layer or search for the viva."
    )
    c1, c2 = st.columns(2)
    with c1:
        layer_opt = st.selectbox(
            "Layer",
            ["All", "1 — flags", "2 — scam types", "3 — risk", "4 — actions"],
        )
    with c2:
        query = st.text_input("Search (id, IF, THEN, why)", "")
    rows = RULES
    if layer_opt != "All":
        layer_n = int(layer_opt[0])
        rows = [r for r in RULES if r["layer"] == layer_n]
    q = query.strip().lower()
    if q:
        rows = [
            r for r in rows
            if q in r["id"].lower()
            or q in r["then"].lower()
            or q in r["why"].lower()
            or q in " ".join(r["if"]).lower()
        ]
    table = [
        {
            "ID": r["id"],
            "layer": r["layer"],
            "IF": " AND ".join(r["if"]),
            "THEN": r["then"],
            "CF": r["cf"],
            "why": r["why"],
        }
        for r in rows
    ]
    st.dataframe(table, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(table)} of {len(RULES)} rules.")


def tab_full_tree():
    st.subheader("Full knowledge-base tree")
    st.caption("Every rule is an edge. This is the family-tree figure for the report.")
    view = st.selectbox(
        "View",
        ["Whole knowledge base"] + [f"Subtree: {SCAM_LABELS[t]}" for t in SCAM_TYPES],
    )
    try:
        if view == "Whole knowledge base":
            st.caption("This graph is large; zoom or pick one scam-type subtree for a readable viva figure.")
            st.graphviz_chart(full_tree_dot())
        else:
            scam = next(t for t in SCAM_TYPES if view.endswith(SCAM_LABELS[t]))
            st.graphviz_chart(scam_subtree_dot(scam))
    except Exception:
        st.warning("Graphviz could not render here. PNG copies are in the docs/ folder.")


def tab_how():
    st.subheader("How it works (viva crib sheet)")
    st.markdown(
        f"""
**What is an expert system?** Software that encodes expert knowledge as **rules**
and reasons over them to give advice **and explain itself**.

**Parts of this system**
- Knowledge base — `rules.py` ({len(FACT_LABELS)} facts, {len(RULES)} rules, actions, helplines)
- Inference engine — `engine.py` (forward chaining + certainty factors)
- Working memory — the `known` dictionary (what is believed, with a CF)
- User interface — this Streamlit app
- Explanation facility — fired-rule trace + family-tree diagram

**Why forward chaining?** The facts are known up front (what you ticked). We
discover the conclusion. Backward chaining is for "prove this goal" problems.

**Certainty factors.** Real rules are not 100% sure, so each has a CF from 0 to 1.
- One rule: `rule_cf = min(CF of conditions) × rule CF`
- Two rules for the same conclusion: `new = old + rule_cf × (1 − old)`

**Five layers** (the tree generations): facts → flags → scam types → risk → actions.

**Conflict resolution**
- Risk rules (R51–R54): **first match wins** (critical, then high, medium, low).
- Flag, scam-type and action rules: **all matches fire**.

**Difference from plain if/else.** Rules are data, separate from the engine.
Adding a rule does not change `engine.py`. The system can show *which* rule fired.

**What if a rule does not exist?** Expert systems are **closed-world**: they
only know what is written in `rules.py`. If no layer-2 (scam-type) rule matches,
the engine records `no_matching_rule` (trace id `GAP`), sets risk to **Low**
via R54, and advises you to verify officially. It will **not** guess a new scam
type. Flags can still fire even when the type is unknown.

**Limitations.** Rules are hand-written, not learned; they depend on honest
answers; they only cover the listed scam types; uncovered patterns look like Low.

**Future work.** Roman-Urdu keyword detection, learning CFs from reported cases,
a backward-chaining mode ("is this a wallet scam?"), adding rules for new scams.
        """
    )
    st.markdown("**Helplines** (verify before you rely on them):")
    for name, value in HELPLINES.items():
        st.write(f"- {name}: {value}")


tab1, tab2, tab3, tab4 = st.tabs(
    ["🔍 Analyze", "📚 Knowledge Base", "🌳 Full Tree", "ℹ️ How it works"]
)
with tab1:
    tab_analyze()
with tab2:
    tab_knowledge_base()
with tab3:
    tab_full_tree()
with tab4:
    tab_how()

st.divider()
st.caption(
    "Educational project, not legal or financial advice. "
    f"Made by {STUDENT_NAME}, {ROLL_NO}."
)
st.caption("Helplines in the How it works tab should be re-checked before submission.")
