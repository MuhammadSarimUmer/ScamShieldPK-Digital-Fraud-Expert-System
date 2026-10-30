"""Build ScamShield_PK_Code_Explanation.pdf at the project root."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fpdf import FPDF

from rules import FACTS, RULES, SCAM_TYPES
from student import ROLL_NO, STUDENT_NAME

OUT = ROOT / "ScamShield_PK_Code_Explanation.pdf"


class PDF(FPDF):
    def header(self):
        self.set_xy(self.l_margin, 10)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(80, 80, 80)
        self.cell(0, 6, "ScamShield PK  |  Expert system code explanation", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(180, 180, 180)
        y = self.get_y() + 1
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.set_y(y + 6)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, f"Page {self.page_no()}  |  Educational project, not legal advice", align="C", new_x="LMARGIN", new_y="NEXT")

    def _w(self):
        return self.epw

    def heading(self, text, size=14):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", size)
        self.set_text_color(20, 60, 90)
        self.ln(4)
        self.set_x(self.l_margin)
        self.multi_cell(self._w(), 8, text)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def p(self, text):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 11)
        self.multi_cell(self._w(), 6, text)
        self.ln(2)

    def bullet(self, text):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 11)
        self.multi_cell(self._w(), 6, f"  -  {text}")

    def code(self, text):
        self.set_x(self.l_margin)
        self.set_font("Courier", "", 8)
        self.set_fill_color(245, 245, 245)
        self.multi_cell(self._w(), 4.5, text, fill=True)
        self.ln(3)

    def box(self, title, body):
        self.set_x(self.l_margin)
        self.set_fill_color(255, 248, 220)
        self.set_font("Helvetica", "B", 12)
        self.multi_cell(self._w(), 7, title, fill=True)
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 11)
        self.multi_cell(self._w(), 6, body, fill=True)
        self.ln(4)


def build():
    pdf = PDF()
    pdf.set_margins(16, 22, 16)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 20)
    pdf.multi_cell(pdf.epw, 10, "ScamShield PK")
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 13)
    pdf.multi_cell(pdf.epw, 7, "Digital Fraud Triage Expert System")
    pdf.ln(2)
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(pdf.epw, 6, f"Student: {STUDENT_NAME}    Roll no: {ROLL_NO}")
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 6, "Course: Artificial Intelligence  |  Type: rule-based expert system")
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(
        pdf.epw, 6,
        f"Knowledge base: {len(RULES)} rules, {len(FACTS)} facts, {len(SCAM_TYPES)} scam types.",
    )
    pdf.ln(2)

    pdf.box(
        "PLACEHOLDER  --  Streamlit Community Cloud URL",
        "Live app URL: _______________________________________________\n"
        "GitHub repo (public): ________________________________________\n"
        "Deploy file: app.py     Branch: main\n"
        "Check from a phone / incognito window that the link opens.\n\n"
        "How to fill this in:\n"
        "1. Push this folder to a public GitHub repository.\n"
        "2. Open https://share.streamlit.io  ->  New app.\n"
        "3. Pick the repo, branch main, main file app.py.\n"
        "4. Copy the public https://....streamlit.app URL here and into README.md.",
    )

    pdf.heading("1. What this program is")
    pdf.p(
        "This is a rule-based expert system, not a chatbot and not a machine-learning "
        "model. Expert knowledge about Pakistan-specific digital fraud (fake JazzCash "
        "agents, BISP SMS, OLX overpayment, courier links, SIM-swap, fake NADRA, and "
        "others) is stored as IF-THEN rules with certainty factors. The engine matches "
        "the user's ticks against those rules and explains every conclusion."
    )
    pdf.p("Five classic expert-system parts:")
    pdf.bullet("Knowledge base  --  rules.py (data, not if/else)")
    pdf.bullet("Inference engine  --  engine.py (forward chaining + CF)")
    pdf.bullet("Working memory  --  the known dictionary")
    pdf.bullet("User interface  --  app.py (Streamlit)")
    pdf.bullet("Explanation facility  --  fired-rule list + family-tree diagram")

    pdf.heading("2. Why forward chaining and certainty factors")
    pdf.p(
        "Facts are known up front (what the user observed), so we chain forward from "
        "data to conclusions. Backward chaining would be for 'prove this goal' questions."
    )
    pdf.p("Certainty factor of one rule:")
    pdf.code("rule_cf = min(CF of each condition) * rule['cf']")
    pdf.p("Two rules supporting the same conclusion (MYCIN-style combine):")
    pdf.code("new = old + rule_cf * (1 - old)")
    pdf.p(
        "Risk rules R51-R54 use first-match conflict resolution (critical, then high, "
        "medium, low). Flag, scam-type, and action rules fire all matches."
    )

    pdf.heading("3. Five layers (the family tree)")
    pdf.bullet("Layer 0  FACTS  --  checkboxes the user ticks")
    pdf.bullet("Layer 1  FLAGS  --  credential_request, impersonation, ...")
    pdf.bullet("Layer 2  SCAM TYPES  --  wallet_fraud, sim_swap_scam, ...")
    pdf.bullet("Layer 3  RISK  --  critical / high / medium / low")
    pdf.bullet("Layer 4  ACTIONS  --  what to do right now")
    pdf.p(
        "If no layer-2 rule matches, the engine does not invent a scam type. It records "
        "a knowledge gap (trace id GAP), sets risk Low, and tells the user to verify "
        "officially. Missing knowledge is not the same as 'safe'."
    )

    pdf.heading("4. File-by-file code explanation")
    pdf.p(
        "rules.py  --  The knowledge base. FACTS, FLAGS, SCAM_TYPES, ACTIONS, HELPLINES, "
        "and RULES (a list of dictionaries). Each rule has id, layer, if, then, cf, why. "
        "Adding a new scam means adding a dict here; engine.py does not change. "
        "validate_knowledge_base() runs at import so a typo in a condition name crashes "
        "loudly instead of silently doing nothing in the viva."
    )
    pdf.p(
        "engine.py  --  infer(facts) is the whole reasoner. clean_facts() drops unknown "
        "ids and duplicates. Phase A forward-chains layers 1-2 until a full pass fires "
        "nothing (each rule at most once). scam_score is the max CF among scam types. "
        "Phase B-1 picks the first matching risk rule. Phase B-2 fires every matching "
        "action. Returns (known, fired) so the UI can show Why?"
    )
    pdf.code(
        "def infer(facts):\n"
        "    known = {f: 1.0 for f in clean_facts(facts)}\n"
        "    # Phase A: while changed, fire unfired layer 1-2 rules\n"
        "    known['scam_score'] = max(scam-type CFs)\n"
        "    # if scam_score == 0: mark no_matching_rule (GAP)\n"
        "    # Phase B-1: first matching risk rule\n"
        "    # Phase B-2: all matching action rules"
    )
    pdf.p(
        "tree.py  --  Builds Graphviz DOT strings. case_tree_dot is the current case. "
        "full_tree_dot is the whole KB. scam_subtree_dot is one scam type for the PDF figures."
    )
    pdf.p(
        "app.py  --  Four tabs: Analyze, Knowledge Base, Full Tree, How it works. "
        "Load example writes session_state before widgets render (Streamlit rule). "
        "Clear resets ticks. Results stay on screen until you analyze again. "
        "Knowledge Base can filter by layer and search."
    )
    pdf.p(
        "scenarios.py / tests/test_engine.py  --  Demo cases double as pytest. "
        "The original 10 assignment scenarios must still pass. Extra cases cover "
        "utility bills, SIM-swap, crypto, charity, and NADRA."
    )
    pdf.p(
        "student.py  --  Name and roll number for the footer. Replace ROLL-NO before submission."
    )

    pdf.heading("5. How to run locally")
    pdf.code("pip install -r requirements.txt\nstreamlit run app.py")
    pdf.p("Tests: pip install -r requirements-dev.txt   then   pytest")
    pdf.p("Rebuild this PDF: python scripts/build_pdf.py")
    pdf.p("Rebuild tree PNGs (needs Graphviz): python scripts/export_trees.py")

    pdf.heading("6. Viva answers (short)")
    pdf.bullet("Expert system = knowledge as rules + engine that explains itself.")
    pdf.bullet("Forward chaining because facts are given first.")
    pdf.bullet("Not plain if/else: rules are data; the Why? trace lists which rule fired.")
    pdf.bullet("Limitation: hand-written rules, honest ticks, uncovered patterns look Low.")
    pdf.bullet("Future: Roman-Urdu keywords, learned CFs, backward-chaining mode.")

    pdf.heading("7. Knowledge sources (cite in the report)")
    pdf.bullet("FIA NR3C public awareness (helpline 1991)")
    pdf.bullet("PTA consumer awareness on SMS/call fraud")
    pdf.bullet("SBP / bank pages: never share OTP/PIN")
    pdf.bullet("JazzCash 4444, Easypaisa 3737, BISP 8171, NADRA 1515")
    pdf.bullet("OLX Pakistan safety tips (overpayment)")
    pdf.p("Re-verify helpline numbers before you submit.")

    pdf.output(str(OUT))
    print("wrote", OUT)


if __name__ == "__main__":
    build()
