"""Dump all rules to docs/rules_table.csv and docs/rules_table.md for the PDF."""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rules import RULES  # noqa: E402

DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)


def main():
    rows = [
        {
            "id": r["id"],
            "layer": r["layer"],
            "if": " AND ".join(r["if"]),
            "then": r["then"],
            "cf": r["cf"],
            "why": r["why"],
        }
        for r in RULES
    ]
    csv_path = DOCS / "rules_table.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "layer", "if", "then", "cf", "why"])
        writer.writeheader()
        writer.writerows(rows)

    md_path = DOCS / "rules_table.md"
    lines = [
        f"# ScamShield PK rules ({len(RULES)})",
        "",
        "| ID | Layer | IF | THEN | CF | why |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        why = r["why"].replace("|", "/")
        lines.append(
            f"| {r['id']} | {r['layer']} | {r['if']} | {r['then']} | {r['cf']} | {why} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {csv_path} and {md_path} ({len(RULES)} rules)")


if __name__ == "__main__":
    main()
