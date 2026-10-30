"""
Family-tree diagrams for the viva / PDF.

Generations (rankdir=TB, rank=same per layer):
  facts (grandchildren) → flags → scam types → risk → actions

Three builders:
  case_tree_dot    — only what fired for this case (Analyze tab)
  full_tree_dot    — whole knowledge base (Full Tree tab / PDF)
  scam_subtree_dot — ancestors of one scam type (12 small PDF figures)
"""

from rules import (
    ACTIONS,
    FACTS,
    FLAGS,
    RISK_LEVELS,
    RULES,
    SCAM_TYPES,
)

# Which generation each node belongs to (for colour + rank).
LAYER_OF = {}
for _f in FACTS:
    LAYER_OF[_f] = 0
for _f in FLAGS:
    LAYER_OF[_f] = 1
for _f in SCAM_TYPES:
    LAYER_OF[_f] = 2
for _f in RISK_LEVELS:
    LAYER_OF[_f] = 3
for _f in ACTIONS:
    LAYER_OF[_f] = 4
LAYER_OF["scam_score"] = 2
LAYER_OF["no_matching_rule"] = 2


COLOUR = {
    0: "#d0ebff",  # facts — light blue
    1: "#fff3bf",  # flags — yellow
    2: "#ffd8a8",  # scam types — orange
    3: "#ffc9c9",  # risk default — red-ish
    4: "#e9ecef",  # actions — grey
}

RISK_COLOUR = {
    "risk_critical": "#fa5252",
    "risk_high": "#ff922b",
    "risk_medium": "#ffd43b",
    "risk_low": "#69db7c",
}


def _node_colour(name):
    if name in RISK_COLOUR:
        return RISK_COLOUR[name]
    return COLOUR.get(LAYER_OF.get(name, 0), "#ffffff")


def _label(name, cf=None):
    """Graphviz node label. CF shown on conclusion nodes."""
    text = name
    if cf is not None:
        text = f"{name}\\n{cf:.2f}"
    return text


def _header():
    return [
        "digraph G {",
        "rankdir=TB;",
        'node [shape=box, style="filled,rounded", fontname="Helvetica", fontsize=10];',
        "edge [fontname=Helvetica, fontsize=9];",
        "graph [bgcolor=white];",
    ]


def _rank_lines(names):
    """Keep each generation on one horizontal row (family-tree look)."""
    buckets = {0: [], 1: [], 2: [], 3: [], 4: []}
    extra = []
    for n in names:
        layer = LAYER_OF.get(n)
        if layer in buckets:
            buckets[layer].append(n)
        else:
            extra.append(n)
    lines = []
    for layer in range(5):
        if buckets[layer]:
            quoted = " ".join(f'"{n}"' for n in buckets[layer])
            lines.append(f"{{ rank=same; {quoted} }}")
    if extra:
        quoted = " ".join(f'"{n}"' for n in extra)
        lines.append(f"{{ rank=same; {quoted} }}")
    return lines


def _node_lines(names, cfs=None):
    lines = []
    for n in names:
        cf = None if cfs is None else cfs.get(n)
        fill = _node_colour(n)
        lines.append(
            f'"{n}" [label="{_label(n, cf)}", fillcolor="{fill}"];'
        )
    return lines


def case_tree_dot(fired, facts, known=None):
    """Nodes and edges for the current case only."""
    names = set(facts)
    edges = []
    for r in fired:
        names.add(r["then"])
        for c in r["if"]:
            names.add(c)
            edges.append((c, r["then"], r["id"]))

    cfs = {}
    if known:
        for n in names:
            if n in known and n not in facts:
                cfs[n] = known[n]

    lines = _header()
    lines.extend(_node_lines(sorted(names), cfs))
    lines.extend(_rank_lines(names))
    for src, dst, rid in edges:
        lines.append(f'"{src}" -> "{dst}" [label="{rid}"];')
    lines.append("}")
    return "\n".join(lines)


def full_tree_dot():
    """Every rule as an edge — the whole knowledge base figure."""
    names = set(FACTS)
    edges = []
    for r in RULES:
        names.add(r["then"])
        for c in r["if"]:
            names.add(c)
            edges.append((c, r["then"], r["id"]))

    lines = _header()
    lines.append("ranksep=1.2;")
    lines.append("nodesep=0.15;")
    lines.append('node [fontsize=8];')
    lines.extend(_node_lines(sorted(names)))
    lines.extend(_rank_lines(names))
    for src, dst, rid in edges:
        lines.append(f'"{src}" -> "{dst}" [label="{rid}"];')
    lines.append("}")
    return "\n".join(lines)


def _ancestors_of(scam_type):
    """Walk backwards: which rules can lead to this scam type?"""
    wanted = {scam_type}
    added = True
    subset = []
    while added:
        added = False
        for r in RULES:
            if r in subset:
                continue
            if r["then"] in wanted:
                subset.append(r)
                for c in r["if"]:
                    wanted.add(c)
                added = True
    return subset, wanted


def scam_subtree_dot(scam_type):
    """Facts and flags that can lead to one scam type (small viva figure)."""
    subset, names = _ancestors_of(scam_type)
    names.add(scam_type)
    lines = _header()
    lines.append(f'labelloc="t"; label="{scam_type}";')
    lines.extend(_node_lines(sorted(names)))
    lines.extend(_rank_lines(names))
    for r in subset:
        for c in r["if"]:
            lines.append(f'"{c}" -> "{r["then"]}" [label="{r["id"]}"];')
    lines.append("}")
    return "\n".join(lines)
