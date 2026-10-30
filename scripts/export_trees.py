"""Write DOT files always; render PNG if the Graphviz binary is installed."""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rules import SCAM_TYPES  # noqa: E402
from tree import full_tree_dot, scam_subtree_dot  # noqa: E402

DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)


def _write_dot(dot_source, path):
    path.write_text(dot_source, encoding="utf-8")
    print("wrote", path)


def _render_png(dot_path, png_path):
    try:
        import graphviz
    except ImportError:
        return False
    if not shutil.which("dot"):
        return False
    src = graphviz.Source(dot_path.read_text(encoding="utf-8"))
    src.format = "png"
    src.render(filename=str(png_path.with_suffix("")), cleanup=True)
    print("wrote", png_path)
    return True


def main():
    jobs = [("full_tree", full_tree_dot())]
    jobs.extend((f"tree_{scam}", scam_subtree_dot(scam)) for scam in SCAM_TYPES)

    png_ok = True
    for name, dot_source in jobs:
        dot_path = DOCS / f"{name}.dot"
        _write_dot(dot_source, dot_path)
        if not _render_png(dot_path, DOCS / f"{name}.png"):
            png_ok = False

    if not png_ok:
        print(
            "DOT files are in docs/. PNG export needs the Graphviz program "
            "(install from https://graphviz.org and re-run this script)."
        )


if __name__ == "__main__":
    main()
