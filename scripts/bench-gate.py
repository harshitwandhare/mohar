"""Fail when a benchmark got slower than main by more than the allowed fraction.

Reads the change estimates criterion writes after `cargo bench -- --baseline main`. A benchmark only
fails when the lower end of its confidence interval is past the limit, so runner noise alone doesn't
block a pull request. Benchmarks with no baseline yet are listed and pass.

Usage: python scripts/bench-gate.py <criterion dir> <max slowdown, e.g. 0.20>
"""

import json
import sys
from pathlib import Path


def main() -> int:
    root, limit = Path(sys.argv[1]), float(sys.argv[2])
    if not root.is_dir():
        print(f"{root}: no criterion results")
        return 1
    failed = False
    seen = 0
    for bench in sorted(p.parent for p in root.rglob("new/estimates.json")):
        name = bench.relative_to(root).as_posix().removesuffix("/new")
        if name.endswith("/base") or "/report" in name:
            continue
        seen += 1
        change = bench.parent / "change" / "estimates.json"
        if not change.exists():
            print(f"new       {name}")
            continue
        mean = json.loads(change.read_text())["mean"]
        point = mean["point_estimate"]
        low = mean["confidence_interval"]["lower_bound"]
        bad = low > limit
        failed |= bad
        print(f"{'SLOWER' if bad else 'ok':<9} {name}: {point:+.1%} (lower bound {low:+.1%})")
    if seen == 0:
        print("no benchmarks found")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
