#!/usr/bin/env python3
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: coverage_check.py <lcov_path> <threshold_percent>", file=sys.stderr)
        return 1

    lcov_path = sys.argv[1]
    try:
        threshold = float(sys.argv[2])
    except ValueError:
        print("invalid threshold_percent", file=sys.stderr)
        return 1

    # Only count core C source files: tiny-frpc/source + wrapper/linux
    include_substrs = ("tiny-frpc/source/", "wrapper/linux/")

    lines = 0
    covered = 0
    in_scope = False

    with open(lcov_path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            if ln.startswith("SF:"):
                sf = ln[3:].strip()
                in_scope = any(s in sf for s in include_substrs)
                continue
            if not in_scope:
                continue
            if ln.startswith("DA:"):
                # DA:<line>,<count>
                parts = ln[3:].split(",")
                if len(parts) >= 2:
                    lines += 1
                    try:
                        if int(parts[1]) > 0:
                            covered += 1
                    except ValueError:
                        pass

    pct = (covered * 100.0 / lines) if lines else 0.0
    print(f"LINE_COVERAGE(core)={pct:.2f}% ({covered}/{lines})")
    if pct < threshold:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


