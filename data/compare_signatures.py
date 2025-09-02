#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

def normalize_sig(sig: str) -> str:
    """
    Normalize a signature string so patterns from both files compare fairly:
    - Uppercase hex bytes
    - Treat '?' and '??' as the same wildcard token '?'
    - Collapse whitespace
    """
    tokens = sig.replace(",", " ").split()
    norm = []
    for t in tokens:
        t = t.upper()
        if t in ("?", "??"):
            norm.append("?")
        else:
            norm.append(t)
    return " ".join(norm)

def load_old(path: Path) -> dict[str, str]:
    """
    data-sig-old.json structure:
    {
      "global_sigs": { name: signature, ... },
      "classes": { "ClassName": { "func_sigs": { "FuncName": signature, ... }}, ... }
    }
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}

    for name, sig in data.get("global_sigs", {}).items():
        if sig and sig != "None":
            out[f"global::{name}"] = sig

    for cls, cls_obj in data.get("classes", {}).items():
        for fn, sig in cls_obj.get("func_sigs", {}).items():
            if sig and sig != "None":
                out[f"{cls}::{fn}"] = sig

    return out

def load_new(path: Path) -> dict[str, str]:
    """
    data-sig.json structure:
    {
      "functions": {
        "Qualified::Name": { "sheet_name": "...", "signature": "..." },
        ...
      }
    }
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for name, obj in data.get("functions", {}).items():
        sig = obj.get("signature")
        if sig and sig != "None":
            out[name] = sig
    return out

def resolve_path(p: str, script_dir: Path) -> Path:
    """
    Resolve file path robustly regardless of current working directory:
    - As given
    - Relative to script_dir
    - If it starts with 'data/', try without it (useful when run from data/)
    - One level up from script_dir (repo root) + given
    """
    cand = Path(p)
    if cand.is_file():
        return cand
    if (script_dir / cand).is_file():
        return script_dir / cand
    if cand.parts and cand.parts[0].lower() == "data":
        cand2 = Path(*cand.parts[1:])
        if cand2.is_file():
            return cand2
        if (script_dir / cand2).is_file():
            return script_dir / cand2
    if (script_dir.parent / cand).is_file():
        return script_dir.parent / cand
    raise FileNotFoundError(f"File not found: {p} (tried: {cand}, {script_dir / cand}, {script_dir.parent / cand})")

def main() -> int:
    ap = argparse.ArgumentParser(description="Compare signature patterns between two JSON files.")
    # Defaults are filenames only; we resolve them against the script location.
    ap.add_argument("--old", default="data-sig-old.json", help="Path to data-sig-old.json")
    ap.add_argument("--new", default="data-sig.json", help="Path to data-sig.json")
    ap.add_argument("--limit", type=int, default=20, help="Max items to list per-difference section")
    ap.add_argument("--list-all", action="store_true", help="List all differences (overrides --limit)")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    try:
        old_path = resolve_path(args.old, script_dir)
        new_path = resolve_path(args.new, script_dir)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2

    old_map_raw = load_old(old_path)
    new_map_raw = load_new(new_path)

    old_map = {k: normalize_sig(v) for k, v in old_map_raw.items()}
    new_map = {k: normalize_sig(v) for k, v in new_map_raw.items()}

    # Pairwise compare where identifiers overlap
    common_keys = set(old_map) & set(new_map)
    pair_mismatch = {k: (old_map[k], new_map[k]) for k in common_keys if old_map[k] != new_map[k]}
    pair_match_count = len(common_keys) - len(pair_mismatch)

    # Set-wise compare (ignoring identifiers)
    set_old = set(old_map.values())
    set_new = set(new_map.values())
    only_in_old = sorted(set_old - set_new)
    only_in_new = sorted(set_new - set_old)
    common_sigs = set_old & set_new

    print("=== Signature Comparison Summary ===")
    print(f"Old file identifiers: {len(old_map):,} (unique sigs: {len(set_old):,})")
    print(f"New file identifiers: {len(new_map):,} (unique sigs: {len(set_new):,})")
    print(f"Overlapping identifiers: {len(common_keys):,}")
    print(f"  - Pairwise matches:   {pair_match_count:,}")
    print(f"  - Pairwise mismatches:{len(pair_mismatch):,}")
    print(f"Set-wise common signatures: {len(common_sigs):,}")
    print(f"Only in OLD (by signature):  {len(only_in_old):,}")
    print(f"Only in NEW (by signature):  {len(only_in_new):,}")
    print()

    def dump_list(title: str, items: list[str]):
        if not items:
            return
        print(title)
        lim = len(items) if args.list_all else min(len(items), args.limit)
        for i in range(lim):
            print(f"  {items[i]}")
        if lim < len(items) and not args.list_all:
            print(f"  ... ({len(items) - lim} more)")
        print()

    # Show pairwise mismatches (if any identifiers happen to overlap)
    if pair_mismatch:
        print("=== Pairwise identifier mismatches (normalized) ===")
        items = list(pair_mismatch.items())
        if not args.list_all:
            items = items[:args.limit]
        for k, (o, n) in items:
            print(f"- {k}")
            print(f"    old: {o}")
            print(f"    new: {n}")
        if len(pair_mismatch) > len(items) and not args.list_all:
            print(f"... ({len(pair_mismatch) - len(items)} more)\n")

    dump_list("=== Signatures only in OLD (normalized) ===", only_in_old)
    dump_list("=== Signatures only in NEW (normalized) ===", only_in_new)

    all_match = (len(only_in_old) == 0 and len(only_in_new) == 0 and len(pair_mismatch) == 0)
    if all_match:
        print("Result: All signatures match (after normalization).")
        return 0
    else:
        print("Result: Differences found.")
        return 1

if __name__ == "__main__":
    sys.exit(main())