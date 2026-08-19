#!/usr/bin/env python3
"""
Compare an LTE-CA or NR-CA "UE capability" CSV export against every RF-card
*_combinations.csv found under a directory of extracted modem.img RF-card
modules, and rank the RF cards by how closely their supported carrier
aggregation combos match the input file.

Usage:
    python3 compare_ca.py <ue_capability.csv> [--dir RF_CARDS_DIR] \
        [--table {auto,lte_ca,nr_ca}] [--top N]

Examples:
    python3 compare_ca.py lteca-2026-08-19_14-42-37.csv
    python3 compare_ca.py nrca-2026-08-19_14-59-54.csv
    python3 compare_ca.py my_capture.csv --dir /path/to/rf_cards --top 10
"""
import argparse
import csv
import glob
import os
import re
import sys

DL_COL_RE = re.compile(r"^(NR )?DL\d+$")

# How to interpret the "expression" column of *_combinations.csv for each
# capability table, and how the UE-capability CSV's own DL-band columns are
# spelled (used only for auto-detection of the table kind).
TABLE_CONFIG = {
    "lte_ca": {
        "expr_prefix": "CA_",
        "token_strip_prefix": "B",
        "detect": lambda header: any(h == "DL1" for h in header)
        and not any(h.startswith("NR ") for h in header),
    },
    "nr_ca": {
        "expr_prefix": "NRCA_",
        "token_strip_prefix": "n",
        "detect": lambda header: any(h.startswith("NR DL") for h in header),
    },
}


def detect_table_kind(header, filename_hint=""):
    for kind, cfg in TABLE_CONFIG.items():
        if cfg["detect"](header):
            return kind
    hint = filename_hint.lower()
    if "nrca" in hint or "nr_ca" in hint or "nr-ca" in hint:
        return "nr_ca"
    if "lteca" in hint or "lte_ca" in hint or "lte-ca" in hint:
        return "lte_ca"
    raise ValueError(
        "Could not auto-detect whether this is an LTE-CA or NR-CA CSV. "
        "Pass --table lte_ca or --table nr_ca explicitly."
    )


def parse_ue_csv(path, table_kind=None):
    """Parse a UE-capability CA CSV into a set of band-combo tuples.

    Each row's DL band columns (DL1/DL2/DL3 for LTE, NR DL1/NR DL2/NR DL3
    for NR) are collected into a sorted tuple, e.g. ('20A', '7C', '3C').
    MIMO layers, modulation, UL-only assignment and BCS are ignored since
    they describe RF sub-variants of the same underlying CA combo.
    """
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f, delimiter=";")
        header = next(reader)
        if table_kind is None:
            table_kind = detect_table_kind(header, filename_hint=os.path.basename(path))

        dl_indices = [i for i, h in enumerate(header) if DL_COL_RE.match(h.strip())]
        if not dl_indices:
            raise ValueError(f"No DL band columns found in header: {header}")

        combos = set()
        for row in reader:
            if not row or not row[0].strip():
                continue
            bands = [row[i].strip() for i in dl_indices if i < len(row) and row[i].strip()]
            if not bands:
                continue
            combos.add(tuple(sorted(bands)))

    return combos, table_kind


def parse_rf_card(dirpath, table_kind):
    files = glob.glob(os.path.join(dirpath, "*_combinations.csv"))
    if not files:
        return set()

    cfg = TABLE_CONFIG[table_kind]
    prefix = cfg["expr_prefix"]
    strip_prefix = cfg["token_strip_prefix"]

    combos = set()
    with open(files[0], newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("table") != table_kind:
                continue
            expr = (row.get("expression") or "").strip()
            if not expr.startswith(prefix):
                continue
            expr = expr[len(prefix):]
            bands = []
            for tok in expr.split("+"):
                tok = tok.strip()
                if tok.startswith(strip_prefix):
                    tok = tok[len(strip_prefix):]
                bands.append(tok)
            combos.add(tuple(sorted(bands)))

    return combos


def find_rf_card_dirs(base_dir):
    dirs = []
    for name in sorted(os.listdir(base_dir)):
        path = os.path.join(base_dir, name)
        if os.path.isdir(path) and glob.glob(os.path.join(path, "*_combinations.csv")):
            dirs.append((name, path))
    return dirs


def main():
    parser = argparse.ArgumentParser(
        description="Match an LTE-CA/NR-CA UE-capability CSV against extracted RF-card combos."
    )
    parser.add_argument("ue_csv", help="Path to the UE-capability CA CSV (LTE or NR).")
    parser.add_argument(
        "--dir",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="Directory containing RF-card subdirs, each with a *_combinations.csv "
        "(default: directory this script lives in).",
    )
    parser.add_argument(
        "--table",
        choices=["auto", "lte_ca", "nr_ca"],
        default="auto",
        help="Force the capability table kind instead of auto-detecting from the CSV header.",
    )
    parser.add_argument(
        "--top", type=int, default=0, help="Only print the top N ranked RF cards (default: all)."
    )
    parser.add_argument(
        "--no-missing",
        action="store_true",
        help="Skip printing the list of combos missing from the best-matching RF card.",
    )
    args = parser.parse_args()

    table_kind = None if args.table == "auto" else args.table
    ue_combos, table_kind = parse_ue_csv(args.ue_csv, table_kind=table_kind)
    ue_ca_only = {c for c in ue_combos if len(c) > 1}
    ue_single = {c for c in ue_combos if len(c) == 1}

    label = "NR-CA" if table_kind == "nr_ca" else "LTE-CA"
    print(
        f"UE capability CSV ({label}, {os.path.basename(args.ue_csv)}): "
        f"{len(ue_combos)} distinct band-combos total "
        f"({len(ue_ca_only)} CA combos with 2+ bands, {len(ue_single)} single-band entries)"
    )
    print()

    rf_dirs = find_rf_card_dirs(args.dir)
    if not rf_dirs:
        print(f"No RF-card subdirectories with *_combinations.csv found under {args.dir}", file=sys.stderr)
        sys.exit(1)

    results = []
    for name, dirpath in rf_dirs:
        card_combos = parse_rf_card(dirpath, table_kind)
        card_ca_only = {c for c in card_combos if len(c) > 1}
        card_single = {c for c in card_combos if len(c) == 1}

        inter = ue_ca_only & card_ca_only
        union = ue_ca_only | card_ca_only
        jaccard = len(inter) / len(union) if union else 0.0
        recall = len(inter) / len(ue_ca_only) if ue_ca_only else 0.0
        precision = len(inter) / len(card_ca_only) if card_ca_only else 0.0
        inter_single = ue_single & card_single

        results.append(
            {
                "dir": name,
                "card_combos": card_combos,
                "card_ca_total": len(card_ca_only),
                "intersection": len(inter),
                "jaccard": jaccard,
                "recall": recall,
                "precision": precision,
                "single_intersection": len(inter_single),
                "single_total_ue": len(ue_single),
            }
        )

    results.sort(key=lambda r: (r["recall"], r["jaccard"]), reverse=True)
    shown = results[: args.top] if args.top > 0 else results

    print(
        f"{'RF card':10s} {'combos':>7s} {'matched':>8s} {'recall%':>8s} "
        f"{'jaccard%':>9s} {'precision%':>10s} {'single match':>13s}"
    )
    for r in shown:
        print(
            f"{r['dir']:10s} {r['card_ca_total']:7d} {r['intersection']:8d} "
            f"{r['recall']*100:7.1f}% {r['jaccard']*100:8.1f}% {r['precision']*100:9.1f}% "
            f"{r['single_intersection']:4d}/{r['single_total_ue']:<4d}"
        )

    print()
    top_recall = results[0]["recall"]
    top_jaccard = max(r["jaccard"] for r in results if r["recall"] == top_recall)
    print("Top candidate(s) by recall (coverage of the input CSV), tie-broken by jaccard:")
    for r in results:
        if r["recall"] == top_recall and r["jaccard"] == top_jaccard:
            print(f"  {r['dir']}  recall={r['recall']*100:.1f}%  jaccard={r['jaccard']*100:.1f}%  combos={r['card_ca_total']}")

    if not args.no_missing:
        best = results[0]
        best_ca = {c for c in best["card_combos"] if len(c) > 1}
        best_single = {c for c in best["card_combos"] if len(c) == 1}
        missing = (ue_ca_only - best_ca) | (ue_single - best_single)
        print()
        print(f"Combos in input CSV but NOT found in best candidate {best['dir']}: {len(missing)}")
        for m in sorted(missing):
            print("   ", "+".join(m))


if __name__ == "__main__":
    main()
