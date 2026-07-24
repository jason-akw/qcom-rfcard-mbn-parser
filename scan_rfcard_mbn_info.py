#!/usr/bin/env python3
"""Scan a directory of RF config MBNs and export RFCard identity information."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import recover_rfcard_combos as rfcard


def inspect_mbn(path: Path) -> dict[str, object]:
    row: dict[str, object] = {
        "file": path.name,
        "path": str(path.resolve()),
        "status": "error",
        "name": None,
        "name_source": None,
        "canonical_xml_variant_name": None,
        "canonical_xml_variant_name_embedded": False,
        "hwid": None,
        "fsid": None,
        "bid": None,
        "key": None,
        "res_dat_path": None,
        "environment_name_high": None,
        "environment_name_low": None,
        "dat_encoding": None,
        "protobuf_size": None,
        "lte_combos": None,
        "nr_ca_combos": None,
        "endc_combos": None,
        "nrdc_combos": None,
        "total_combos": None,
        "high_lte_combos": None,
        "high_nr_ca_combos": None,
        "high_endc_combos": None,
        "high_nrdc_combos": None,
        "low_lte_combos": None,
        "low_nr_ca_combos": None,
        "low_endc_combos": None,
        "low_nrdc_combos": None,
        "error": None,
    }
    try:
        dats = rfcard.extract_rfc_dats(path.read_bytes())
        res_items = [
            (name, data)
            for name, data in dats.items()
            if name.lower().endswith("_res.dat")
        ]
        if not res_items:
            raise ValueError("No /rfc/*_res.dat item found")
        if len(res_items) != 1:
            raise ValueError(f"Expected one res DAT, found {len(res_items)}")

        dat_name, res_dat = res_items[0]
        encoding, protobuf_payload, message = rfcard.parse_res_dat(res_dat)
        info = rfcard.read_rfcard_info(dat_name, path.name, message.rrc)
        rrc = message.rrc

        # Count the compiled reference records directly. This deliberately does
        # not materialize combo strings or emit XML/DIAG combo output.
        high_lte = int(rrc.lte_info_per_band_sub_cap_high_num)
        high_nr_ca = int(rrc.nr5g_info_per_band_sub_cap_high_num)
        high_endc = int(rrc.lte_nr5g_info_per_band_sub_cap_high_num)
        high_nrdc = int(rrc.nr5g_nr5g_info_per_band_sub_cap_high_num)
        low_lte = int(rrc.lte_info_per_band_sub_cap_low_num)
        low_nr_ca = int(rrc.nr5g_info_per_band_sub_cap_low_num)
        low_endc = int(rrc.lte_nr5g_info_per_band_sub_cap_low_num)
        low_nrdc = int(rrc.nr5g_nr5g_info_per_band_sub_cap_low_num)

        lte = high_lte + low_lte
        nr_ca = high_nr_ca + low_nr_ca
        endc = high_endc + low_endc
        nrdc = high_nrdc + low_nrdc
        row.update(info)
        row.update(
            {
                "status": "ok",
                "dat_encoding": encoding,
                "protobuf_size": len(protobuf_payload),
                "lte_combos": lte,
                "nr_ca_combos": nr_ca,
                "endc_combos": endc,
                "nrdc_combos": nrdc,
                "total_combos": lte + nr_ca + endc + nrdc,
                "high_lte_combos": high_lte,
                "high_nr_ca_combos": high_nr_ca,
                "high_endc_combos": high_endc,
                "high_nrdc_combos": high_nrdc,
                "low_lte_combos": low_lte,
                "low_nr_ca_combos": low_nr_ca,
                "low_endc_combos": low_endc,
                "low_nrdc_combos": low_nrdc,
            }
        )
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--json", type=Path, dest="json_output")
    parser.add_argument("--csv", type=Path, dest="csv_output")
    args = parser.parse_args()

    root = args.directory.resolve()
    files = sorted(root.rglob("*.mbn"), key=lambda item: str(item).lower())
    rows = [inspect_mbn(path) for path in files]

    json_output = args.json_output or root / "rfcard_info_all.json"
    csv_output = args.csv_output or root / "rfcard_info_all.csv"
    json_output.write_text(
        json.dumps(
            {
                "directory": str(root),
                "total": len(rows),
                "success": sum(row["status"] == "ok" for row in rows),
                "failed": sum(row["status"] != "ok" for row in rows),
                "cards": rows,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    fieldnames = list(rows[0]) if rows else [
        "file",
        "path",
        "status",
        "name",
        "hwid",
        "fsid",
        "bid",
        "key",
        "error",
    ]
    with csv_output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "directory": str(root),
        "total": len(rows),
        "success": sum(row["status"] == "ok" for row in rows),
        "failed": sum(row["status"] != "ok" for row in rows),
        "json": str(json_output.resolve()),
        "csv": str(csv_output.resolve()),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
