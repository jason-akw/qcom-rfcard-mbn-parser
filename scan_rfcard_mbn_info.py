#!/usr/bin/env python3
"""Scan a directory of RF config MBNs and export RFCard identity information."""

from __future__ import annotations

import argparse
import csv
import json
import re
import struct
import sys
from pathlib import Path

import legacy_rfcard_parser as legacy
import new_rfcard_parser as rfcard


def _identity_token(token: str | None) -> int | None:
    if token is None:
        return None
    base = 16 if any(character.isalpha() for character in token) else 10
    return int(token, base)


def _legacy_public_count(
    blob: bytes,
    symbols: list[legacy.DynamicSymbol],
    suffix: str,
    *,
    excluded_markers: tuple[str, ...] = (),
) -> int:
    counts: set[int] = set()
    for symbol in symbols:
        name = symbol.name.lower()
        if (
            symbol.file_offset is None
            or "internal" in name
            or not name.endswith(suffix)
            or any(marker in name for marker in excluded_markers)
        ):
            continue
        counts.add(struct.unpack_from("<H", blob, symbol.file_offset)[0])
    if len(counts) > 1:
        raise ValueError(
            f"Conflicting public combo counts for {suffix}: {sorted(counts)}"
        )
    return next(iter(counts), 0)


def _inspect_legacy_mbn(
    path: Path,
    blob: bytes,
    row: dict[str, object],
) -> dict[str, object]:
    image = legacy.Elf32Image(blob)
    symbols = image.dynamic_symbols()
    name = legacy.rfcard_name_from_symbols(image)
    if name is None:
        raise ValueError("No generated RFCard dynamic symbol found")

    identity = re.fullmatch(
        r"(?P<hwid>[0-9A-F]+)_(?P<fsid>[0-9A-F]+)"
        r"(?:_(?P<bid>[0-9A-F]+))?",
        path.stem,
        re.IGNORECASE,
    )
    hwid = _identity_token(identity.group("hwid")) if identity else None
    fsid = _identity_token(identity.group("fsid")) if identity else None
    bid = _identity_token(identity.group("bid")) if identity else None
    if identity and bid is None:
        bid = 0

    lte = _legacy_public_count(
        blob,
        symbols,
        "_lte_combos_info_table_sub_cap_high",
    )
    nr_ca = _legacy_public_count(
        blob,
        symbols,
        "_nr5g_combos_info_table_sub_cap_high",
        excluded_markers=("_lte_nr5g_", "_nr5g_nr5g_"),
    )
    endc = _legacy_public_count(
        blob,
        symbols,
        "_lte_nr5g_combos_info_table_sub_cap_high",
    )
    nrdc = _legacy_public_count(
        blob,
        symbols,
        "_nr5g_nr5g_combos_info_table_sub_cap_high",
    )
    row.update(
        {
            "status": "ok",
            "name": name,
            "name_source": "ELF dynamic symbol",
            "hwid": hwid,
            "fsid": fsid,
            "bid": bid,
            "key": path.stem,
            "lte_combos": lte,
            "nr_ca_combos": nr_ca,
            "endc_combos": endc,
            "nrdc_combos": nrdc,
            "total_combos": lte + nr_ca + endc + nrdc,
            "high_lte_combos": lte,
            "high_nr_ca_combos": nr_ca,
            "high_endc_combos": endc,
            "high_nrdc_combos": nrdc,
            "low_lte_combos": 0,
            "low_nr_ca_combos": 0,
            "low_endc_combos": 0,
            "low_nrdc_combos": 0,
        }
    )
    return row


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
        blob = path.read_bytes()
        if not path.name.lower().startswith("rf_config_"):
            return _inspect_legacy_mbn(path, blob, row)

        dats = rfcard.extract_rfc_dats(blob)
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
