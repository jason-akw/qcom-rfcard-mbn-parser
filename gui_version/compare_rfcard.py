#!/usr/bin/env python3
"""Compare modern Qualcomm RFCard MBN capability tables.

The script recursively scans rf_config_*.mbn files, decodes them through
new_rfcard_parser.py, and writes two human-readable reports:

    rfcard_lte_compare.txt
    rfcard_nr_compare.txt

By default, the naturally first filename is the reference profile. Use
--reference to choose another file by filename, relative path, or unique
substring.

Both this script and new_rfcard_parser.py should normally be kept in the same
folder.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

try:
    import new_rfcard_parser as rfcard
except ImportError as exc:
    raise SystemExit(
        "Could not import new_rfcard_parser.py. Put it beside this comparison "
        "script, or add its folder to PYTHONPATH."
    ) from exc


SECTION_LABELS = {
    "ca_4g_combos": "LTE CA",
    "ca_5g_combos": "NR-CA",
    "ca_4g_5g_combos": "EN-DC",
    "ca_5g_5g_combos": "NR-DC",
}
NR_SECTION_KEYS = ("ca_5g_combos", "ca_4g_5g_combos", "ca_5g_5g_combos")
LTE_SECTION_KEYS = ("ca_4g_combos",)


@dataclass(frozen=True, order=True)
class ComboSignature:
    section: str
    expression: str
    attributes: tuple[tuple[str, str], ...] = ()

    def display(self, include_section: bool = False) -> str:
        text = self.expression
        if self.attributes:
            props = ", ".join(f"{key}={value}" for key, value in self.attributes)
            text += f"  {{{props}}}"
        if include_section:
            return f"[{SECTION_LABELS.get(self.section, self.section)}] {text}"
        return text


@dataclass
class Profile:
    path: Path
    relative_path: str
    name: str
    identity: dict[str, object]
    dat_encoding: str
    protobuf_size: int
    raw_counts: dict[str, int] = field(default_factory=dict)
    signatures: dict[str, set[ComboSignature]] = field(default_factory=dict)
    lte_bands: set[int] = field(default_factory=set)
    nr_bands: set[int] = field(default_factory=set)

    @property
    def lte_signatures(self) -> set[ComboSignature]:
        return set().union(*(self.signatures.get(key, set()) for key in LTE_SECTION_KEYS))

    @property
    def nr_signatures(self) -> set[ComboSignature]:
        return set().union(*(self.signatures.get(key, set()) for key in NR_SECTION_KEYS))


@dataclass
class Failure:
    path: Path
    relative_path: str
    error: str


def natural_key(text: str) -> tuple[object, ...]:
    return tuple(
        int(part) if part.isdigit() else part.casefold()
        for part in re.split(r"(\d+)", text)
    )


def combo_sort_key(signature: ComboSignature) -> tuple[object, ...]:
    return (
        SECTION_LABELS.get(signature.section, signature.section),
        natural_key(signature.expression),
        signature.attributes,
    )


def extract_bands(expression: str) -> tuple[set[int], set[int]]:
    # Reconstructed expressions use uppercase B for LTE and uppercase N for NR.
    lte = {int(value) for value in re.findall(r"(?<![A-Za-z0-9_])B(\d+)", expression)}
    nr = {int(value) for value in re.findall(r"(?<![A-Za-z0-9_])N(\d+)", expression)}
    return lte, nr


def find_res_dat(path: Path) -> tuple[str, bytes]:
    dats = rfcard.extract_rfc_dats(path.read_bytes())
    res_items = [
        (name, data) for name, data in dats.items()
        if name.lower().endswith("_res.dat")
    ]
    if not res_items:
        raise ValueError("No /rfc/*_res.dat item found")
    if len(res_items) != 1:
        names = ", ".join(name for name, _ in res_items)
        raise ValueError(f"Expected one res DAT, found {len(res_items)}: {names}")
    return res_items[0]


def parse_profile(path: Path, root: Path) -> Profile:
    dat_name, res_dat = find_res_dat(path)
    encoding, protobuf_payload, message = rfcard.parse_res_dat(res_dat)
    identity = rfcard.read_rfcard_info(dat_name, path.name, message.rrc)
    sections = rfcard.recover_sections(message, rfcard.enum_assignments())

    signatures: dict[str, set[ComboSignature]] = defaultdict(set)
    raw_counts: dict[str, int] = defaultdict(int)
    lte_bands: set[int] = set()
    nr_bands: set[int] = set()

    for _tier, typed_sections in sections.items():
        for section, combos in typed_sections.items():
            raw_counts[section] += len(combos)
            for expression, attrs in combos:
                signature = ComboSignature(
                    section=section,
                    expression=expression,
                    attributes=tuple(sorted((str(k), str(v)) for k, v in attrs.items())),
                )
                signatures[section].add(signature)
                current_lte, current_nr = extract_bands(expression)
                lte_bands.update(current_lte)
                nr_bands.update(current_nr)

    try:
        relative = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        relative = str(path.resolve())

    return Profile(
        path=path,
        relative_path=relative,
        name=path.name,
        identity=identity,
        dat_encoding=encoding,
        protobuf_size=len(protobuf_payload),
        raw_counts=dict(raw_counts),
        signatures=dict(signatures),
        lte_bands=lte_bands,
        nr_bands=nr_bands,
    )


def format_band_set(bands: Iterable[int], prefix: str) -> str:
    values = sorted(set(bands))
    return ", ".join(f"{prefix}{band}" for band in values) if values else "(none)"


def identity_text(profile: Profile) -> str:
    info = profile.identity
    pieces = [profile.relative_path]
    card_name = info.get("name")
    if card_name:
        pieces.append(f"name={card_name}")
    ids = []
    for label in ("hwid", "fsid", "bid"):
        value = info.get(label)
        if value is not None:
            ids.append(f"{label.upper()}={value}")
    if ids:
        pieces.append(" ".join(ids))
    return " | ".join(pieces)


def signature_digest(signatures: Iterable[ComboSignature]) -> str:
    digest = hashlib.sha256()
    for signature in sorted(signatures, key=combo_sort_key):
        digest.update(signature.section.encode("utf-8"))
        digest.update(b"\0")
        digest.update(signature.expression.encode("utf-8"))
        digest.update(b"\0")
        for key, value in signature.attributes:
            digest.update(key.encode("utf-8"))
            digest.update(b"=")
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
        digest.update(b"\n")
    return digest.hexdigest()


def add_list(lines: list[str], title: str, values: Sequence[str], limit: int) -> None:
    lines.append(f"{title}: {len(values)}")
    if not values:
        lines.append("  (none)")
        return
    shown = values if limit == 0 else values[:limit]
    lines.extend(f"  {value}" for value in shown)
    if limit and len(values) > limit:
        lines.append(f"  ... {len(values) - limit} more omitted by --max-list")


def add_failures(lines: list[str], failures: Sequence[Failure]) -> None:
    if not failures:
        return
    lines.extend(["", "FAILED FILES", "------------"])
    for failure in failures:
        lines.append(f"{failure.relative_path}: {failure.error}")


def add_equivalence_groups(
    lines: list[str],
    profiles: Sequence[Profile],
    selector,
) -> None:
    groups: dict[str, list[Profile]] = defaultdict(list)
    for profile in profiles:
        groups[signature_digest(selector(profile))].append(profile)

    lines.extend(["", "IDENTICAL COMBINATION GROUPS", "----------------------------"])
    ordered = sorted(
        groups.values(),
        key=lambda group: natural_key(group[0].relative_path),
    )
    for index, group in enumerate(ordered, start=1):
        count = len(selector(group[0]))
        lines.append(f"Group {index}: {count} unique exact combinations")
        for profile in group:
            lines.append(f"  {identity_text(profile)}")


def make_lte_report(
    profiles: Sequence[Profile],
    reference: Profile,
    failures: Sequence[Failure],
    root: Path,
    limit: int,
) -> str:
    lines = [
        "Qualcomm RFCard LTE Comparison",
        "==============================",
        f"Scanned root: {root}",
        f"Reference: {identity_text(reference)}",
        f"Successfully parsed: {len(profiles)}",
        f"Failed: {len(failures)}",
        "",
        "Counts distinguish raw table records from unique exact combinations.",
        "Exact signatures include reconstructed combo attributes such as power class",
        "or TX switching when the parser exposes them.",
        "",
        "PROFILE INVENTORY",
        "-----------------",
    ]

    for profile in profiles:
        raw = sum(profile.raw_counts.get(key, 0) for key in LTE_SECTION_KEYS)
        unique = len(profile.lte_signatures)
        lines.extend([
            identity_text(profile),
            f"  LTE CA raw records: {raw}",
            f"  LTE CA unique exact combinations: {unique}",
            f"  LTE bands ({len(profile.lte_bands)}): {format_band_set(profile.lte_bands, 'B')}",
        ])

    add_equivalence_groups(lines, profiles, lambda profile: profile.lte_signatures)

    ref_combos = reference.lte_signatures
    ref_bands = reference.lte_bands
    lines.extend(["", "DIFFERENCES FROM REFERENCE", "--------------------------"])
    for profile in profiles:
        if profile is reference:
            continue
        added_bands = profile.lte_bands - ref_bands
        removed_bands = ref_bands - profile.lte_bands
        added = sorted(profile.lte_signatures - ref_combos, key=combo_sort_key)
        removed = sorted(ref_combos - profile.lte_signatures, key=combo_sort_key)
        lines.extend([
            "",
            identity_text(profile),
            f"  LTE bands added: {format_band_set(added_bands, 'B')}",
            f"  LTE bands removed: {format_band_set(removed_bands, 'B')}",
            f"  Net unique combo change: {len(added) - len(removed):+d}",
        ])
        add_list(lines, "  LTE combos added", [item.display() for item in added], limit)
        add_list(lines, "  LTE combos removed", [item.display() for item in removed], limit)

    add_failures(lines, failures)
    lines.append("")
    return "\n".join(lines)


def category_counts(profile: Profile) -> str:
    parts = []
    for key in NR_SECTION_KEYS:
        raw = profile.raw_counts.get(key, 0)
        unique = len(profile.signatures.get(key, set()))
        parts.append(f"{SECTION_LABELS[key]}={raw} raw/{unique} unique")
    return "; ".join(parts)


def make_nr_report(
    profiles: Sequence[Profile],
    reference: Profile,
    failures: Sequence[Failure],
    root: Path,
    limit: int,
) -> str:
    lines = [
        "Qualcomm RFCard NR Comparison",
        "=============================",
        f"Scanned root: {root}",
        f"Reference: {identity_text(reference)}",
        f"Successfully parsed: {len(profiles)}",
        f"Failed: {len(failures)}",
        "",
        "NR comparison includes NR-CA, EN-DC, and NR-DC as separate signature",
        "categories. Identical visible expressions in different categories are not",
        "collapsed together.",
        "",
        "PROFILE INVENTORY",
        "-----------------",
    ]

    for profile in profiles:
        raw = sum(profile.raw_counts.get(key, 0) for key in NR_SECTION_KEYS)
        unique = len(profile.nr_signatures)
        lines.extend([
            identity_text(profile),
            f"  NR-related raw records: {raw}",
            f"  NR-related unique exact combinations: {unique}",
            f"  Breakdown: {category_counts(profile)}",
            f"  NR bands ({len(profile.nr_bands)}): {format_band_set(profile.nr_bands, 'n')}",
        ])

    add_equivalence_groups(lines, profiles, lambda profile: profile.nr_signatures)

    ref_combos = reference.nr_signatures
    ref_bands = reference.nr_bands
    lines.extend(["", "DIFFERENCES FROM REFERENCE", "--------------------------"])
    for profile in profiles:
        if profile is reference:
            continue
        added_bands = profile.nr_bands - ref_bands
        removed_bands = ref_bands - profile.nr_bands
        added = sorted(profile.nr_signatures - ref_combos, key=combo_sort_key)
        removed = sorted(ref_combos - profile.nr_signatures, key=combo_sort_key)
        lines.extend([
            "",
            identity_text(profile),
            f"  NR bands added: {format_band_set(added_bands, 'n')}",
            f"  NR bands removed: {format_band_set(removed_bands, 'n')}",
            f"  Net unique combo change: {len(added) - len(removed):+d}",
        ])
        add_list(
            lines,
            "  NR-related combos added",
            [item.display(include_section=True) for item in added],
            limit,
        )
        add_list(
            lines,
            "  NR-related combos removed",
            [item.display(include_section=True) for item in removed],
            limit,
        )

    add_failures(lines, failures)
    lines.append("")
    return "\n".join(lines)


def choose_reference(profiles: Sequence[Profile], requested: str | None) -> Profile:
    if not profiles:
        raise ValueError("No successfully parsed RFCard profiles are available")
    if not requested:
        return profiles[0]

    requested_folded = requested.casefold()
    exact = [
        profile for profile in profiles
        if profile.name.casefold() == requested_folded
        or profile.relative_path.casefold() == requested_folded
        or str(profile.path.resolve()).casefold() == requested_folded
    ]
    if len(exact) == 1:
        return exact[0]

    partial = [
        profile for profile in profiles
        if requested_folded in profile.relative_path.casefold()
    ]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise ValueError(f"Reference {requested!r} did not match any parsed MBN")
    matches = ", ".join(profile.relative_path for profile in partial)
    raise ValueError(f"Reference {requested!r} is ambiguous: {matches}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recursively compare modern Qualcomm rf_config MBN LTE and NR "
            "capability tables."
        )
    )
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=Path("."),
        help="directory containing rf_config_*.mbn files (default: current directory)",
    )
    parser.add_argument(
        "--reference",
        help="reference filename, relative path, or unique path substring",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="report output directory (default: scanned directory)",
    )
    parser.add_argument(
        "--lte-output",
        default="rfcard_lte_compare.txt",
        help="LTE report filename",
    )
    parser.add_argument(
        "--nr-output",
        default="rfcard_nr_compare.txt",
        help="NR report filename",
    )
    parser.add_argument(
        "--pattern",
        default="rf_config_*.mbn",
        help="recursive filename glob (default: rf_config_*.mbn)",
    )
    parser.add_argument(
        "--max-list",
        type=int,
        default=0,
        metavar="N",
        help="maximum added/removed combos listed per comparison; 0 means all",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.directory.resolve()
    if not root.is_dir():
        print(f"error: directory not found: {root}", file=sys.stderr)
        return 2
    if args.max_list < 0:
        print("error: --max-list cannot be negative", file=sys.stderr)
        return 2

    files = sorted(root.rglob(args.pattern), key=lambda path: natural_key(str(path)))
    if not files:
        print(f"error: no files matching {args.pattern!r} below {root}", file=sys.stderr)
        return 1

    profiles: list[Profile] = []
    failures: list[Failure] = []
    for index, path in enumerate(files, start=1):
        try:
            relative = str(path.resolve().relative_to(root))
        except ValueError:
            relative = str(path.resolve())
        print(f"[{index}/{len(files)}] Parsing {relative}")
        try:
            profiles.append(parse_profile(path, root))
        except Exception as exc:  # Keep scanning other bundled SKUs.
            failures.append(Failure(path, relative, f"{type(exc).__name__}: {exc}"))
            print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)

    profiles.sort(key=lambda profile: natural_key(profile.relative_path))
    try:
        reference = choose_reference(profiles, args.reference)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output_dir = (args.output_dir or root).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    lte_path = output_dir / args.lte_output
    nr_path = output_dir / args.nr_output

    lte_path.write_text(
        make_lte_report(profiles, reference, failures, root, args.max_list),
        encoding="utf-8",
        newline="\n",
    )
    nr_path.write_text(
        make_nr_report(profiles, reference, failures, root, args.max_list),
        encoding="utf-8",
        newline="\n",
    )

    print()
    print(f"Reference: {identity_text(reference)}")
    print(f"Parsed: {len(profiles)}; failed: {len(failures)}")
    print(f"Wrote {lte_path}")
    print(f"Wrote {nr_path}")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
