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
import csv
import datetime
import functools
import hashlib
import itertools
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


_COMBO_TOKEN_RE = re.compile(
    r"^(?P<rat>[BN])(?P<band>\d+)"
    r"(?P<dl_class>_|[A-Z]|X\d+)"
    r"(?:\[(?P<dl_side>[^\]]*)\])?"
    r"(?:;(?P<ul_class>[A-Z]|X\d+)\[(?P<ul_side>[^\]]*)\])?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ComboDetails:
    """Comparison dimensions extracted from one reconstructed combo expression."""

    topology: tuple[tuple[str, int, str, str], ...]
    bandwidth: tuple[tuple[str, ...], ...]
    mimo: tuple[tuple[str, ...], ...]


def _split_side(side: str | None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split a side such as ``100x4,100x4`` into BW and MIMO tuples.

    Older LTE expressions can contain a plain antenna enum/index such as
    ``B3A[3]``.  In that case the value is treated as MIMO/antenna information
    and no bandwidth value is claimed.
    """
    bandwidth: list[str] = []
    mimo: list[str] = []
    if not side:
        return (), ()

    for part in side.split(","):
        part = part.strip()
        if not part:
            continue
        if "x" in part:
            bw, layers = part.rsplit("x", 1)
            bandwidth.append(bw.strip())
            mimo.append(layers.strip())
        else:
            # Legacy/reconstructed LTE syntax often stores only antenna enum.
            mimo.append(part)
    return tuple(bandwidth), tuple(mimo)


@functools.lru_cache(maxsize=None)
def combo_details(signature: ComboSignature) -> ComboDetails | None:
    """Return topology, BW and MIMO dimensions for variant-aware comparison."""
    topology: list[tuple[str, int, str, str]] = []
    bandwidth: list[tuple[str, ...]] = []
    mimo: list[tuple[str, ...]] = []

    for token in signature.expression.split("+"):
        match = _COMBO_TOKEN_RE.fullmatch(token.strip())
        if match is None:
            return None

        rat = match.group("rat").upper()
        band = int(match.group("band"))
        dl_class = match.group("dl_class").upper()
        ul_class = (match.group("ul_class") or "").upper()

        dl_bw, dl_mimo = _split_side(match.group("dl_side"))
        ul_bw, ul_mimo = _split_side(match.group("ul_side"))

        topology.append((rat, band, dl_class, ul_class))
        bandwidth.append(dl_bw + ul_bw)
        mimo.append(dl_mimo + ul_mimo)

    return ComboDetails(
        topology=tuple(topology),
        bandwidth=tuple(bandwidth),
        mimo=tuple(mimo),
    )


def removed_combo_status(
    removed: ComboSignature,
    current_signatures: Iterable[ComboSignature],
) -> str:
    """Explain whether a removed exact signature survives as another variant."""
    removed_details = combo_details(removed)
    if removed_details is None:
        return "Exact combo removed"

    candidates: list[tuple[tuple[int, int, int, str], str]] = []
    for current in current_signatures:
        if current.section != removed.section:
            continue
        current_details = combo_details(current)
        if current_details is None:
            continue
        if current_details.topology != removed_details.topology:
            continue

        bw_changed = current_details.bandwidth != removed_details.bandwidth
        mimo_changed = current_details.mimo != removed_details.mimo
        properties_changed = current.attributes != removed.attributes

        if bw_changed and mimo_changed:
            status = "Combo still exists, BW and MIMO changed"
        elif bw_changed:
            status = "Combo still exists, BW changed"
        elif mimo_changed:
            status = "Combo still exists, MIMO changed"
        elif properties_changed:
            status = "Combo still exists, properties changed"
        else:
            # Should normally be impossible because exact signatures were
            # removed with set subtraction, but keep the function defensive.
            status = "Combo still exists"

        # Prefer the closest surviving variant when several share a topology.
        rank = (
            int(bw_changed) + int(mimo_changed) + int(properties_changed),
            int(bw_changed) + int(mimo_changed),
            int(properties_changed),
            current.expression,
        )
        candidates.append((rank, status))

    if not candidates:
        return "Combo completely gone"

    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def format_removed_combo(
    signature: ComboSignature,
    current_signatures: Iterable[ComboSignature],
    *,
    include_section: bool = False,
) -> str:
    base = signature.display(include_section=include_section)
    return f"{base} ({removed_combo_status(signature, current_signatures)})"


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
        add_list(
            lines,
            "  LTE combos removed",
            [format_removed_combo(item, profile.lte_signatures) for item in removed],
            limit,
        )

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
            [
                format_removed_combo(
                    item,
                    profile.nr_signatures,
                    include_section=True,
                )
                for item in removed
            ],
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
    timestamp = datetime.datetime.now().strftime("%y%m%d%H%M%S")
    comp_dir = output_dir / f"compare-{timestamp}"
    comp_dir.mkdir(parents=True, exist_ok=True)
    lte_path = comp_dir / args.lte_output
    nr_path = comp_dir / args.nr_output

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

    csv_paths = write_simplified_comparison_csvs(profiles, comp_dir)

    print()
    print(f"Reference: {identity_text(reference)}")
    print(f"Parsed: {len(profiles)}; failed: {len(failures)}")
    print(f"Created folder: {comp_dir.name}")
    print(f"Wrote {lte_path}")
    print(f"Wrote {nr_path}")
    for cp in csv_paths:
        print(f"Wrote {cp}")
    return 0 if not failures else 2


_CC_CLASS_MAP = {
    "A": 1,
    "B": 2,
    "C": 2,
    "D": 3,
    "E": 4,
    "F": 5,
    "G": 6,
    "H": 7,
    "I": 8,
}


def format_signature_component(
    rat: str,
    band: int,
    dl_class: str,
) -> tuple[str, int, int, int, str]:
    is_nr = 1 if rat.upper() == "N" else 0
    prefix = "n" if is_nr else ""
    dl_str = "" if dl_class in ("-", "", "_", None, "X0", "0") else dl_class.upper()
    class_str = "" if dl_str in ("A", "") else dl_str
    if dl_str or class_str:
        comp_str = f"{prefix}{band}{class_str}"
    else:
        comp_str = f"{prefix}{band}_"
    cc = _CC_CLASS_MAP.get(dl_str, 1)
    return comp_str, cc, is_nr, band, dl_str


def combo_signature_key(
    table_key: str,
    components: Sequence[tuple[str, int, str]],
) -> tuple[int, tuple[tuple[int, int, str], ...], str]:
    formatted = [format_signature_component(*c) for c in components]
    if table_key == "endc":
        lte_parts = [f[0] for f in formatted if f[2] == 0]
        nr_parts = [f[0] for f in formatted if f[2] == 1]
        combo_str = f"{'-'.join(lte_parts)}_{'-'.join(nr_parts)}"
    elif table_key == "nrdc":
        fr1_parts = [f[0] for f in formatted if f[3] < 100]
        fr2_parts = [f[0] for f in formatted if f[3] >= 100]
        if fr1_parts and fr2_parts:
            combo_str = f"{'-'.join(fr1_parts)}_{'-'.join(fr2_parts)}"
        else:
            combo_str = "-".join(f[0] for f in formatted)
    else:
        combo_str = "-".join(f[0] for f in formatted)

    total_cc = sum(f[1] for f in formatted)
    band_tuple = tuple((f[2], f[3], f[4]) for f in formatted)
    return total_cc, band_tuple, combo_str


NR_SDL_BANDS = {29, 67, 75, 76}
LTE_SDL_BANDS = {29, 32, 67, 75, 76}


def get_profile_simplified_combos(
    profile: Profile,
) -> dict[str, dict[str, tuple[int, tuple[tuple[int, int, str], ...], str]]]:
    mapping = {
        "ca_4g_combos": "lte_ca",
        "ca_4g_5g_combos": "endc",
        "ca_5g_combos": "nr_ca",
        "ca_5g_5g_combos": "nrdc",
    }
    result: dict[str, dict[str, tuple[int, tuple[tuple[int, int, str], ...], str]]] = {}
    for section_key, table_key in mapping.items():
        unique: dict[str, tuple[int, tuple[tuple[int, int, str], ...], str]] = {}
        for sig in profile.signatures.get(section_key, set()):
            details = combo_details(sig)
            if not details:
                continue
            comps = [(rat, band, dl_class) for rat, band, dl_class, _ul in details.topology]
            if table_key == "endc":
                lte_comps = [c for c in comps if c[0].upper() != "N"]
                nr_comps = [c for c in comps if c[0].upper() == "N"]
                for l_r in range(1, len(lte_comps) + 1):
                    for l_sub in itertools.combinations(lte_comps, l_r):
                        if all(c[1] in LTE_SDL_BANDS for c in l_sub):
                            continue
                        for n_r in range(1, len(nr_comps) + 1):
                            for n_sub in itertools.combinations(nr_comps, n_r):
                                if all(c[1] in NR_SDL_BANDS for c in n_sub):
                                    continue
                                sub = list(l_sub) + list(n_sub)
                                k = combo_signature_key(table_key, sub)
                                unique[k[2]] = k
            elif table_key == "nr_ca":
                for r in range(1, len(comps) + 1):
                    for sub in itertools.combinations(comps, r):
                        if all(c[1] in NR_SDL_BANDS for c in sub):
                            continue
                        k = combo_signature_key(table_key, list(sub))
                        unique[k[2]] = k
            elif table_key == "lte_ca":
                for r in range(1, len(comps) + 1):
                    for sub in itertools.combinations(comps, r):
                        if all(c[1] in LTE_SDL_BANDS for c in sub):
                            continue
                        k = combo_signature_key(table_key, list(sub))
                        unique[k[2]] = k
            elif table_key == "nrdc":
                fr1_comps = [c for c in comps if c[1] < 100]
                fr2_comps = [c for c in comps if c[1] >= 100]
                if fr1_comps and fr2_comps:
                    for f1_r in range(1, len(fr1_comps) + 1):
                        for f1_sub in itertools.combinations(fr1_comps, f1_r):
                            if all(c[1] in NR_SDL_BANDS for c in f1_sub):
                                continue
                            for f2_r in range(1, len(fr2_comps) + 1):
                                for f2_sub in itertools.combinations(fr2_comps, f2_r):
                                    sub = list(f1_sub) + list(f2_sub)
                                    k = combo_signature_key(table_key, sub)
                                    unique[k[2]] = k
                else:
                    for r in range(1, len(comps) + 1):
                        for sub in itertools.combinations(comps, r):
                            k = combo_signature_key(table_key, list(sub))
                            unique[k[2]] = k
            else:
                k = combo_signature_key(table_key, comps)
                unique[k[2]] = k
        result[table_key] = unique
    return result


def write_simplified_comparison_csvs(
    profiles: Sequence[Profile],
    output_root: Path,
) -> list[Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    names = [p.name for p in profiles]
    headers = []
    seen: dict[str, int] = {}
    for p in profiles:
        count = seen.get(p.name, 0) + 1
        seen[p.name] = count
        if names.count(p.name) > 1:
            headers.append(f"{p.name} ({p.relative_path})")
        else:
            headers.append(p.name)

    parsed_cards = [get_profile_simplified_combos(p) for p in profiles]

    table_specs = [
        ("lte_ca", "LTE CA", "rfcard_compare_lte.csv"),
        ("endc", "EN-DC", "rfcard_compare_endc.csv"),
        ("nr_ca", "NR-CA", "rfcard_compare_nrca.csv"),
        ("nrdc", "NR-DC", "rfcard_compare_nrdc.csv"),
    ]

    written_paths: list[Path] = []

    for table_key, table_label, filename in table_specs:
        all_combos: dict[str, tuple[int, tuple[tuple[int, int, str, str], ...], str]] = {}
        for card_data in parsed_cards:
            table_combos = card_data.get(table_key, {})
            for combo_str, sort_key in table_combos.items():
                if combo_str not in all_combos:
                    all_combos[combo_str] = sort_key

        if not all_combos:
            continue

        sorted_combos = [k[2] for k in sorted(all_combos.values())]
        target_path = output_root / filename
        with target_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            for combo_str in sorted_combos:
                row = [
                    combo_str if combo_str in card_data.get(table_key, {}) else ""
                    for card_data in parsed_cards
                ]
                writer.writerow(row)
        written_paths.append(target_path)

    # Master combined CSV
    all_path = output_root / "rfcard_compare_all.csv"
    with all_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for table_key, table_label, _ in table_specs:
            all_combos = {}
            for card_data in parsed_cards:
                table_combos = card_data.get(table_key, {})
                for combo_str, sort_key in table_combos.items():
                    if combo_str not in all_combos:
                        all_combos[combo_str] = sort_key

            if not all_combos:
                continue

            sorted_combos = [k[2] for k in sorted(all_combos.values())]
            writer.writerow([f"=== {table_label} ==="] * len(headers))
            for combo_str in sorted_combos:
                row = [
                    combo_str if combo_str in card_data.get(table_key, {}) else ""
                    for card_data in parsed_cards
                ]
                writer.writerow(row)
            writer.writerow([""] * len(headers))
    written_paths.append(all_path)

    return written_paths


if __name__ == "__main__":
    raise SystemExit(main())