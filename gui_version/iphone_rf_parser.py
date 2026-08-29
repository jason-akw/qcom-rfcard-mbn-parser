#!/usr/bin/env python3
r"""Recover Qualcomm RFCards from Apple iPhone baseband firmware.

Android exposes RF cards as ``rf_config_<HWID>_<FSID>_<BID>.mbn`` files sitting
in a FAT/EXT modem image, so the normal importer finds them by name.  Apple
ships the same Qualcomm cards, but stores them **compressed and
content-addressed** inside the ``bbcfg.mbn`` member of a ``.bbfw``, which is why
no ``rf_config_*`` or ``*_res.dat`` name appears anywhere in an iPhone firmware.

Container layout (verified on Mav24/iPhone 16 and Mav25/iPhone 17 firmware):

    bbcfg.mbn
      +0x00  u32  0x43464700   'GFC\0'
      +0x04  u32  version (3)
      +0x14  u32  payload size == file size - 40
      +0x28  str  "BBCFGMBN0", followed by BER/DER records

    The last top-level record (tag 0xA9) is a content-addressed blob store:

      30 <len>                     SEQUENCE, one per stored blob
        9f 64 <len> <40 hex>       content name (SHA-1 of the payload)
        9f 65 <len> <payload>      payload

    A payload starting with 'MAVZ' is Apple-compressed:

      'MAVZ' + u32 uncompressed_size + zlib stream

    Mav25 payloads are Qualcomm MBN ELFs containing the Large-EFS item
    ``/rfc/<HWID>_<FSET>_res.dat``.  Mav24 and older payloads are the legacy
    RF-card ELF itself; their generated dynamic symbols begin with
    ``rfc_hwid<HWID>_``.

Apple's cards carry no BID, so this module synthesises one - the card's ordinal
within the store - purely so the file can be named the way every downstream
tool expects.  ``synthetic_bid`` is recorded for every card in the
``rfcard_info_all.json`` sidecar.  Mav24 legacy ELFs also carry no numeric FSET,
so zero is synthesised for that filename field and the full generated RF-card
name is retained in the sidecar.

Use from the GUI:
    ``image_extractor.extract_bbcfg`` delegates here, so importing a ``.bbfw``
    (or a bare ``bbcfg.mbn``) lists the cards like an Android ``modem.img``.

Use standalone:
    python iphone_rf_parser.py <ipsw|bbfw|bbcfg.mbn> -o out_dir
    python iphone_rf_parser.py <ipsw|bbfw|bbcfg.mbn> --list
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import re
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator

import legacy_rf_parser as legacy

logger = logging.getLogger(__name__)

# The fourcc varies by payload class: '\x00GFC' on bbcfg.mbn, '\x00WOP' on
# pt.mbn.  The BBCFGMBN0 marker plus the size field is what identifies the
# container, so the fourcc is recorded rather than required.
KNOWN_FOURCC = {b"\x00GFC", b"\x00WOP"}
BBCFG_MARKER = b"BBCFGMBN0"
RECORDS_START = 0x28
STORE_TAG = "a9"
NAME_TAG = "9f64"
PAYLOAD_TAG = "9f65"
EFS_PATH_TAG = "9f8374"
EFS_VALUE_TAG = "9f8376"
MAVZ_MAGIC = b"MAVZ"
ELF32_MAGIC = b"\x7fELF\x01\x01"

RES_DAT_RE = re.compile(rb"/rfc/(\d+)_(\d+)_res\.dat")
CMN_DAT_RE = re.compile(rb"/rfc/(\d+)_(\d+)_cmn\.dat")
LEGACY_RFCARD_RE = re.compile(r"^rfc_hwid(\d+)(?:_|$)", re.IGNORECASE)
CONTENT_NAME_RE = re.compile(rb"[0-9a-f]{40}")
BBFW_MEMBER_RE = re.compile(r"\.bbfw$", re.IGNORECASE)
BBCFG_MEMBER_RE = re.compile(r"(^|/)bbcfg\.mbn$", re.IGNORECASE)


class IPhoneRFError(RuntimeError):
    """Raised when a file is not usable Apple baseband firmware."""


@dataclass
class RFCard:
    """One RF card, with the provenance needed to re-derive it."""

    ordinal: int
    hwid: int
    fset: int
    synthetic_bid: int
    filename: str
    bbcfg_offset: int
    store_index: int
    content_name: str
    compressed_len: int
    raw_size: int
    sha256: str
    generation: str
    rfcard_name: str | None
    fset_is_synthetic: bool
    res_dat: str | None
    cmn_dat: str | None

    def as_row(self) -> dict:
        row = asdict(self)
        row["bbcfg_offset"] = f"0x{self.bbcfg_offset:08x}"
        return row


# ---------------------------------------------------------------------------
# BER helpers
# ---------------------------------------------------------------------------


def _read_tlv(blob: bytes, pos: int) -> tuple[str, int, int]:
    """Return (tag_hex, length, body_offset) for the TLV at ``pos``."""
    start = pos
    if blob[pos] & 0x1F == 0x1F:
        pos += 1
        while blob[pos] & 0x80:
            pos += 1
    pos += 1
    tag = blob[start:pos].hex()
    length = blob[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4:
            raise IPhoneRFError(f"unsupported BER length form at 0x{start:x}")
        length = int.from_bytes(blob[pos:pos + count], "big")
        pos += count
    return tag, length, pos


def _walk(blob: bytes, start: int, end: int) -> Iterator[tuple[str, int, int, int]]:
    """Yield (tag, offset, length, body) for each TLV in [start, end)."""
    pos = start
    while pos < end:
        tag, length, body = _read_tlv(blob, pos)
        if body + length > end:
            raise IPhoneRFError(f"record at 0x{pos:x} overruns its container")
        yield tag, pos, length, body
        pos = body + length


# ---------------------------------------------------------------------------
# Container access
# ---------------------------------------------------------------------------


def is_bbcfg(blob: bytes) -> bool:
    return len(blob) >= 0x31 and blob[0x28:0x31] == BBCFG_MARKER


def container_info(blob: bytes) -> dict:
    if not is_bbcfg(blob):
        raise IPhoneRFError("not an Apple BBCFG container (no BBCFGMBN0 marker)")
    fourcc = blob[:4]
    version = struct.unpack_from("<I", blob, 4)[0]
    declared = struct.unpack_from("<I", blob, 0x14)[0]
    if declared != len(blob) - 40:
        logger.warning("bbcfg payload size %d != file size - 40 (%d)",
                       declared, len(blob) - 40)
    if fourcc not in KNOWN_FOURCC:
        logger.info("unfamiliar BBCFG fourcc %r; parsing anyway", fourcc)
    return {"fourcc": fourcc.decode("ascii", "replace"), "version": version,
            "payload_size": declared, "size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest()}


def _store_bounds(blob: bytes) -> tuple[int, int] | None:
    """Return (start, end) of the content-addressed blob store body, if present.

    Returns None rather than raising: a BBCFG container that holds no store, or
    whose record grammar this walker does not fully cover (``pt.mbn`` uses BER
    length forms not seen in ``bbcfg.mbn``), simply has no cards to offer.
    """
    try:
        for tag, _offset, length, body in _walk(blob, RECORDS_START, len(blob)):
            if tag == STORE_TAG:
                return body, body + length
    except (IPhoneRFError, IndexError) as exc:
        logger.info("BER walk stopped early (%s); falling back to a MAVZ scan", exc)
    return None


def iter_store_blobs(blob: bytes) -> Iterator[tuple[int, int, str, int, int]]:
    """Yield (index, record_offset, content_name, payload_offset, payload_len).

    Walks the tag-0xA9 store when it is readable, and otherwise scans for MAVZ
    payloads directly.  Both paths recover the same 42 payloads from the
    reference image, so the fallback is a safety net rather than a guess.
    """
    bounds = _store_bounds(blob)
    if bounds is None:
        yield from _scan_mavz_blobs(blob)
        return
    start, end = bounds
    for index, (_tag, offset, length, body) in enumerate(_walk(blob, start, end)):
        name = None
        payload = None
        for child_tag, _, child_len, child_body in _walk(blob, body, body + length):
            if child_tag == NAME_TAG:
                name = blob[child_body:child_body + child_len].decode("ascii", "replace")
            elif child_tag == PAYLOAD_TAG:
                payload = (child_body, child_len)
        if payload is None:
            continue
        yield index, offset, name or "", payload[0], payload[1]


def _scan_mavz_blobs(blob: bytes) -> Iterator[tuple[int, int, str, int, int]]:
    """Locate MAVZ payloads without relying on the record grammar."""
    for index, match in enumerate(re.finditer(MAVZ_MAGIC, blob)):
        offset = match.start()
        names = CONTENT_NAME_RE.findall(blob[max(0, offset - 300):offset])
        name = names[-1].decode() if names else ""
        yield index, offset, name, offset, len(blob) - offset


def decompress_mavz(blob: bytes, offset: int) -> tuple[bytes, int]:
    """Decompress the MAVZ payload at ``offset``; return (raw, compressed_len)."""
    declared = struct.unpack_from("<I", blob, offset + 4)[0]
    stream = zlib.decompressobj()
    raw = stream.decompress(blob[offset + 8:])
    if len(raw) != declared:
        raise IPhoneRFError(
            f"MAVZ at 0x{offset:x}: {len(raw)} bytes != declared {declared}")
    compressed_len = len(blob) - offset - 8 - len(stream.unused_data)
    return raw, compressed_len


# ---------------------------------------------------------------------------
# RF card recovery
# ---------------------------------------------------------------------------


def legacy_rfcard_identity(raw: bytes) -> tuple[int, str] | None:
    """Return ``(HWID, generated name)`` for a legacy RF-card ELF.

    The generated name is a much stronger discriminator than ELF magic alone:
    BBCFG stores several unrelated executable payloads alongside RF cards.
    Malformed or unsupported ELFs are simply not RF-card candidates.
    """
    if not raw.startswith(ELF32_MAGIC):
        return None
    try:
        image = legacy.Elf32Image(raw)
        card_name = legacy.rfcard_name_from_symbols(image)
    except (legacy.ParseError, IndexError, struct.error):
        return None
    if card_name is None:
        return None
    match = LEGACY_RFCARD_RE.match(card_name)
    if match is None:
        return None
    return int(match.group(1)), card_name


def iter_rfcards(blob: bytes) -> Iterator[tuple[RFCard, bytes]]:
    """Yield every RF card in a bbcfg image together with its MBN bytes."""
    ordinal = 0
    for index, _rec_off, name, payload_off, _payload_len in iter_store_blobs(blob):
        if blob[payload_off:payload_off + 4] != MAVZ_MAGIC:
            continue
        try:
            raw, compressed_len = decompress_mavz(blob, payload_off)
        except (zlib.error, IPhoneRFError) as exc:
            logger.warning("skipping blob %s: %s", name, exc)
            continue
        res = RES_DAT_RE.search(raw)
        cmn = CMN_DAT_RE.search(raw) if res else None
        if res:
            hwid, fset = int(res.group(1)), int(res.group(2))
            filename = f"rf_config_{hwid}_{fset}_{ordinal}.mbn"
            generation = "DAT/protobuf"
            rfcard_name = None
            fset_is_synthetic = False
        else:
            legacy_identity = legacy_rfcard_identity(raw)
            if legacy_identity is None:
                continue
            hwid, rfcard_name = legacy_identity
            fset = 0
            # A numeric legacy basename makes the analyzer select
            # legacy_rf_parser; rf_config_* would select DAT/protobuf.
            filename = f"{hwid}_{fset}_{ordinal}.mbn"
            generation = "Legacy ELF"
            fset_is_synthetic = True
        card = RFCard(
            ordinal=ordinal,
            hwid=hwid,
            fset=fset,
            synthetic_bid=ordinal,
            filename=filename,
            bbcfg_offset=payload_off,
            store_index=index,
            content_name=name,
            compressed_len=compressed_len,
            raw_size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
            generation=generation,
            rfcard_name=rfcard_name,
            fset_is_synthetic=fset_is_synthetic,
            res_dat=res.group(0).decode() if res else None,
            cmn_dat=cmn.group(0).decode() if cmn else None,
        )
        ordinal += 1
        yield card, raw


# ---------------------------------------------------------------------------
# Input handling: bbcfg.mbn, .bbfw, .ipsw
# ---------------------------------------------------------------------------


def _member_matching(archive: zipfile.ZipFile, pattern: re.Pattern) -> str | None:
    for name in archive.namelist():
        if pattern.search(name):
            return name
    return None


def load_bbcfg(path: Path) -> tuple[bytes, str]:
    """Return (bbcfg bytes, description) for an IPSW, .bbfw, or bbcfg.mbn."""
    with path.open("rb") as handle:
        head = handle.read(0x40)
    if is_bbcfg(head):
        return path.read_bytes(), path.name

    if not zipfile.is_zipfile(path):
        raise IPhoneRFError(f"{path.name}: not a BBCFG container or archive")

    with zipfile.ZipFile(path) as archive:
        member = _member_matching(archive, BBCFG_MEMBER_RE)
        if member:
            return archive.read(member), f"{path.name}!{member}"
        # An IPSW holds the baseband as a nested .bbfw archive.
        bbfw = _member_matching(archive, BBFW_MEMBER_RE)
        if not bbfw:
            raise IPhoneRFError(
                f"{path.name}: no bbcfg.mbn and no .bbfw member; "
                "is this an iPhone firmware archive?")
        with archive.open(bbfw) as handle:
            import io
            nested = io.BytesIO(handle.read())
        with zipfile.ZipFile(nested) as inner:
            member = _member_matching(inner, BBCFG_MEMBER_RE)
            if not member:
                raise IPhoneRFError(f"{path.name}!{bbfw}: no bbcfg.mbn member")
            return inner.read(member), f"{path.name}!{bbfw}!{member}"


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_rfcards(blob: bytes, out_dir: Path, source: str = "") -> list[RFCard]:
    """Write every RF card in ``blob`` to ``out_dir`` with a sidecar manifest."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cards: list[RFCard] = []
    for card, raw in iter_rfcards(blob):
        (out_dir / card.filename).write_bytes(raw)
        cards.append(card)
    if cards:
        _write_sidecars(cards, out_dir, blob, source)
    return cards


def _write_sidecars(cards: list[RFCard], out_dir: Path, blob: bytes, source: str) -> None:
    rows = [card.as_row() for card in cards]
    with (out_dir / "rfcard_info_all.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "rfcard_info_all.json").write_text(
        json.dumps(
            {
                "source": source,
                "container": container_info(blob),
                "bid_note": ("synthetic_bid is this tool's ordinal, not a value "
                             "read from the firmware; Apple RF cards carry no BID"),
                "legacy_fset_note": ("fset is synthesised as zero for legacy ELF "
                                     "cards; use rfcard_name for their full generated identity"),
                "cards": rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def extract_efs_items(blob: bytes, out_dir: Path) -> int:
    """Write the EFS path/value records, preserving duplicate pathnames."""
    out_dir.mkdir(parents=True, exist_ok=True)
    seen: dict[str, list[bytes]] = {}
    written = 0
    position = 0
    while True:
        index = blob.find(bytes.fromhex(EFS_PATH_TAG), position)
        if index < 0:
            break
        try:
            _tag, path_len, path_body = _read_tlv(blob, index)
            name = blob[path_body:path_body + path_len].decode("utf-8").strip("\x00")
            value_index = blob.find(bytes.fromhex(EFS_VALUE_TAG),
                                    path_body + path_len,
                                    path_body + path_len + 64)
            if value_index < 0:
                position = path_body + path_len
                continue
            _vtag, value_len, value_body = _read_tlv(blob, value_index)
            value = blob[value_body:value_body + value_len]
        except (IPhoneRFError, UnicodeDecodeError, IndexError):
            position = index + 3
            continue
        previous = seen.setdefault(name, [])
        if value not in previous:
            # Distinct payloads under one pathname are configuration variants;
            # keep every one instead of letting the last write win.
            suffix = f".{len(previous)}" if previous else ""
            target = out_dir / (name.lstrip("/") + suffix)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            previous.append(value)
            written += 1
        position = value_body + value_len
    return written


def extract_bbcfg_tree(path: Path, out_dir: Path, with_efs: bool = True) -> list[RFCard]:
    """Entry point used by ``image_extractor.extract_bbcfg``."""
    blob, source = load_bbcfg(path)
    cards = extract_rfcards(blob, out_dir / "rfcards", source)
    if with_efs:
        try:
            extract_efs_items(blob, out_dir / "efs")
        except Exception as exc:  # never let the EFS tree break card recovery
            logger.warning("EFS extraction failed for %s: %s", path, exc)
    return cards


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract Qualcomm RF cards from Apple iPhone baseband firmware.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Accepts an .ipsw, a .bbfw, or a bare bbcfg.mbn.",
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path,
                        help="write RF cards here (default: <input stem>_rfcards)")
    parser.add_argument("--list", action="store_true",
                        help="list the cards without writing anything")
    parser.add_argument("--efs", action="store_true",
                        help="also write the BBCFG EFS item tree")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")

    try:
        blob, source = load_bbcfg(args.input)
        info = container_info(blob)
    except IPhoneRFError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"{source}: BBCFGMBN0 v{info['version']} ({info['fourcc']!r}), "
          f"{info['size']:,} bytes")

    if args.list:
        cards = [card for card, _ in iter_rfcards(blob)]
        for card in cards:
            identity = card.res_dat or card.rfcard_name or "unknown"
            print(f"  [{card.ordinal:2d}] {card.filename:28s} "
                  f"{card.raw_size:>8,} bytes  {identity}  "
                  f"bbcfg@0x{card.bbcfg_offset:08x}  {card.content_name[:12]}")
        print(f"{len(cards)} RF card(s)")
        return 0

    out_dir = args.output_dir or args.input.with_name(args.input.stem + "_rfcards")
    cards = extract_rfcards(blob, out_dir, source)
    for card in cards:
        print(f"  {card.filename:28s} <- bbcfg@0x{card.bbcfg_offset:08x} "
              f"({card.raw_size:,} bytes, {card.content_name[:12]})")
    if args.efs:
        count = extract_efs_items(blob, out_dir.parent / (out_dir.name + "_efs"))
        print(f"  {count} EFS items")
    if not cards:
        print("no RF cards found", file=sys.stderr)
        return 1
    print(f"{len(cards)} RF card(s) -> {out_dir}")
    print("note: the third filename field is a synthesised ordinal, not a "
          "firmware BID; see rfcard_info_all.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
