#!/usr/bin/env python3
"""Container/filesystem extraction helpers for the upstream GUI analyzer.

This module re-implements the recursive detection and extraction logic from
``qcom-rfcard-mbn-parser-fork/extract_rfcards.py`` in a form suitable for the
upstream ``qualcomm_rf_combo_analyzer`` data model.  It discovers
``rf_config_<HWID>_<FSID>_<BID>.mbn`` files inside Android modem firmware
containers (sparse, payload, super, ext4, EROFS, squashfs, F2FS, UBI, FAT,
gzip/xz/zstd/zip/tar/7z, etc.) and returns the paths of any matching MBNs plus
co-located sidecar files.

All external helpers are optional; missing tools are logged once and skipped.
"""

from __future__ import annotations

import gzip
import logging
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

RFCARD_PATTERN = re.compile(
    r"^rf_config_[0-9A-Fa-f]{3,6}_[0-9A-Fa-f]{1,4}_[0-9A-Fa-f]{1,4}\.mbn$"
)

# Files that add context around an rf_config MBN (kept when present in the same
# directory).  The fork also recognises ``rfcard_info_all.(csv|json)``.
SIDECAR_PATTERNS = (
    re.compile(r"^rf_config_.*_combos\.xml$"),
    re.compile(r"^rf_config_.*_combos_.*\.txt$"),
    re.compile(r"^mbn_ota\.md5sum$"),
    re.compile(r"^rfcard_info_all\.(csv|json)$"),
)

MAGIC_MAX = 4096
MAX_RECURSION_DEPTH = 8
MIN_CONTAINER_SIZE = 512


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


@dataclass
class ToolStatus:
    """Track which external helpers were checked and found missing."""

    missing: set[str] = field(default_factory=set)
    checked: set[str] = field(default_factory=set)

    def check(self, cmd: str) -> bool:
        """Return True if ``cmd`` is available; cache and log misses."""
        if cmd in self.checked:
            return cmd not in self.missing
        self.checked.add(cmd)
        if _have(cmd):
            return True
        self.missing.add(cmd)
        logger.warning("External helper %r not found; some containers may be skipped", cmd)
        return False

    def report(self) -> None:
        if self.missing:
            logger.warning(
                "Some external tools were not available; certain container types "
                "may have been skipped: %s",
                ", ".join(sorted(self.missing)),
            )


@dataclass
class ExtractContext:
    workdir: Path
    tools: ToolStatus
    outputs: list[Path] = field(default_factory=list)


class ExtractionError(RuntimeError):
    """Raised when a container cannot be processed."""


def _new_workdir(ctx: ExtractContext, tag: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f"{tag}_", dir=ctx.workdir))


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    logger.debug("$ %s", " ".join(str(x) for x in cmd))
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _read_magic(path: Path, n: int = MAGIC_MAX) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(n)
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect(path: Path) -> str:
    """Return a short type tag for ``path`` based on magic bytes."""
    head = _read_magic(path)
    if not head:
        return "empty"

    if head.startswith(b"\x3a\xff\x26\xed"):
        return "sparse"
    if head.startswith(b"CrAU"):
        return "payload"
    if head.startswith(b"ANDROID!"):
        return "bootimg"
    # Android super.img: LP_METADATA_GEOMETRY_MAGIC at offset 0x1000.
    if len(head) >= 0x1000 + 4:
        if head[:4] == b"gsla" or head[0x1000:0x1004] == b"gsla":
            return "super"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head[:4] == b"7z\xbc\xaf" and head[4:6] == b"\x27\x1c":
        return "7z"
    if head.startswith((b"hsqs", b"sqsh")):
        return "squashfs"
    # tar (ustar magic at offset 257).
    if len(head) >= 265 and head[257:262] == b"ustar":
        return "tar"
    # ext2/3/4 - superblock magic 0x53EF at offset 0x438.
    if len(head) >= 0x43A and head[0x438:0x43A] == b"\x53\xef":
        return "ext4"
    # EROFS - superblock magic 0xE0F5E1E2 at offset 0x400.
    if len(head) >= 0x404 and head[0x400:0x404] == b"\xe2\xe1\xf5\xe0":
        return "erofs"
    # F2FS - superblock magic 0xF2F52010 at offset 0x400 (LE).
    if len(head) >= 0x404 and head[0x400:0x404] == b"\x10\x20\xf5\xf2":
        return "f2fs"
    # UBI.
    if head.startswith(b"UBI#"):
        return "ubi"
    # FAT12/16/32: OEM name at offset 3.
    if len(head) >= 11 and head[3:11].rstrip(b"\x00 ") in (
        b"MSDOS5.0",
        b"MSWIN4.1",
        b"mkfs.fat",
        b"FAT     ",
        b"MSDOS",
    ):
        return "fat"
    if len(head) >= 0x1FE and head[0x1FE:0x200] == b"\x55\xaa":
        # Last-resort MBR-style boot signature; likely FAT or a partition table.
        return "fat_or_mbr"
    return "unknown"


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


def extract_sparse(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("simg2img"):
        return None
    out = _new_workdir(ctx, "sparse") / (path.stem + ".raw")
    res = _run(["simg2img", str(path), str(out)])
    if res.returncode != 0 or not out.exists() or out.stat().st_size == 0:
        logger.warning("simg2img failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_ext4(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("debugfs"):
        return None
    out = _new_workdir(ctx, "ext4")
    res = _run(["debugfs", "-R", f"rdump / {out}", str(path)])
    # ``debugfs`` returns 0 even when it warns about chown; treat any files as success.
    produced = any(out.rglob("*"))
    if not produced:
        logger.warning("debugfs produced nothing for %s: %s", path, _stderr(res))
        return None
    return out


def extract_erofs(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("fsck.erofs"):
        return None
    out = _new_workdir(ctx, "erofs")
    res = _run(["fsck.erofs", f"--extract={out}", "--no-preserve", str(path)])
    if res.returncode != 0:
        logger.warning("fsck.erofs failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_7z(path: Path, ctx: ExtractContext, tag: str) -> Path | None:
    if not ctx.tools.check("7z"):
        return None
    out = _new_workdir(ctx, tag)
    res = _run(["7z", "x", "-y", f"-o{out}", str(path)])
    if res.returncode != 0 and not any(out.rglob("*")):
        logger.warning("7z x failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_squashfs(path: Path, ctx: ExtractContext) -> Path | None:
    if _have("unsquashfs"):
        out = _new_workdir(ctx, "squashfs")
        res = _run(["unsquashfs", "-d", str(out / "root"), "-f", str(path)])
        if res.returncode == 0 and any(out.rglob("*")):
            return out
    return extract_7z(path, ctx, "squashfs")


def extract_gzip(path: Path, ctx: ExtractContext) -> Path | None:
    out = _new_workdir(ctx, "gzip") / (path.stem or "inner.bin")
    try:
        with gzip.open(path, "rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    except OSError as exc:
        logger.warning("gzip decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_xz(path: Path, ctx: ExtractContext) -> Path | None:
    try:
        import lzma  # stdlib
    except ImportError:
        logger.warning("python lzma module unavailable")
        return None
    out = _new_workdir(ctx, "xz") / (path.stem or "inner.bin")
    try:
        with lzma.open(path, "rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    except (OSError, lzma.LZMAError) as exc:
        logger.warning("xz decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_zstd(path: Path, ctx: ExtractContext) -> Path | None:
    if _have("zstd"):
        out = _new_workdir(ctx, "zstd") / (path.stem or "inner.bin")
        res = _run(["zstd", "-d", "-f", "-o", str(out), str(path)])
        if res.returncode == 0 and out.exists():
            return out
    try:
        import zstandard  # optional
    except ImportError:
        logger.warning("zstd binary missing and python 'zstandard' not installed")
        return None
    out = _new_workdir(ctx, "zstd") / (path.stem or "inner.bin")
    try:
        with path.open("rb") as src, out.open("wb") as dst:
            zstandard.ZstdDecompressor().copy_stream(src, dst)
    except Exception as exc:  # noqa: BLE001
        logger.warning("zstd decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_tar(path: Path, ctx: ExtractContext) -> Path | None:
    out = _new_workdir(ctx, "tar")
    try:
        with tarfile.open(path, "r:*") as tar:
            try:
                tar.extractall(out, filter="data")  # type: ignore[call-arg]
            except TypeError:
                tar.extractall(out)  # pragma: no cover
    except (tarfile.TarError, OSError) as exc:
        logger.warning("tar extract failed for %s: %s", path, exc)
        return None
    return out


def extract_super(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("lpunpack"):
        return None
    out = _new_workdir(ctx, "super")
    res = _run(["lpunpack", str(path), str(out)])
    if res.returncode != 0:
        logger.warning("lpunpack failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_payload(path: Path, ctx: ExtractContext) -> Path | None:
    for cmd in ("payload-dumper-go", "payload_dumper"):
        if _have(cmd):
            out = _new_workdir(ctx, "payload")
            args = (
                [cmd, "-o", str(out), str(path)]
                if cmd == "payload-dumper-go"
                else [cmd, "--out", str(out), str(path)]
            )
            res = _run(args)
            if res.returncode == 0 and any(out.rglob("*")):
                return out
    logger.warning(
        "%s looks like an OTA payload; install payload-dumper-go or the "
        "'payload_dumper' Python package and rerun.",
        path.name,
    )
    return None


def extract_f2fs(path: Path, ctx: ExtractContext) -> Path | None:  # noqa: ARG001
    logger.warning(
        "%s looks like an F2FS image; F2FS extraction is not supported by this tool",
        path.name,
    )
    return None


def extract_ubi(path: Path, ctx: ExtractContext) -> Path | None:  # noqa: ARG001
    logger.warning(
        "%s looks like a UBI image; UBI extraction is not supported by this tool",
        path.name,
    )
    return None


def _stderr(res: subprocess.CompletedProcess) -> str:
    return res.stderr.decode(errors="replace").strip()


# ---------------------------------------------------------------------------
# Recursion driver
# ---------------------------------------------------------------------------

EXTRACTORS: dict[str, Callable[[Path, ExtractContext], Path | None]] = {
    "sparse": extract_sparse,
    "ext4": extract_ext4,
    "erofs": extract_erofs,
    "fat": lambda p, c: extract_7z(p, c, "fat"),
    "fat_or_mbr": lambda p, c: extract_7z(p, c, "fat_or_mbr"),
    "squashfs": extract_squashfs,
    "gzip": extract_gzip,
    "xz": extract_xz,
    "zstd": extract_zstd,
    "zip": lambda p, c: extract_7z(p, c, "zip"),
    "7z": lambda p, c: extract_7z(p, c, "7z"),
    "tar": extract_tar,
    "super": extract_super,
    "payload": extract_payload,
    "f2fs": extract_f2fs,
    "ubi": extract_ubi,
}


def unwrap(path: Path, ctx: ExtractContext, depth: int = 0) -> None:
    """Recursively unwrap ``path`` and register extracted file-tree roots.

    Every produced directory is appended to ``ctx.outputs``; scanning happens
    afterwards so that the same logic can be used by the GUI without copying
    files to a destination directory.
    """
    if depth > MAX_RECURSION_DEPTH:
        logger.warning("Max recursion depth reached at %s", path)
        return
    if not path.exists() or path.stat().st_size < MIN_CONTAINER_SIZE:
        return

    tag = detect(path)
    logger.info("detect: %s -> %s", path, tag)

    if tag in ("empty", "unknown", "bootimg"):
        return

    extractor = EXTRACTORS.get(tag)
    if extractor is None:
        logger.debug("No extractor for tag %s", tag)
        return

    produced = extractor(path, ctx)
    if produced is None:
        return

    if produced.is_dir():
        ctx.outputs.append(produced)
        for child in produced.rglob("*"):
            if child.is_file():
                _maybe_unwrap_child(child, ctx, depth + 1)
    else:
        unwrap(produced, ctx, depth + 1)


def _maybe_unwrap_child(path: Path, ctx: ExtractContext, depth: int) -> None:
    """Only recurse into children whose magic clearly identifies a container."""
    tag = detect(path)
    if tag in EXTRACTORS:
        unwrap(path, ctx, depth)


# ---------------------------------------------------------------------------
# Public API for the analyzer
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Paths discovered inside an extracted container."""

    mbns: list[Path]
    sidecars: list[Path]
    scratch_dir: Path


def is_rfcard_name(name: str) -> bool:
    return bool(RFCARD_PATTERN.match(name))


def is_sidecar_name(name: str) -> bool:
    return any(pattern.match(name) for pattern in SIDECAR_PATTERNS)


def discover_candidates(root: Path) -> tuple[list[Path], list[Path]]:
    """Walk ``root`` and return all MBN and sidecar paths."""
    mbns: list[Path] = []
    sidecars: list[Path] = []
    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = list(root.rglob("*"))
    else:
        candidates = []
    for path in candidates:
        if not path.is_file():
            continue
        name = path.name
        if is_rfcard_name(name):
            mbns.append(path)
        elif is_sidecar_name(name):
            sidecars.append(path)
    return mbns, sidecars


def sidecars_in_directory(directory: Path, sidecars: list[Path]) -> dict[str, str]:
    return {path.name: str(path) for path in sidecars if path.parent == directory}


def scan_container(path: Path) -> ScanResult:
    """Recursively unwrap ``path`` and return discovered candidates.

    The returned ``ScanResult.scratch_dir`` contains all extracted content and
    must remain valid while the caller still needs to read the files.  Callers
    can safely leave cleanup to the operating system; this module does not
    delete scratch directories automatically so that GUI exports/comparisons
    continue to work after the scan finishes.
    """
    if not path.is_file():
        raise ExtractionError(f"Not a file: {path}")
    if path.stat().st_size < MIN_CONTAINER_SIZE:
        raise ExtractionError(f"File too small to be a container: {path}")

    scratch = Path(tempfile.mkdtemp(prefix="rfcards_gui_"))
    logger.info("Extraction scratch directory: %s", scratch)

    ctx = ExtractContext(workdir=scratch, tools=ToolStatus())
    unwrap(path, ctx)
    ctx.tools.report()

    all_mbns: list[Path] = []
    all_sidecars: list[Path] = []
    for output in ctx.outputs:
        mbns, sidecars = discover_candidates(output)
        all_mbns.extend(mbns)
        all_sidecars.extend(sidecars)

    return ScanResult(mbns=all_mbns, sidecars=all_sidecars, scratch_dir=scratch)


__all__ = [
    "ExtractionError",
    "ExtractContext",
    "ScanResult",
    "ToolStatus",
    "detect",
    "discover_candidates",
    "extract_7z",
    "extract_erofs",
    "extract_ext4",
    "extract_gzip",
    "extract_payload",
    "extract_squashfs",
    "extract_sparse",
    "extract_super",
    "extract_tar",
    "extract_xz",
    "extract_zstd",
    "is_rfcard_name",
    "is_sidecar_name",
    "scan_container",
    "sidecars_in_directory",
    "unwrap",
]
