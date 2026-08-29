from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui_version"
sys.path.insert(0, str(GUI))

import image_extractor
import iphone_rf_parser as iphone
import qualcomm_rf_combo_analyzer as analyzer


class LegacyBBCFGDiscoveryTests(unittest.TestCase):
    def test_legacy_identity_comes_from_generated_dynamic_symbol(self) -> None:
        raw = iphone.ELF32_MAGIC + b"legacy fixture"
        with (
            mock.patch.object(iphone.legacy, "Elf32Image") as image_type,
            mock.patch.object(
                iphone.legacy,
                "rfcard_name_from_symbols",
                return_value="rfc_hwid2024_mav24p2_p1_main_ww_g_ag",
            ) as name_from_symbols,
        ):
            identity = iphone.legacy_rfcard_identity(raw)

        self.assertEqual(
            identity,
            (2024, "rfc_hwid2024_mav24p2_p1_main_ww_g_ag"),
        )
        name_from_symbols.assert_called_once_with(image_type.return_value)

    def test_legacy_identity_rejects_an_unrelated_elf(self) -> None:
        raw = iphone.ELF32_MAGIC + b"unrelated fixture"
        with (
            mock.patch.object(iphone.legacy, "Elf32Image"),
            mock.patch.object(
                iphone.legacy,
                "rfcard_name_from_symbols",
                return_value=None,
            ),
        ):
            self.assertIsNone(iphone.legacy_rfcard_identity(raw))

    def test_store_yields_modern_and_legacy_names_for_their_parsers(self) -> None:
        blob = bytearray(64)
        blob[8:12] = iphone.MAVZ_MAGIC
        blob[32:36] = iphone.MAVZ_MAGIC
        modern_raw = b"wrapper /rfc/2025_0_res.dat /rfc/2025_0_cmn.dat"
        legacy_raw = iphone.ELF32_MAGIC + b"legacy"
        store_rows = [
            (3, 4, "modern-content", 8, 10),
            (7, 28, "legacy-content", 32, 10),
        ]

        def decompressed(_blob: bytes, offset: int) -> tuple[bytes, int]:
            return (modern_raw, 101) if offset == 8 else (legacy_raw, 202)

        with (
            mock.patch.object(iphone, "iter_store_blobs", return_value=store_rows),
            mock.patch.object(iphone, "decompress_mavz", side_effect=decompressed),
            mock.patch.object(
                iphone,
                "legacy_rfcard_identity",
                return_value=(2024, "rfc_hwid2024_mav24p2_p1_main_ww_g_ag"),
            ),
        ):
            cards = [card for card, _raw in iphone.iter_rfcards(bytes(blob))]

        self.assertEqual(
            [card.filename for card in cards],
            ["rf_config_2025_0_0.mbn", "2024_0_1.mbn"],
        )
        self.assertEqual(
            [card.generation for card in cards],
            ["DAT/protobuf", "Legacy ELF"],
        )
        self.assertFalse(cards[0].fset_is_synthetic)
        self.assertTrue(cards[1].fset_is_synthetic)
        self.assertEqual(cards[1].rfcard_name, "rfc_hwid2024_mav24p2_p1_main_ww_g_ag")
        self.assertIsNone(cards[1].res_dat)


class ExtractedLegacyRoutingTests(unittest.TestCase):
    def test_image_extractor_discovers_numeric_legacy_names(self) -> None:
        self.assertTrue(image_extractor.is_rfcard_name("2024_0_17.mbn"))
        self.assertTrue(image_extractor.is_rfcard_name("710_0.mbn"))
        self.assertTrue(image_extractor.is_rfcard_name("rf_config_2025_0_3.mbn"))
        self.assertFalse(image_extractor.is_rfcard_name("2024.mbn"))

    def test_numeric_mbn_in_rfcards_directory_is_routed_to_legacy_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            mbn = scratch / "bbcfg" / "rfcards" / "2024_0_0.mbn"
            mbn.parent.mkdir(parents=True)
            mbn.write_bytes(iphone.ELF32_MAGIC + b"fixture")
            result = image_extractor.ScanResult(
                mbns=[mbn],
                sidecars=[],
                scratch_dir=scratch,
            )

            with mock.patch.object(analyzer, "_combo_counts", return_value=(1, "0+0+0=0")):
                records = analyzer._records_from_extraction(result)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].generation, "Legacy ELF")
        self.assertEqual(records[0].hwid, 2024)
        self.assertEqual(records[0].bid, 0)

    def test_unrelated_numeric_mbn_outside_known_rf_directories_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            mbn = scratch / "mcfg" / "2024_0_0.mbn"
            mbn.parent.mkdir(parents=True)
            mbn.write_bytes(iphone.ELF32_MAGIC + b"fixture")
            result = image_extractor.ScanResult(
                mbns=[mbn],
                sidecars=[],
                scratch_dir=scratch,
            )
            records = analyzer._records_from_extraction(result)

        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
