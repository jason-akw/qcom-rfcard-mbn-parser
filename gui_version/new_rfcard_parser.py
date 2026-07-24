#!/usr/bin/env python3
r"""
Recover the LTE/NR combo portion of a Qualcomm RFCard from rf_config_*.mbn.

Tested against the RFPD layout in MPSS.DE.9.0. Python standard library only.

Examples:
    python recover_rfcard_combos.py rf_config_xxx.mbn --diag
    python recover_rfcard_combos.py card_res.dat
"""

from __future__ import annotations

import argparse
import ctypes
import json
import re
import struct
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

class NRBandGroup(ctypes.LittleEndianStructure):
    _pack_ = 4
    _fields_ = [
        ("tech", ctypes.c_uint32, 2),
        ("band", ctypes.c_uint32, 9),
        ("dl_bw_class", ctypes.c_uint32, 5),
        ("dl_bw_per_cc", ctypes.c_uint32, 7),
        ("ul_bw_class", ctypes.c_uint32, 5),
        ("ul_bw_per_cc", ctypes.c_uint32, 7),
        ("dl_max_antennas_index", ctypes.c_uint32, 7),
        ("ul_max_antennas_index", ctypes.c_uint32, 7),
        ("max_scs", ctypes.c_uint32, 3),
        ("ul_qam_cap_index", ctypes.c_uint32, 2),
        ("srs_tx_switch_type", ctypes.c_uint32, 4),
        ("tx_switch_impact_to_rx", ctypes.c_uint32, 2),
        ("tx_switch_with_another_band", ctypes.c_uint32, 2),
        ("srs_carrier_hop", ctypes.c_uint32, 1),
        ("srs_carrier_hop_src", ctypes.c_uint32, 2),
        ("rx_limit", ctypes.c_uint32, 1),
        ("num_tx_meeting_combo_pc", ctypes.c_uint32, 2),
        ("link_id", ctypes.c_uint32, 2),
    ]


class NRComboProperty(ctypes.LittleEndianStructure):
    _pack_ = 2
    _fields_ = [
        ("power_class", ctypes.c_uint16, 3),
        ("tdd_ant_swt_fdd_disruption", ctypes.c_uint16, 1),
        ("simultaneousRxTxInterBandENDC", ctypes.c_uint16, 1),
        ("simultaneousRxTxInterBandCA", ctypes.c_uint16, 1),
        ("ul_tx_switch_type", ctypes.c_uint8, 2),
        ("intra_contig_type", ctypes.c_uint8, 3),
        ("srs_cs_type", ctypes.c_uint8, 3),
        ("intra_ulca_dual_pa", ctypes.c_uint16, 1),
        ("simultaneousRxTxInterBandSUL", ctypes.c_uint16, 1),
        ("num_bands", ctypes.c_uint8, 6),
        ("has_bcs5_counterpart", ctypes.c_uint8, 1),
        ("higher_power_limit", ctypes.c_uint8, 1),
        ("bcs_num", ctypes.c_uint8),
        ("env_mode_mask_idx", ctypes.c_uint16),
        ("env_mode_subset_mask_idx", ctypes.c_uint16),
        ("simul_rxtx_bmap_idx", ctypes.c_uint16),
        ("simul_sul_rxtx_bmap_idx", ctypes.c_uint16),
    ]


def extract_rfc_dats(blob: bytes) -> dict[str, bytes]:
    """Find Large-EFS /rfc/*.dat items even when MCFG is inside a signed ELF MBN."""
    found: dict[str, bytes] = {}
    pattern = re.compile(rb"/rfc/[^\x00\r\n]{1,240}\.dat\x00", re.IGNORECASE)
    for match in pattern.finditer(blob):
        path_with_nul = match.group(0)
        path = path_with_nul[:-1].decode("utf-8", "replace")
        # Immediately before the path: TLV type 0x0001 and uint16 path length.
        if match.start() < 4:
            continue
        tlv_type, path_len = struct.unpack_from("<HH", blob, match.start() - 4)
        if tlv_type != 1 or path_len != len(path_with_nul):
            continue
        data_hdr = match.end()
        if data_hdr + 6 > len(blob):
            continue
        data_type, data_len = struct.unpack_from("<HI", blob, data_hdr)
        if data_type != 2 or data_hdr + 6 + data_len > len(blob):
            continue
        found[path] = blob[data_hdr + 6 : data_hdr + 6 + data_len]
    return found


def enum_assignments() -> dict[str, int]:
    """Enums used by the MPSS.DE.9.0 NR5G_8RX RFCard schema."""
    bw_names = [
        "DEFAULT", "5", "10", "15", "20", "20_20", "20_20_20",
        "20_20_20_20", "20_20_20_20_20", "25", "30", "40", "50",
        "50_50", "50_50_50", "50_50_50_50", "50_50_50_50_50", "60",
        "70", "80", "90", "100", "100_60", "100_100", "100_100_100",
        "100_100_100_100", "100_100_100_100_100",
        "100_100_100_100_100_100", "100_100_100_100_100_100_100",
        "100_100_100_100_100_100_100_100", "40_40", "60_40",
        "100_40", "200", "200_200", "200_200_200", "200_200_200_200",
        "10_10", "25_25", "40_10", "40_20", "35", "30_20", "60_60",
        "30_30", "45", "50_5", "50_10", "50_15", "50_20", "40_15",
        "15_15", "30_25", "20_10", "20_15", "5_5", "80_80", "80_20",
        "40_30", "100_90", "30_10", "100_20", "80_40", "50_40",
        "100_50", "100_80",
    ]
    result = {f"BW_{name}": index for index, name in enumerate(bw_names)}

    antenna_names = ["INVALID", "1", "2", "4"]
    for count in range(2, 9):
        antenna_names.append("_".join(["1"] * count))
        antenna_names.extend(
            "_".join(["2"] * leading + ["1"] * (count - leading))
            for leading in range(1, count + 1)
        )
        antenna_names.extend(
            "_".join(["4"] * leading + ["2"] * (count - leading))
            for leading in range(1, count + 1)
        )
    antenna_names.extend(["8", "8_4", "8_4_4", "8_8", "6", "4_8", "6_4", "4_6", "6_6"])
    result.update(
        {f"ANTENNA_{name}": index for index, name in enumerate(antenna_names)}
    )
    return result


def dat_payload_candidates(dat: bytes):
    """RFPD default DAT = hash byte + uint32 raw size + zlib(protobuf)."""
    yielded = set()
    # MCFG may prepend a few bytes of EFS metadata before the actual DAT.
    for base in range(min(32, max(0, len(dat) - 5))):
        expected = struct.unpack_from("<I", dat, base + 1)[0]
        try:
            raw = zlib.decompress(dat[base + 5 :])
            if len(raw) == expected:
                yielded.add(raw)
                label = "hash+size+zlib"
                if base:
                    label = f"{base}-byte-metadata+" + label
                yield label, raw
        except zlib.error:
            pass
    for base in range(min(32, max(0, len(dat) - 4))):
        expected = struct.unpack_from("<I", dat, base)[0]
        raw = dat[base + 4 :]
        if len(raw) == expected and raw not in yielded:
            yielded.add(raw)
            label = "size+raw"
            if base:
                label = f"{base}-byte-metadata+" + label
            yield label, raw
    if dat not in yielded:
        yield "raw", dat


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data) and shift < 70:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise ValueError("Truncated protobuf varint")


def protobuf_fields(data: bytes) -> dict[int, list[tuple[int, object]]]:
    result: dict[int, list[tuple[int, object]]] = {}
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("Invalid protobuf field zero")
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 1:
            if pos + 8 > len(data):
                raise ValueError("Truncated protobuf fixed64")
            value, pos = data[pos : pos + 8], pos + 8
        elif wire == 2:
            size, pos = read_varint(data, pos)
            if pos + size > len(data):
                raise ValueError("Truncated protobuf length-delimited field")
            value, pos = data[pos : pos + size], pos + size
        elif wire == 5:
            if pos + 4 > len(data):
                raise ValueError("Truncated protobuf fixed32")
            value, pos = data[pos : pos + 4], pos + 4
        else:
            raise ValueError(f"Unsupported protobuf wire type {wire}")
        result.setdefault(number, []).append((wire, value))
    return result


def proto_bytes(fields, number: int) -> bytes:
    return b"".join(value for wire, value in fields.get(number, []) if wire == 2)


def proto_uint(fields, number: int) -> int:
    values = [value for wire, value in fields.get(number, []) if wire == 0]
    return int(values[-1]) if values else 0


def proto_repeated_uint(fields, number: int) -> list[int]:
    result = []
    for wire, value in fields.get(number, []):
        if wire == 0:
            result.append(int(value))
        elif wire == 2:
            pos = 0
            while pos < len(value):
                item, pos = read_varint(value, pos)
                result.append(item)
    return result


def make_rrc_view(payload: bytes):
    outer = protobuf_fields(payload)
    rrc_messages = [value for wire, value in outer.get(7, []) if wire == 2]
    if not rrc_messages:
        raise ValueError("res protobuf has no rrc field #7")
    fields = protobuf_fields(rrc_messages[-1])
    mapping = {
        "NR_band_group_table_high": ("bytes", 1),
        "NR_band_group_table_low": ("bytes", 2),
        "lte_info_per_band_sub_cap_high": ("bytes", 3),
        "nr5g_info_per_band_sub_cap_high": ("bytes", 4),
        "lte_nr5g_info_per_band_sub_cap_high": ("bytes", 5),
        "nr5g_nr5g_info_per_band_sub_cap_high": ("bytes", 6),
        "lte_info_per_band_sub_cap_high_num": ("uint", 7),
        "nr5g_info_per_band_sub_cap_high_num": ("uint", 8),
        "lte_nr5g_info_per_band_sub_cap_high_num": ("uint", 9),
        "nr5g_nr5g_info_per_band_sub_cap_high_num": ("uint", 10),
        "nr5g_band_group_indices_table_sub_cap_high": ("bytes", 11),
        "nr5g_band_group_indices_offset_table_sub_cap_high": ("repeated", 12),
        "nr5g_combo_properties_table_sub_cap_high": ("bytes", 13),
        "lte_nr5g_band_group_indices_table_sub_cap_high": ("bytes", 14),
        "lte_nr5g_band_group_indices_offset_table_sub_cap_high": ("repeated", 15),
        "lte_nr5g_combo_properties_table_sub_cap_high": ("bytes", 16),
        "nr5g_nr5g_band_group_indices_table_sub_cap_high": ("bytes", 17),
        "nr5g_nr5g_band_group_indices_offset_table_sub_cap_high": ("repeated", 18),
        "nr5g_nr5g_combo_properties_table_sub_cap_high": ("bytes", 19),
        "lte_info_per_band_sub_cap_low": ("bytes", 39),
        "nr5g_info_per_band_sub_cap_low": ("bytes", 40),
        "lte_nr5g_info_per_band_sub_cap_low": ("bytes", 41),
        "nr5g_nr5g_info_per_band_sub_cap_low": ("bytes", 42),
        "lte_info_per_band_sub_cap_low_num": ("uint", 43),
        "nr5g_info_per_band_sub_cap_low_num": ("uint", 44),
        "lte_nr5g_info_per_band_sub_cap_low_num": ("uint", 45),
        "nr5g_nr5g_info_per_band_sub_cap_low_num": ("uint", 46),
        "nr5g_band_group_indices_table_sub_cap_low": ("bytes", 47),
        "nr5g_band_group_indices_offset_table_sub_cap_low": ("repeated", 48),
        "nr5g_combo_properties_table_sub_cap_low": ("bytes", 49),
        "lte_nr5g_band_group_indices_table_sub_cap_low": ("bytes", 50),
        "lte_nr5g_band_group_indices_offset_table_sub_cap_low": ("repeated", 51),
        "lte_nr5g_combo_properties_table_sub_cap_low": ("bytes", 52),
        "nr5g_nr5g_band_group_indices_table_sub_cap_low": ("bytes", 53),
        "nr5g_nr5g_band_group_indices_offset_table_sub_cap_low": ("repeated", 54),
        "nr5g_nr5g_combo_properties_table_sub_cap_low": ("bytes", 55),
        "env_name_high": ("string", 73),
        "env_name_low": ("string", 74),
    }
    values = {}
    for name, (kind, number) in mapping.items():
        if kind == "bytes":
            values[name] = proto_bytes(fields, number)
        elif kind == "uint":
            values[name] = proto_uint(fields, number)
        elif kind == "string":
            values[name] = proto_bytes(fields, number).decode("utf-8", "replace")
        else:
            values[name] = proto_repeated_uint(fields, number)
    return SimpleNamespace(**values)


def parse_res_dat(dat: bytes):
    errors = []
    for encoding, payload in dat_payload_candidates(dat):
        try:
            rrc = make_rrc_view(payload)
            return encoding, payload, SimpleNamespace(rrc=rrc)
        except Exception as exc:
            errors.append(f"{encoding}: {exc}")
    raise ValueError("Cannot parse res DAT protobuf: " + "; ".join(errors))


def chunks(data: bytes, size: int):
    return [data[pos : pos + size] for pos in range(0, len(data) - size + 1, size)]


def wrapper_bytes(values, expected_size: int) -> bytes:
    values = list(values)
    if len(values) == expected_size and all(0 <= value <= 0xFF for value in values):
        return bytes(values)
    raw32 = b"".join(struct.pack("<I", value) for value in values)
    if len(raw32) >= expected_size:
        return raw32[:expected_size]
    raise ValueError(f"Unexpected wrapper length {len(values)} for {expected_size} bytes")


def decode_lte_combo(raw: bytes) -> str:
    # Native layout: bool + one pad + 6 * 8-byte per-band records = 50 bytes.
    groups = []
    for index in range(6):
        pos = 2 + index * 8
        band, dl_cls, dl_ant, ul_cls, ul_ant, _ul_qam = struct.unpack_from(
            "<HBBBBB", raw, pos
        )
        if band == 0:
            continue
        dl_letter = chr(64 + dl_cls) if 1 <= dl_cls <= 26 else f"X{dl_cls}"
        text = f"B{band}{dl_letter}[{dl_ant}]"
        if ul_cls:
            ul_letter = chr(64 + ul_cls) if 1 <= ul_cls <= 26 else f"X{ul_cls}"
            text += f";{ul_letter}[{ul_ant}]"
        groups.append(text)
    return "+".join(groups)


def reverse_enum(enum_map: dict[str, int], prefix: str) -> dict[int, str]:
    return {
        value: name[len(prefix) :]
        for name, value in enum_map.items()
        if name.startswith(prefix)
        and not name.endswith(
            ("_SIZE", "_MAX_NUM", "_INVALID_INDEX", "_INVALID", "_DEFAULT")
        )
    }


def struct_from_bytes(cls, raw: bytes):
    if len(raw) < ctypes.sizeof(cls):
        raise ValueError(f"Short {cls.__name__}: {len(raw)}")
    return cls.from_buffer_copy(raw[: ctypes.sizeof(cls)])


def decode_nr_property(raw: bytes):
    """RFPD compacts the 24 consecutive property bitfields into three bytes."""
    if len(raw) < 12:
        raise ValueError(f"Short NRComboProperty: {len(raw)}")
    bits = int.from_bytes(raw[:3], "little")
    return SimpleNamespace(
        power_class=(bits >> 0) & 0x7,
        tdd_ant_swt_fdd_disruption=(bits >> 3) & 0x1,
        simultaneousRxTxInterBandENDC=(bits >> 4) & 0x1,
        simultaneousRxTxInterBandCA=(bits >> 5) & 0x1,
        ul_tx_switch_type=(bits >> 6) & 0x3,
        intra_contig_type=(bits >> 8) & 0x7,
        srs_cs_type=(bits >> 11) & 0x7,
        intra_ulca_dual_pa=(bits >> 14) & 0x1,
        simultaneousRxTxInterBandSUL=(bits >> 15) & 0x1,
        num_bands=(bits >> 16) & 0x3F,
        has_bcs5_counterpart=(bits >> 22) & 0x1,
        higher_power_limit=(bits >> 23) & 0x1,
        bcs_num=raw[3],
        env_mode_mask_idx=struct.unpack_from("<H", raw, 4)[0],
        env_mode_subset_mask_idx=struct.unpack_from("<H", raw, 6)[0],
        simul_rxtx_bmap_idx=struct.unpack_from("<H", raw, 8)[0],
        simul_sul_rxtx_bmap_idx=struct.unpack_from("<H", raw, 10)[0],
    )


def format_side(bw_name: str | None, antenna_name: str | None) -> str:
    layers = [] if not antenna_name else [int(x) for x in antenna_name.split("_")]
    bws = [] if not bw_name else [int(x) for x in bw_name.split("_")]
    count = max(len(layers), len(bws), 1)
    if not layers:
        layers = [0] * count
    if not bws:
        return ",".join(str(layer) for layer in layers)
    if len(layers) < len(bws):
        layers.extend([layers[-1]] * (len(bws) - len(layers)))
    return ",".join(f"{bw}x{layer}" for bw, layer in zip(bws, layers))


def decode_nr_band_group(
    bg: NRBandGroup, bw_by_value: dict[int, str], ant_by_value: dict[int, str]
) -> str:
    prefix = "B" if bg.tech == 1 else "N" if bg.tech == 2 else f"T{bg.tech}-"
    if bg.dl_bw_class:
        dl_class = (
            chr(64 + bg.dl_bw_class)
            if 1 <= bg.dl_bw_class <= 26
            else f"X{bg.dl_bw_class}"
        )
        dl = format_side(
            bw_by_value.get(bg.dl_bw_per_cc),
            ant_by_value.get(bg.dl_max_antennas_index),
        )
        text = f"{prefix}{bg.band}{dl_class}[{dl}]"
    else:
        # RFCard's canonical syntax for a supplementary-uplink/UL-only
        # component is N<band>_;<UL class>[<UL BW>x<antennas>].
        text = f"{prefix}{bg.band}_"
    if bg.ul_bw_class:
        ul_class = (
            chr(64 + bg.ul_bw_class)
            if 1 <= bg.ul_bw_class <= 26
            else f"X{bg.ul_bw_class}"
        )
        ul = format_side(
            bw_by_value.get(bg.ul_bw_per_cc),
            ant_by_value.get(bg.ul_max_antennas_index),
        )
        text += f";{ul_class}[{ul}]"
    return text


def property_attributes(prop: NRComboProperty) -> dict[str, str]:
    attrs: dict[str, str] = {}
    pc = {1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "1.5"}.get(
        prop.power_class
    )
    if pc:
        attrs["pc"] = pc
    tx_switch = {
        1: "switchedUL",
        2: "dualUL",
        3: "switchedUL,dualUL",
    }.get(prop.ul_tx_switch_type)
    if tx_switch:
        attrs["tx_switching"] = tx_switch
    if prop.higher_power_limit:
        attrs["higher_power_limit"] = "ENABLE"
    return attrs


def decode_lte_section(rrc, suffix: str):
    field = f"lte_info_per_band_sub_cap_{suffix}"
    raw = bytes(getattr(rrc, field))
    size = 50
    count = int(getattr(rrc, f"{field}_num"))
    return [
        (decode_lte_combo(item), {})
        for item in chunks(raw, size)[:count]
        if decode_lte_combo(item)
    ]


def decode_nr_section(rrc, prefix: str, suffix: str, enum_map: dict[str, int]):
    records = nr_section_records(rrc, prefix, suffix)
    bw_by_value = reverse_enum(enum_map, "BW_")
    ant_by_value = reverse_enum(enum_map, "ANTENNA_")
    result = []
    for band_groups, prop in records:
        text_groups = [
            decode_nr_band_group(bg, bw_by_value, ant_by_value)
            for bg in band_groups
        ]
        result.append(("+".join(text_groups), property_attributes(prop)))
    return result


def nr_section_records(rrc, prefix: str, suffix: str):
    ref_raw = bytes(getattr(rrc, f"{prefix}_info_per_band_sub_cap_{suffix}"))
    bg_raw = bytes(getattr(rrc, f"NR_band_group_table_{suffix}"))
    index_raw = bytes(
        getattr(rrc, f"{prefix}_band_group_indices_table_sub_cap_{suffix}")
    )
    offsets = list(
        getattr(rrc, f"{prefix}_band_group_indices_offset_table_sub_cap_{suffix}")
    )
    prop_raw = bytes(
        getattr(rrc, f"{prefix}_combo_properties_table_sub_cap_{suffix}")
    )

    ref_count = int(getattr(rrc, f"{prefix}_info_per_band_sub_cap_{suffix}_num"))
    refs = [
        struct.unpack("<HH", item)
        for item in chunks(ref_raw, 4)
    ][:ref_count]
    band_groups = [
        struct_from_bytes(NRBandGroup, item)
        for item in chunks(bg_raw, ctypes.sizeof(NRBandGroup))
    ]
    properties = [decode_nr_property(item) for item in chunks(prop_raw, 12)]

    result = []
    for bg_table_index, prop_index in refs:
        if prop_index >= len(properties):
            continue
        prop = properties[prop_index]
        count = int(prop.num_bands)
        if count <= 0 or count > len(offsets):
            continue
        # The flattened table contains uint16 band-group indices; offsets count
        # entries rather than bytes.
        start_entry = int(offsets[count - 1]) + bg_table_index * count
        start = start_entry * 2
        raw_indices = index_raw[start : start + count * 2]
        if len(raw_indices) != count * 2:
            continue
        bg_indices = struct.unpack("<" + "H" * count, raw_indices)
        selected_groups = []
        for bg_index in bg_indices:
            if bg_index >= len(band_groups):
                selected_groups = []
                break
            selected_groups.append(band_groups[bg_index])
        if selected_groups:
            result.append((selected_groups, prop))
    return result


def b0cd_v41_packets(rrc, suffix: str, packet_combos: int = 100) -> list[bytes]:
    """Build headerless Qualcomm 0xB0CD v41 payloads."""
    field = f"lte_info_per_band_sub_cap_{suffix}"
    raw_combos = chunks(bytes(getattr(rrc, field)), 50)[
        : int(getattr(rrc, f"{field}_num"))
    ]
    encoded = []
    for raw in raw_combos:
        components = []
        for index in range(6):
            pos = 2 + index * 8
            band, dl_cls, dl_ant, ul_cls, ul_ant, ul_qam = struct.unpack_from(
                "<HBBBBB", raw, pos
            )
            if band:
                components.append(
                    struct.pack(
                        "<HBBBBB",
                        band,
                        dl_cls,
                        ul_cls,
                        dl_ant,
                        ul_ant,
                        ul_qam,
                    )
                )
        if components:
            encoded.append(bytes([len(components)]) + b"".join(components))

    result = []
    for start in range(0, len(encoded), packet_combos):
        current = encoded[start : start + packet_combos]
        result.append(bytes([41, len(current)]) + b"".join(current))
    return result


def b826_v22_component(bg: NRBandGroup) -> bytes:
    """Encode one RFCard band group in the 10-byte 0xB826 v22 component layout."""
    if bg.band > 0x1FF:
        raise ValueError(f"0xB826 v22 band exceeds 9 bits: {bg.band}")
    dl_ant = int(bg.dl_max_antennas_index)
    ul_ant = int(bg.ul_max_antennas_index)
    dl_bw = int(bg.dl_bw_per_cc)
    ul_bw = int(bg.ul_bw_per_cc)
    if dl_ant > 0x7F or ul_ant > 0x1F or dl_bw > 0x7F or ul_bw > 0x7F:
        raise ValueError("0xB826 v22 component field exceeds its bit width")

    head = (
        int(bg.band)
        | ((1 if bg.tech == 2 else 0) << 9)
        | ((int(bg.dl_bw_class) & 0x1F) << 10)
        | ((dl_ant & 1) << 15)
    )
    byte1 = ((dl_ant >> 1) & 0x3F) | ((int(bg.ul_bw_class) & 0x03) << 6)
    byte2 = ((int(bg.ul_bw_class) >> 2) & 0x07) | ((ul_ant & 0x1F) << 3)
    qam = int(bg.ul_qam_cap_index) & 0x03
    byte3 = ((qam & 1) << 2) | (((qam >> 1) & 1) << 1) | ((dl_bw & 1) << 7)
    byte4 = ((dl_bw >> 1) & 0x3F) | ((ul_bw & 0x03) << 6)
    byte5 = (ul_bw >> 2) & 0x1F
    return struct.pack("<HBBBBB", head, byte1, byte2, byte3, byte4, byte5) + b"\x00\x00\x00"


def b826_v22_packets(
    records,
    source: int,
    packet_combos: int = 100,
) -> list[bytes]:
    """Build headerless Qualcomm 0xB826 v22 payloads."""
    encoded = []
    for band_groups, prop in records:
        count = len(band_groups)
        if not 1 <= count <= 15:
            raise ValueError(f"0xB826 v22 supports 1..15 components, got {count}")
        features = (count << 6) | ((int(prop.ul_tx_switch_type) & 0x03) << 13)
        encoded.append(
            struct.pack("<H", features)
            + b"\x00" * 13
            + b"".join(b826_v22_component(bg) for bg in band_groups)
        )

    total = len(encoded)
    result = []
    for start in range(0, total, packet_combos):
        current = encoded[start : start + packet_combos]
        header = struct.pack("<HHHHHB", 22, 0, total, start, len(current), source)
        result.append(header + b"".join(current))
    return result


def write_diag_hexdump(packets: list[tuple[str, bytes]], destination: Path):
    lines = [
        "# Headerless Qualcomm DIAG log payloads; one Payload block per packet.",
        "# 0xB0CD uses v41; 0xB826 uses v22.",
        "",
    ]
    for label, payload in packets:
        lines.append(f"# {label}")
        lines.append("Payload: " + payload.hex())
        lines.append("")
    destination.write_text("\n".join(lines), encoding="ascii")


def recover_sections(message, enum_map):
    sections = {}
    for suffix in ("high", "low"):
        current = {
            "ca_4g_combos": decode_lte_section(message.rrc, suffix),
            "ca_5g_combos": decode_nr_section(
                message.rrc, "nr5g", suffix, enum_map
            ),
            "ca_4g_5g_combos": decode_nr_section(
                message.rrc, "lte_nr5g", suffix, enum_map
            ),
            "ca_5g_5g_combos": decode_nr_section(
                message.rrc, "nr5g_nr5g", suffix, enum_map
            ),
        }
        current = {key: value for key, value in current.items() if value}
        if current:
            sections[suffix] = current
    return sections


def read_rfcard_info(dat_name: str, input_name: str, rrc) -> dict[str, object]:
    """Recover the RFCard identifiers and embedded RRC environment names."""
    dat_match = re.search(
        r"(?:^|/)(?P<hwid>\d+)_(?P<fsid>\d+)_(?:res|cmn)\.dat$",
        dat_name,
        re.IGNORECASE,
    )
    mbn_match = re.search(
        r"rf_config_(?P<hwid>\d+)_(?P<fsid>\d+)_(?P<bid>\d+)\.mbn$",
        input_name,
        re.IGNORECASE,
    )

    hwid = int(dat_match.group("hwid")) if dat_match else None
    fsid = int(dat_match.group("fsid")) if dat_match else None
    bid = int(mbn_match.group("bid")) if mbn_match else None
    if mbn_match:
        file_hwid = int(mbn_match.group("hwid"))
        file_fsid = int(mbn_match.group("fsid"))
        if hwid is None:
            hwid = file_hwid
        if fsid is None:
            fsid = file_fsid

    env_high = str(getattr(rrc, "env_name_high", "")).strip()
    env_low = str(getattr(rrc, "env_name_low", "")).strip()
    display_name = env_high or env_low
    if not display_name and hwid is not None and fsid is not None:
        display_name = f"RFCARD_HWID{hwid}_FSID{fsid}"

    key = f"{hwid}_{fsid}" if hwid is not None and fsid is not None else None
    return {
        "name": display_name or None,
        "name_source": (
            "res.rrc.env_name_high"
            if env_high
            else "res.rrc.env_name_low"
            if env_low
            else "derived_from_hwid_fsid"
            if display_name
            else None
        ),
        "canonical_xml_variant_name": None,
        "canonical_xml_variant_name_embedded": False,
        "hwid": hwid,
        "fsid": fsid,
        "bid": bid,
        "key": key,
        "res_dat_path": dat_name,
        "environment_name_high": env_high or None,
        "environment_name_low": env_low or None,
    }


def write_xml(sections, destination: Path, card_name: str):
    root = ET.Element("ca_combo_list")
    root.append(
        ET.Comment(
            "Semantically reconstructed from compiled RRC tables; "
            "ordering, seed flags, source grouping and generated/original status are not recoverable."
        )
    )
    for suffix, typed_sections in sections.items():
        group = ET.SubElement(root, "combo_group", {"target": f"recovered_{suffix}"})
        cards = ET.SubElement(group, "cards_supported")
        ET.SubElement(cards, "card_name").text = card_name
        for section_name, combos in typed_sections.items():
            section = ET.SubElement(group, section_name)
            for text, attrs in combos:
                ET.SubElement(section, "ca_combo", attrs).text = text
    ET.indent(root)
    destination.write_bytes(
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        + ET.tostring(root, encoding="utf-8")
        + b"\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="rf_config_*.mbn or *_res.dat")
    parser.add_argument("-o", "--output", type=Path, help="output combo XML")
    parser.add_argument(
        "--diag",
        action="store_true",
        help="also write headerless 0xB0CD v41 and 0xB826 v22 hexdumps",
    )
    parser.add_argument(
        "--card-info",
        action="store_true",
        help="print RFCard identity/name information and exit",
    )
    parser.add_argument(
        "--rfpd",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--keep-dat", action="store_true", help="write extracted /rfc/*.dat files"
    )
    args = parser.parse_args()

    blob = args.input.read_bytes()
    if args.input.name.lower().endswith(".dat"):
        dat_name = args.input.name
        res_dat = blob
        dats = {dat_name: blob}
    else:
        dats = extract_rfc_dats(blob)
        res_items = [
            (name, data)
            for name, data in dats.items()
            if name.lower().endswith("_res.dat")
        ]
        if not res_items:
            raise SystemExit("No /rfc/*_res.dat Large-EFS item found in the MBN")
        if len(res_items) > 1:
            names = ", ".join(name for name, _ in res_items)
            raise SystemExit(f"More than one res DAT found; extract one explicitly: {names}")
        dat_name, res_dat = res_items[0]

    encoding, protobuf_payload, message = parse_res_dat(res_dat)
    card_info = read_rfcard_info(dat_name, args.input.name, message.rrc)
    if args.card_info:
        print(json.dumps({"rfcard": card_info}, ensure_ascii=False, indent=2))
        return 0

    enum_map = enum_assignments()
    sections = recover_sections(message, enum_map)

    output = args.output or args.input.with_name(args.input.stem + "_combos.xml")
    write_xml(
        sections,
        output,
        str(card_info["name"] or "RECOVERED_FROM_MBN"),
    )

    diag_outputs = {}
    if args.diag:
        b0cd_packets = []
        b826_packets = []
        for suffix in ("high", "low"):
            lte_packets = b0cd_v41_packets(message.rrc, suffix)
            b0cd_packets.extend(
                (f"{suffix} packet {index + 1}/{len(lte_packets)}", payload)
                for index, payload in enumerate(lte_packets)
            )

            source_sections = (
                ("NR-CA", "nr5g", 4),
                ("EN-DC", "lte_nr5g", 3),
                ("NR-DC", "nr5g_nr5g", 5),
            )
            for label, prefix, source in source_sections:
                records = nr_section_records(message.rrc, prefix, suffix)
                packets = b826_v22_packets(records, source) if records else []
                b826_packets.extend(
                    (
                        f"{suffix} {label} source={source} "
                        f"packet {index + 1}/{len(packets)}",
                        payload,
                    )
                    for index, payload in enumerate(packets)
                )

        b0cd_output = output.with_name(output.stem + "_0xB0CD_v41.txt")
        b826_output = output.with_name(output.stem + "_0xB826_v22.txt")
        write_diag_hexdump(b0cd_packets, b0cd_output)
        write_diag_hexdump(b826_packets, b826_output)
        diag_outputs = {
            "0xB0CD_v41": str(b0cd_output),
            "0xB0CD_packets": len(b0cd_packets),
            "0xB826_v22": str(b826_output),
            "0xB826_packets": len(b826_packets),
        }

    if args.keep_dat and not args.input.name.lower().endswith(".dat"):
        dat_dir = output.with_suffix("")
        dat_dir.mkdir(parents=True, exist_ok=True)
        for name, data in dats.items():
            (dat_dir / Path(name).name).write_bytes(data)

    counts = {
        cap: {kind: len(combos) for kind, combos in values.items()}
        for cap, values in sections.items()
    }
    print(
        json.dumps(
            {
                "input": str(args.input),
                "dat": dat_name,
                "dat_encoding": encoding,
                "protobuf_size": len(protobuf_payload),
                "rfcard": card_info,
                "counts": counts,
                "output": str(output),
                "diag": diag_outputs,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
