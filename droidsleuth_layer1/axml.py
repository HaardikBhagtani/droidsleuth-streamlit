from __future__ import annotations

import struct
from dataclasses import dataclass


class AxmlParseError(Exception):
    """Raised when binary Android XML cannot be parsed."""


UTF8_FLAG = 0x00000100
CHUNK_XML = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_XML_RESOURCE_MAP = 0x0180
CHUNK_XML_START_NAMESPACE = 0x0100
CHUNK_XML_START_ELEMENT = 0x0102
TYPE_STRING = 0x03
ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class ManifestSummary:
    package_name: str | None
    version_code: str | None
    version_name: str | None
    permissions: list[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]
    suspicious_keywords: list[str]


class StringPool:
    def __init__(self, strings: list[str]):
        self.strings = strings

    def get(self, index: int) -> str | None:
        if index == 0xFFFFFFFF:
            return None
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return None


def _read_utf8_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise AxmlParseError("String pool UTF-8 length is out of bounds")
    first = data[offset]
    offset += 1
    if first & 0x80:
        if offset >= len(data):
            raise AxmlParseError("String pool UTF-8 continuation is out of bounds")
        second = data[offset]
        offset += 1
        return ((first & 0x7F) << 7) | second, offset
    return first, offset


def _read_utf16_length(data: bytes, offset: int) -> tuple[int, int]:
    try:
        (first,) = struct.unpack_from("<H", data, offset)
    except struct.error as exc:
        raise AxmlParseError("String pool UTF-16 length is out of bounds") from exc
    offset += 2
    if first & 0x8000:
        try:
            (second,) = struct.unpack_from("<H", data, offset)
        except struct.error as exc:
            raise AxmlParseError("String pool UTF-16 continuation is out of bounds") from exc
        offset += 2
        return ((first & 0x7FFF) << 16) | second, offset
    return first, offset


def _parse_string_pool(data: bytes, offset: int) -> tuple[StringPool, int]:
    try:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    except struct.error as exc:
        raise AxmlParseError("String pool header is truncated") from exc
    if chunk_type != CHUNK_STRING_POOL:
        raise AxmlParseError("Expected string pool chunk")
    if offset + chunk_size > len(data):
        raise AxmlParseError("String pool chunk exceeds manifest size")

    try:
        string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<IIIII", data, offset + 8
        )
    except struct.error as exc:
        raise AxmlParseError("String pool metadata is truncated") from exc
    is_utf8 = bool(flags & UTF8_FLAG)
    strings_offset = offset + strings_start
    offsets_base = offset + header_size
    strings: list[str] = []

    for index in range(string_count):
        try:
            (string_offset,) = struct.unpack_from("<I", data, offsets_base + (index * 4))
        except struct.error as exc:
            raise AxmlParseError("String pool offsets table is truncated") from exc
        cursor = strings_offset + string_offset
        if cursor >= len(data):
            raise AxmlParseError("String pool entry offset exceeds manifest size")
        if is_utf8:
            _, cursor = _read_utf8_length(data, cursor)
            byte_len, cursor = _read_utf8_length(data, cursor)
            raw = data[cursor : cursor + byte_len]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            char_len, cursor = _read_utf16_length(data, cursor)
            raw = data[cursor : cursor + (char_len * 2)]
            strings.append(raw.decode("utf-16le", errors="replace"))

    if style_count and styles_start == 0:
        raise AxmlParseError("Invalid string pool styles section")

    return StringPool(strings), offset + chunk_size


def _coerce_typed_value(data_type: int, data_value: int, raw_value: str | None, pool: StringPool) -> str | None:
    if raw_value is not None:
        return raw_value
    if data_type == TYPE_STRING:
        return pool.get(data_value)
    if data_type == 0x10:
        return str(data_value)
    if data_type == 0x12:
        return "true" if data_value else "false"
    if data_type == 0x11:
        return hex(data_value)
    return None


def parse_manifest(data: bytes) -> ManifestSummary:
    if len(data) < 8:
        raise AxmlParseError("Manifest is too small")

    try:
        chunk_type, header_size, file_size = struct.unpack_from("<HHI", data, 0)
    except struct.error as exc:
        raise AxmlParseError("Manifest header is truncated") from exc
    if chunk_type != CHUNK_XML:
        raise AxmlParseError("Not a binary Android XML document")
    if file_size > len(data):
        raise AxmlParseError("Manifest chunk size exceeds file size")

    cursor = header_size
    pool, cursor = _parse_string_pool(data, cursor)
    namespace_map: dict[int, str] = {}
    package_name = None
    version_code = None
    version_name = None
    permissions: list[str] = []
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    providers: list[str] = []
    keyword_hits: set[str] = set()
    keywords = ("pmkisan", "pm kisan", "aadhaar", "aadhar", "ekyc", "kisan", "yojana")

    while cursor + 8 <= len(data):
        try:
            chunk_type, _chunk_header_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
        except struct.error as exc:
            raise AxmlParseError("Manifest chunk header is truncated") from exc
        if chunk_size == 0:
            raise AxmlParseError("Invalid chunk size in manifest")
        if cursor + chunk_size > len(data):
            raise AxmlParseError("Manifest chunk exceeds file size")

        if chunk_type == CHUNK_XML_RESOURCE_MAP:
            cursor += chunk_size
            continue

        if chunk_type == CHUNK_XML_START_NAMESPACE:
            try:
                _, _, _, _line_no, prefix_idx, uri_idx = struct.unpack_from("<HHIIII", data, cursor)
            except struct.error as exc:
                raise AxmlParseError("Manifest namespace chunk is truncated") from exc
            uri = pool.get(uri_idx)
            if uri is not None:
                namespace_map[prefix_idx] = uri
        elif chunk_type == CHUNK_XML_START_ELEMENT:
            try:
                _, _, namespace_idx, name_idx = struct.unpack_from("<IIII", data, cursor + 8)
                attr_start, attr_size, attr_count, _, _, _ = struct.unpack_from("<HHHHHH", data, cursor + 24)
            except struct.error as exc:
                raise AxmlParseError("Manifest start-element chunk is truncated") from exc
            _ = namespace_idx
            tag_name = pool.get(name_idx)
            if tag_name is None:
                cursor += chunk_size
                continue

            attrs: dict[str, str] = {}
            attr_cursor = cursor + 16 + attr_start
            for _ in range(attr_count):
                try:
                    ns_idx, attr_name_idx, raw_value_idx = struct.unpack_from("<III", data, attr_cursor)
                    _, _, typed_type = struct.unpack_from("<HBB", data, attr_cursor + 12)
                    typed_data = struct.unpack_from("<I", data, attr_cursor + 16)[0]
                except struct.error as exc:
                    raise AxmlParseError("Manifest attribute block is truncated") from exc
                attr_name = pool.get(attr_name_idx)
                if attr_name is None:
                    attr_name = pool.get(ns_idx)
                raw_value = pool.get(raw_value_idx)
                value = _coerce_typed_value(typed_type, typed_data, raw_value, pool)
                ns_name = namespace_map.get(ns_idx)
                if attr_name and value is not None:
                    qualified = f"{ns_name}:{attr_name}" if ns_name else attr_name
                    attrs[qualified] = value
                    lowered = value.lower()
                    for keyword in keywords:
                        if keyword in lowered:
                            keyword_hits.add(keyword)
                attr_cursor += attr_size if attr_size else 20

            if tag_name == "manifest":
                package_name = attrs.get("package")
                version_code = attrs.get(f"{ANDROID_NS}:versionCode")
                version_name = attrs.get(f"{ANDROID_NS}:versionName")
            elif tag_name in {"uses-permission", "uses-permission-sdk-23"}:
                name = attrs.get(f"{ANDROID_NS}:name") or attrs.get("name")
                if name:
                    permissions.append(name)
            elif tag_name == "activity":
                name = attrs.get(f"{ANDROID_NS}:name") or attrs.get("name")
                if name:
                    activities.append(name)
            elif tag_name == "service":
                name = attrs.get(f"{ANDROID_NS}:name") or attrs.get("name")
                if name:
                    services.append(name)
            elif tag_name == "receiver":
                name = attrs.get(f"{ANDROID_NS}:name") or attrs.get("name")
                if name:
                    receivers.append(name)
            elif tag_name == "provider":
                name = attrs.get(f"{ANDROID_NS}:name") or attrs.get("name")
                if name:
                    providers.append(name)

        cursor += chunk_size
        if cursor >= file_size:
            break

    return ManifestSummary(
        package_name=package_name,
        version_code=version_code,
        version_name=version_name,
        permissions=sorted(set(permissions)),
        activities=sorted(set(activities)),
        services=sorted(set(services)),
        receivers=sorted(set(receivers)),
        providers=sorted(set(providers)),
        suspicious_keywords=sorted(keyword_hits),
    )
