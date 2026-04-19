from __future__ import annotations

import re
import struct
from dataclasses import dataclass


class DexParseError(Exception):
    """Raised when a DEX file cannot be parsed."""


API_HINT_PATTERNS = {
    "accessibility": ("AccessibilityService", "BIND_ACCESSIBILITY_SERVICE"),
    "overlay": ("SYSTEM_ALERT_WINDOW", "WindowManager", "TYPE_APPLICATION_OVERLAY"),
    "sms": ("SmsManager", "READ_SMS", "RECEIVE_SMS", "SEND_SMS"),
    "telephony": ("TelephonyManager", "getDeviceId", "getSubscriberId", "READ_PHONE_STATE"),
    "dynamic_loading": ("DexClassLoader", "PathClassLoader", "loadClass"),
    "webview": ("WebView", "loadUrl", "addJavascriptInterface"),
    "runtime_exec": ("Runtime;->exec", "ProcessBuilder", "/system/bin/sh", "su", "magisk"),
    "package_install": ("PackageInstaller", "REQUEST_INSTALL_PACKAGES", "ACTION_INSTALL_PACKAGE"),
    "boot_persistence": ("BOOT_COMPLETED", "RECEIVE_BOOT_COMPLETED"),
}

URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,}")
ANTI_ANALYSIS_TOKENS = (
    "goldfish",
    "genymotion",
    "qemu",
    "frida",
    "xposed",
    "magisk",
    "isdebuggerconnected",
    "test-keys",
    "supersu",
    "busybox",
    "zygisk",
    "riru",
)


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    cursor = offset
    while True:
        if cursor >= len(data):
            raise DexParseError("Unexpected end of data while reading ULEB128")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, cursor
        shift += 7
        if shift > 35:
            raise DexParseError("ULEB128 too large")


def _read_c_string(data: bytes, offset: int) -> tuple[bytes, int]:
    end = offset
    while end < len(data) and data[end] != 0:
        end += 1
    if end >= len(data):
        raise DexParseError("Missing string terminator")
    return data[offset:end], end + 1


@dataclass
class DexSummary:
    filename: str
    version: str
    class_count: int
    class_names: list[str]
    string_count: int
    sampled_strings: list[str]
    anti_analysis_strings: list[str]
    api_hints: list[str]
    url_count: int


class DexParser:
    """Minimal DEX parser for string and class recovery."""

    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 112:
            raise DexParseError("DEX payload is too small")
        if not data.startswith(b"dex\n"):
            raise DexParseError("Not a DEX file")

    def summarize(self, filename: str, preview_limit: int = 25) -> DexSummary:
        version = self.data[4:7].decode("ascii", errors="replace")
        string_ids_size, string_ids_off = struct.unpack_from("<II", self.data, 56)
        type_ids_size, type_ids_off = struct.unpack_from("<II", self.data, 64)
        class_defs_size, class_defs_off = struct.unpack_from("<II", self.data, 96)

        strings = self._read_strings(string_ids_size, string_ids_off)
        types = self._read_types(type_ids_size, type_ids_off, strings)
        classes = self._read_classes(class_defs_size, class_defs_off, types)
        sampled_strings = self._sample_strings(strings, preview_limit)
        anti_analysis_strings = self._collect_anti_analysis_strings(strings, preview_limit)
        api_hints = self._collect_api_hints(strings)
        url_count = self._count_urls(strings)

        return DexSummary(
            filename=filename,
            version=version,
            class_count=len(classes),
            class_names=classes[:preview_limit],
            string_count=len(strings),
            sampled_strings=sampled_strings,
            anti_analysis_strings=anti_analysis_strings,
            api_hints=api_hints,
            url_count=url_count,
        )

    def _read_strings(self, size: int, offset: int) -> list[str]:
        strings: list[str] = []
        for index in range(size):
            item_offset = offset + (index * 4)
            if item_offset + 4 > len(self.data):
                raise DexParseError("String ID table exceeds file size")
            (string_data_off,) = struct.unpack_from("<I", self.data, item_offset)
            _, cursor = _read_uleb128(self.data, string_data_off)
            raw, _ = _read_c_string(self.data, cursor)
            strings.append(raw.decode("utf-8", errors="replace"))
        return strings

    def _read_types(self, size: int, offset: int, strings: list[str]) -> list[str]:
        types: list[str] = []
        for index in range(size):
            item_offset = offset + (index * 4)
            if item_offset + 4 > len(self.data):
                raise DexParseError("Type ID table exceeds file size")
            (descriptor_idx,) = struct.unpack_from("<I", self.data, item_offset)
            try:
                types.append(strings[descriptor_idx])
            except IndexError as exc:
                raise DexParseError("Type descriptor index out of range") from exc
        return types

    def _read_classes(self, size: int, offset: int, types: list[str]) -> list[str]:
        classes: list[str] = []
        class_def_size = 32
        for index in range(size):
            item_offset = offset + (index * class_def_size)
            if item_offset + class_def_size > len(self.data):
                raise DexParseError("Class definition table exceeds file size")
            class_idx = struct.unpack_from("<I", self.data, item_offset)[0]
            try:
                classes.append(types[class_idx])
            except IndexError as exc:
                raise DexParseError("Class index out of range") from exc
        return classes

    def _sample_strings(self, strings: list[str], limit: int) -> list[str]:
        samples: list[str] = []
        for value in strings:
            lowered = value.lower()
            if (
                "http://" in lowered
                or "https://" in lowered
                or "accessibility" in lowered
                or "sms" in lowered
                or "telephony" in lowered
                or "dexclassloader" in lowered
                or "packageinstaller" in lowered
                or "boot_completed" in lowered
                or "overlay" in lowered
            ):
                samples.append(value[:160])
            if len(samples) >= limit:
                break
        return samples

    def _collect_api_hints(self, strings: list[str]) -> list[str]:
        haystack = "\n".join(strings)
        hits = []
        for label, patterns in API_HINT_PATTERNS.items():
            if any(pattern in haystack for pattern in patterns):
                hits.append(label)
        return sorted(hits)

    def _collect_anti_analysis_strings(self, strings: list[str], limit: int) -> list[str]:
        hits: list[str] = []
        for value in strings:
            lowered = value.lower()
            if any(token in lowered for token in ANTI_ANALYSIS_TOKENS):
                hits.append(value[:200])
            if len(hits) >= limit:
                break
        return hits

    def _count_urls(self, strings: list[str]) -> int:
        count = 0
        for value in strings:
            if URL_RE.search(value.encode("utf-8", errors="ignore")):
                count += 1
        return count
