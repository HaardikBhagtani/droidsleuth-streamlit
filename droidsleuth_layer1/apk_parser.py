from __future__ import annotations

import binascii
import json
import struct
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

from .axml import AxmlParseError, parse_manifest
from .deep_static import build_deep_static_intelligence
from .dex import DexParseError, DexParser
from .layer2 import build_layer2_assessment, collect_keyword_hits
from .signature_engine import run_signature_engine
from .triage import build_static_triage


class ApkAnalysisError(Exception):
    """Raised when an APK cannot be analyzed."""


EOCD_SIGNATURE = 0x06054B50
CD_SIGNATURE = 0x02014B50
LOCAL_SIGNATURE = 0x04034B50


@dataclass
class CentralDirectoryEntry:
    filename: str
    local_header_offset: int
    compression_method: int
    compressed_size: int
    uncompressed_size: int
    crc32: str
    flag_bits: int
    local_compression_method: int | None = None
    local_name_length: int | None = None
    local_extra_length: int | None = None


class ApkAnalyzer:
    """Central-directory-first APK analyzer."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            raise ApkAnalysisError(f"APK not found: {self.path}")
        self.data = self.path.read_bytes()
        self._recovery_notes: list[dict[str, int | str]] = []

    def analyze(self) -> dict:
        self._recovery_notes = []
        eocd_offset = self._find_eocd()
        entries = self._parse_central_directory(eocd_offset)
        anomalies = self._detect_anomalies(entries, eocd_offset)
        manifest = self._extract_manifest(entries)
        dex = self._extract_dex(entries)
        anomalies["extraction_recoveries"] = list(self._recovery_notes)
        anomalies["recovered_entry_count"] = len(self._recovery_notes)
        anomalies["badpack_suspected"] = bool(
            self._recovery_notes
            or anomalies.get("mismatched_local_vs_central_compression")
            or anomalies.get("unsupported_compression_methods")
        )
        static_triage = build_static_triage(
            apk_name=self.path.name,
            size_bytes=len(self.data),
            entries=entries,
            anomalies=anomalies,
            manifest=manifest,
            dex=dex,
        )
        keyword_hits = collect_keyword_hits(self.path.name, entries, manifest)
        deep_static = build_deep_static_intelligence(
            apk_path=self.path,
            anomalies=anomalies,
            manifest=manifest,
            dex=dex,
            entries=entries,
            static_triage=static_triage,
            keyword_hits=keyword_hits,
        )
        signature_engine = run_signature_engine(
            anomalies=anomalies,
            manifest=manifest,
            dex=dex,
            static_triage=static_triage,
            call_graph=deep_static.get("call_graph", {}),
            cfg_analysis=deep_static.get("cfg_analysis", {}),
            anti_analysis=deep_static.get("anti_analysis", {}),
            c2_static=deep_static.get("c2_static", {}),
            family_analysis=deep_static.get("family_analysis", {}),
            keyword_hits=keyword_hits,
        )
        return {
            "file": str(self.path),
            "size_bytes": len(self.data),
            "apk_name": self.path.name,
            "entry_count": len(entries),
            "entries": [asdict(entry) for entry in entries],
            "anomalies": anomalies,
            "manifest": manifest,
            "dex": dex,
            "static_triage": static_triage,
            "layer2_deep_static": deep_static,
            "layer25_signatures": signature_engine,
            "layer2": build_layer2_assessment(
                apk_name=self.path.name,
                size_bytes=len(self.data),
                entries=entries,
                anomalies=anomalies,
                manifest=manifest,
                dex=dex,
                static_triage=static_triage,
                deep_static=deep_static,
                signature_engine=signature_engine,
            ),
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.analyze(), indent=indent, ensure_ascii=True)

    def _find_eocd(self) -> int:
        start = max(0, len(self.data) - (22 + 65535))
        tail = self.data[start:]
        matches = []
        for index in range(len(tail) - 3):
            if struct.unpack_from("<I", tail, index)[0] == EOCD_SIGNATURE:
                matches.append(start + index)
        if not matches:
            raise ApkAnalysisError("End of central directory record not found")
        return matches[-1]

    def _parse_central_directory(self, eocd_offset: int) -> list[CentralDirectoryEntry]:
        eocd = self.data[eocd_offset : eocd_offset + 22]
        if len(eocd) < 22:
            raise ApkAnalysisError("EOCD record is truncated")

        _, _, _, _, total_records, cd_size, cd_offset, _ = struct.unpack("<IHHHHIIH", eocd)
        entries: list[CentralDirectoryEntry] = []
        cursor = cd_offset
        end = cd_offset + cd_size

        while cursor < end:
            if cursor + 46 > len(self.data):
                raise ApkAnalysisError("Central directory is truncated")
            signature = struct.unpack_from("<I", self.data, cursor)[0]
            if signature != CD_SIGNATURE:
                raise ApkAnalysisError(f"Invalid central directory signature at offset {cursor}")

            (
                _sig,
                _version_made_by,
                _version_needed,
                flag_bits,
                compression_method,
                _mod_time,
                _mod_date,
                crc32,
                compressed_size,
                uncompressed_size,
                name_length,
                extra_length,
                comment_length,
                _disk_start,
                _internal_attr,
                _external_attr,
                local_header_offset,
            ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", self.data, cursor)

            name_start = cursor + 46
            name_end = name_start + name_length
            filename = self.data[name_start:name_end].decode("utf-8", errors="replace")
            local_meta = self._read_local_header(local_header_offset)
            entries.append(
                CentralDirectoryEntry(
                    filename=filename,
                    local_header_offset=local_header_offset,
                    compression_method=compression_method,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    crc32=f"{crc32:08x}",
                    flag_bits=flag_bits,
                    local_compression_method=local_meta.get("compression_method"),
                    local_name_length=local_meta.get("name_length"),
                    local_extra_length=local_meta.get("extra_length"),
                )
            )
            cursor = name_end + extra_length + comment_length

        if total_records and total_records != len(entries):
            raise ApkAnalysisError(
                f"Central directory entry mismatch: expected {total_records}, parsed {len(entries)}"
            )
        return entries

    def _read_local_header(self, offset: int) -> dict[str, int | None]:
        if offset + 30 > len(self.data):
            return {"compression_method": None, "name_length": None, "extra_length": None}
        signature = struct.unpack_from("<I", self.data, offset)[0]
        if signature != LOCAL_SIGNATURE:
            return {"compression_method": None, "name_length": None, "extra_length": None}

        (
            _sig,
            _version_needed,
            _flag_bits,
            compression_method,
            _mod_time,
            _mod_date,
            _crc32,
            _compressed_size,
            _uncompressed_size,
            name_length,
            extra_length,
        ) = struct.unpack_from("<IHHHHHIIIHH", self.data, offset)

        return {
            "compression_method": compression_method,
            "name_length": name_length,
            "extra_length": extra_length,
        }

    def _detect_anomalies(self, entries: list[CentralDirectoryEntry], eocd_offset: int) -> dict:
        eocd_hits = 0
        for index in range(len(self.data) - 3):
            if struct.unpack_from("<I", self.data, index)[0] == EOCD_SIGNATURE:
                eocd_hits += 1

        mismatched_headers = []
        unsupported_methods = []
        suspicious_names = []
        for entry in entries:
            if (
                entry.local_compression_method is not None
                and entry.local_compression_method != entry.compression_method
            ):
                mismatched_headers.append(entry.filename)
            if entry.compression_method not in (0, 8):
                unsupported_methods.append(
                    {"filename": entry.filename, "compression_method": entry.compression_method}
                )
            lowered = entry.filename.lower()
            if "pmkisan" in lowered or "aadhaar" in lowered or "ekyc" in lowered:
                suspicious_names.append(entry.filename)

        return {
            "selected_eocd_offset": eocd_offset,
            "multiple_eocd_records": eocd_hits > 1,
            "mismatched_local_vs_central_compression": mismatched_headers,
            "unsupported_compression_methods": unsupported_methods,
            "suspicious_filenames": sorted(set(suspicious_names)),
            "has_android_manifest": any(entry.filename == "AndroidManifest.xml" for entry in entries),
            "dex_file_count": sum(1 for entry in entries if entry.filename.endswith(".dex")),
        }

    def _extract_manifest(self, entries: list[CentralDirectoryEntry]) -> dict:
        manifest_entry = next((entry for entry in entries if entry.filename == "AndroidManifest.xml"), None)
        if manifest_entry is None:
            return {"status": "missing"}

        try:
            manifest_bytes = self._extract_entry_bytes(manifest_entry)
        except ApkAnalysisError as exc:
            return {"status": "error", "error": str(exc)}

        try:
            summary = parse_manifest(manifest_bytes)
        except AxmlParseError as exc:
            return {
                "status": "raw_only",
                "error": str(exc),
                "size_bytes": len(manifest_bytes),
                "crc32": f"{binascii.crc32(manifest_bytes) & 0xFFFFFFFF:08x}",
            }

        result = asdict(summary)
        result["status"] = "decoded"
        result["size_bytes"] = len(manifest_bytes)
        result["crc32"] = f"{binascii.crc32(manifest_bytes) & 0xFFFFFFFF:08x}"
        return result

    def _extract_dex(self, entries: list[CentralDirectoryEntry]) -> list[dict]:
        results = []
        dex_entries = [entry for entry in entries if entry.filename.endswith(".dex")]
        for entry in dex_entries:
            try:
                dex_bytes = self._extract_entry_bytes(entry)
                results.append(asdict(DexParser(dex_bytes).summarize(entry.filename)))
            except (ApkAnalysisError, DexParseError) as exc:
                results.append({"filename": entry.filename, "status": "error", "error": str(exc)})
        return results

    def _extract_entry_bytes(self, entry: CentralDirectoryEntry) -> bytes:
        offset = entry.local_header_offset
        if offset + 30 > len(self.data):
            raise ApkAnalysisError(f"Local header for {entry.filename} is truncated")

        signature = struct.unpack_from("<I", self.data, offset)[0]
        if signature != LOCAL_SIGNATURE:
            raise ApkAnalysisError(f"Invalid local header signature for {entry.filename}")

        (
            _sig,
            _version_needed,
            _flag_bits,
            _local_method,
            _mod_time,
            _mod_date,
            _crc32,
            _compressed_size,
            _uncompressed_size,
            name_length,
            extra_length,
        ) = struct.unpack_from("<IHHHHHIIIHH", self.data, offset)

        data_start = offset + 30 + name_length + extra_length
        data_end = data_start + entry.compressed_size
        if data_end > len(self.data):
            raise ApkAnalysisError(f"Compressed payload for {entry.filename} is truncated")

        raw = self.data[data_start:data_end]
        methods = [entry.compression_method]
        if (
            entry.local_compression_method is not None
            and entry.local_compression_method != entry.compression_method
        ):
            methods.append(entry.local_compression_method)
        for fallback in (8, 0):
            if fallback not in methods:
                methods.append(fallback)

        errors: list[str] = []
        for index, method in enumerate(methods):
            if method == 0:
                if index > 0:
                    self._record_recovery(entry, "stored_fallback", entry.compression_method, method)
                return raw
            if method == 8:
                try:
                    payload = zlib.decompress(raw, -15)
                except zlib.error as exc:
                    errors.append(f"deflate failed: {exc}")
                    continue
                if index > 0:
                    self._record_recovery(entry, "deflate_fallback", entry.compression_method, method)
                return payload
            errors.append(f"unsupported method {method}")

        raise ApkAnalysisError(
            f"Unable to recover {entry.filename}; attempted methods {methods}: {'; '.join(errors)}"
        )

    def _record_recovery(
        self,
        entry: CentralDirectoryEntry,
        strategy: str,
        central_method: int,
        recovered_method: int,
    ) -> None:
        note = {
            "filename": entry.filename,
            "strategy": strategy,
            "central_method": central_method,
            "local_method": entry.local_compression_method if entry.local_compression_method is not None else -1,
            "recovered_method": recovered_method,
        }
        if note not in self._recovery_notes:
            self._recovery_notes.append(note)
