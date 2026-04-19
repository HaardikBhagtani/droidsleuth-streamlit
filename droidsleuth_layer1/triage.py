from __future__ import annotations

import math
import re
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .apk_parser import CentralDirectoryEntry


SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_PHONE_STATE",
}

SENSITIVE_FILE_HINTS = (
    ".p12",
    ".bks",
    ".keystore",
    ".pem",
    ".der",
    ".crt",
    ".cer",
)

RANDOM_TOKEN = re.compile(r"^[A-Za-z0-9]{10,}$")


def _is_randomish_segment(segment: str) -> bool:
    if len(segment) < 10:
        return False
    base = segment.rsplit(".", 1)[0]
    if not RANDOM_TOKEN.fullmatch(base):
        return False
    letters = sum(ch.isalpha() for ch in base)
    digits = sum(ch.isdigit() for ch in base)
    vowels = sum(ch.lower() in "aeiou" for ch in base)
    if letters == 0:
        return False
    if digits > 0:
        return True
    if base.islower():
        return False
    if base[:1].isupper() and base[1:].islower():
        return False
    return vowels <= max(2, len(base) // 4) and len(set(base.lower())) > max(6, len(base) // 3)


def _class_name_obfuscation_ratio(dex: list[dict]) -> tuple[float, int]:
    sample_count = 0
    suspicious_count = 0
    for dex_entry in dex:
        for class_name in dex_entry.get("class_names", []):
            sample_count += 1
            descriptor = class_name.strip("L;")
            parts = [part for part in descriptor.split("/") if part]
            if not parts:
                continue
            bad_parts = 0
            for part in parts:
                base = part.split("$", 1)[0]
                if len(base) >= 10 and (base.lower() == base or _is_randomish_segment(base)):
                    bad_parts += 1
            if bad_parts >= max(1, math.ceil(len(parts) / 2)):
                suspicious_count += 1
    if sample_count == 0:
        return 0.0, 0
    return suspicious_count / sample_count, sample_count


def build_static_triage(
    *,
    apk_name: str,
    size_bytes: int,
    entries: list[CentralDirectoryEntry],
    anomalies: dict,
    manifest: dict,
    dex: list[dict],
) -> dict:
    reasons: list[str] = []
    score = 0

    long_names = [entry.filename for entry in entries if len(entry.filename) >= 180]
    randomish_names = []
    for entry in entries:
        segments = [segment for segment in entry.filename.split("/") if segment]
        if any(_is_randomish_segment(segment) for segment in segments):
            randomish_names.append(entry.filename)

    sensitive_assets = [
        entry.filename for entry in entries if entry.filename.lower().endswith(SENSITIVE_FILE_HINTS)
    ]

    if anomalies.get("multiple_eocd_records"):
        score += 20
        reasons.append("multiple EOCD records detected")
    if anomalies.get("mismatched_local_vs_central_compression"):
        score += 20
        reasons.append("local and central compression metadata do not match")
    if anomalies.get("unsupported_compression_methods"):
        score += 15
        reasons.append("nonstandard ZIP compression methods present")
    if anomalies.get("recovered_entry_count"):
        score += min(20, 8 * int(anomalies["recovered_entry_count"]))
        reasons.append("payload recovery required fallback extraction after ZIP method issues")
    if anomalies.get("suspicious_filenames"):
        score += 15
        reasons.append("APK name or file paths reference PM Kisan, Aadhaar, or eKYC terms")
    if long_names:
        score += 15
        reasons.append("contains extremely long path names that may stress ZIP/APK tooling")
    if len(randomish_names) >= 25:
        score += 20
        reasons.append("contains many random-looking filenames or resource paths")
    elif len(randomish_names) >= 8:
        score += 10
        reasons.append("contains several random-looking filenames or resource paths")
    if sensitive_assets:
        score += 10
        reasons.append("bundles certificate or keystore-like assets")

    if manifest.get("status") == "decoded":
        permissions = set(manifest.get("permissions", []))
        risky = sorted(permissions & SENSITIVE_PERMISSIONS)
        if risky:
            score += min(20, 4 * len(risky))
            reasons.append("requests sensitive Android permissions")
    elif manifest.get("status") == "error":
        score += 10
        reasons.append("manifest could not be extracted cleanly")

    obfuscation_ratio, sampled_classes = _class_name_obfuscation_ratio(dex)
    if sampled_classes >= 10 and obfuscation_ratio >= 0.75:
        score += 20
        reasons.append("DEX class names appear heavily obfuscated")
    elif sampled_classes >= 10 and obfuscation_ratio >= 0.4:
        score += 10
        reasons.append("DEX class names show moderate obfuscation")

    entry_extensions = Counter(
        entry.filename.rsplit(".", 1)[-1].lower() if "." in entry.filename else "<none>" for entry in entries
    )

    verdict = "low"
    if score >= 60:
        verdict = "high"
    elif score >= 30:
        verdict = "medium"

    return {
        "verdict": verdict,
        "score": min(score, 100),
        "reasons": reasons,
        "signals": {
            "apk_name": apk_name,
            "size_bytes": size_bytes,
            "randomish_filename_count": len(randomish_names),
            "very_long_filename_count": len(long_names),
            "sensitive_asset_count": len(sensitive_assets),
            "sampled_class_name_count": sampled_classes,
            "obfuscation_ratio": round(obfuscation_ratio, 3),
            "top_extensions": entry_extensions.most_common(10),
        },
        "examples": {
            "randomish_filenames": randomish_names[:5],
            "very_long_filenames": long_names[:3],
            "sensitive_assets": sensitive_assets[:5],
        },
    }
