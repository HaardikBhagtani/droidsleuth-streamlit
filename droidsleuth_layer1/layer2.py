from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .apk_parser import CentralDirectoryEntry


GOVERNMENT_INDIA_KEYWORDS = {
    "pmkisan",
    "pm kisan",
    "aadhaar",
    "aadhar",
    "ekyc",
    "e-kyc",
    "digilocker",
    "umang",
    "epfo",
    "ayushman",
    "bhim",
    "kisan",
    "yojana",
}

FINANCIAL_FRAUD_KEYWORDS = {
    "bank",
    "loan",
    "upi",
    "wallet",
    "payment",
    "reward",
    "cashback",
    "credit",
    "debit",
    "account",
    "otp",
    "kyc",
}

CREDENTIAL_THEFT_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.POST_NOTIFICATIONS",
}

HIGH_RISK_API_HINTS = {
    "accessibility",
    "overlay",
    "sms",
    "telephony",
    "dynamic_loading",
    "runtime_exec",
    "package_install",
    "boot_persistence",
}


def _keyword_hits(values: list[str], keywords: set[str]) -> list[str]:
    haystacks = " ".join(value.lower() for value in values)
    return sorted(keyword for keyword in keywords if keyword in haystacks)


def _collect_name_corpus(apk_name: str, entries: list[CentralDirectoryEntry], manifest: dict) -> list[str]:
    values = [apk_name]
    values.extend(entry.filename for entry in entries)
    values.extend(manifest.get("permissions", []))
    values.extend(manifest.get("activities", []))
    values.extend(manifest.get("services", []))
    values.extend(manifest.get("receivers", []))
    values.extend(manifest.get("providers", []))
    values.extend(manifest.get("suspicious_keywords", []))
    return values


def collect_keyword_hits(
    apk_name: str,
    entries: list[CentralDirectoryEntry],
    manifest: dict,
) -> dict[str, int | list[str]]:
    name_corpus = _collect_name_corpus(apk_name, entries, manifest)
    india_govt_hits = _keyword_hits(name_corpus, GOVERNMENT_INDIA_KEYWORDS)
    financial_hits = _keyword_hits(name_corpus, FINANCIAL_FRAUD_KEYWORDS)
    return {
        "india_govt_hits": india_govt_hits,
        "financial_hits": financial_hits,
        "india_govt_keyword_count": len(india_govt_hits),
        "financial_keyword_count": len(financial_hits),
    }


def build_layer2_assessment(
    *,
    apk_name: str,
    size_bytes: int,
    entries: list[CentralDirectoryEntry],
    anomalies: dict,
    manifest: dict,
    dex: list[dict],
    static_triage: dict,
    deep_static: dict | None = None,
    signature_engine: dict | None = None,
) -> dict:
    deep_static = deep_static or {}
    signature_engine = signature_engine or {}
    permissions = set(manifest.get("permissions", []))
    dex_class_total = sum(item.get("class_count", 0) for item in dex if isinstance(item.get("class_count"), int))
    dex_string_total = sum(item.get("string_count", 0) for item in dex if isinstance(item.get("string_count"), int))
    dex_url_total = sum(item.get("url_count", 0) for item in dex if isinstance(item.get("url_count"), int))
    native_lib_count = sum(1 for entry in entries if entry.filename.endswith(".so"))
    native_arches = {
        entry.filename.split("/")[1]
        for entry in entries
        if entry.filename.startswith("lib/") and len(entry.filename.split("/")) >= 3
    }
    certificate_asset_count = static_triage["signals"]["sensitive_asset_count"]
    obfuscation_ratio = static_triage["signals"]["obfuscation_ratio"]
    randomish_filename_count = static_triage["signals"]["randomish_filename_count"]
    long_filename_count = static_triage["signals"]["very_long_filename_count"]
    unsupported_method_count = len(anomalies.get("unsupported_compression_methods", []))
    mismatch_count = len(anomalies.get("mismatched_local_vs_central_compression", []))
    recovered_entry_count = int(anomalies.get("recovered_entry_count", 0))
    sensitive_permission_count = len(permissions & CREDENTIAL_THEFT_PERMISSIONS)
    dex_error_count = sum(1 for item in dex if item.get("status") == "error")
    component_count = sum(
        len(manifest.get(section, []))
        for section in ("activities", "services", "receivers", "providers")
    )
    api_hints = sorted(
        {
            hint
            for item in dex
            for hint in item.get("api_hints", [])
            if isinstance(hint, str)
        }
    )
    high_risk_api_hint_count = len([hint for hint in api_hints if hint in HIGH_RISK_API_HINTS])

    keyword_hits = collect_keyword_hits(apk_name, entries, manifest)
    india_govt_hits = keyword_hits["india_govt_hits"]
    financial_hits = keyword_hits["financial_hits"]
    call_graph = deep_static.get("call_graph", {})
    cfg_analysis = deep_static.get("cfg_analysis", {})
    anti_analysis = deep_static.get("anti_analysis", {})
    c2_static = deep_static.get("c2_static", {})
    family_analysis = deep_static.get("family_analysis", {})
    deep_features = deep_static.get("features", {})
    signature_matches = signature_engine.get("matches", [])
    signature_score = int(signature_engine.get("score", 0))
    behavior_sequences = call_graph.get("behavioral_sequences", [])
    family_hints_from_engine = family_analysis.get("family_hints", [])

    features = {
        "size_bytes": size_bytes,
        "entry_count": len(entries),
        "dex_file_count": anomalies.get("dex_file_count", 0),
        "dex_class_total": dex_class_total,
        "dex_string_total": dex_string_total,
        "dex_error_count": dex_error_count,
        "dex_url_total": dex_url_total,
        "native_lib_count": native_lib_count,
        "native_arch_count": len(native_arches),
        "certificate_asset_count": certificate_asset_count,
        "unsupported_method_count": unsupported_method_count,
        "compression_mismatch_count": mismatch_count,
        "recovered_entry_count": recovered_entry_count,
        "multiple_eocd_records": int(bool(anomalies.get("multiple_eocd_records"))),
        "manifest_decoded": int(manifest.get("status") == "decoded"),
        "manifest_error": int(manifest.get("status") == "error"),
        "permission_count": len(permissions),
        "component_count": component_count,
        "credential_theft_permission_count": sensitive_permission_count,
        "randomish_filename_count": randomish_filename_count,
        "very_long_filename_count": long_filename_count,
        "obfuscation_ratio": obfuscation_ratio,
        "api_hint_count": len(api_hints),
        "high_risk_api_hint_count": high_risk_api_hint_count,
        "india_govt_keyword_count": len(india_govt_hits),
        "financial_keyword_count": len(financial_hits),
        "triage_score": static_triage["score"],
        "deep_behavioral_sequence_count": int(deep_features.get("behavioral_sequence_count", 0)),
        "deep_sensitive_api_total": int(deep_features.get("sensitive_api_total", 0)),
        "deep_sensitive_api_edge_hits": int(deep_features.get("sensitive_api_edge_hits", 0)),
        "reflection_usage_count": int(deep_features.get("reflection_usage_count", 0)),
        "dynamic_class_loading_count": int(deep_features.get("dynamic_class_loading_count", 0)),
        "anti_analysis_indicator_count": int(deep_features.get("anti_analysis_indicator_count", 0)),
        "anti_analysis_risk_score": int(deep_features.get("anti_analysis_risk_score", 0)),
        "c2_url_count": int(deep_features.get("c2_url_count", 0)),
        "c2_domain_count": int(deep_features.get("c2_domain_count", 0)),
        "c2_ip_count": int(deep_features.get("c2_ip_count", 0)),
        "c2_decoded_url_count": int(deep_features.get("c2_decoded_url_count", 0)),
        "c2_suspicious_network_indicator_count": int(
            deep_features.get("c2_suspicious_network_indicator_count", 0)
        ),
        "family_hint_count": int(deep_features.get("family_hint_count", 0)),
        "signature_match_count": len(signature_matches),
        "signature_score": signature_score,
    }

    malicious_score = 0
    reasons: list[str] = []
    family_hints: list[str] = []

    if unsupported_method_count:
        malicious_score += 12
        reasons.append("uses unsupported or nonstandard ZIP methods")
    if mismatch_count:
        malicious_score += 10
        reasons.append("local and central ZIP metadata disagree")
    if recovered_entry_count:
        malicious_score += min(16, 8 * recovered_entry_count)
        reasons.append("required fallback payload recovery after ZIP method inconsistencies")
    if long_filename_count:
        malicious_score += 10
        reasons.append("contains path-length anomalies")
    if certificate_asset_count:
        malicious_score += 8
        reasons.append("bundles certificate or keystore-like assets")
    if obfuscation_ratio >= 0.75:
        malicious_score += 18
        reasons.append("DEX names are heavily obfuscated")
    elif obfuscation_ratio >= 0.4:
        malicious_score += 10
        reasons.append("DEX names are moderately obfuscated")
    if randomish_filename_count >= 8:
        malicious_score += 8
        reasons.append("contains many random-looking resource or asset names")
    if manifest.get("status") == "error":
        malicious_score += 8
        reasons.append("manifest could not be decoded cleanly")
    if component_count >= 25:
        malicious_score += 8
        reasons.append("contains an unusually large Android component surface")
    elif component_count >= 10:
        malicious_score += 4
        reasons.append("contains a moderately large Android component surface")
    if sensitive_permission_count >= 3:
        malicious_score += 15
        reasons.append("requests a high-risk permission combination")
    elif sensitive_permission_count >= 1:
        malicious_score += 6
        reasons.append("requests permissions often abused by malware")
    if high_risk_api_hint_count >= 6:
        malicious_score += 22
        reasons.append("DEX strings indicate very high API risk density")
    elif high_risk_api_hint_count >= 5:
        malicious_score += 18
        reasons.append("DEX strings suggest multiple high-risk Android APIs or behaviors")
    elif high_risk_api_hint_count >= 3:
        malicious_score += 14
        reasons.append("DEX strings suggest multiple high-risk Android APIs or behaviors")
    elif high_risk_api_hint_count >= 1:
        malicious_score += 6
        reasons.append("DEX strings suggest risky Android APIs or behaviors")
    if dex_url_total >= 5:
        malicious_score += 4
        reasons.append("contains multiple embedded URLs in DEX strings")
    if static_triage["score"] >= 70:
        malicious_score += 14
        reasons.append("static triage score is already high")
    elif static_triage["score"] >= 40:
        malicious_score += 10
        reasons.append("static triage score is elevated")
    elif static_triage["score"] >= 20:
        malicious_score += 6
        reasons.append("static triage score is moderately elevated")
    if anomalies.get("multiple_eocd_records"):
        malicious_score += 12
        reasons.append("contains multiple EOCD records")
    if india_govt_hits:
        malicious_score += 8
        reasons.append("contains Indian government impersonation keywords")
        family_hints.append("government_impersonation_india")
    if financial_hits:
        malicious_score += 6
        reasons.append("contains financial or KYC themed keywords")
        family_hints.append("financial_fraud")

    if behavior_sequences:
        behavior_score = 0
        if "dropper_loader_sequence" in behavior_sequences:
            behavior_score += 8
        if "credential_exfiltration_sequence" in behavior_sequences:
            behavior_score += 8
        if "device_or_contact_exfiltration_sequence" in behavior_sequences:
            behavior_score += 8
        if "sms_or_deviceid_with_network_sequence" in behavior_sequences:
            behavior_score += 6
        if "overlay_attack_sequence" in behavior_sequences:
            overlay_backing = bool(
                {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"} <= permissions
                or financial_hits
                or "banker" in family_hints_from_engine
                or signature_score >= 15
            )
            behavior_score += 6 if overlay_backing else 2
        if behavior_score:
            malicious_score += min(18, behavior_score)
            reasons.append("deep call-graph analysis recovered suspicious behavioral sequences")
    if features["deep_sensitive_api_total"] >= 4 and (
        sensitive_permission_count >= 2
        or financial_hits
        or india_govt_hits
        or (behavior_sequences and (family_hints_from_engine or signature_score >= 15))
    ):
        malicious_score += 8
        reasons.append("deep static API analysis aligns with other suspicious evidence")
    elif features["deep_sensitive_api_total"] >= 2 and behavior_sequences and (
        family_hints_from_engine or signature_score >= 15 or financial_hits or india_govt_hits
    ):
        malicious_score += 5
        reasons.append("deep static API analysis reinforces behavioral sequences")
    if features["dynamic_class_loading_count"] and (
        unsupported_method_count or recovered_entry_count or "dropper_loader_sequence" in behavior_sequences
    ):
        malicious_score += 8
        reasons.append("control-flow analysis found dynamic code loading tied to evasive packaging or loader behavior")
    elif features["reflection_usage_count"] >= 3 and behavior_sequences:
        malicious_score += 4
        reasons.append("control-flow analysis found reflective behavior near suspicious call patterns")
    anti_analysis_context = bool(
        unsupported_method_count
        or recovered_entry_count
        or obfuscation_ratio >= 0.4
        or features["c2_decoded_url_count"]
        or features["c2_suspicious_network_indicator_count"] >= 2
        or signature_score >= 15
        or family_hints_from_engine
    )
    if (
        features["anti_analysis_indicator_count"] >= 3
        and features["anti_analysis_risk_score"] >= 25
        and anti_analysis_context
    ):
        malicious_score += min(10, 3 * features["anti_analysis_indicator_count"])
        reasons.append("static anti-analysis indicators align with stronger evasive or malicious evidence")
    elif features["anti_analysis_indicator_count"] and unsupported_method_count:
        malicious_score += 4
        reasons.append("anti-analysis indicators appear alongside evasive archive behavior")
    if features["c2_decoded_url_count"] or (
        features["c2_suspicious_network_indicator_count"] >= 2 and features["c2_url_count"]
    ):
        malicious_score += min(10, 4 + 2 * features["c2_suspicious_network_indicator_count"])
        reasons.append("static C2 extraction found suspicious or obfuscated network indicators")
    if signature_score >= 30:
        malicious_score += min(16, max(6, signature_score // 6))
        reasons.append("Layer 2.5 signature engine matched malware-oriented patterns")
    elif signature_score >= 15 and (
        unsupported_method_count
        or behavior_sequences
        or financial_hits
        or india_govt_hits
        or sensitive_permission_count >= 1
        or family_hints_from_engine
    ):
        malicious_score += 5
        reasons.append("Layer 2.5 signatures reinforce other suspicious static evidence")
    if family_hints_from_engine:
        family_hints.extend(family_hints_from_engine)
        backed_family_context = bool(
            sensitive_permission_count >= 1
            or high_risk_api_hint_count >= 3
            or static_triage["score"] >= 20
            or signature_score >= 15
            or unsupported_method_count
            or recovered_entry_count
        )
        if backed_family_context:
            if "credential_theft_overlay" in family_hints_from_engine:
                malicious_score += 12
                reasons.append("family inference detected banker-style overlay permission combination")
            if "banker" in family_hints_from_engine:
                malicious_score += 10
                reasons.append("family inference detected banker-style behavior cluster")
            if "dropper" in family_hints_from_engine or "dropper_loader" in family_hints_from_engine:
                malicious_score += 6
                reasons.append("family inference detected dropper or loader behavior cluster")
            if "spyware" in family_hints_from_engine and (
                sensitive_permission_count >= 1 or high_risk_api_hint_count >= 5
            ):
                malicious_score += 6
                reasons.append("family inference detected spyware-style monitoring capability cluster")
            if "financial_fraud" in family_hints_from_engine and (
                financial_hits or sensitive_permission_count >= 1
            ):
                malicious_score += 6
                reasons.append("family inference detected financial fraud behavior cluster")
        if family_analysis.get("family_scores", {}).get(family_analysis.get("top_family") or "", 0) >= 35:
            reasons.append("family inference aligns with known malware behavior clusters")

    if (
        high_risk_api_hint_count >= 5
        and sensitive_permission_count >= 1
        and (family_hints_from_engine or "credential_theft_overlay" in family_hints)
    ):
        malicious_score += 6
        reasons.append("permission, API, and family evidence jointly indicate credential-theft risk")
    if (
        static_triage["score"] >= 20
        and high_risk_api_hint_count >= 5
        and (signature_score >= 15 or family_hints_from_engine)
    ):
        malicious_score += 4
        reasons.append("multiple static evidence layers converge on suspicious behavior")

    if (
        obfuscation_ratio >= 0.75
        and (unsupported_method_count or long_filename_count or randomish_filename_count >= 5)
    ):
        family_hints.append("dropper_loader")

    if {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"} & permissions:
        family_hints.append("credential_theft_overlay")

    family_hints = sorted(set(family_hints))
    malicious_score = min(malicious_score, 100)
    malicious_probability = round(malicious_score / 100.0, 3)
    confidence = round(0.5 + (abs(malicious_score - 50) / 100.0), 3)
    label = "malicious" if malicious_score >= 47 else "non_malicious"

    if label == "non_malicious" and static_triage["score"] == 0 and not family_hints:
        reasons.append("no strong malicious indicators were recovered from current static features")

    return {
        "features": features,
        "classification": {
            "label": label,
            "malicious_probability": malicious_probability,
            "confidence": min(confidence, 0.99),
            "reasons": reasons,
            "family_hints": family_hints,
            "api_hints": api_hints,
            "native_arches": sorted(native_arches),
            "behavioral_sequences": behavior_sequences,
            "signature_rule_ids": [match["rule_id"] for match in signature_matches],
            "top_family": family_analysis.get("top_family"),
        },
    }
