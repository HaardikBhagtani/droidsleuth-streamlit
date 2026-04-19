from __future__ import annotations


def infer_malware_families(
    *,
    permissions: set[str],
    layer2_features: dict,
    call_graph: dict,
    cfg_analysis: dict,
    anti_analysis: dict,
    c2_static: dict,
    keyword_hits: dict,
) -> dict:
    sms_permissions = {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
    }
    surveillance_permissions = {
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_FINE_LOCATION",
    }
    scores: dict[str, int] = {
        "banker": 0,
        "spyware": 0,
        "dropper": 0,
        "government_impersonation_india": 0,
    }
    reasons: dict[str, list[str]] = {family: [] for family in scores}

    sequences = set(call_graph.get("behavioral_sequences", []))
    sensitive_api_counts = call_graph.get("sensitive_api_counts", {})
    anti_features = anti_analysis.get("features", {})
    c2_features = c2_static.get("features", {})
    overlay_permission_pair = {
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
    } <= permissions
    banker_context = bool(
        keyword_hits.get("financial_keyword_count", 0)
        or permissions & sms_permissions
        or sensitive_api_counts.get("sms", 0)
        or sensitive_api_counts.get("telephony_id", 0)
        or c2_features.get("decoded_url_count", 0)
        or c2_features.get("suspicious_network_indicator_count", 0) >= 2
    )

    if overlay_permission_pair:
        scores["banker"] += 20
        reasons["banker"].append("overlay plus accessibility permission pair present")
    if "overlay_attack_sequence" in sequences and (overlay_permission_pair or banker_context):
        scores["banker"] += 25
        reasons["banker"].append("call graph suggests overlay abuse with fraud-oriented context")
    if (permissions & sms_permissions and sensitive_api_counts.get("sms", 0)) or keyword_hits.get("financial_keyword_count", 0):
        scores["banker"] += 15
        reasons["banker"].append("financial or OTP/SMS behavior present")
    if c2_features.get("decoded_url_count", 0) or (
        c2_features.get("url_count", 0) and c2_features.get("suspicious_network_indicator_count", 0)
    ):
        scores["banker"] += 10
        reasons["banker"].append("network endpoints embedded in APK")

    if (permissions & surveillance_permissions) and (
        sensitive_api_counts.get("telephony_id", 0) or sensitive_api_counts.get("contacts", 0)
    ):
        scores["spyware"] += 20
        reasons["spyware"].append("device or contact collection APIs present")
    if "device_or_contact_exfiltration_sequence" in sequences or "credential_exfiltration_sequence" in sequences:
        scores["spyware"] += 20
        reasons["spyware"].append("call graph suggests exfiltration behavior")
    if anti_features.get("anti_analysis_indicator_count", 0) >= 2 and c2_features.get("suspicious_network_indicator_count", 0):
        scores["spyware"] += 10
        reasons["spyware"].append("anti-analysis behavior often associated with surveillance malware")
    if c2_features.get("decoded_url_count", 0) or (
        c2_features.get("url_count", 0) and c2_features.get("suspicious_network_indicator_count", 0) >= 2
    ):
        scores["spyware"] += 10
        reasons["spyware"].append("suspicious static C2 indicators present")

    if (
        sensitive_api_counts.get("dynamic_loading", 0)
        or cfg_analysis["features"].get("dynamic_class_loading_count", 0)
    ) and (
        "dropper_loader_sequence" in sequences
        or layer2_features.get("unsupported_method_count", 0)
        or layer2_features.get("recovered_entry_count", 0)
    ):
        scores["dropper"] += 25
        reasons["dropper"].append("dynamic class loading behavior present")
    if "dropper_loader_sequence" in sequences:
        scores["dropper"] += 25
        reasons["dropper"].append("call graph suggests staged payload loading or install flow")
    if layer2_features.get("unsupported_method_count", 0) or layer2_features.get("recovered_entry_count", 0):
        scores["dropper"] += 15
        reasons["dropper"].append("archive structure shows evasive or malformed packaging")
    if anti_features.get("conditional_payload_branch_count", 0) and (
        layer2_features.get("unsupported_method_count", 0)
        or layer2_features.get("recovered_entry_count", 0)
        or "dropper_loader_sequence" in sequences
    ):
        scores["dropper"] += 10
        reasons["dropper"].append("conditional payload execution indicators present")

    if keyword_hits.get("india_govt_keyword_count", 0):
        scores["government_impersonation_india"] += 30
        reasons["government_impersonation_india"].append("Indian government-themed keywords detected")
    if keyword_hits.get("financial_keyword_count", 0):
        scores["government_impersonation_india"] += 10
        reasons["government_impersonation_india"].append("KYC or payment lure language detected")
    if "banker" in [family for family, score in scores.items() if score >= 20]:
        scores["government_impersonation_india"] += 10
        reasons["government_impersonation_india"].append("banking-style overlay tactics align with fraud impersonation")

    sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    family_hints = [family for family, score in sorted_scores if score >= 25]

    return {
        "family_scores": scores,
        "family_hints": family_hints,
        "family_reasons": reasons,
        "top_family": sorted_scores[0][0] if sorted_scores and sorted_scores[0][1] >= 25 else None,
    }
