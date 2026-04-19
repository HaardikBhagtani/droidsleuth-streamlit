from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SignatureMatch:
    rule_id: str
    severity: int
    description: str


def run_signature_engine(
    *,
    anomalies: dict,
    manifest: dict,
    dex: list[dict],
    static_triage: dict,
    call_graph: dict,
    cfg_analysis: dict,
    anti_analysis: dict,
    c2_static: dict,
    family_analysis: dict,
    keyword_hits: dict,
) -> dict:
    permissions = set(manifest.get("permissions", []))
    api_hints = {
        hint
        for item in dex
        for hint in item.get("api_hints", [])
        if isinstance(hint, str)
    }
    overlay_permission_pair = {
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
    } <= permissions
    banker_score = family_analysis.get("family_scores", {}).get("banker", 0)
    matches: list[SignatureMatch] = []

    def add(rule_id: str, severity: int, description: str) -> None:
        matches.append(SignatureMatch(rule_id=rule_id, severity=severity, description=description))

    if anomalies.get("recovered_entry_count") and (
        anomalies.get("mismatched_local_vs_central_compression")
        or anomalies.get("unsupported_compression_methods")
    ):
        add("SIG.BADPACK.RECOVERY", 18, "BadPack-style archive inconsistency required fallback payload recovery")

    if {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"} <= permissions:
        add("SIG.BANKER.OVERLAY", 24, "Accessibility plus overlay permissions match banker-style fraud patterns")

    if "overlay_attack_sequence" in call_graph.get("behavioral_sequences", []) and (
        overlay_permission_pair or banker_score >= 45
    ):
        add("SIG.BEHAVIOR.OVERLAY_SEQUENCE", 18, "Call graph contains an overlay attack interaction pattern")

    if "sms" in api_hints and keyword_hits.get("financial_keyword_count", 0):
        add("SIG.FRAUD.OTP_SMS", 15, "SMS handling appears alongside financial or OTP lure language")

    if cfg_analysis["features"].get("dynamic_class_loading_count", 0) and (
        "dropper_loader_sequence" in call_graph.get("behavioral_sequences", [])
        or anomalies.get("unsupported_compression_methods")
        or anomalies.get("recovered_entry_count")
    ):
        add("SIG.DROPPER.DYNAMIC_LOAD", 20, "Control-flow analysis found dynamic class loading behavior")

    if anti_analysis["features"].get("anti_analysis_indicator_count", 0) >= 3 and anti_analysis["features"].get(
        "conditional_payload_branch_count", 0
    ):
        add("SIG.ARA.STATIC_GATING", 14, "Multiple static anti-analysis indicators were found")

    if c2_static["features"].get("decoded_url_count", 0) or c2_static["features"].get("decoded_domain_count", 0):
        add("SIG.C2.OBFUSCATED_INDICATOR", 16, "Encoded or obfuscated network indicators decode into URLs/domains")

    if c2_static["features"].get("suspicious_network_indicator_count", 0) >= 2 and (
        c2_static["features"].get("url_count", 0) or c2_static["features"].get("decoded_url_count", 0)
    ):
        add("SIG.C2.SUSPICIOUS_ENDPOINT", 14, "Suspicious static network infrastructure indicators were found")

    if keyword_hits.get("india_govt_keyword_count", 0) >= 2:
        add("SIG.INDIA.GOVT.IMPERSONATION", 16, "Government-themed lure keywords suggest India-focused impersonation")

    family_scores = family_analysis.get("family_scores", {})
    if family_scores.get("spyware", 0) >= 50:
        add("SIG.FAMILY.SPYWARE", 15, "Feature fusion aligns with spyware-style collection and exfiltration")
    if family_scores.get("dropper", 0) >= 50:
        add("SIG.FAMILY.DROPPER", 17, "Feature fusion aligns with staged dropper or loader behavior")
    if family_scores.get("banker", 0) >= 45:
        add("SIG.FAMILY.BANKER", 17, "Feature fusion aligns with banker-style overlay or credential capture")

    score = min(100, sum(match.severity for match in matches))
    return {
        "status": "ok",
        "score": score,
        "match_count": len(matches),
        "matches": [
            {
                "rule_id": match.rule_id,
                "severity": match.severity,
                "description": match.description,
            }
            for match in matches
        ],
    }
