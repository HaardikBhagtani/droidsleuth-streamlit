from __future__ import annotations

from collections import Counter


EMULATOR_PATTERNS = (
    "ro.kernel.qemu",
    "genymotion",
    "generic_x86",
    "sdk_gphone",
    "goldfish",
    "ranchu",
)

ROOT_PATTERNS = (
    "/system/xbin/su",
    "/system/bin/su",
    "test-keys",
    "magisk",
    "supersu",
    "busybox",
)

DEBUGGER_PATTERNS = (
    "isDebuggerConnected",
    "waitingForDebugger",
    "android.os.debug",
)

HOOK_PATTERNS = (
    "frida",
    "xposed",
    "substrate",
    "zygisk",
    "riru",
)


def _collect_text_haystacks(dex: list[dict], entries: list[object], manifest: dict) -> list[str]:
    corpus: list[str] = []
    for item in dex:
        corpus.extend(value for value in item.get("sampled_strings", []) if isinstance(value, str))
        corpus.extend(value for value in item.get("anti_analysis_strings", []) if isinstance(value, str))
        corpus.extend(value for value in item.get("class_names", []) if isinstance(value, str))
    corpus.extend(getattr(entry, "filename", "") for entry in entries)
    corpus.extend(manifest.get("permissions", []))
    corpus.extend(manifest.get("activities", []))
    corpus.extend(manifest.get("services", []))
    corpus.extend(manifest.get("receivers", []))
    return corpus


def analyze_anti_analysis(
    *,
    dex: list[dict],
    entries: list[object],
    manifest: dict,
    call_graph: dict,
    cfg_analysis: dict,
) -> dict:
    corpus = "\n".join(value.lower() for value in _collect_text_haystacks(dex, entries, manifest))
    detections = Counter()
    findings: list[str] = []
    cfg_features = cfg_analysis.get("features", {})

    emulator_hits = [pattern for pattern in EMULATOR_PATTERNS if pattern in corpus]
    root_hits = [pattern for pattern in ROOT_PATTERNS if pattern in corpus]
    debugger_hits = [pattern for pattern in DEBUGGER_PATTERNS if pattern.lower() in corpus]
    hook_hits = [pattern for pattern in HOOK_PATTERNS if pattern in corpus]

    if len(emulator_hits) >= 2 or (emulator_hits and cfg_features.get("anti_analysis_branch_method_count", 0)):
        detections["emulator_checks"] += 1
        findings.append("static emulator-detection strings present")
    if len(root_hits) >= 2 or (root_hits and cfg_features.get("anti_analysis_branch_method_count", 0)):
        detections["root_checks"] += 1
        findings.append("static root-detection strings present")
    if debugger_hits:
        detections["debugger_checks"] += 1
        findings.append("debugger-detection strings present")
    if len(hook_hits) >= 2 or (hook_hits and cfg_features.get("anti_analysis_branch_method_count", 0)):
        detections["hook_framework_checks"] += 1
        findings.append("hook or instrumentation framework strings present")

    if cfg_features.get("anti_analysis_branch_method_count", 0):
        detections["conditional_payload_branches"] += cfg_features["anti_analysis_branch_method_count"]
        findings.append("anti-analysis indicators appear inside branched control-flow")

    if "dropper_loader_sequence" in call_graph.get("behavioral_sequences", []):
        detections["conditional_payload_execution"] += 1
        findings.append("dynamic-loading flow suggests staged payload execution")

    risk_score = min(
        100,
        detections["emulator_checks"] * 15
        + detections["root_checks"] * 15
        + detections["debugger_checks"] * 12
        + detections["hook_framework_checks"] * 12
        + min(20, detections["conditional_payload_branches"] * 4)
        + detections["conditional_payload_execution"] * 15,
    )

    return {
        "status": "ok",
        "features": {
            "anti_analysis_indicator_count": sum(detections.values()),
            "anti_analysis_risk_score": risk_score,
            "emulator_check_count": detections["emulator_checks"],
            "root_check_count": detections["root_checks"],
            "debugger_check_count": detections["debugger_checks"],
            "hook_check_count": detections["hook_framework_checks"],
            "conditional_payload_branch_count": detections["conditional_payload_branches"],
        },
        "findings": findings,
        "pattern_counts": dict(sorted(detections.items())),
    }
