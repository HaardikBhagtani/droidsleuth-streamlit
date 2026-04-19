from __future__ import annotations

from pathlib import Path

from .anti_analysis import analyze_anti_analysis
from .c2_static import analyze_c2_indicators
from .callgraph import analyze_api_call_graph
from .cfg_analysis import analyze_control_flow
from .family_classifier import infer_malware_families


def build_deep_static_intelligence(
    *,
    apk_path: str | Path,
    anomalies: dict,
    manifest: dict,
    dex: list[dict],
    entries: list[object],
    static_triage: dict,
    keyword_hits: dict,
) -> dict:
    call_graph = analyze_api_call_graph(apk_path)
    cfg_analysis = analyze_control_flow(apk_path)
    anti_analysis = analyze_anti_analysis(
        dex=dex,
        entries=entries,
        manifest=manifest,
        call_graph=call_graph,
        cfg_analysis=cfg_analysis,
    )
    c2_static = analyze_c2_indicators(apk_path)
    permissions = set(manifest.get("permissions", []))
    layer2_stub_features = {
        "unsupported_method_count": len(anomalies.get("unsupported_compression_methods", [])),
        "recovered_entry_count": int(anomalies.get("recovered_entry_count", 0)),
        "triage_score": static_triage.get("score", 0),
    }
    family_analysis = infer_malware_families(
        permissions=permissions,
        layer2_features=layer2_stub_features,
        call_graph=call_graph,
        cfg_analysis=cfg_analysis,
        anti_analysis=anti_analysis,
        c2_static=c2_static,
        keyword_hits=keyword_hits,
    )

    aggregate_features = {}
    aggregate_features.update(call_graph.get("features", {}))
    aggregate_features.update(cfg_analysis.get("features", {}))
    aggregate_features.update(anti_analysis.get("features", {}))
    aggregate_features.update(
        {
            f"c2_{key}": value
            for key, value in c2_static.get("features", {}).items()
        }
    )
    aggregate_features["family_hint_count"] = len(family_analysis.get("family_hints", []))

    return {
        "status": "ok",
        "features": aggregate_features,
        "call_graph": call_graph,
        "cfg_analysis": cfg_analysis,
        "anti_analysis": anti_analysis,
        "c2_static": c2_static,
        "family_analysis": family_analysis,
    }
