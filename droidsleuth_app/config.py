from __future__ import annotations

from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parents[0]
SRC_ROOT = PROJECT_ROOT / "src"
LOCAL_PACKAGE_ROOT = APP_ROOT

LOCAL_BUNDLE = APP_ROOT / "droidsleuth_best_bundle.pkl"
FALLBACK_BUNDLES = [
    LOCAL_BUNDLE,
    PROJECT_ROOT / "output_2000_calibrated" / "droidsleuth_best_bundle.pkl",
    PROJECT_ROOT / "output" / "droidsleuth_best_bundle.pkl",
]

PACKAGE_SEARCH_ROOTS = [
    LOCAL_PACKAGE_ROOT,
    SRC_ROOT,
]

APP_TITLE = "DroidSleuth"
APP_SUBTITLE = (
    "Five-layer static APK malware triage with resilient parsing, core static "
    "extraction, deep static analysis, signature matching, and a bundled production model."
)

ABOUT_STATS = {
    "dataset": "2000 APKs (1000 malicious, 1000 benign)",
    "features": "42 numeric features",
    "best_model": "XGBoost",
    "accuracy": "0.970",
    "precision": "0.990",
    "recall": "0.950",
    "f1": "0.969",
    "auc": "0.992",
}

ABOUT_POINTS = [
    "Five-layer static-only APK analysis pipeline with custom resilient parsing.",
    "Layer 1 recovers APK structure, manifest content, DEX payloads, and archive anomalies.",
    "Layers 2-4 combine core static extraction, deep-static analysis, and signature-based scoring.",
    "Layer 5 applies the bundled XGBoost model selected from large-scale DroidSleuth evaluation.",
]

