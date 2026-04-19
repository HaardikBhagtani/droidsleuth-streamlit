from __future__ import annotations

from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parents[0]
SRC_ROOT = PROJECT_ROOT / "src"

LOCAL_BUNDLE = APP_ROOT / "droidsleuth_best_bundle.pkl"
FALLBACK_BUNDLES = [
    LOCAL_BUNDLE,
    PROJECT_ROOT / "output_2000_calibrated" / "droidsleuth_best_bundle.pkl",
    PROJECT_ROOT / "output" / "droidsleuth_best_bundle.pkl",
]

APP_TITLE = "DroidSleuth"
APP_SUBTITLE = (
    "Static APK malware triage with resilient parsing, deep static "
    "signals, signature matching, and a bundled production model."
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
    "Static-only APK analysis pipeline with custom resilient parsing.",
    "Binary AndroidManifest decoding, DEX feature extraction, and layered heuristic scoring.",
    "Androguard-backed deep-static layer with graph and CFG-derived features.",
    "Bundled ML model selected from large-scale DroidSleuth evaluation.",
]

