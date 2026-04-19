from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path

import joblib
import pandas as pd

from .config import FALLBACK_BUNDLES, SRC_ROOT


if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from droidsleuth_layer1.apk_parser import ApkAnalyzer  # noqa: E402


def suppress_noisy_logs() -> None:
    logger_names = (
        "androguard",
        "androguard.misc",
        "androguard.core.analysis.analysis",
        "androguard.core.apk",
        "androguard.core.axml",
    )
    logging.disable(logging.CRITICAL)
    for name in logger_names:
        logger = logging.getLogger(name)
        logger.disabled = True
        logger.setLevel(logging.CRITICAL)
        logger.propagate = False
        logger.handlers.clear()
    try:
        from loguru import logger as loguru_logger

        loguru_logger.remove()
    except Exception:
        pass


def pick_default_bundle() -> Path | None:
    for path in FALLBACK_BUNDLES:
        if path.exists():
            return path
    return None


def load_bundle(bundle_path: Path) -> dict:
    return joblib.load(bundle_path)


def analyze_apk_file(apk_bytes: bytes, filename: str) -> dict:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as handle:
        handle.write(apk_bytes)
        temp_path = Path(handle.name)

    try:
        report = ApkAnalyzer(temp_path).analyze()
        report["file"] = filename
        report["apk_name"] = filename
        return report
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def build_row_from_report(report: dict) -> dict:
    classification = report["layer2"]["classification"]
    row = {
        "file": report.get("file", report.get("apk_name", "")),
        "apk_name": report.get("apk_name", ""),
        "ground_truth": "",
        "analysis_status": "ok",
        "analysis_error": "",
        "predicted_label": classification["label"],
        "malicious_probability": classification["malicious_probability"],
        "confidence": classification["confidence"],
        "family_hints": "|".join(classification.get("family_hints", [])),
        "api_hints": "|".join(classification.get("api_hints", [])),
        "behavioral_sequences": "|".join(classification.get("behavioral_sequences", [])),
        "signature_rule_ids": "|".join(classification.get("signature_rule_ids", [])),
        "top_family": classification.get("top_family") or "",
        "reasons": " | ".join(classification.get("reasons", [])),
    }
    row.update(report["layer2"]["features"])
    return row


def build_model_frame(row: dict, bundle: dict) -> pd.DataFrame:
    df = pd.DataFrame([row])
    drop_columns = bundle["drop_columns"]
    zero_variance_columns = bundle["zero_variance_columns"]
    feature_columns = bundle["feature_columns"]
    fillna_value = bundle.get("fillna_value", 0.0)

    X = df.drop(columns=drop_columns, errors="ignore").select_dtypes(include="number")
    X = X.drop(columns=zero_variance_columns, errors="ignore")
    X = X.reindex(columns=feature_columns, fill_value=fillna_value).fillna(fillna_value)
    return X


def score_report(report: dict, bundle: dict) -> dict:
    row = build_row_from_report(report)
    X = build_model_frame(row, bundle)
    model = bundle["model"]
    ml_pred = int(model.predict(X)[0])
    ml_prob = float(model.predict_proba(X)[0][1])
    ml_label = "malicious" if ml_pred == 1 else "non_malicious"

    return {
        "row": row,
        "features_frame": X,
        "label": ml_label,
        "probability": ml_prob,
        "confidence": max(ml_prob, 1 - ml_prob),
    }


def format_report_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


