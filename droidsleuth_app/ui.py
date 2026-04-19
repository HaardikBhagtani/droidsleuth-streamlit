from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from .config import ABOUT_POINTS, ABOUT_STATS, APP_SUBTITLE, APP_TITLE


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(16, 185, 129, 0.10), transparent 28%),
                radial-gradient(circle at top right, rgba(245, 158, 11, 0.10), transparent 24%),
                linear-gradient(180deg, #f7f8f4 0%, #eef1eb 100%);
        }
        .hero {
            padding: 1.9rem 2rem;
            border-radius: 28px;
            background:
                radial-gradient(circle at 15% 20%, rgba(244, 211, 94, 0.12), transparent 20%),
                linear-gradient(135deg, #10231f 0%, #173a30 50%, #275745 100%);
            color: #f6f7f3;
            box-shadow: 0 24px 52px rgba(18, 38, 32, 0.18);
            border: 1px solid rgba(255,255,255,0.08);
            margin-bottom: 1rem;
        }
        .hero h1 {
            margin: 0 0 0.3rem 0;
            font-size: 2.45rem;
            letter-spacing: -0.02em;
        }
        .hero p {
            margin: 0;
            color: rgba(246,247,243,0.88);
            font-size: 1.02rem;
            line-height: 1.5;
        }
        .hero-kicker {
            display: inline-block;
            margin-bottom: 0.8rem;
            padding: 0.28rem 0.7rem;
            border-radius: 999px;
            background: rgba(255,255,255,0.10);
            border: 1px solid rgba(255,255,255,0.12);
            color: rgba(246,247,243,0.92);
            font-size: 0.76rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-weight: 700;
        }
        .metric-card, .feature-card, .about-card {
            background: rgba(255,255,255,0.88);
            border: 1px solid rgba(18,38,32,0.08);
            border-radius: 20px;
            padding: 1rem;
            box-shadow: 0 10px 30px rgba(26, 41, 31, 0.08);
        }
        .metric-card, .feature-card {
            min-height: 140px;
        }
        .metric-title, .feature-title, .about-title {
            font-size: 0.88rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #557064;
            margin-bottom: 0.7rem;
            font-weight: 700;
        }
        .metric-value, .feature-value {
            font-size: 2rem;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 0.45rem;
        }
        .metric-caption, .feature-caption, .about-copy {
            font-size: 0.94rem;
            color: #586267;
            line-height: 1.45;
        }
        .section-label {
            margin-top: 1.2rem;
            margin-bottom: 0.6rem;
            font-size: 1.05rem;
            font-weight: 800;
            color: #1a352b;
            letter-spacing: -0.01em;
        }
        .analysis-shell {
            background: rgba(255,255,255,0.54);
            border: 1px solid rgba(18,38,32,0.06);
            border-radius: 22px;
            padding: 1rem 1rem 0.4rem 1rem;
            box-shadow: 0 14px 32px rgba(26, 41, 31, 0.05);
        }
        .callout {
            border-left: 4px solid #2a6a4f;
            background: rgba(255,255,255,0.86);
            padding: 0.9rem 1rem;
            border-radius: 12px;
            color: #1e2930;
            box-shadow: 0 8px 24px rgba(26, 41, 31, 0.06);
        }
        .tag-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.35rem;
        }
        .tag {
            background: #e8efe7;
            color: #214636;
            border: 1px solid #c7d7cb;
            border-radius: 999px;
            padding: 0.3rem 0.7rem;
            font-size: 0.82rem;
            font-weight: 600;
        }
        .about-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.8rem;
        }
        .about-stat {
            padding: 0.85rem 0.95rem;
            border-radius: 16px;
            background: #f5f8f3;
            border: 1px solid #dce8df;
        }
        .about-stat-label {
            color: #5e7269;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.35rem;
            font-weight: 700;
        }
        .about-stat-value {
            color: #163126;
            font-size: 1.1rem;
            font-weight: 800;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero() -> None:
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-kicker">Android Malware Analysis</div>
            <h1>{APP_TITLE}</h1>
            <p>{APP_SUBTITLE}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(title: str, value: str, caption: str, tone: str = "neutral") -> None:
    tone_map = {
        "malicious": "#8b1e1e",
        "benign": "#1f5d3f",
        "neutral": "#1f2937",
        "warning": "#8a5a00",
    }
    accent = tone_map.get(tone, tone_map["neutral"])
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">{title}</div>
            <div class="metric-value" style="color:{accent};">{value}</div>
            <div class="metric-caption">{caption}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_feature_card(title: str, value: str, caption: str) -> None:
    st.markdown(
        f"""
        <div class="feature-card">
            <div class="feature-title">{title}</div>
            <div class="feature-value">{value}</div>
            <div class="feature-caption">{caption}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_about_section() -> None:
    left, right = st.columns([1.1, 0.9], gap="large")
    with left:
        st.markdown(
            """
            <div class="about-card">
                <div class="about-title">About The Tool</div>
                <div class="about-copy">
                    DroidSleuth is a static Android APK malware analysis tool designed for analyst-facing
                    triage and thesis-grade evaluation. It combines resilient APK parsing, manifest and DEX
                    feature extraction, signature matching, deep-static analysis, and a final
                    XGBoost classifier trained on a balanced 2000-APK dataset.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("")
        for point in ABOUT_POINTS:
            st.markdown(f"- {point}")
    with right:
        stat_items = list(ABOUT_STATS.items())
        for index in range(0, len(stat_items), 2):
            cols = st.columns(2, gap="small")
            for col, (label, value) in zip(cols, stat_items[index:index + 2]):
                with col:
                    st.markdown(
                        f"""
                        <div class="about-stat">
                            <div class="about-stat-label">{label.replace('_', ' ')}</div>
                            <div class="about-stat-value">{value}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )


def feature_cards(report: dict) -> list[tuple[str, str, str]]:
    features = report["layer2"]["features"]
    classification = report["layer2"]["classification"]
    return [
        ("Permissions", str(features.get("permission_count", 0)), "Declared Android permissions"),
        ("Components", str(features.get("component_count", 0)), "Activities, services, receivers, providers"),
        ("Triage Score", str(features.get("triage_score", 0)), "Structural anomaly score from Layer 1"),
        ("Signature Score", str(features.get("signature_score", 0)), "Layer 2.5 matched-signature score"),
        ("API Hints", str(features.get("high_risk_api_hint_count", 0)), "High-risk static API hint count"),
        ("Family Hints", str(len(classification.get("family_hints", []))), "Static family inferences"),
    ]


def deep_static_frame(report: dict) -> pd.DataFrame:
    features = report.get("layer2_deep_static", {}).get("features", {})
    ordered = [
        "deep_behavioral_sequence_count",
        "deep_sensitive_api_edge_hits",
        "deep_sensitive_api_total",
        "dynamic_class_loading_count",
        "reflection_usage_count",
        "anti_analysis_indicator_count",
        "anti_analysis_risk_score",
        "c2_url_count",
        "c2_domain_count",
        "c2_ip_count",
        "c2_decoded_url_count",
        "c2_suspicious_network_indicator_count",
        "family_hint_count",
    ]
    rows = [{"Feature": key, "Value": features.get(key, 0)} for key in ordered]
    return pd.DataFrame(rows)


def apk_overview_frame(upload_name: str, bundle_path: Path, report: dict) -> pd.DataFrame:
    features = report["layer2"]["features"]
    classification = report["layer2"]["classification"]
    return pd.DataFrame(
        [
            ("File", upload_name),
            ("Bundle", bundle_path.name),
            ("Manifest decoded", "Yes" if features.get("manifest_decoded") else "No"),
            ("DEX files", int(features.get("dex_file_count", 0))),
            ("Entries", int(features.get("entry_count", 0))),
            ("Top family", classification.get("top_family") or "-"),
        ],
        columns=["Item", "Value"],
    )

