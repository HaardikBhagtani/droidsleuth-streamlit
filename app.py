from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from droidsleuth_app.services import (
    analyze_apk_file,
    format_report_json,
    load_bundle,
    pick_default_bundle,
    score_report,
    suppress_noisy_logs,
)
from droidsleuth_app.ui import (
    apk_overview_frame,
    deep_static_frame,
    feature_cards,
    inject_css,
    render_about_section,
    render_feature_card,
    render_hero,
    render_metric_card,
)


def main() -> None:
    suppress_noisy_logs()
    st.set_page_config(
        page_title="DroidSleuth Static APK Analyzer",
        page_icon="DS",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()
    render_hero()

    default_bundle = pick_default_bundle()
    if default_bundle is None:
        st.error("Bundled model file not found. Expected `streamlit/droidsleuth_best_bundle.pkl`.")
        return

    with st.sidebar:
        st.header("Analysis")
        uploaded_apk = st.file_uploader("Upload APK", type=["apk"])
        st.divider()
        st.subheader("About")
        st.caption(
            "Static APK malware triage interface for the bundled DroidSleuth model. "
            "Use the About tab in the main view for architecture and evaluation details."
        )
    bundle_path = Path(default_bundle)

    analysis_tab, about_tab = st.tabs(["Analysis", "About"])

    with about_tab:
        render_about_section()

    with analysis_tab:
        st.markdown('<div class="analysis-shell">', unsafe_allow_html=True)
        if uploaded_apk is None:
            st.markdown(
                """
                <div class="callout">
                    Upload an APK to generate a full static report, run the saved ML bundle, and review
                    both the rule-based and model-based verdicts in one place.
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown("</div>", unsafe_allow_html=True)
            return

        with st.spinner("Analyzing APK and scoring with the bundled model..."):
            bundle = load_bundle(bundle_path)
            report = analyze_apk_file(uploaded_apk.getvalue(), uploaded_apk.name)
            scored = score_report(report, bundle)

        classification = report["layer2"]["classification"]
        ml_label = scored["label"]
        ml_prob = scored["probability"]
        ml_confidence = scored["confidence"]
        row = scored["row"]
        verdict_tone = "malicious" if ml_label == "malicious" else "benign"

        top_metrics = st.columns(4)
        with top_metrics[0]:
            render_metric_card("ML Verdict", ml_label.replace("_", " ").title(), "Final saved-model prediction", verdict_tone)
        with top_metrics[1]:
            render_metric_card("ML Probability", f"{ml_prob:.1%}", "Probability of maliciousness", "warning")
        with top_metrics[2]:
            render_metric_card(
                "Rule Verdict",
                classification["label"].replace("_", " ").title(),
                "Layer 2 / 2.5 heuristic verdict",
                "warning" if classification["label"] == "malicious" else "neutral",
            )
        with top_metrics[3]:
            render_metric_card("Model Confidence", f"{ml_confidence:.1%}", "Distance from the decision boundary", "neutral")

        st.markdown('<div class="section-label">Feature Snapshot</div>', unsafe_allow_html=True)
        feature_cols = st.columns(3)
        cards = feature_cards(report)
        for idx, card in enumerate(cards):
            with feature_cols[idx % 3]:
                render_feature_card(*card)

        left, right = st.columns([1.15, 0.85], gap="large")

        with left:
            st.markdown('<div class="section-label">Why The APK Was Flagged</div>', unsafe_allow_html=True)
            reasons = classification.get("reasons", [])
            if reasons:
                for reason in reasons:
                    st.markdown(f"- {reason}")
            else:
                st.write("No rule-based reasons were returned.")

            st.markdown('<div class="section-label">Static Tags</div>', unsafe_allow_html=True)
            tags = (
                classification.get("family_hints", [])
                + classification.get("behavioral_sequences", [])
                + classification.get("api_hints", [])
            )
            if tags:
                st.markdown(
                    '<div class="tag-row">' + "".join(f'<span class="tag">{tag}</span>' for tag in tags) + "</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.caption("No family, behavioral, or API tags were extracted.")

            st.markdown('<div class="section-label">Deep Static Signals</div>', unsafe_allow_html=True)
            st.dataframe(deep_static_frame(report), use_container_width=True, hide_index=True)

        with right:
            st.markdown('<div class="section-label">APK Overview</div>', unsafe_allow_html=True)
            st.dataframe(apk_overview_frame(uploaded_apk.name, bundle_path, report), use_container_width=True, hide_index=True)

            st.markdown('<div class="section-label">Signature Matches</div>', unsafe_allow_html=True)
            rule_ids = classification.get("signature_rule_ids", [])
            if rule_ids:
                st.dataframe(pd.DataFrame({"Rule ID": rule_ids}), use_container_width=True, hide_index=True)
            else:
                st.caption("No Layer 2.5 signatures matched.")

            st.markdown('<div class="section-label">Download Report</div>', unsafe_allow_html=True)
            st.download_button(
                "Download JSON analysis",
                data=format_report_json(report),
                file_name=f"{Path(uploaded_apk.name).stem}_droidsleuth_report.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown('<div class="section-label">Raw Feature Row</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame([row]), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()

