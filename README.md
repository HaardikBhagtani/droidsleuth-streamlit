# DroidSleuth Streamlit App

This folder contains a deployable Streamlit interface for the DroidSleuth APK malware detector.

## Included Artifacts

- `app.py`: Streamlit entry point
- `droidsleuth_app/`: modular application code
- `droidsleuth_layer1/`: bundled runtime analysis package for Streamlit deployment
- `droidsleuth_best_bundle.pkl`: bundled XGBoost model copied into the app folder for self-contained deployment
- `.streamlit/config.toml`: theme configuration

## What The App Does

- accepts an uploaded `.apk`
- runs the local DroidSleuth static analysis pipeline
- rebuilds the same feature row used during ML training
- scores the APK with the shipped model bundle
- presents:
  - final ML verdict
  - malicious probability and confidence
  - rule-based Layer 2 / 2.5 verdict
  - feature snapshot
  - deep-static signals
  - matched signatures
  - JSON report download
  - a dedicated About section with architecture and evaluation details

## Final Model

Bundled model:

- `D:\Major Project\streamlit\droidsleuth_best_bundle.pkl`

This is the XGBoost bundle selected from the 2000-APK evaluation.

## Run Locally

From the project root:

```powershell
pip install -r streamlit\requirements.txt
streamlit run streamlit\app.py
```

## Notes

- The app first uses the bundled `droidsleuth_layer1` package inside this folder and falls back to the project `src` layout when available.
- The app suppresses most Androguard logging to keep the UI clean.
- The ML prediction shown in the UI is the final saved-model verdict.
- The rule-based verdict shown in the UI is the internal Layer 2 / 2.5 heuristic output and is included for analyst visibility.
- The shipped model keeps deployment simpler because the UI does not depend on `output_2000_calibrated` being present elsewhere.

