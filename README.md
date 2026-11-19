# MailGuard AI — High-Accuracy Spam & Phishing Detection App

A full-stack machine learning web application and upgraded Google Colab notebook that detects **Ham (Legitimate)**, **Spam (Promotional)**, and **Phishing (Malicious)** emails and SMS messages with explainable URL & social-engineering forensics.

## What Was Upgraded
- **Word + Character N-Gram TF-IDF (`sublinear_tf=True`)**: Captures phrases (`verify your`, `free entry`) and character obfuscations (`£1000`, `.xyz`, `0800`, typosquatting).
- **14 Handcrafted Security Signals**: URL count, raw IP URLs, URL shorteners, high-risk TLDs, `@` redirect obfuscation, brand impersonation on non-official domains, urgency cues, credential-harvesting cues, financial lures, digit/uppercase ratios, and length.
- **Soft-Voting Ensemble**: Weighted combination of `LogisticRegression` (balanced), `CalibratedClassifierCV(LinearSVC)` (balanced), and `ComplementNB`.
- **Hybrid Phishing Risk Engine**: Combines 3-class ML probabilities with real-time URL/domain inspection and inline threat highlighting.

## Project Structure
```text
mailguard-ai/
├── app.py                              # FastAPI server + REST API + static frontend
├── ml/
│   ├── features.py                     # Phishing signal analyzer + sklearn feature pipeline
│   └── train.py                        # Dataset loader, benchmark evaluator & 3-class trainer
├── notebooks/
│   └── spam_phishing_upgraded.ipynb    # Ready-to-upload Google Colab notebook
├── static/
│   ├── index.html                      # MailGuard AI dashboard
│   ├── styles.css                      # Dark-mode cybersecurity UI
│   └── app.js                          # Live scanner, batch/CSV scanner & model telemetry
├── model_artifacts/                    # Saved model (.joblib) & metrics.json
└── requirements.txt
```

## Quick Start
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Train & benchmark the 3-class model (downloads SMS Spam + Phishing Email datasets)
python ml/train.py

# 3. Start the web app
python app.py
```
Then open **http://127.0.0.1:8000** in your browser.
