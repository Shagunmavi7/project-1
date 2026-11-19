# 📧 MailGuard AI — High-Accuracy Spam & Phishing Detection System

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/Shagunmavi7/project-1)

A complete machine learning web application and upgraded Google Colab notebook that classifies emails and SMS messages into **Ham (Legitimate)**, **Spam (Promotional)**, and **Phishing (Malicious)** with explainable URL forensics and social-engineering detection.

---

## 🚀 Key Results & Highlights

- **98.48% 3-Class Test Accuracy & 97.66% Macro F1** across 14,174 unique messages:
  - **Ham:** 98.51% Precision · 99.11% Recall · **98.81% F1**
  - **Phishing:** 98.33% Precision · 98.01% Recall · **98.17% F1**
  - **Spam:** 99.17% Precision · 93.02% Recall · **96.00% F1**
- **Spam vs. Ham Upgrade (Deduplicated SMS dataset):**
  - Accuracy improved from **95.83% → 99.32%**
  - Spam Recall surged from **67.97% → 95.31%** (+27.34% more spam detected)
  - 5-Fold Stratified Cross-Validation: **99.13%** (±0.31%) Accuracy
- **Explainable Hybrid Threat Engine:**
  - Real-time URL parser flags raw IP addresses, URL shorteners (`bit.ly`, `tinyurl`), high-risk TLDs (`.xyz`, `.top`, `.tk`), and `@` redirect tricks.
  - **Brand Impersonation Detector:** Catches non-official domains posing as PayPal, Apple, Amazon, Chase, Netflix, Google, DHL, USPS, and more.
  - Regex detection for urgency/lockout pressure, credential harvesting, and financial lures.
  - Returns character spans for **inline threat highlighting** in the web dashboard.

---

## 🛠️ Tech Stack

| Area | Tools & Libraries |
|---|---|
| **Language** | Python 3.14+ |
| **Backend API** | FastAPI, Uvicorn, Pydantic |
| **Machine Learning** | scikit-learn (VotingClassifier, CalibratedClassifierCV, LinearSVC, LogisticRegression, ComplementNB) |
| **NLP & Vectors** | Word TF-IDF (1–2 n-grams) + Char-wb TF-IDF (3–5 n-grams) + Custom Signal Transformer |
| **Data Processing** | Pandas, NumPy, joblib |
| **Frontend UI** | HTML5, CSS3 (Modern Dark-Mode Cyber Theme), Vanilla JavaScript (Zero heavy dependencies) |
| **Deployment** | Netlify (`netlify.toml` included), Render, or Localhost |
| **Notebooks** | Jupyter / Google Colab |

---

## 📂 Project Structure

```text
project-1/
├── app.py                              # FastAPI backend & REST API server
├── netlify.toml                        # Netlify publish & routing configuration
├── requirements.txt                    # Python project dependencies
├── README.md                           # Documentation, benchmarks & 1-click deploy button
│
├── ml/
│   ├── __init__.py
│   ├── features.py                     # Feature union, URL forensics & phishing analyzer
│   └── train.py                        # Training, 5-fold CV & benchmark evaluation pipeline
│
├── static/
│   ├── index.html                      # MailGuard AI dashboard (Live Scanner, Batch, Telemetry)
│   ├── styles.css                      # Cyber-security dark theme & responsive UI
│   ├── app.js                          # Client-side scanner, SVG gauge, presets & CSV dropzone
│   └── metrics.json                    # Telemetry & confusion matrix for static deployments
│
├── notebooks/
│   └── spam_phishing_upgraded.ipynb    # Upgraded Colab notebook (Baseline vs. Upgraded)
│
├── model_artifacts/
│   ├── spam_phishing_model.joblib      # Trained 3-class Soft-Voting Ensemble model
│   └── metrics.json                    # Saved benchmark results & confusion matrix
│
└── data/
    ├── mail_data.csv                   # SMS spam dataset
    └── sms.tsv                         # Source SMS dataset
```

---

## 💡 Quick Start & Usage

### 1. One-Click Deploy to Netlify
Click the button below to deploy the full interactive application to Netlify:

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/Shagunmavi7/project-1)

### 2. Local Setup
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Run Web Application Locally
```bash
python app.py
```
Open **http://127.0.0.1:8000** in your web browser.

---

## 📄 License

This project is licensed under the MIT License.
