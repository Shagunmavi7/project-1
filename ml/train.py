"""
Training & benchmarking script for MailGuard AI.
1. Benchmarks Original Baseline vs. Upgraded Ensemble on the SMS Spam dataset.
2. Combines SMS Spam + Public Phishing Email dataset + Smishing patterns.
3. Trains the 3-Class (Ham / Spam / Phishing) Ensemble and saves model + metrics.json.
"""

import json
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from ml.features import build_ensemble_pipeline, build_feature_union

DATA_DIR = BASE_DIR / "data"
ARTIFACT_DIR = BASE_DIR / "model_artifacts"
DATA_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

SMISHING_SAMPLES = [
    "URGENT: Your bank account has been suspended due to unusual activity. Verify immediately at http://secure-bank-verify.xyz/login",
    "USPS Alert: Your package could not be delivered due to an incomplete address. Confirm details here: http://usps-redelivery-track.top/confirm",
    "PayPal Security: We detected an unauthorized sign-in. Restore access within 24 hours: http://paypal-account-check.online/auth",
    "Apple ID Locked: Your iCloud account has been restricted. Sign in now to unlock: http://apple-id-support.click/verify",
    "Netflix: Your payment failed and your membership is on hold. Update your billing card now at http://netflix-billing-update.xyz",
    "Chase Bank Alert: Your debit card is temporarily locked. Click http://192.168.45.12/chase-unlock to verify your PIN and restore access.",
    "IRS Final Notice: You have an unclaimed tax refund. Confirm your SSN and bank details at http://irs-refund-claim.site/portal",
    "Amazon Security: An order of $899 was placed on your account. If this wasn't you, cancel immediately: http://bit.ly/amz-verify-99",
    "DHL Express: Customs fee of $2.99 is required to release your parcel. Pay now at http://dhl-parcel-fee.tk/pay",
    "Microsoft Account: Unusual login detected from Russia. Confirm your password immediately: http://ms-account-security.work/signin",
    "Bank Alert: Your online banking access will be deactivated in 24 hours. Validate your OTP and account at http://verify-mybank.pw",
    "FedEx: Delivery attempt failed. Update your shipping address within 48 hours or parcel returns: http://tinyurl.com/fedex-reconfirm",
    "WhatsApp Security: Your account is scheduled for suspension. Verify your 6-digit code at http://whatsapp-verify.club/check",
    "Citibank: Suspicious wire transfer of $1,450 pending. Log in immediately to block it: http://citi-fraud-alert.xyz/login",
    "Google Security Alert: Someone tried to change your password. Review activity now: http://google-security-check.ru/verify",
    "Wells Fargo: Action required to keep your checking account active. Confirm your card details at http://wf-secure-portal.online",
]


def load_sms_dataset() -> pd.DataFrame:
    csv_path = DATA_DIR / "mail_data.csv"
    tsv_path = DATA_DIR / "sms.tsv"
    if csv_path.exists():
        print(f"Loading cached SMS dataset from {csv_path}")
        raw = pd.read_csv(csv_path).fillna("")
    elif tsv_path.exists():
        print(f"Loading local SMS dataset from {tsv_path}")
        raw = pd.read_csv(tsv_path, sep="\t", header=None, names=["Category", "Message"])
        raw.to_csv(csv_path, index=False)
    else:
        url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
        print(f"Downloading SMS Spam dataset from {url} ...")
        raw = pd.read_csv(url, sep="\t", header=None, names=["Category", "Message"])
        raw.to_csv(csv_path, index=False)
        print(f"Saved {len(raw)} rows to {csv_path}")

    df = raw[["Category", "Message"]].copy()
    df["Category"] = df["Category"].astype(str).str.strip().str.lower()
    df["Message"] = df["Message"].astype(str).str.strip()
    df = df[df["Category"].isin(["ham", "spam"]) & (df["Message"].str.len() > 0)]
    return df


def load_phishing_dataset() -> pd.DataFrame:
    cache_path = DATA_DIR / "phishing_email_clean.csv"
    raw_local = DATA_DIR / "Phishing_Email.csv"
    if cache_path.exists():
        print(f"Loading cached phishing dataset from {cache_path}")
        return pd.read_csv(cache_path).dropna()

    phish_df = None
    if raw_local.exists():
        print(f"Loading local phishing dataset from {raw_local}")
        phish_df = pd.read_csv(raw_local)
    else:
        sources = [
            "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv",
            "https://huggingface.co/datasets/sahith002/phishing-email-dataset/resolve/main/Phishing_Email.csv",
        ]
        for url in sources:
            try:
                print(f"Downloading phishing dataset from {url} ...")
                phish_df = pd.read_csv(url)
                print(f"Downloaded {len(phish_df)} rows!")
                break
            except Exception as exc:
                print(f"Mirror failed ({url}): {exc}")

    if phish_df is None:
        raise RuntimeError("Could not download public phishing dataset from Hugging Face mirrors.")

    text_col = [c for c in phish_df.columns if "text" in c.lower()][0]
    label_col = [c for c in phish_df.columns if "type" in c.lower() or "label" in c.lower()][0]

    clean = phish_df[[text_col, label_col]].dropna().copy()
    clean.columns = ["Message", "RawLabel"]
    clean["Message"] = clean["Message"].astype(str).str.strip()
    clean["RawLabel"] = clean["RawLabel"].astype(str).str.strip().str.lower()
    clean = clean[
        (clean["Message"].str.lower() != "empty")
        & (clean["Message"].str.len() >= 15)
    ].drop_duplicates(subset=["Message"])

    clean["Category"] = np.where(
        clean["RawLabel"].str.contains("phish") | (clean["RawLabel"] == "1"),
        "phishing",
        "ham",
    )
    clean = clean[["Message", "Category"]].reset_index(drop=True)
    clean.to_csv(cache_path, index=False)
    print(f"Cached {len(clean)} clean phishing/safe emails to {cache_path}")
    return clean


def main():
    t0 = time.time()
    sms_raw = load_sms_dataset()
    sms_clean = sms_raw.drop_duplicates(subset=["Message"]).reset_index(drop=True)
    print(f"SMS Dataset: {len(sms_raw)} total -> {len(sms_clean)} unique messages")

    # ---- PART 1: Binary Spam vs. Ham Benchmark ----
    X_sms = sms_clean["Message"]
    y_sms = (sms_clean["Category"] == "spam").astype(int)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_sms, y_sms, test_size=0.2, random_state=42, stratify=y_sms
    )

    binary_models = {
        "Original Baseline (TF-IDF + LR)": Pipeline([
            ("tfidf", TfidfVectorizer(min_df=1, stop_words="english", lowercase=True)),
            ("clf", LogisticRegression(max_iter=1000)),
        ]),
        "Upgraded LR (Word+Char+Signals)": Pipeline([
            ("features", build_feature_union(15000, 15000)),
            ("clf", LogisticRegression(C=4.0, class_weight="balanced", max_iter=1000, random_state=42)),
        ]),
        "Upgraded LinearSVC (Calibrated)": Pipeline([
            ("features", build_feature_union(15000, 15000)),
            ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced", random_state=42), cv=3)),
        ]),
        "Upgraded Ensemble (LR + SVM + CNB)": build_ensemble_pipeline(15000, 15000),
    }

    binary_results = []
    for name, pipe in binary_models.items():
        pipe.fit(X_tr, y_tr)
        preds = pipe.predict(X_te)
        probs = pipe.predict_proba(X_te)[:, 1]
        row = {
            "model": name,
            "accuracy": round(float(accuracy_score(y_te, preds)), 4),
            "precision": round(float(precision_score(y_te, preds)), 4),
            "recall": round(float(recall_score(y_te, preds)), 4),
            "f1": round(float(f1_score(y_te, preds)), 4),
            "roc_auc": round(float(roc_auc_score(y_te, probs)), 4),
        }
        binary_results.append(row)
        print(f"[Binary] {name:36s} | Acc={row['accuracy']:.4f} | Prec={row['precision']:.4f} | Rec={row['recall']:.4f} | F1={row['f1']:.4f} | AUC={row['roc_auc']:.4f}")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_acc = cross_val_score(build_ensemble_pipeline(15000, 15000), X_sms, y_sms, cv=cv, scoring="accuracy")
    cv_f1 = cross_val_score(build_ensemble_pipeline(15000, 15000), X_sms, y_sms, cv=cv, scoring="f1")
    print(f"[Binary 5-Fold CV] Accuracy={cv_acc.mean():.4f} (+/- {cv_acc.std():.4f}) | Spam F1={cv_f1.mean():.4f} (+/- {cv_f1.std():.4f})")

    # ---- PART 2: 3-Class (Ham / Spam / Phishing) Dataset ----
    phish_clean = load_phishing_dataset()
    sms_ham = sms_clean[sms_clean["Category"] == "ham"][["Message", "Category"]]
    sms_spam = sms_clean[sms_clean["Category"] == "spam"][["Message", "Category"]]
    email_ham = phish_clean[phish_clean["Category"] == "ham"][["Message", "Category"]].sample(
        n=min(4500, int((phish_clean["Category"] == "ham").sum())), random_state=42
    )
    email_phish = phish_clean[phish_clean["Category"] == "phishing"][["Message", "Category"]].sample(
        n=min(4500, int((phish_clean["Category"] == "phishing").sum())), random_state=42
    )
    smishing_df = pd.DataFrame({"Message": SMISHING_SAMPLES, "Category": "phishing"})

    combined_df = (
        pd.concat([sms_ham, email_ham, sms_spam, email_phish, smishing_df], ignore_index=True)
        .drop_duplicates(subset=["Message"])
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )
    class_counts = combined_df["Category"].value_counts().to_dict()
    print(f"\n3-Class Combined Dataset ({len(combined_df)} unique rows): {class_counts}")

    X_3 = combined_df["Message"]
    y_3 = combined_df["Category"]
    X_train_3, X_test_3, y_train_3, y_test_3 = train_test_split(
        X_3, y_3, test_size=0.2, random_state=42, stratify=y_3
    )

    model_3 = build_ensemble_pipeline(max_word_features=30000, max_char_features=25000)
    print("Training 3-class Ham / Spam / Phishing ensemble...")
    model_3.fit(X_train_3, y_train_3)

    y_pred_3 = model_3.predict(X_test_3)
    acc_3 = float(accuracy_score(y_test_3, y_pred_3))
    macro_f1_3 = float(f1_score(y_test_3, y_pred_3, average="macro"))
    weighted_f1_3 = float(f1_score(y_test_3, y_pred_3, average="weighted"))
    report_dict = classification_report(y_test_3, y_pred_3, output_dict=True)

    labels_order = ["ham", "spam", "phishing"]
    cm_3 = confusion_matrix(y_test_3, y_pred_3, labels=labels_order).tolist()

    print(f"\n[3-Class] Test Accuracy={acc_3:.4f} ({acc_3*100:.2f}%) | Macro F1={macro_f1_3:.4f}")
    print(classification_report(y_test_3, y_pred_3, digits=4))

    model_path = ARTIFACT_DIR / "spam_phishing_model.joblib"
    joblib.dump(model_3, model_path)

    metrics = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_seconds": round(time.time() - t0, 1),
        "binary_benchmark": {
            "dataset_total_rows": int(len(sms_raw)),
            "dataset_unique_rows": int(len(sms_clean)),
            "models": binary_results,
            "cv_5fold_accuracy_mean": round(float(cv_acc.mean()), 4),
            "cv_5fold_accuracy_std": round(float(cv_acc.std()), 4),
            "cv_5fold_f1_mean": round(float(cv_f1.mean()), 4),
            "cv_5fold_f1_std": round(float(cv_f1.std()), 4),
        },
        "three_class": {
            "dataset_unique_rows": int(len(combined_df)),
            "class_counts": {k: int(v) for k, v in class_counts.items()},
            "test_size": int(len(y_test_3)),
            "accuracy": round(acc_3, 4),
            "macro_f1": round(macro_f1_3, 4),
            "weighted_f1": round(weighted_f1_3, 4),
            "labels_order": labels_order,
            "confusion_matrix": cm_3,
            "per_class": {
                lbl: {
                    "precision": round(float(report_dict[lbl]["precision"]), 4),
                    "recall": round(float(report_dict[lbl]["recall"]), 4),
                    "f1": round(float(report_dict[lbl]["f1-score"]), 4),
                    "support": int(report_dict[lbl]["support"]),
                }
                for lbl in labels_order
            },
        },
        "architecture": {
            "features": [
                "Word TF-IDF (1–2 n-grams, sublinear TF, 30k features)",
                "Character TF-IDF (char_wb 3–5 n-grams, sublinear TF, 25k features)",
                "14 Security & Structural Signals (URLs, IP links, TLDs, shorteners, brand spoofing, urgency & credential cues)",
            ],
            "ensemble": [
                "Logistic Regression (C=4.0, class_weight=balanced, weight=2)",
                "Calibrated LinearSVC (C=1.0, class_weight=balanced, weight=3)",
                "Complement Naive Bayes (alpha=0.2, weight=1)",
            ],
            "hybrid_guard": "Combines ML probabilities with real-time URL forensics and phishing risk scoring (0–100).",
        },
    }

    metrics_path = ARTIFACT_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\nSaved model to {model_path}")
    print(f"Saved metrics to {metrics_path}")


if __name__ == "__main__":
    main()
