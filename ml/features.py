"""
Feature extraction, URL/phishing signal analysis, and ML pipeline builders
for MailGuard AI (3-Class Ham / Spam / Phishing Detection).
"""

import re
from urllib.parse import urlparse

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import LinearSVC

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly",
}

SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".ru", ".cn", ".buzz", ".support", ".online",
    ".site", ".pw", ".icu", ".vip",
)

OFFICIAL_BRAND_DOMAINS = {
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.in", "amzn.to"),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com", "office.com"),
    "google": ("google.com", "gmail.com", "accounts.google.com"),
    "netflix": ("netflix.com",),
    "chase": ("chase.com",),
    "citibank": ("citi.com", "citibank.com"),
    "wellsfargo": ("wellsfargo.com",),
    "irs": ("irs.gov",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "ups": ("ups.com",),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com", "fb.com"),
    "whatsapp": ("whatsapp.com",),
    "dropbox": ("dropbox.com",),
    "linkedin": ("linkedin.com",),
}

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\b24\s*hours?\b", r"\b48\s*hours?\b",
    r"\bsuspended\b", r"\blocked\b", r"\brestricted\b", r"\bdeactivated\b",
    r"\bunauthorized\b", r"\bunusual\s+(?:login|activity|sign-?in)\b",
    r"\bsecurity\s+alert\b", r"\baction\s+required\b", r"\bfinal\s+notice\b",
    r"\bwill\s+be\s+(?:closed|terminated|locked|suspended)\b",
    r"\bcompromised\b", r"\bexpir(?:e|es|ing|ed)\b", r"\baccount\s+on\s+hold\b",
]

CREDENTIAL_PATTERNS = [
    r"\bverify\s+your\b", r"\bconfirm\s+your\b", r"\bupdate\s+your\b",
    r"\bvalidate\s+your\b", r"\bpassword\b", r"\botp\b", r"\bpin\s+code\b",
    r"\bssn\b", r"\bsocial\s+security\b", r"\bcredit\s+card\b",
    r"\bbank\s+(?:account|details|card)\b", r"\bbilling\s+info(?:rmation)?\b",
    r"\bverify\s+(?:identity|account|now)\b", r"\bclick\s+(?:here|the\s+link|below)\b",
    r"\blog\s*in\b", r"\bsign\s*in\b", r"\brestore\s+access\b",
    r"\benter\s+your\s+(?:pin|code|details)\b",
]

FINANCIAL_PATTERNS = [
    r"\bwire\s+transfer\b", r"\binvoice\b", r"\brefund\b", r"\btax\b",
    r"\bpayment\s+(?:failed|declined|overdue|pending)\b",
    r"\baccount\s+(?:number|balance)\b", r"\bclaim\s+your\b",
    r"\bprize\b", r"\bwallet\b", r"\bcrypto\b", r"\bcustoms\s+fee\b",
]

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]]+", flags=re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,;:!?") for u in URL_REGEX.findall(str(text))]


def analyze_phishing_signals(text: str) -> dict:
    """
    Analyze text for phishing & spam indicators.
    Returns numeric features (for ML), risk score (0-100), structured red flags,
    inspected URLs, and character spans for UI highlighting.
    """
    text_str = str(text)
    lower = text_str.lower()
    urls = extract_urls(text_str)

    red_flags = []
    inspected_urls = []
    highlights = []
    risk_score = 0

    has_ip_url = 0
    has_shortener = 0
    has_suspicious_tld = 0
    has_at_in_url = 0
    has_brand_impersonation = 0
    has_insecure_http = 0

    domains = []
    for match in URL_REGEX.finditer(text_str):
        raw_url = match.group(0).rstrip(".,;:!?")
        start, end = match.start(), match.start() + len(raw_url)
        parsed_u = raw_url if raw_url.lower().startswith("http") else "http://" + raw_url
        try:
            parsed = urlparse(parsed_u)
            host = (parsed.hostname or "").lower()
            scheme = (parsed.scheme or "http").lower()
        except Exception:
            host = ""
            scheme = "http"

        url_flags = []
        if host:
            domains.append(host)
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
            has_ip_url = 1
            url_flags.append("Raw IP Address")
        if host in URL_SHORTENERS or any(host.endswith("." + s) for s in URL_SHORTENERS):
            has_shortener = 1
            url_flags.append("URL Shortener")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            has_suspicious_tld = 1
            url_flags.append("High-Risk TLD")
        if "@" in raw_url:
            has_at_in_url = 1
            url_flags.append("Redirect Obfuscation (@)")
        if raw_url.lower().startswith("http://"):
            has_insecure_http = 1
            url_flags.append("Unencrypted HTTP")

        inspected_urls.append({
            "raw": raw_url,
            "host": host or "unknown",
            "protocol": scheme,
            "flags": url_flags,
            "suspicious": len(url_flags) > 0,
        })
        highlights.append({
            "start": start,
            "end": end,
            "text": raw_url,
            "category": "url_danger" if url_flags else "url_info",
        })

    # Brand impersonation check
    impersonated_brands = []
    if domains:
        for brand, official_list in OFFICIAL_BRAND_DOMAINS.items():
            if re.search(rf"\b{re.escape(brand)}\b", lower):
                for item in inspected_urls:
                    host = item["host"]
                    if host != "unknown" and not any(
                        host == off or host.endswith("." + off) for off in official_list
                    ):
                        has_brand_impersonation = 1
                        impersonated_brands.append(f"{brand.title()} -> {host}")
                        if f"Impersonates {brand.title()}" not in item["flags"]:
                            item["flags"].append(f"Impersonates {brand.title()}")
                            item["suspicious"] = True
                        break

    def collect_matches(patterns, category):
        hits = 0
        matched_terms = []
        for pat in patterns:
            found = list(re.finditer(pat, text_str, flags=re.IGNORECASE))
            if found:
                hits += 1
                matched_terms.append(found[0].group(0))
                for m in found:
                    highlights.append({
                        "start": m.start(),
                        "end": m.end(),
                        "text": m.group(0),
                        "category": category,
                    })
        return hits, matched_terms

    urgency_hits, urgency_terms = collect_matches(URGENCY_PATTERNS, "urgency")
    credential_hits, credential_terms = collect_matches(CREDENTIAL_PATTERNS, "credential")
    financial_hits, financial_terms = collect_matches(FINANCIAL_PATTERNS, "financial")

    if has_ip_url:
        risk_score += 40
        red_flags.append({
            "severity": "critical",
            "category": "URL",
            "title": "Raw IP Address Link",
            "detail": "Link points directly to a numeric IP address instead of a verified domain name.",
        })
    if has_brand_impersonation:
        risk_score += 40
        red_flags.append({
            "severity": "critical",
            "category": "Impersonation",
            "title": "Possible Brand Impersonation",
            "detail": f"Message references a known brand but links to a non-official host ({', '.join(impersonated_brands[:3])}).",
        })
    if has_suspicious_tld:
        risk_score += 25
        red_flags.append({
            "severity": "high",
            "category": "URL",
            "title": "High-Risk Domain Extension",
            "detail": "Embedded URL uses a top-level domain frequently abused in phishing campaigns.",
        })
    if has_at_in_url:
        risk_score += 30
        red_flags.append({
            "severity": "high",
            "category": "URL",
            "title": "URL Obfuscation (@ Symbol)",
            "detail": "Contains an '@' inside the URL, often used to disguise the real destination host.",
        })
    if has_shortener:
        risk_score += 20
        red_flags.append({
            "severity": "medium",
            "category": "URL",
            "title": "Shortened URL Detected",
            "detail": "Uses a link shortener that hides the true destination website.",
        })
    if has_insecure_http and (credential_hits > 0 or urgency_hits > 0):
        risk_score += 15
        red_flags.append({
            "severity": "medium",
            "category": "Transport",
            "title": "Unencrypted HTTP Link with Sensitive Request",
            "detail": "Plain HTTP link paired with account security or login language.",
        })
    if credential_hits > 0:
        risk_score += min(30, credential_hits * 15)
        red_flags.append({
            "severity": "high",
            "category": "Credentials",
            "title": "Credential or Verification Harvesting",
            "detail": f"Detected {credential_hits} sensitive prompt(s): {', '.join(credential_terms[:4])}.",
        })
    if urgency_hits > 0:
        risk_score += min(25, urgency_hits * 12)
        red_flags.append({
            "severity": "medium",
            "category": "Social Engineering",
            "title": "Urgency / Account Lockout Pressure",
            "detail": f"Detected {urgency_hits} pressure cue(s): {', '.join(urgency_terms[:4])}.",
        })
    if financial_hits > 0 and (len(urls) > 0 or urgency_hits > 0 or credential_hits > 0):
        risk_score += min(15, financial_hits * 8)
        red_flags.append({
            "severity": "medium",
            "category": "Financial",
            "title": "Financial or Payment Lure",
            "detail": f"Detected {financial_hits} financial cue(s): {', '.join(financial_terms[:4])}.",
        })

    risk_score = min(100, risk_score)
    length = max(len(text_str), 1)
    digits = sum(c.isdigit() for c in text_str)
    uppers = sum(c.isupper() for c in text_str)
    exclamations = text_str.count("!")
    currencies = len(re.findall(r"[$£€₹]", text_str))

    numeric_features = [
        len(urls),
        has_ip_url,
        has_shortener,
        has_suspicious_tld,
        has_at_in_url,
        has_brand_impersonation,
        urgency_hits,
        credential_hits,
        financial_hits,
        digits / length,
        uppers / length,
        min(exclamations, 10),
        min(currencies, 10),
        float(np.log1p(length)),
    ]

    # Deduplicate overlapping highlight spans (keep longest / earliest)
    highlights.sort(key=lambda h: (h["start"], -(h["end"] - h["start"])))
    merged_highlights = []
    last_end = -1
    for h in highlights:
        if h["start"] >= last_end:
            merged_highlights.append(h)
            last_end = h["end"]

    return {
        "numeric_features": numeric_features,
        "risk_score": risk_score,
        "red_flags": red_flags,
        "urls": inspected_urls,
        "highlights": merged_highlights,
        "stats": {
            "length": len(text_str),
            "word_count": len(text_str.split()),
            "url_count": len(urls),
            "digit_ratio": round(digits / length, 4),
            "upper_ratio": round(uppers / length, 4),
        },
    }


class MessageFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.array(
            [analyze_phishing_signals(text)["numeric_features"] for text in X],
            dtype=float,
        )


def build_feature_union(max_word_features: int = 25000, max_char_features: int = 25000):
    return FeatureUnion([
        (
            "word_tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                sublinear_tf=True,
                min_df=2,
                max_features=max_word_features,
                strip_accents="unicode",
            ),
        ),
        (
            "char_tfidf",
            TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                sublinear_tf=True,
                min_df=3,
                max_features=max_char_features,
            ),
        ),
        (
            "signal_features",
            Pipeline([
                ("extract", MessageFeatureExtractor()),
                ("scale", MinMaxScaler(clip=True)),
            ]),
        ),
    ])


def build_ensemble_pipeline(max_word_features: int = 25000, max_char_features: int = 25000):
    clf_lr = LogisticRegression(
        C=4.0, class_weight="balanced", max_iter=1000, random_state=42
    )
    clf_svm = CalibratedClassifierCV(
        estimator=LinearSVC(C=1.0, class_weight="balanced", random_state=42),
        cv=3,
    )
    clf_cnb = ComplementNB(alpha=0.2)

    voting_clf = VotingClassifier(
        estimators=[("lr", clf_lr), ("svm", clf_svm), ("cnb", clf_cnb)],
        voting="soft",
        weights=[2, 3, 1],
    )
    return Pipeline([
        ("features", build_feature_union(max_word_features, max_char_features)),
        ("clf", voting_clf),
    ])


def predict_with_explanation(message: str, model) -> dict:
    """Run hybrid ML + Phishing Signal analysis and return rich JSON payload."""
    probs = model.predict_proba([message])[0]
    classes = list(model.classes_)
    prob_map = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}

    ml_label = max(prob_map, key=prob_map.get)
    sig = analyze_phishing_signals(message)
    risk_score = sig["risk_score"]

    # Hybrid escalation rule: strong URL/phishing indicators confirm/escalate phishing
    final_label = ml_label
    escalated = False
    if risk_score >= 55 and (
        prob_map.get("phishing", 0.0) >= 0.20 or prob_map.get("spam", 0.0) >= 0.25
    ):
        if final_label != "phishing":
            escalated = True
        final_label = "phishing"
    elif risk_score >= 70:
        if final_label != "phishing":
            escalated = True
        final_label = "phishing"

    # Unified 0-100 threat score blending ML malicious probability and phishing signals
    malicious_prob = prob_map.get("phishing", 0.0) * 100.0 + prob_map.get("spam", 0.0) * 65.0
    threat_score = int(round(min(100.0, max(malicious_prob, risk_score * 0.95))))
    if final_label == "ham" and risk_score < 25:
        threat_score = min(threat_score, 24)
    elif final_label == "phishing":
        threat_score = max(threat_score, 72)

    if final_label == "phishing":
        risk_level = "CRITICAL" if (risk_score >= 60 or prob_map.get("phishing", 0.0) >= 0.80) else "HIGH"
        verdict_summary = (
            "High-confidence phishing indicators detected. This message attempts to steal credentials, "
            "impersonate a trusted service, or lure you to a malicious link."
        )
        recommended_action = (
            "Do NOT click any links, download attachments, or reply with personal data. "
            "Report as phishing and verify directly on the official website."
        )
    elif final_label == "spam":
        risk_level = "MEDIUM"
        verdict_summary = (
            "Unsolicited promotional or bulk spam pattern detected based on text, n-gram, and structural cues."
        )
        recommended_action = (
            "Avoid replying or texting back shortcodes. Mark as spam and delete."
        )
    else:
        if risk_score >= 30:
            risk_level = "LOW"
            verdict_summary = (
                "Classified as legitimate (Ham), though minor cautionary signals were noted. Review links carefully."
            )
            recommended_action = "Appears safe overall, but double-check any embedded URLs before clicking."
        else:
            risk_level = "SAFE"
            verdict_summary = (
                "No spam or phishing threat patterns detected. Message structure and language look legitimate."
            )
            recommended_action = "Safe to read and respond normally."

    return {
        "prediction": final_label.upper(),
        "ml_prediction": ml_label.upper(),
        "escalated_by_signals": escalated,
        "confidence": round(prob_map[ml_label], 4),
        "probabilities": {
            "ham": prob_map.get("ham", 0.0),
            "spam": prob_map.get("spam", 0.0),
            "phishing": prob_map.get("phishing", 0.0),
        },
        "threat_score": threat_score,
        "phishing_risk_score": risk_score,
        "risk_level": risk_level,
        "verdict_summary": verdict_summary,
        "recommended_action": recommended_action,
        "red_flags": sig["red_flags"],
        "urls": sig["urls"],
        "highlights": sig["highlights"],
        "stats": sig["stats"],
    }
