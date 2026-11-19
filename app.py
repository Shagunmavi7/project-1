"""
MailGuard AI — FastAPI Server for High-Accuracy Spam & Phishing Detection.
Serves both the REST API and the premium frontend dashboard.
"""

import csv
import io
import json
from pathlib import Path
from typing import Optional

import joblib
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ml.features import predict_with_explanation

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
ARTIFACT_DIR = BASE_DIR / "model_artifacts"
MODEL_PATH = ARTIFACT_DIR / "spam_phishing_model.joblib"
METRICS_PATH = ARTIFACT_DIR / "metrics.json"

app = FastAPI(
    title="MailGuard AI — Spam & Phishing Detection API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_model = None
_metrics = None


def get_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise HTTPException(
                status_code=503,
                detail="Trained model not found. Run `python ml/train.py` first.",
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def get_metrics():
    global _metrics
    if _metrics is None and METRICS_PATH.exists():
        _metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    return _metrics or {}


class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=25000)
    subject: Optional[str] = Field(default="", max_length=500)


class BatchAnalyzeRequest(BaseModel):
    messages: list[str] = Field(..., min_length=1, max_length=500)


@app.on_event("startup")
def startup_load():
    if MODEL_PATH.exists():
        get_model()
    get_metrics()


@app.get("/api/health")
def health():
    metrics = get_metrics()
    three_class = metrics.get("three_class", {})
    return {
        "status": "ok" if MODEL_PATH.exists() else "model_missing",
        "model_loaded": _model is not None or MODEL_PATH.exists(),
        "accuracy": three_class.get("accuracy"),
        "macro_f1": three_class.get("macro_f1"),
        "classes": ["ham", "spam", "phishing"],
    }


@app.get("/api/metrics")
def metrics_endpoint():
    metrics = get_metrics()
    if not metrics:
        raise HTTPException(status_code=404, detail="Metrics not generated yet.")
    return metrics


@app.post("/api/analyze")
def analyze_single(req: AnalyzeRequest):
    full_text = req.message.strip()
    if req.subject and req.subject.strip():
        full_text = f"Subject: {req.subject.strip()}\n\n{full_text}"
    if not full_text:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    model = get_model()
    result = predict_with_explanation(full_text, model)
    result["analyzed_text"] = full_text
    return result


@app.post("/api/analyze-batch")
def analyze_batch(req: BatchAnalyzeRequest):
    model = get_model()
    items = []
    counts = {"HAM": 0, "SPAM": 0, "PHISHING": 0}
    for idx, raw_msg in enumerate(req.messages, start=1):
        msg = raw_msg.strip()
        if not msg:
            continue
        res = predict_with_explanation(msg, model)
        counts[res["prediction"]] = counts.get(res["prediction"], 0) + 1
        items.append({
            "index": idx,
            "preview": msg[:140] + ("..." if len(msg) > 140 else ""),
            "message": msg,
            "prediction": res["prediction"],
            "risk_level": res["risk_level"],
            "threat_score": res["threat_score"],
            "phishing_risk_score": res["phishing_risk_score"],
            "probabilities": res["probabilities"],
            "red_flag_count": len(res["red_flags"]),
            "top_flag": res["red_flags"][0]["title"] if res["red_flags"] else "None",
        })
    return {
        "total": len(items),
        "summary": counts,
        "results": items,
    }


@app.post("/api/analyze-csv")
async def analyze_csv(file: UploadFile = File(...), limit: int = 200):
    model = get_model()
    raw_bytes = await file.read()
    try:
        decoded = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not decode CSV: {exc}")

    reader = csv.DictReader(io.StringIO(decoded))
    fieldnames = reader.fieldnames or []
    # Find message column automatically
    msg_col = None
    for candidate in ("Message", "message", "Email Text", "email_text", "text", "Text", "body", "Body", "content"):
        if candidate in fieldnames:
            msg_col = candidate
            break
    if msg_col is None and fieldnames:
        msg_col = fieldnames[-1]
    if msg_col is None:
        raise HTTPException(status_code=400, detail="CSV appears to be empty or has no header row.")

    items = []
    counts = {"HAM": 0, "SPAM": 0, "PHISHING": 0}
    for idx, row in enumerate(reader, start=1):
        if len(items) >= max(1, min(limit, 500)):
            break
        msg = (row.get(msg_col) or "").strip()
        if not msg:
            continue
        res = predict_with_explanation(msg, model)
        counts[res["prediction"]] = counts.get(res["prediction"], 0) + 1
        items.append({
            "index": idx,
            "preview": msg[:140] + ("..." if len(msg) > 140 else ""),
            "message": msg,
            "prediction": res["prediction"],
            "risk_level": res["risk_level"],
            "threat_score": res["threat_score"],
            "phishing_risk_score": res["phishing_risk_score"],
            "probabilities": res["probabilities"],
            "red_flag_count": len(res["red_flags"]),
            "top_flag": res["red_flags"][0]["title"] if res["red_flags"] else "None",
        })

    return {
        "filename": file.filename,
        "detected_column": msg_col,
        "total": len(items),
        "summary": counts,
        "results": items,
    }


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_index():
    return FileResponse(STATIC_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
