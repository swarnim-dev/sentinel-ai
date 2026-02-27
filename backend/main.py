from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict

import os
import sys

# Add current directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.url_model import URLModel
from models.email_model import EmailModel
from models.headers_check import check_headers_for_anomalies
from models.file_scanner import scan_file
from explain.shap_explainer import get_url_explanation, get_text_explanation

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

app = FastAPI(
    title="AI Phishing Detector API",
    description="Early warning system backend for URLs and Emails with explainability."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For extension, we allow all or specify extension id
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Models
url_model_instance = URLModel()
email_model_instance = EmailModel()

# Pydantic Schemas
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    body_text: str
    headers: Optional[Dict[str, str]] = {}

class FeedbackRequest(BaseModel):
    item_type: str        # 'url' or 'email'
    url: str = ""         # The actual URL for feature extraction
    user_label: str       # 'safe' or 'phishing'
    prediction_was: str   # What the model predicted

@app.post("/predict/url")
async def predict_url(req: URLRequest):
    # Base prediction
    result = url_model_instance.predict(req.url)
    
    if "error" in result:
        return result # E.g., model not loaded
        
    # Explainability
    if result["prediction"] == "phishing" and url_model_instance.model:
        features_df = url_model_instance.extract_features(req.url)
        reasons = get_url_explanation(url_model_instance.model, features_df)
    else:
        reasons = []
        
    result["explanations"] = reasons
    return result

@app.post("/predict/email")
async def predict_email(req: EmailRequest):
    # Check headers
    header_res = check_headers_for_anomalies(req.headers)
    
    # Check text
    text_res = email_model_instance.predict(req.body_text)
    
    if "error" in text_res:
        text_res = {"risk_score": 0.0, "prediction": "unknown"}
    
    # Combine scores (simple weighted average or overriding logic)
    text_risk = text_res["risk_score"]
    header_risk = header_res["header_risk_score"]
    
    # If headers are highly risky (e.g. 0.8 fails verification), it's bad.
    combined_risk = max(text_risk, header_risk)
    prediction = "phishing" if combined_risk > 0.5 else "safe"
    
    explanations = header_res["anomalies_detected"]
    
    # Add text explainability if risky
    if text_risk > 0.5 and email_model_instance.model and email_model_instance.vectorizer:
        text_reasons = get_text_explanation(
            email_model_instance.vectorizer, 
            email_model_instance.model, 
            req.body_text
        )
        explanations.extend(text_reasons)
        
    return {
        "url_or_subject": req.headers.get("Subject", "Email"),
        "risk_score": round(combined_risk, 2),
        "prediction": prediction,
        "text_risk": round(text_risk, 2),
        "header_risk": round(header_risk, 2),
        "explanations": explanations
    }

@app.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    from feedback_store import store_feedback, count_feedback, RETRAIN_THRESHOLD

    if req.item_type == "url" and req.url:
        # Extract features from the URL so we can retrain on them
        features_df = url_model_instance.extract_features(req.url)
        features_dict = features_df.iloc[0].to_dict()

        total = store_feedback(
            url=req.url,
            features_dict=features_dict,
            user_label=req.user_label,
            prediction_was=req.prediction_was
        )

        # If retrain was triggered, hot-reload the model
        if total >= RETRAIN_THRESHOLD:
            url_model_instance.load_model()

        return {
            "status": "success",
            "message": f"Feedback stored. {total}/{RETRAIN_THRESHOLD} corrections until next retrain.",
            "feedback_count": total,
            "retrain_threshold": RETRAIN_THRESHOLD
        }
    else:
        return {
            "status": "success",
            "message": "Feedback acknowledged (email feedback is noted but not used for retraining yet)."
        }

@app.get("/feedback/status")
async def feedback_status():
    from feedback_store import count_feedback, RETRAIN_THRESHOLD
    total = count_feedback()
    return {
        "feedback_count": total,
        "retrain_threshold": RETRAIN_THRESHOLD,
        "progress_percent": round((total / RETRAIN_THRESHOLD) * 100, 1)
    }

@app.post("/scan/file")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """Scan an uploaded file (max 10MB) for malicious indicators."""
    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size is {MAX_FILE_SIZE // (1024*1024)} MB."
        )

    result = scan_file(file.filename, content)
    return result

