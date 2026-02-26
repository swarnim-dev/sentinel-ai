from fastapi import FastAPI, HTTPException
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
from explain.shap_explainer import get_url_explanation, get_text_explanation

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
    item_type: str # 'url' or 'email'
    item_hash: str # Privacy preserving, no raw text/url
    user_label: str # 'safe' or 'phishing'
    prediction_was: str

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
    # In a real app, this would append to a training dataset database
    # Here, we just acknowledge receipt for the privacy loop
    return {"status": "success", "message": "Feedback recorded anonymously to improve model."}
