import joblib
import os
import pandas as pd

class EmailModel:
    def __init__(self, vectorizer_path="email_vectorizer.pkl", model_path="email_model.pkl"):
        self.vectorizer_path = vectorizer_path
        self.model_path = model_path
        self.vectorizer = None
        self.model = None
        self.load_models()

    def load_models(self):
        if os.path.exists(self.vectorizer_path) and os.path.exists(self.model_path):
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.model = joblib.load(self.model_path)
            print(f"Loaded Email models from {self.model_path}")
        else:
            print(f"Warning: Email models {self.model_path} not found. Please run train_email.py")

    def predict(self, text):
        if not self.model or not self.vectorizer:
            return {"risk_score": 0.5, "prediction": "unknown", "error": "Model not loaded"}
        
        # We need generic features for SHAP. The TF-IDF itself provides feature explanations.
        # But for direct prediction:
        X = self.vectorizer.transform([text])
        prob = self.model.predict_proba(X)[0]
        
        # Assuming binary: 0 = safe, 1 = phishing
        risk_score = float(prob[1]) if len(prob) > 1 else float(prob[0])
        prediction = "phishing" if risk_score > 0.5 else "safe"
        
        return {
            "risk_score": risk_score,
            "prediction": prediction
        }
