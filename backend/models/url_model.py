"""
URL Feature Extraction and Prediction using the trained RandomForest model.
Feature names are aligned to the Kaggle "Phishing Website Detector" dataset:
  UsingIP, LongURL, ShortURL, Symbol@, Redirecting//, PrefixSuffix-,
  SubDomains, HTTPS, DomainRegLen, Favicon, NonStdPort, HTTPSDomainURL,
  RequestURL, AnchorURL, LinksInScriptTags, ServerFormHandler, InfoEmail,
  AbnormalURL, WebsiteForwarding, StatusBarCust, DisableRightClick,
  UsingPopupWindow, IframeRedirection, AgeofDomain, DNSRecording,
  WebsiteTraffic, PageRank, GoogleIndex, LinksPointingToPage, StatsReport
"""

import re
import joblib
import os
import urllib.parse
import pandas as pd
import numpy as np


class URLModel:
    def __init__(self, model_path="url_model.pkl", features_path="url_features.pkl"):
        self.model_path = model_path
        self.features_path = features_path
        self.model = None
        self.feature_names = None
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print(f"Loaded URL model from {self.model_path}")
        else:
            print(f"Warning: URL model {self.model_path} not found. Please train first.")

        if os.path.exists(self.features_path):
            self.feature_names = joblib.load(self.features_path)
            print(f"Loaded {len(self.feature_names)} feature names")
        else:
            print("Warning: url_features.pkl not found. Feature alignment may fail.")

    def extract_features(self, url: str) -> pd.DataFrame:
        """
        Extract the 30 features expected by the Kaggle dataset model from a raw URL string.
        Values follow the dataset convention: 1 = legitimate, -1 = phishing, 0 = suspicious.
        """
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or ""
        path = parsed.path or ""
        scheme = parsed.scheme or ""

        features = {
            # 1. UsingIP – Is the host an IP address?
            "UsingIP": -1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 1,

            # 2. LongURL – Length of the full URL
            "LongURL": 1 if len(url) < 54 else (0 if len(url) <= 75 else -1),

            # 3. ShortURL – Is a URL shortener used?
            "ShortURL": -1 if re.search(
                r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|short\.to", url, re.I
            ) else 1,

            # 4. Symbol@ – Does the URL contain '@'?
            "Symbol@": -1 if "@" in url else 1,

            # 5. Redirecting// – Double-slash redirect after protocol
            "Redirecting//": -1 if url.rfind("//") > 7 else 1,

            # 6. PrefixSuffix- – Hyphen in the domain part
            "PrefixSuffix-": -1 if "-" in domain else 1,

            # 7. SubDomains – Number of dots in host
            "SubDomains": (
                1 if domain.count(".") <= 1
                else 0 if domain.count(".") == 2
                else -1
            ),

            # 8. HTTPS – Is the connection over HTTPS?
            "HTTPS": 1 if scheme == "https" else -1,

            # 9. DomainRegLen – Cannot determine without WHOIS, default suspicious
            "DomainRegLen": -1,

            # 10. Favicon – Cannot determine statically, default suspicious
            "Favicon": -1,

            # 11. NonStdPort – Non-standard port in URL
            "NonStdPort": (
                -1 if parsed.port and parsed.port not in (80, 443) else 1
            ),

            # 12. HTTPSDomainURL – 'https' token inside the domain itself (spoofing trick)
            "HTTPSDomainURL": -1 if "https" in domain.lower() else 1,

            # 13. RequestURL – Cannot determine without page content, default suspicious
            "RequestURL": -1,

            # 14. AnchorURL – Cannot determine without page content
            "AnchorURL": -1,

            # 15. LinksInScriptTags – Cannot determine without page content
            "LinksInScriptTags": -1,

            # 16. ServerFormHandler – Cannot determine without page content
            "ServerFormHandler": -1,

            # 17. InfoEmail – Does the page submit data to an email?
            "InfoEmail": -1 if "mailto:" in url.lower() else 1,

            # 18. AbnormalURL – Domain not in the URL body (simplified heuristic)
            "AbnormalURL": -1,

            # 19. WebsiteForwarding – Redirect count unknown, default safe
            "WebsiteForwarding": 0,

            # 20. StatusBarCust – Cannot determine without JS analysis
            "StatusBarCust": 1,

            # 21. DisableRightClick – Cannot determine without JS analysis
            "DisableRightClick": 1,

            # 22. UsingPopupWindow – Cannot determine without JS analysis
            "UsingPopupWindow": 1,

            # 23. IframeRedirection – Cannot determine without page content
            "IframeRedirection": 1,

            # 24. AgeofDomain – Would need WHOIS, default suspicious
            "AgeofDomain": -1,

            # 25. DNSRecording – Would need DNS lookup, default present
            "DNSRecording": 1,

            # 26. WebsiteTraffic – Would need Alexa/SimilarWeb, default suspicious
            "WebsiteTraffic": -1,

            # 27. PageRank – Would need external API, default suspicious
            "PageRank": -1,

            # 28. GoogleIndex – Assume indexed
            "GoogleIndex": 1,

            # 29. LinksPointingToPage – Would need backlink data, default suspicious
            "LinksPointingToPage": 0,

            # 30. StatsReport – Would need PhishTank/StopBadware, default safe
            "StatsReport": 1,
        }

        df = pd.DataFrame([features])

        # Align columns to the order the model was trained on
        if self.feature_names:
            for col in self.feature_names:
                if col not in df.columns:
                    df[col] = 0
            df = df[self.feature_names]

        return df

    def predict(self, url: str) -> dict:
        if not self.model:
            return {"risk_score": 0.5, "prediction": "unknown", "error": "Model not loaded"}

        features_df = self.extract_features(url)
        prob = self.model.predict_proba(features_df)[0]

        # Class 0 = safe, Class 1 = phishing (as mapped during training)
        risk_score = round(float(prob[1]) if len(prob) > 1 else float(prob[0]), 3)
        prediction = "phishing" if risk_score > 0.5 else "safe"

        return {
            "risk_score": risk_score,
            "prediction": prediction,
            "url": url,
        }
