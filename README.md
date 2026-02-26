# Sentinel AI — Phishing Early Warning System

An AI-powered browser extension that detects phishing URLs and suspicious emails in real-time using explainable machine learning. Built for students interested in cybersecurity.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green) ![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest%20V3-yellow)

---

## Features

| Feature | Description |
|---|---|
| **URL Classifier** | RandomForest trained on the Kaggle "Phishing Website Detector" dataset (11K+ samples, 97% accuracy) |
| **Email Text Scanner** | TF-IDF + Naive Bayes model detects phishing language in email bodies |
| **Header Anomaly Checks** | Detects SPF/DKIM failures and From/Reply-To mismatches |
| **SHAP Explainability** | Every prediction comes with plain-English reasons (e.g. "The URL uses a raw IP address instead of a domain name") |
| **Site Blocking** | Phishing sites are blocked before loading, with a full interstitial page |
| **Privacy Feedback Loop** | Users can mark predictions as safe/phishing without exposing raw data |

---

## Architecture

```
phishing_detector/
├── backend/
│   ├── main.py                  # FastAPI server (/predict/url, /predict/email, /feedback)
│   ├── train_url.py             # Train URL model on Kaggle dataset
│   ├── train_email.py           # Train email text model
│   ├── models/
│   │   ├── url_model.py         # URL feature extractor + prediction
│   │   ├── email_model.py       # TF-IDF email classifier
│   │   └── headers_check.py     # SPF/DKIM/Reply-To rule checks
│   └── explain/
│       └── shap_explainer.py    # SHAP explanations → plain English
├── extension/
│   ├── manifest.json            # Chrome Manifest V3
│   ├── background.js            # Intercepts navigation, calls API
│   ├── content.js               # Injects warning banners on pages
│   ├── blocked.html / .js       # Full-page interstitial for blocked sites
│   ├── popup.html / .js         # Extension popup dashboard
│   └── styles.css               # All styling
└── data/                        # Kaggle dataset (not in git)
```

---

## Quick Start

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/<your-username>/phishing-detector.git
cd phishing-detector
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Download Dataset

Download the [Phishing Website Detector](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector) dataset from Kaggle and place `phishing.csv` in the `data/` folder.

### 3. Train Models

```bash
cd backend
python train_url.py      # Trains RandomForest URL classifier (~97% accuracy)
python train_email.py    # Trains TF-IDF email classifier
```

### 4. Start the API

```bash
cd backend
uvicorn main:app --port 8000
```

### 5. Load the Extension

1. Open `chrome://extensions/` in Chrome/Brave/Edge
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. The Sentinel icon will appear in your toolbar

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/predict/url` | Scan a URL → risk score + SHAP reasons |
| `POST` | `/predict/email` | Scan email body + headers → risk score + reasons |
| `POST` | `/feedback` | Submit anonymous feedback to improve the model |

### Example

```bash
curl -X POST http://127.0.0.1:8000/predict/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/paypal-login/secure"}'
```

---

## Tech Stack

- **Backend:** Python, FastAPI, scikit-learn, SHAP, Pandas
- **ML Models:** RandomForest (URL), Naive Bayes + TF-IDF (Email)
- **Extension:** JavaScript, Chrome Manifest V3
- **Dataset:** [Kaggle Phishing Website Detector](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)

---

## License

MIT
