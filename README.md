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
| **Site Blocking** | Phishing sites are blocked **before loading** with a full-screen interstitial warning page |
| **Auto-Retrain Feedback Loop** | Model learns from user corrections — auto-retrains after every 500 reports |
| **Weekly Digital Hygiene Report** | Tracks browsing habits locally and displays a visual dashboard with safety score, daily chart, and flagged domains |

---

## How It Works

```
User visits a URL
    ↓
Background script intercepts BEFORE page loads
    ↓
Sends URL to FastAPI backend → RandomForest extracts 30 features → predicts
    ↓
┌─ Safe → Page loads normally
└─ Phishing → Page BLOCKED, interstitial shown with:
       • Risk percentage gauge
       • SHAP-generated plain-English reasons
       • "Go Back to Safety" / "I understand, proceed" buttons
           ↓
   If user clicks "proceed" → feedback correction stored
       ↓
   After 500 corrections → MODEL AUTO-RETRAINS
       • Merges original Kaggle data + user corrections
       • Retrains RandomForest (200 trees)
       • Hot-reloads model (no restart needed)
       • Clears feedback file, cycle repeats
```

---

## Architecture

```
phishing_detector/
├── backend/
│   ├── main.py                  # FastAPI server with all endpoints
│   ├── train_url.py             # Train URL model on Kaggle dataset
│   ├── train_email.py           # Train email text model
│   ├── feedback_store.py        # Feedback CSV storage + auto-retrain logic
│   ├── models/
│   │   ├── url_model.py         # 30-feature URL extractor + prediction
│   │   ├── email_model.py       # TF-IDF email classifier
│   │   └── headers_check.py     # SPF/DKIM/Reply-To rule checks
│   └── explain/
│       └── shap_explainer.py    # SHAP explanations → plain English
├── extension/
│   ├── manifest.json            # Chrome Manifest V3
│   ├── background.js            # Intercepts navigation + logs scans
│   ├── content.js               # Injects warning banners on pages
│   ├── blocked.html / .js       # Full-page interstitial for blocked sites
│   ├── report.html / .js        # Weekly Digital Hygiene Report dashboard
│   ├── popup.html / .js         # Extension popup dashboard
│   └── styles.css               # All styling
└── data/                        # Kaggle dataset (not in git)
```

---

## Quick Start

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/swarnim-dev/sentinel-ai.git
cd sentinel-ai
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
| `POST` | `/feedback` | Submit a correction (triggers retrain at 500) |
| `GET` | `/feedback/status` | Check progress toward next auto-retrain |

### Example — Scan a URL

```bash
curl -X POST http://127.0.0.1:8000/predict/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/paypal-login/secure"}'
```

### Example — Check Retrain Progress

```bash
curl http://127.0.0.1:8000/feedback/status
# → {"feedback_count": 42, "retrain_threshold": 500, "progress_percent": 8.4}
```

---

## Auto-Retrain Feedback Loop

The model improves over time through user feedback:

1. When a user clicks **"I understand, proceed"** on a blocked page, a correction is stored with the URL's 30 extracted features
2. Corrections accumulate in `backend/feedback_log.csv`
3. At **500 corrections**, the system automatically:
   - Merges the original 11K Kaggle samples with the 500 user-labeled corrections
   - Retrains the RandomForest classifier (200 trees)
   - Saves the updated model and hot-reloads it (no server restart)
   - Clears the feedback file — the cycle resets for the next 500

---

## Weekly Digital Hygiene Report

Click **"View Weekly Report"** in the extension popup to see:

- **Stat cards** — Total scans, safe sites, threats blocked, unique domains
- **Safety Score** — Color-coded ring (Excellent / Good / Fair / Poor)
- **Daily bar chart** — Safe vs phishing breakdown for the last 7 days
- **Top flagged domains** — Riskiest sites you've encountered

All data is stored **locally in Chrome storage** — nothing is sent to any server.

---

## Tech Stack

- **Backend:** Python, FastAPI, scikit-learn, SHAP, Pandas
- **ML Models:** RandomForest (URL), Naive Bayes + TF-IDF (Email)
- **Extension:** JavaScript, Chrome Manifest V3
- **Dataset:** [Kaggle Phishing Website Detector](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)

---

## License

MIT
