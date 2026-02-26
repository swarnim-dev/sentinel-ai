"""
Feedback storage and auto-retrain logic.
Stores user corrections to a CSV. When the count reaches RETRAIN_THRESHOLD,
automatically retrains the URL model on the original data + corrections,
then clears the feedback file.
"""

import csv
import os
import threading
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

FEEDBACK_FILE = os.path.join(os.path.dirname(__file__), "feedback_log.csv")
RETRAIN_THRESHOLD = 500
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
CSV_PATH = os.path.join(DATA_DIR, "phishing.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_model.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "url_features.pkl")

FEEDBACK_COLUMNS = [
    "url", "user_label", "prediction_was",
    # All 30 features extracted at prediction time
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport"
]


def _ensure_file():
    """Create the feedback CSV with headers if it doesn't exist."""
    if not os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEEDBACK_COLUMNS)


def count_feedback():
    """Return the number of feedback entries currently stored."""
    _ensure_file()
    with open(FEEDBACK_FILE, "r") as f:
        return max(0, sum(1 for _ in f) - 1)  # subtract header


def store_feedback(url: str, features_dict: dict, user_label: str, prediction_was: str):
    """
    Append one feedback row. Returns the new total count.
    If count >= RETRAIN_THRESHOLD, triggers retraining in a background thread.
    """
    _ensure_file()

    row = [url, user_label, prediction_was]
    for col in FEEDBACK_COLUMNS[3:]:  # the 30 feature columns
        row.append(features_dict.get(col, 0))

    with open(FEEDBACK_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)

    total = count_feedback()
    print(f"[Feedback] Stored correction #{total}: {user_label} (was {prediction_was})")

    if total >= RETRAIN_THRESHOLD:
        print(f"[Feedback] Threshold reached ({total} >= {RETRAIN_THRESHOLD}). Triggering retrain...")
        thread = threading.Thread(target=retrain_with_feedback, daemon=True)
        thread.start()

    return total


def retrain_with_feedback():
    """
    Merge original Kaggle data with feedback corrections, retrain the model,
    save the new model, and clear the feedback file.
    """
    try:
        print("[Retrain] Starting auto-retrain...")

        # Load original data
        original_df = pd.read_csv(CSV_PATH)
        target_col = "class"
        drop_cols = [target_col]
        if "Index" in original_df.columns:
            drop_cols.append("Index")

        X_orig = original_df.drop(columns=drop_cols)
        y_orig = original_df[target_col].map({-1: 1, 1: 0})

        # Load feedback data
        feedback_df = pd.read_csv(FEEDBACK_FILE)
        feature_cols = FEEDBACK_COLUMNS[3:]  # The 30 feature columns

        X_feedback = feedback_df[feature_cols].astype(float)
        # user_label: "phishing" -> 1, "safe" -> 0
        y_feedback = feedback_df["user_label"].map({"phishing": 1, "safe": 0})

        # Align columns
        for col in X_orig.columns:
            if col not in X_feedback.columns:
                X_feedback[col] = 0
        X_feedback = X_feedback[X_orig.columns]

        # Merge
        X_combined = pd.concat([X_orig, X_feedback], ignore_index=True)
        y_combined = pd.concat([y_orig, y_feedback], ignore_index=True)

        print(f"[Retrain] Combined dataset: {len(X_combined)} samples "
              f"({len(X_orig)} original + {len(X_feedback)} feedback)")

        # Train
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
        )

        clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)

        acc = clf.score(X_test, y_test)
        print(f"[Retrain] New model accuracy: {acc:.4f}")

        # Save new model
        joblib.dump(clf, MODEL_PATH)
        joblib.dump(X_orig.columns.tolist(), FEATURES_PATH)
        print(f"[Retrain] Model saved to {MODEL_PATH}")

        # Clear feedback file (reset for next batch)
        with open(FEEDBACK_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEEDBACK_COLUMNS)
        print(f"[Retrain] Feedback file cleared. Ready for next {RETRAIN_THRESHOLD} corrections.")

        return True

    except Exception as e:
        print(f"[Retrain] ERROR: {e}")
        return False
