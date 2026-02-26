"""
Train a RandomForest classifier on the Kaggle Phishing Website Detector dataset.
Expects ../data/phishing.csv with 30 feature columns + 'class' target.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os

DATA_DIR = "../data"
CSV_PATH = os.path.join(DATA_DIR, "phishing.csv")
MODEL_PATH = "url_model.pkl"
FEATURES_PATH = "url_features.pkl"

def train_model():
    print(f"Loading data from {CSV_PATH}...")
    df = pd.read_csv(CSV_PATH)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # Target column is 'class' in this dataset: -1 = phishing, 1 = safe
    target_col = "class"

    # Drop the 'Index' column if present (it's just a row id)
    drop_cols = [target_col]
    if "Index" in df.columns:
        drop_cols.append("Index")

    X = df.drop(columns=drop_cols)
    # Map: -1 (phishing) -> 1, 1 (safe) -> 0  (1 = bad for risk score)
    y = df[target_col].map({-1: 1, 1: 0})

    # Save feature names for inference alignment
    feature_names = X.columns.tolist()
    joblib.dump(feature_names, FEATURES_PATH)
    print(f"Saved {len(feature_names)} feature names to {FEATURES_PATH}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Test set:     {X_test.shape[0]} samples")
    print("Training RandomForestClassifier (200 trees)...")

    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    acc = clf.score(X_test, y_test)
    print(f"\nTest accuracy: {acc:.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, clf.predict(X_test), target_names=["Safe", "Phishing"]))

    joblib.dump(clf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
