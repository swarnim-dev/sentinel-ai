import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
import joblib

VECTORIZER_PATH = "email_vectorizer.pkl"
MODEL_PATH = "email_model.pkl"

def train_dummy_model():
    """
    Trains a basic TF-IDF + Naive Bayes/Logistic Regression model on a simple dataset.
    In a real scenario, we would use enron-spam or similar.
    """
    print("Training basic email text classifier...")
    
    # Minimal dummy dataset to allow testing the pipeline.
    # We simulate a mix of safe and phishing text.
    data = [
        {"text": "Hey John, can we meet tomorrow for lunch?", "label": 0},
        {"text": "Your account has been suspended. Please click here to verify your identity.", "label": 1},
        {"text": "URGENT: Invoice attached. Please pay immediately.", "label": 1},
        {"text": "Meeting notes from today's sprint planning.", "label": 0},
        {"text": "Win a free iPhone! Click the link below to claim your prize.", "label": 1},
        {"text": "Please review the attached PR for the new feature.", "label": 0},
        {"text": "Final warning: Your mailbox is full. Upgrade storage now.", "label": 1},
        {"text": "Hey mom, just checking in. Call me later.", "label": 0},
        {"text": "Verify your PayPal account immediately or it will be locked.", "label": 1},
        {"text": "Thanks for the feedback, we will look into it.", "label": 0}
    ]
    df = pd.DataFrame(data)
    
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X = vectorizer.fit_transform(df['text'])
    y = df['label']
    
    clf = MultinomialNB()
    clf.fit(X, y)
    
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(clf, MODEL_PATH)
    
    print(f"Saved {VECTORIZER_PATH} and {MODEL_PATH}")

if __name__ == "__main__":
    train_dummy_model()
