"""
SHAP-based and heuristic explainability layer.
Translates model feature importances into plain-English, student-friendly reasons.
"""

import shap
import numpy as np

# ─────────────────────────────────────────────
#  Plain English explanations keyed by the
#  EXACT Kaggle dataset column names
# ─────────────────────────────────────────────
FEATURE_EXPLANATIONS = {
    # URL structural features
    "UsingIP":              "The link uses a raw IP address instead of a domain name — a common phishing trick to bypass filters.",
    "LongURL":              "The URL is unusually long, which can be used to hide the real destination.",
    "ShortURL":             "The link uses a URL shortener (e.g. bit.ly), masking where it actually leads.",
    "Symbol@":              "The URL contains an '@' symbol, which makes browsers ignore everything before it — a classic redirect trick.",
    "Redirecting//":        "The URL has an unexpected double-slash redirect, possibly sending you to a different site.",
    "PrefixSuffix-":        "The domain contains a hyphen (e.g. paypal-login.com), often used to imitate legitimate brands.",
    "SubDomains":           "The URL has multiple subdomains (e.g. secure.login.bank.example.com), making it look official when it isn't.",
    "HTTPS":                "The site does not use HTTPS, so your connection is not encrypted.",
    "DomainRegLen":         "The domain was registered for a very short period — phishing sites are often short-lived.",
    "Favicon":              "The site loads its favicon from a different domain, which is unusual for legitimate sites.",
    "NonStdPort":           "The URL uses a non-standard port, which legitimate websites rarely do.",
    "HTTPSDomainURL":       "The word 'https' appears inside the domain name itself — a spoofing trick to look secure.",
    "RequestURL":           "External resources on this page are loaded from suspicious origins.",
    "AnchorURL":            "Links on this page point to a different domain than expected.",
    "LinksInScriptTags":    "Script or link tags reference external, potentially untrusted sources.",
    "ServerFormHandler":    "Form data may be submitted to a suspicious or blank destination.",
    "InfoEmail":            "The page sends data to an email address instead of a secure server.",
    "AbnormalURL":          "The URL structure is abnormal compared to the domain it claims to be.",
    "WebsiteForwarding":    "The page redirects you through multiple URLs — commonly used in phishing chains.",
    "StatusBarCust":        "The site customises the browser status bar to hide the true link destination.",
    "DisableRightClick":    "Right-click is disabled, preventing you from inspecting the page — a phishing red flag.",
    "UsingPopupWindow":     "The site uses pop-up windows, which can be used to steal credentials.",
    "IframeRedirection":    "The page uses hidden iframes that may load malicious content.",
    "AgeofDomain":          "The domain is very new — most phishing sites are created days before an attack.",
    "DNSRecording":         "No DNS record was found for this domain, suggesting it may be fake.",
    "WebsiteTraffic":       "The site has very low traffic, which is uncommon for legitimate organisations.",
    "PageRank":             "The site has a very low PageRank, indicating low trust and authority.",
    "GoogleIndex":          "The site is not indexed by Google — legitimate sites almost always are.",
    "LinksPointingToPage":  "Very few or no external sites link to this page — a sign of low trust.",
    "StatsReport":          "This URL appears in known phishing/malware blacklists.",
}

# Generic email text keywords
EMAIL_TEXT_EXPLANATIONS = {
    "urgent":      "The email creates a false sense of urgency (e.g. 'urgent', 'immediately').",
    "verify":      "The email asks you to verify your account details — a classic phishing tactic.",
    "suspended":   "The email threatens account suspension to pressure you into acting quickly.",
    "password":    "The email mentions passwords or login credentials.",
    "login":       "The email includes an unexpected login link or prompt.",
    "update":      "The email requests an unexpected update of your personal information.",
    "account":     "The email refers to your 'account' combined with urgent language.",
    "click":       "The email pressures you to click a link immediately.",
    "immediately": "The email demands immediate action — a pressure tactic.",
}


def get_url_explanation(model, features_df):
    """Return a list of plain-English reasons a URL was flagged, using SHAP TreeExplainer."""
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features_df)

        # Binary classification: shap_values may be a list [class_0, class_1]
        if isinstance(shap_values, list):
            sv = shap_values[1][0]
        else:
            sv = shap_values[0]

        feature_names = features_df.columns
        contributions = sorted(zip(feature_names, sv), key=lambda x: x[1], reverse=True)

        reasons = []
        for feat, val in contributions[:5]:
            if val > 0.01:
                reasons.append(
                    FEATURE_EXPLANATIONS.get(feat, f"Suspicious indicator: {feat}")
                )

        return reasons if reasons else ["The overall URL pattern matches known phishing websites."]
    except Exception as e:
        print(f"SHAP Explainer Error: {e}")
        return ["The URL matches patterns commonly seen in phishing links."]


def get_text_explanation(vectorizer, model, text):
    """Explain an email text prediction using TF-IDF feature log-probabilities."""
    try:
        X = vectorizer.transform([text])
        feature_names = vectorizer.get_feature_names_out()
        nonzero_indices = X.nonzero()[1]

        if hasattr(model, "feature_log_prob_"):
            phishing_probs = model.feature_log_prob_[1]
            safe_probs = model.feature_log_prob_[0]
            diff = phishing_probs - safe_probs

            text_word_diffs = [(feature_names[i], diff[i]) for i in nonzero_indices]
            text_word_diffs.sort(key=lambda x: x[1], reverse=True)

            reasons = []
            for word, score in text_word_diffs[:3]:
                if score > 0:
                    reasons.append(
                        EMAIL_TEXT_EXPLANATIONS.get(
                            word,
                            f"Use of suspicious or manipulative language (e.g. '{word}').",
                        )
                    )
            return list(set(reasons)) if reasons else ["The wording and tone match known phishing emails."]
    except Exception as e:
        print(f"Text Explainer Error: {e}")

    return ["The wording matches patterns commonly seen in phishing emails."]
