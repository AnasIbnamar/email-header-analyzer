import os
import json
import pickle
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")


def extract_features(report):
    """
    Convert a report dict into a numeric feature vector for ML.
    These are the signals our model learns from.
    """
    features = []

    # SPF features
    spf_status = report.get("spf", {}).get("status", "")
    spf_verdict = report.get("spf", {}).get("verdict", "")
    features.append(1 if spf_status == "found" else 0)
    features.append(1 if spf_verdict == "strict" else 0)
    features.append(1 if spf_verdict == "soft_fail" else 0)
    features.append(1 if spf_verdict == "dangerous" else 0)

    # DMARC features
    dmarc_status = report.get("dmarc", {}).get("status", "")
    dmarc_policy = report.get("dmarc", {}).get("policy", "")
    features.append(1 if dmarc_status == "found" else 0)
    features.append(1 if dmarc_policy == "reject" else 0)
    features.append(1 if dmarc_policy == "quarantine" else 0)
    features.append(1 if dmarc_policy == "none" else 0)

    # DKIM features
    features.append(1 if report.get("dkim", {}).get("present", False) else 0)

    # Spoofing features
    warnings = report.get("spoofing_warnings", [])
    features.append(len(warnings))
    features.append(1 if any("Reply-To" in w for w in warnings) else 0)
    features.append(1 if any("Return-Path" in w for w in warnings) else 0)
    features.append(1 if any("Message-ID" in w for w in warnings) else 0)

    # IP reputation features
    geo = report.get("geo", [])
    malicious_count = sum(1 for g in geo if g.get("abuse", {}).get("verdict") == "malicious")
    suspicious_count = sum(1 for g in geo if g.get("abuse", {}).get("verdict") == "suspicious")
    max_abuse_score  = max((g.get("abuse", {}).get("abuse_score", 0) for g in geo), default=0)
    has_tor = any(g.get("abuse", {}).get("is_tor", False) for g in geo)

    features.append(malicious_count)
    features.append(suspicious_count)
    features.append(max_abuse_score / 100.0)
    features.append(1 if has_tor else 0)

    # Provider features
    provider = report.get("provider", {})
    provider_risk = provider.get("risk", "neutral")
    features.append(1 if provider_risk == "high" else 0)
    features.append(1 if provider_risk == "medium" else 0)
    features.append(1 if provider_risk == "low" else 0)
    provider_type = provider.get("type", "")
    features.append(1 if provider_type == "script" else 0)
    features.append(1 if provider_type == "esp" else 0)

    # Delivery chain features
    chain = report.get("parsed", {}).get("received_chain", [])
    features.append(len(chain))
    features.append(1 if len(chain) == 0 else 0)

    # Existing rule-based score as a feature
    features.append(report.get("risk_score", 0) / 100.0)

    return np.array(features, dtype=float)


def build_training_data():
    """
    Build a labeled training dataset from known patterns.
    Labels: 0 = clean, 1 = suspicious, 2 = malicious
    """
    X = []
    y = []

    # --- MALICIOUS examples (label=2) ---

    # Classic phishing: no SPF, no DMARC, no DKIM, PHPMailer, Reply-To mismatch
    X.append([0,0,0,0, 0,0,0,0, 0, 2,1,1,1, 2,0,0.95,1, 1,0,0,1,0, 1,0, 0.85])
    y.append(2)

    # Phishing with soft-fail SPF, no DMARC, no DKIM, reply-to mismatch
    X.append([1,0,1,0, 0,0,0,0, 0, 1,1,0,0, 1,0,0.80,0, 1,0,0,1,0, 2,0, 0.70])
    y.append(2)

    # Tor exit node, PHPMailer, no auth
    X.append([0,0,0,0, 0,0,0,0, 0, 1,1,1,0, 3,1,1.00,1, 1,0,0,1,0, 3,0, 0.90])
    y.append(2)

    # Domain spoofing, dangerous SPF (+all), no DKIM
    X.append([1,0,0,1, 0,0,0,0, 0, 2,1,1,1, 0,0,0.60,0, 1,0,0,1,0, 1,0, 0.80])
    y.append(2)

    # Multiple malicious IPs, no auth, script mailer
    X.append([0,0,0,0, 0,0,0,0, 0, 3,1,1,1, 3,2,0.98,0, 1,0,0,1,0, 3,0, 0.95])
    y.append(2)

    # Sextortion pattern: spoofed from, no auth, The Bat mailer
    X.append([0,0,0,0, 0,0,0,0, 0, 2,1,1,0, 1,0,0.70,0, 0,1,0,0,0, 2,0, 0.65])
    y.append(2)

    # --- SUSPICIOUS examples (label=1) ---

    # Has SPF but weak DMARC (p=none), no DKIM, one warning
    X.append([1,1,0,0, 1,0,0,1, 0, 1,0,1,0, 0,0,0.20,0, 0,1,0,0,0, 2,0, 0.45])
    y.append(1)

    # Good SPF, no DMARC, no DKIM, self-hosted server
    X.append([1,1,0,0, 0,0,0,0, 0, 1,0,0,0, 0,1,0.30,0, 0,1,0,0,0, 1,0, 0.40])
    y.append(1)

    # Soft-fail SPF, quarantine DMARC, no DKIM
    X.append([1,0,1,0, 1,0,1,0, 0, 0,0,0,0, 0,0,0.10,0, 0,1,0,0,0, 2,0, 0.35])
    y.append(1)

    # Has DKIM but suspicious provider, reply-to mismatch
    X.append([1,1,0,0, 1,0,0,1, 1, 1,1,0,0, 0,1,0.40,0, 0,1,0,0,0, 2,0, 0.45])
    y.append(1)

    # Low abuse score IP, some warnings
    X.append([0,0,0,0, 0,0,0,0, 0, 1,0,1,0, 0,0,0.25,0, 1,0,0,1,0, 1,0, 0.50])
    y.append(1)

    # --- CLEAN examples (label=0) ---

    # Perfect: strict SPF, reject DMARC, DKIM present, reputable ESP
    X.append([1,1,0,0, 1,1,0,0, 1, 0,0,0,0, 0,0,0.00,0, 0,0,1,0,1, 2,0, 0.05])
    y.append(0)

    # Gmail: trusted provider, all auth present
    X.append([1,1,0,0, 1,1,0,0, 1, 0,0,0,0, 0,0,0.00,0, 0,0,1,0,0, 1,0, 0.00])
    y.append(0)

    # SendGrid: ESP with strict auth
    X.append([1,1,0,0, 1,1,0,0, 1, 0,0,0,0, 0,0,0.02,0, 0,0,1,0,1, 2,0, 0.05])
    y.append(0)

    # Outlook: Microsoft infrastructure
    X.append([1,1,0,0, 1,1,0,0, 1, 0,0,0,0, 0,0,0.00,0, 0,0,1,0,0, 2,0, 0.00])
    y.append(0)

    # Good auth, no warnings, clean IPs
    X.append([1,1,0,0, 1,0,1,0, 1, 0,0,0,0, 0,0,0.05,0, 0,0,1,0,1, 3,0, 0.10])
    y.append(0)

    # Mailchimp newsletter: all good
    X.append([1,1,0,0, 1,1,0,0, 1, 0,0,0,0, 0,0,0.00,0, 0,0,1,0,1, 1,0, 0.00])
    y.append(0)

    return np.array(X), np.array(y)


def train_model():
    """Train a Random Forest classifier and save it."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline

    X, y = build_training_data()

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42,
            class_weight="balanced"
        ))
    ])

    model.fit(X, y)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print(f"Model trained on {len(X)} samples and saved to {MODEL_PATH}")
    return model


def load_model():
    """Load model from disk, training it first if it doesn't exist."""
    if not os.path.exists(MODEL_PATH):
        return train_model()
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def predict_risk(report):
    """
    Run ML prediction on a report.
    Returns verdict label, confidence score 0-100, and probabilities.
    """
    try:
        model = load_model()
        features = extract_features(report).reshape(1, -1)

        label = model.predict(features)[0]
        proba = model.predict_proba(features)[0]

        label_map = {0: "clean", 1: "suspicious", 2: "malicious"}
        verdict = label_map.get(label, "unknown")

        # Convert to 0-100 confidence score
        # Score = weighted sum: clean=0, suspicious=50, malicious=100
        ml_score = int(proba[1] * 50 + proba[2] * 100)
        confidence = int(max(proba) * 100)

        return {
            "verdict": verdict,
            "ml_score": min(ml_score, 100),
            "confidence": confidence,
            "probabilities": {
                "clean":      round(float(proba[0]) * 100, 1),
                "suspicious": round(float(proba[1]) * 100, 1),
                "malicious":  round(float(proba[2]) * 100, 1)
            }
        }

    except Exception as e:
        return {
            "verdict": "unknown",
            "ml_score": 0,
            "confidence": 0,
            "probabilities": {"clean": 0, "suspicious": 0, "malicious": 0},
            "error": str(e)
        }