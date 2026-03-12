import pickle
import os
from file_feature_adapter import extract_features_from_file

ML_MODEL_PATH = "ml_model.pkl"

_model = None


def get_ml_model():
    """
    Load ML model once and reuse it
    """
    global _model

    if _model is None:
        if not os.path.exists(ML_MODEL_PATH):
            raise FileNotFoundError("ML model not found. Train the model first.")

        with open(ML_MODEL_PATH, "rb") as f:
            _model = pickle.load(f)

        print("[✓] ML model loaded successfully")

    return _model



def scan_file(file_path):

    model = get_ml_model()

    features = extract_features_from_file(file_path)

    # safely read file content
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()
    except:
        content = ""

    suspicious_keywords = [
        "cmd.exe",
        "powershell",
        "virtualallocex",
        "createremotethread",
        "writeprocessmemory",
        "rundll32"
    ]

    keyword_flag = any(word in content for word in suspicious_keywords)

    prediction = model.predict([features])[0]
    confidence = max(model.predict_proba([features])[0])

    if keyword_flag:
        verdict = "malicious"
    else:
        verdict = "benign"

    return {
        "verdict": verdict,
        "confidence": float(confidence)
    }