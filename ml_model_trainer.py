import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

DATASET_PATH = "Malware_Dataset.csv"
MODEL_PATH = "ml_model.pkl"


def train_model():

    print("\n==============================")
    print("Malware Detection Model Training")
    print("==============================")

    # Load dataset
    data = pd.read_csv(DATASET_PATH)

    print(f"[INFO] Dataset loaded with {len(data)} samples")

    # Remove hash column if it exists
    if "hash" in data.columns:
        data = data.drop("hash", axis=1)

    # Target label
    y = data["classification"]

    # Encode labels (malware / benign)
    encoder = LabelEncoder()
    y = encoder.fit_transform(y)

    # Features
    X = data.drop("classification", axis=1)

    print(f"[INFO] Number of features: {X.shape[1]}")

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(f"[INFO] Training samples: {len(X_train)}")
    print(f"[INFO] Testing samples: {len(X_test)}")

    # Train Random Forest model
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )

    print("[INFO] Training model...")

    model.fit(X_train, y_train)

    # Evaluate model
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print("\nModel Evaluation")
    print("----------------")
    print("Accuracy:", round(accuracy * 100, 2), "%")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print("\n[✓] Model saved successfully as ml_model.pkl")


if __name__ == "__main__":
    train_model()