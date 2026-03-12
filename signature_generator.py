import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle

# Load dataset
data = pd.read_csv("malware_dataset.csv")

# Remove hash column
data = data.drop("hash", axis=1)

# Target column
y = data["classification"]

# Encode labels
encoder = LabelEncoder()
y = encoder.fit_transform(y)

# Features
X = data.drop("classification", axis=1)

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# Accuracy
print("Accuracy:", model.score(X_test, y_test))

# Save model
with open("ml_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model saved successfully")