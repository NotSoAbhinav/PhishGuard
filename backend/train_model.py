import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

from feature_extractor import extract_features

# Load dataset
df = pd.read_csv("../dataset/urls.csv")

# Extract features
X = df["url"].apply(lambda url: extract_features(url)).tolist()
y = df["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved as model.pkl")