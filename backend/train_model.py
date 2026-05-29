import pandas as pd
import pickle
import os
import json
import datetime
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from feature_extractor import extract_features

def train_and_save_model(dataset_path=None, model_path="model.pkl", version="3.0.0"):
    if dataset_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dataset_path = os.path.join(base_dir, "..", "dataset", "urls.csv")
    
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")
        
    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    
    print("Extracting features (24 dimensions)...")
    X = df["url"].apply(lambda url: extract_features(url)).tolist()
    y = df["label"].tolist()
    
    # 5-Fold Stratified Cross-Validation
    print("Running 5-Fold Cross-Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    clf_cv = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42
    )
    cv_scores = cross_val_score(clf_cv, X, y, cv=cv, scoring="accuracy")
    cv_mean = float(cv_scores.mean())
    print(f"Cross-Validation Accuracy: {cv_mean * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train final model
    print("Training final model...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Test Set Accuracy: {acc * 100:.2f}%")
    
    # Save model
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print(f"Model saved to: {model_path}")
    
    # Save versioning metadata
    metadata_path = model_path.replace(".pkl", "_metadata.json")
    metadata = {
        "version": version,
        "trained_at": datetime.datetime.utcnow().isoformat() + "Z",
        "samples_count": len(X),
        "cv_accuracy": cv_mean,
        "test_accuracy": float(acc),
        "features_count": 24
    }
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to: {metadata_path}")
    
    return model, cv_mean

if __name__ == "__main__":
    train_and_save_model(version="3.0.0")