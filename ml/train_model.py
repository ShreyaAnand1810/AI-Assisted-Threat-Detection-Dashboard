import os
import joblib
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split

from preprocess import preprocess_data, fit_transform_encoders, transform_encoders
from evaluate import evaluate_model

"""
Machine Learning Model Training Pipeline for Network Threat Detection.

Pipeline Steps:
1. Dataset Loading & Path Resolution
2. Data Cleaning & Feature / Target Separation
3. Stratified Train / Test Split (Prevents Data Leakage)
4. Feature Encoding (Fitted on Train Set only)
5. Model Building & Training (XGBClassifier)
6. Model Evaluation (via ml/evaluate.py)
7. Save Artifacts (threat_model.pkl & label_encoder.pkl)
"""

def main():
    # -------------------------------------------------------------
    # 1. Dataset Path Resolution & Loading
    # -------------------------------------------------------------
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(project_root, "dataset", "malware_dataset.csv")

    print(f"Loading Dataset from: {dataset_path}")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at path: {dataset_path}")

    df = pd.read_csv(dataset_path)
    print(f"Dataset Loaded Successfully! Shape: {df.shape}")
    print("\nDataset Preview:")
    print(df.head())

    # -------------------------------------------------------------
    # 2. Data Cleaning & Preprocessing (Features vs Target Separation)
    # -------------------------------------------------------------
    X, y = preprocess_data(df, target_col="label")
    print(f"\nExtracted Features: {list(X.columns)}")

    # -------------------------------------------------------------
    # 3. Train/Test Split (Stratified to maintain class distributions)
    # -------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if len(y.unique()) > 1 else None
    )
    print(f"\nTrain set size: {len(X_train)} samples | Test set size: {len(X_test)} samples")

    # -------------------------------------------------------------
    # 4. Feature Encoding (Fit ON TRAIN ONLY to prevent Data Leakage)
    # -------------------------------------------------------------
    X_train_encoded, encoders = fit_transform_encoders(X_train, categorical_cols=["extension"])
    X_test_encoded = transform_encoders(X_test, encoders)

    # -------------------------------------------------------------
    # 5. Build and Train Model (XGBClassifier)
    # -------------------------------------------------------------
    # XGBoost is selected as it excels at tabular threat feature data, handles
    # non-linear relations well, and provides high precision & recall.
    print("\nBuilding XGBoost Threat Detection Model...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        random_state=42,
        eval_metric="logloss"
    )

    print("Training Model...")
    model.fit(X_train_encoded, y_train)
    print("Model Training Completed Successfully!")

    # -------------------------------------------------------------
    # 6. Evaluation (Using ml/evaluate.py module)
    # -------------------------------------------------------------
    print("\nEvaluating Model Performance...")
    metrics = evaluate_model(model, X_test_encoded, y_test)

    # -------------------------------------------------------------
    # 7. Save Artifacts (threat_model.pkl & label_encoder.pkl)
    # -------------------------------------------------------------
    ml_dir = os.path.join(project_root, "ml")
    os.makedirs(ml_dir, exist_ok=True)

    model_save_path = os.path.join(ml_dir, "threat_model.pkl")
    label_encoder_path = os.path.join(ml_dir, "label_encoder.pkl")
    legacy_encoder_path = os.path.join(ml_dir, "encoders.pkl")

    # Save Model (.pkl)
    joblib.dump(model, model_save_path)
    print(f"\nTrained model saved to: {model_save_path}")

    # Save Label Encoder (.pkl)
    joblib.dump(encoders, label_encoder_path)
    joblib.dump(encoders, legacy_encoder_path)  # Dual save for legacy predictor compatibility
    print(f"Label Encoders saved to: {label_encoder_path} and {legacy_encoder_path}")

    print("\n[SUCCESS] ML Training Pipeline Execution Finished!")

if __name__ == "__main__":
    main()