import pandas as pd
from sklearn.preprocessing import LabelEncoder

"""
Preprocessing module for ML Threat Detection Pipeline.
Handles data cleaning, train/test feature encoding without data leakage,
and transformation of unseen evaluation/inference samples.
"""

def clean_data(df):
    """
    Cleans raw dataset: standardizes column names, removes missing values and duplicate rows.
    """
    df = df.copy()
    
    # Standardize column names (map 'filesize' to 'size' if present)
    if "filesize" in df.columns and "size" not in df.columns:
        df.rename(columns={"filesize": "size"}, inplace=True)
        
    # Drop non-feature identifier columns if present
    id_cols = [c for c in ["md5", "sha256", "filename", "filepath", "id"] if c in df.columns]
    if id_cols:
        df.drop(columns=id_cols, inplace=True)
        
    # Drop nulls and duplicates
    df = df.dropna().drop_duplicates()
    return df


def preprocess_data(df, target_col="label"):
    """
    Cleans raw dataframe and separates features (X) and target variable (y).
    """
    df_clean = clean_data(df)
    
    if target_col in df_clean.columns:
        X = df_clean.drop(columns=[target_col])
        y = df_clean[target_col]
    else:
        X = df_clean
        y = None
        
    return X, y


def fit_transform_encoders(X_train, categorical_cols=None):
    """
    Fits LabelEncoders strictly on X_train to prevent data leakage.
    Returns transformed X_train dataframe and the fitted encoders dictionary.
    """
    if categorical_cols is None:
        categorical_cols = ["extension"]
        
    X_train_encoded = X_train.copy()
    encoders = {}
    
    for col in categorical_cols:
        if col in X_train_encoded.columns:
            le = LabelEncoder()
            X_train_encoded[col] = le.fit_transform(X_train_encoded[col].astype(str))
            encoders[col] = le
            
    return X_train_encoded, encoders


def transform_encoders(X_df, encoders):
    """
    Transforms evaluation or test feature samples using pre-fitted encoders.
    Handles unseen target classes safely without throwing exceptions.
    """
    X_encoded = X_df.copy()
    
    for col, le in encoders.items():
        if col in X_encoded.columns:
            known_classes = set(le.classes_)
            # Map unseen values safely to class 0 (or first class in encoder)
            X_encoded[col] = X_encoded[col].astype(str).apply(
                lambda val: le.transform([val])[0] if val in known_classes else 0
            )
            
    return X_encoded