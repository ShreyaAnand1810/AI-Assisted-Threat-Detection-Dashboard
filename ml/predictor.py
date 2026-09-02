import os
import time
import logging
from datetime import datetime, timezone
import joblib
import pandas as pd

# Import feature extractor and preprocessor utilities
try:
    from ml.feature_extractor import extract_features
    from ml.preprocess import transform_encoders
except ImportError:
    from feature_extractor import extract_features
    from preprocess import transform_encoders

"""
AI Threat Detection - Prediction Module

Production-ready predictor that handles:
- Singleton model and encoder loading
- Flexible input handling (File paths, Dictionaries, DataFrames)
- Feature extraction & preprocessing
- Model inference & probability calculation
- Dynamic risk level classification
- Comprehensive logging and timing metrics
- Robust error handling
"""

# Configure logger for prediction module
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] ThreatPredictor: %(message)s"
)
logger = logging.getLogger("ThreatPredictor")

# Define project directories and model artifact paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, "ml", "threat_model.pkl")
LABEL_ENCODER_PATH = os.path.join(PROJECT_ROOT, "ml", "label_encoder.pkl")
LEGACY_ENCODER_PATH = os.path.join(PROJECT_ROOT, "ml", "encoders.pkl")


class ThreatPredictor:
    """
    Singleton Threat Predictor class that loads model artifacts once into memory
    and exposes prediction functionality.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ThreatPredictor, cls).__new__(cls)
            cls._instance._load_artifacts()
        return cls._instance

    def _load_artifacts(self):
        """Loads trained XGBoost model and label encoders once into memory."""
        self.model = None
        self.encoders = {}
        self.model_name = "Unknown Model"

        # 1. Load Model
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.model_name = type(self.model).__name__
                logger.info(f"Successfully loaded model '{self.model_name}' from: {MODEL_PATH}")
            except Exception as e:
                logger.error(f"Failed to load model file at {MODEL_PATH}: {str(e)}")
        else:
            logger.warning(f"Model file not found at path: {MODEL_PATH}")

        # 2. Load Encoders (Supports label_encoder.pkl with fallback to encoders.pkl)
        encoder_file = None
        if os.path.exists(LABEL_ENCODER_PATH):
            encoder_file = LABEL_ENCODER_PATH
        elif os.path.exists(LEGACY_ENCODER_PATH):
            encoder_file = LEGACY_ENCODER_PATH

        if encoder_file:
            try:
                self.encoders = joblib.load(encoder_file)
                logger.info(f"Successfully loaded encoders from: {encoder_file}")
            except Exception as e:
                logger.error(f"Failed to load encoders from {encoder_file}: {str(e)}")
        else:
            logger.warning("No label encoder artifact found.")

    def calculate_risk(self, confidence: float, prediction_label: int) -> tuple[str, str]:
        """
        Calculates Risk Level and Recommendation based on model prediction and confidence score.
        
        Configurable Risk Thresholds:
        - Confidence < 50%: Low Risk
        - 50% <= Confidence < 80%: Medium Risk
        - 80% <= Confidence < 95%: High Risk
        - Confidence >= 95%: Critical Risk
        """
        if prediction_label == 1:
            if confidence >= 95.0:
                return "Critical", "Quarantine Immediately"
            elif confidence >= 80.0:
                return "High", "Move file to quarantine and investigate"
            elif confidence >= 50.0:
                return "Medium", "Review file manually"
            else:
                return "Low", "Monitor file activity"
        else:
            return "Low", "No action required"

    def predict(self, input_data) -> dict:
        """
        Executes complete prediction workflow for given input data.
        Accepts:
        - File path string (runs feature extraction automatically)
        - Feature dictionary
        - Pandas DataFrame
        """
        start_time = time.time()
        logger.info("Prediction request started.")

        # --- 1. Error Handling: Check Model Availability ---
        if self.model is None:
            logger.error("Prediction failed: Model is not loaded.")
            return {
                "status": "error",
                "prediction": "Unknown",
                "prediction_label": "Error",
                "threat_type": "Unknown",
                "confidence": 0.0,
                "confidence_str": "0.00%",
                "risk": "Error",
                "risk_level": "Error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model_used": self.model_name,
                "processing_time_ms": round((time.time() - start_time) * 1000, 2),
                "recommendation": "Model file missing or corrupted. Please run ml/train_model.py first."
            }

        # --- 2. Error Handling & Input Normalization ---
        features = {}
        if input_data is None:
            logger.error("Prediction failed: Input data is None.")
            return self._build_error_response("Input data cannot be None.", start_time)

        try:
            if isinstance(input_data, str):
                # Input is a file path
                if not os.path.exists(input_data):
                    logger.error(f"File not found: {input_data}")
                    return self._build_error_response(f"Target file path does not exist: {input_data}", start_time)
                logger.info(f"Extracting features from file: {input_data}")
                features = extract_features(input_data)
            elif isinstance(input_data, dict):
                features = input_data.copy()
            elif isinstance(input_data, pd.DataFrame):
                if input_data.empty:
                    return self._build_error_response("Input DataFrame is empty.", start_time)
                features = input_data.iloc[0].to_dict()
            else:
                return self._build_error_response("Unsupported input data format.", start_time)

        except Exception as e:
            logger.error(f"Error during feature extraction/input parsing: {str(e)}")
            return self._build_error_response(f"Feature processing error: {str(e)}", start_time)

        # --- 3. Feature Mapping & Preprocessing ---
        try:
            file_size = features.get("size", features.get("filesize", 0))
            raw_extension = str(features.get("extension", "")).lower()
            entropy = float(features.get("entropy", 0.0))

            sample_df = pd.DataFrame([{
                "size": file_size,
                "entropy": entropy,
                "extension": raw_extension
            }])

            # Apply pre-fitted encoders
            if self.encoders:
                encoded_sample = transform_encoders(sample_df, self.encoders)
            else:
                encoded_sample = sample_df

            # Ensure exact feature column order expected by model
            feature_cols = ["size", "entropy", "extension"]
            encoded_sample = encoded_sample[feature_cols]

        except Exception as e:
            logger.error(f"Preprocessing error: {str(e)}")
            return self._build_error_response(f"Preprocessing error: {str(e)}", start_time)

        # --- 4. Model Prediction & Probability Calculation ---
        try:
            raw_pred = self.model.predict(encoded_sample)[0]
            prediction_int = int(raw_pred)

            # Use predict_proba if supported
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(encoded_sample)[0]
                confidence_val = float(max(probabilities) * 100)
            else:
                logger.warning("Model does not support predict_proba; defaulting confidence to 100%.")
                confidence_val = 100.0

            confidence_val = round(confidence_val, 2)

        except Exception as e:
            logger.error(f"Inference error during model.predict(): {str(e)}")
            return self._build_error_response(f"Model prediction error: {str(e)}", start_time)

        # --- 5. Class Label Mapping & Risk Classification ---
        if prediction_int == 1:
            prediction_str = "Threat Detected"
            threat_type = "Malicious"
        else:
            prediction_str = "Safe"
            threat_type = "Safe"

        risk_level, recommendation = self.calculate_risk(confidence_val, prediction_int)
        processing_time = round((time.time() - start_time) * 1000, 2)

        logger.info(f"Prediction completed in {processing_time}ms: {prediction_str} ({threat_type}) | Confidence: {confidence_val}% | Risk: {risk_level}")

        # --- 6. Return Structured Output ---
        return {
            "status": "success",
            "prediction": prediction_str,
            "prediction_label": prediction_str,
            "threat_type": threat_type,
            "predicted_class": threat_type,
            "confidence": confidence_val,
            "confidence_str": f"{confidence_val:.2f}%",
            "risk": risk_level,
            "risk_level": risk_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_used": self.model_name,
            "processing_time_ms": processing_time,
            "recommendation": recommendation,
            "features_analyzed": {
                "size": file_size,
                "entropy": entropy,
                "extension": raw_extension
            }
        }

    def _build_error_response(self, message: str, start_time: float) -> dict:
        """Constructs standardized error dictionary."""
        return {
            "status": "error",
            "prediction": "Unknown",
            "prediction_label": "Error",
            "threat_type": "Error",
            "predicted_class": "Error",
            "confidence": 0.0,
            "confidence_str": "0.00%",
            "risk": "Error",
            "risk_level": "Error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_used": self.model_name,
            "processing_time_ms": round((time.time() - start_time) * 1000, 2),
            "recommendation": f"Error encountered: {message}"
        }


# Module-level convenience function for single-line calls
_predictor_instance = ThreatPredictor()

def predict(input_data):
    """
    Global entry point for predictions.
    Delegates to ThreatPredictor singleton.
    """
    return _predictor_instance.predict(input_data)


# -------------------------------------------------------------
# 10. Self-Testing Harness
# -------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("      AI THREAT PREDICTOR - VERIFICATION TEST SUITE      ")
    print("=" * 60)

    # Test Case 1: High Risk Malicious Sample
    test_sample_malicious = {
        "filesize": 654321,
        "extension": ".exe",
        "entropy": 7.94
    }
    print("\n--- Test Case 1: Suspicious Executable ---")
    res1 = predict(test_sample_malicious)
    print(f"Input       : {test_sample_malicious}")
    print(f"Prediction  : {res1['prediction']}")
    print(f"Threat Type : {res1['threat_type']}")
    print(f"Confidence  : {res1['confidence_str']}")
    print(f"Risk Level  : {res1['risk_level']}")
    print(f"Model Used  : {res1['model_used']}")
    print(f"Timestamp   : {res1['timestamp']}")
    print(f"Latency     : {res1['processing_time_ms']} ms")

    # Test Case 2: Low Risk Benign Sample
    test_sample_benign = {
        "filesize": 15234,
        "extension": ".docx",
        "entropy": 5.10
    }
    print("\n--- Test Case 2: Benign Document ---")
    res2 = predict(test_sample_benign)
    print(f"Input       : {test_sample_benign}")
    print(f"Prediction  : {res2['prediction']}")
    print(f"Threat Type : {res2['threat_type']}")
    print(f"Confidence  : {res2['confidence_str']}")
    print(f"Risk Level  : {res2['risk_level']}")

    # Test Case 3: Error Handling Test (Invalid Input)
    print("\n--- Test Case 3: Error Handling (None Input) ---")
    res3 = predict(None)
    print(f"Status      : {res3['status']}")
    print(f"Error Msg   : {res3['recommendation']}")

    print("\n" + "=" * 60)
    print("              ALL PREDICTOR TESTS COMPLETED             ")
    print("=" * 60)
