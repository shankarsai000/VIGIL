import os
import json
import pickle
import logging
import warnings
import numpy as np
import joblib

# Suppress sklearn/joblib unpickling and feature names warning
warnings.filterwarnings("ignore")

logger = logging.getLogger("vigil.services.telemetry")

MODEL_DIR = "backend/models/telemetry/"
COLUMNS_PATH = os.path.join(MODEL_DIR, "vigil_feature_columns.json")
SCALER_PATH = os.path.join(MODEL_DIR, "vigil_scaler.pkl")
RF_PATH = os.path.join(MODEL_DIR, "vigil_random_forest.pkl")
IF_PATH = os.path.join(MODEL_DIR, "vigil_isolation_forest.pkl")
ENCODERS_PATH = os.path.join(MODEL_DIR, "vigil_label_encoders.pkl")

class TelemetryService:
    def __init__(self):
        self.columns = []
        self.scaler = None
        self.rf_model = None
        self.if_model = None
        self.encoders = None
        self.is_loaded = False
        
        self.load_models()

    def load_models(self):
        try:
            # 1. Load columns
            if os.path.exists(COLUMNS_PATH):
                with open(COLUMNS_PATH, "r") as f:
                    self.columns = json.load(f)
                logger.info(f"Loaded {len(self.columns)} feature columns schema.")
            
            # 2. Load Joblib/Pickle modules
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
            
            if os.path.exists(RF_PATH):
                self.rf_model = joblib.load(RF_PATH)
            
            if os.path.exists(IF_PATH):
                self.if_model = joblib.load(IF_PATH)
                    
            if os.path.exists(ENCODERS_PATH):
                self.encoders = joblib.load(ENCODERS_PATH)
            
            self.is_loaded = (self.rf_model is not None) and (self.scaler is not None)
            logger.info(f"Telemetry ML Service successfully bootstrapped: Loaded={self.is_loaded}")
        except Exception as e:
            logger.error(f"Error loading telemetry ML models: {e}", exc_info=True)
            self.is_loaded = False

    def predict_anomaly(self, feature_data: dict) -> float:
        """Evaluates telemetry feature data and returns an anomaly score from 0.0 to 1.0."""
        if not self.is_loaded or not self.columns:
            # High-fidelity fallback based on rate and size
            logger.warning("Telemetry ML Models not loaded. Utilizing high-fidelity statistical fallback.")
            rate = feature_data.get("pkt_rate", 0.0)
            payload_size = feature_data.get("sbytes", 0.0)
            
            # Simulated threat scale based on metrics
            score = 0.0
            if rate > 200.0:
                score += 0.4
            if payload_size > 50000.0:
                score += 0.4
            return min(1.0, score)

        try:
            # Build feature array matching schema columns
            vector = []
            for col in self.columns:
                val = feature_data.get(col, 0.0)
                # Parse or encode string values if encoder exists
                if isinstance(val, str) and self.encoders and col in self.encoders:
                    try:
                        val = self.encoders[col].transform([val])[0]
                    except Exception:
                        val = 0.0
                vector.append(float(val) if val is not None else 0.0)
            
            X = np.array([vector])
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict Random Forest anomaly class probability
            # Class 1 typically corresponds to anomaly/attack
            proba = self.rf_model.predict_proba(X_scaled)[0]
            rf_score = float(proba[1]) if len(proba) > 1 else 0.0
            
            # Incorporate Isolation Forest density scoring
            if self.if_model:
                if_raw = self.if_model.score_samples(X_scaled)[0]
                # Map raw score [-1.0, 0.0] where lower is anomaly
                if_score = float(np.clip((0.5 - if_raw) / 1.0, 0.0, 1.0))
                # Hybrid model average
                final_score = 0.7 * rf_score + 0.3 * if_score
            else:
                final_score = rf_score
                
            return float(np.clip(final_score, 0.0, 1.0))
        except Exception as e:
            logger.error(f"Telemetry ML prediction error: {e}")
            return 0.0

# Singleton service instance
telemetry_service = TelemetryService()
