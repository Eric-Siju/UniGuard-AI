"""
Machine Learning Threat Detection & Anomaly Classification Engine
Uses Scikit-Learn RandomForestClassifier and IsolationForest with Explainable AI (XAI).
No external cloud AI APIs required - 100% offline, reproducible, and verifiable.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    confusion_matrix, classification_report
)

from backend.app.core.config import SAVED_MODELS_DIR, DATA_DIR
from backend.app.engine.feature_extractor import FEATURE_COLUMNS, extract_flow_features

MODEL_FILE = SAVED_MODELS_DIR / "rf_detector.joblib"
ISOLATION_FILE = SAVED_MODELS_DIR / "isolation_forest.joblib"
SCALER_FILE = SAVED_MODELS_DIR / "feature_scaler.joblib"
ENCODER_FILE = SAVED_MODELS_DIR / "label_encoder.joblib"
METADATA_FILE = SAVED_MODELS_DIR / "model_evaluation.json"

FEATURE_READABLE_NAMES = {
    "duration": "Flow Duration (sec)",
    "total_bytes": "Total Bytes Transferred",
    "total_packets": "Total Packet Count",
    "packets_per_sec": "Packet Velocity (pkts/sec)",
    "bytes_per_sec": "Bandwidth Velocity (bytes/sec)",
    "avg_packet_size": "Mean Packet Size",
    "packet_size_std": "Packet Size Variance",
    "iat_mean": "Mean Inter-Arrival Time",
    "iat_std": "Inter-Arrival Jitter (std dev)",
    "iat_min": "Minimum Packet Gap",
    "iat_max": "Maximum Packet Gap",
    "fan_in": "Destination Convergence (Fan-In)",
    "fan_out": "Host Dispersion (Fan-Out)",
    "unique_dst_ports": "Unique Destination Ports",
    "unique_src_ports": "Unique Source Ports",
    "conn_frequency": "Connection Frequency",
    "syn_count": "TCP SYN Flag Count",
    "ack_count": "TCP ACK Flag Count",
    "rst_count": "TCP RST Flag Count",
    "syn_ratio": "SYN-to-Total-Flags Ratio",
    "dns_query_length": "DNS Query Length (chars)",
    "dns_entropy": "DNS Domain Shannon Entropy",
    "dns_digit_ratio": "DNS Query Numeric Ratio",
    "dns_subdomain_depth": "DNS Subdomain Label Depth",
    "outbound_bytes": "Outbound Volume (bytes)",
    "outbound_ratio": "Outbound-to-Inbound Ratio"
}

class MLThreatDetector:
    """Supervised Multi-Class Classifier and Unsupervised Anomaly Detector."""
    def __init__(self):
        self.rf_model: Optional[RandomForestClassifier] = None
        self.iso_model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.evaluation_metadata: Dict[str, Any] = {}
        self.is_loaded = False
        
        self.load_models()

    def load_models(self) -> bool:
        """Loads trained weights and scalers from disk if available."""
        if (
            MODEL_FILE.exists() and
            ISOLATION_FILE.exists() and
            SCALER_FILE.exists() and
            ENCODER_FILE.exists()
        ):
            try:
                self.rf_model = joblib.load(MODEL_FILE)
                self.iso_model = joblib.load(ISOLATION_FILE)
                self.scaler = joblib.load(SCALER_FILE)
                self.label_encoder = joblib.load(ENCODER_FILE)
                if METADATA_FILE.exists():
                    import json
                    self.evaluation_metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
                self.is_loaded = True
                return True
            except Exception as e:
                print(f"[!] Warning loading models: {e}")
                self.is_loaded = False
                return False
        self.is_loaded = False
        return False

    def train(self, dataset_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes end-to-end ML training pipeline:
        Loads dataset, extracts features, splits, trains RF & IsolationForest,
        computes verified metrics, and saves model checkpoints.
        """
        if dataset_path is None:
            dataset_path = str(DATA_DIR / "combined_demo.csv")
            
        print(f"[*] Training ML model with dataset: {dataset_path}")
        df = pd.read_csv(dataset_path)
        
        # Build feature rows
        feature_rows = []
        labels = []
        for _, row in df.iterrows():
            flow_dict = row.to_dict()
            feats = extract_flow_features(flow_dict, update_context=False)
            feature_rows.append([feats[col] for col in FEATURE_COLUMNS])
            labels.append(str(flow_dict.get("threat_label", "Normal")))
            
        X = np.array(feature_rows, dtype=np.float32)
        # Handle any possible NaNs or infs cleanly
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(labels)
        classes = list(self.label_encoder.classes_)
        
        # Split 70% Train, 30% Test (stratified)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.30, random_state=42, stratify=y
        )
        
        # Fit scaler on training set
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Supervised Random Forest Classifier
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_train_scaled, y_train)
        
        # Train Unsupervised Isolation Forest for Zero-Day Anomaly Detection
        self.iso_model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42,
            n_jobs=-1
        )
        self.iso_model.fit(X_train_scaled)
        
        # Comprehensive Evaluation on Test Set
        y_pred = self.rf_model.predict(X_test_scaled)
        acc = float(accuracy_score(y_test, y_pred))
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted", zero_division=0
        )
        
        cm = confusion_matrix(y_test, y_pred).tolist()
        report = classification_report(y_test, y_pred, target_names=classes, output_dict=True, zero_division=0)
        
        # False positive & false negative rates for "Normal" vs "Threat"
        normal_idx = classes.index("Normal") if "Normal" in classes else 0
        normal_mask = (y_test == normal_idx)
        threat_mask = ~normal_mask
        
        fp = int(np.sum((y_pred != normal_idx) & normal_mask))
        total_normal = int(np.sum(normal_mask))
        fp_rate = float(fp / total_normal) if total_normal > 0 else 0.0
        
        fn = int(np.sum((y_pred == normal_idx) & threat_mask))
        total_threats = int(np.sum(threat_mask))
        fn_rate = float(fn / total_threats) if total_threats > 0 else 0.0
        
        # Global Feature Importance Ranking
        importances = self.rf_model.feature_importances_
        feature_rankings = []
        for name, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True):
            feature_rankings.append({
                "feature": name,
                "display_name": FEATURE_READABLE_NAMES.get(name, name),
                "importance": round(float(imp), 4)
            })
            
        metadata = {
            "model_name": "UniGuard-RF-Detector-v1",
            "model_type": "RandomForestClassifier (100 trees) + IsolationForest",
            "version": "1.0.0",
            "training_timestamp": datetime.utcnow().isoformat(),
            "dataset_name": Path(dataset_path).name,
            "sample_count": int(len(X)),
            "feature_count": len(FEATURE_COLUMNS),
            "classes": classes,
            "accuracy": round(acc, 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": cm,
            "classification_report": report,
            "false_positive_rate": round(fp_rate, 4),
            "false_negative_rate": round(fn_rate, 4),
            "top_features": feature_rankings[:10],
            "all_features": feature_rankings,
            "is_active": True
        }
        
        # Save checkpoints
        SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.rf_model, MODEL_FILE)
        joblib.dump(self.iso_model, ISOLATION_FILE)
        joblib.dump(self.scaler, SCALER_FILE)
        joblib.dump(self.label_encoder, ENCODER_FILE)
        
        import json
        METADATA_FILE.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        
        self.evaluation_metadata = metadata
        self.is_loaded = True
        print(f"[?] Model trained successfully! Accuracy: {acc*100:.2f}%, F1: {f1:.4f}")
        return metadata

    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Runs real-time inference on an extracted feature dictionary.
        Returns predicted threat class, probabilities, anomaly score, and XAI feature contributions.
        """
        if not self.is_loaded:
            # Fallback if model not trained yet
            return {
                "prediction": "Normal",
                "confidence": 0.50,
                "probabilities": {"Normal": 0.50},
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "contributing_features": []
            }
            
        vector = np.array([[features.get(col, 0.0) for col in FEATURE_COLUMNS]], dtype=np.float32)
        vector = np.nan_to_num(vector, nan=0.0, posinf=1e6, neginf=-1e6)
        
        scaled_vector = self.scaler.transform(vector)
        
        # Supervised prediction & class probabilities
        probas = self.rf_model.predict_proba(scaled_vector)[0]
        classes = self.label_encoder.classes_
        prob_dict = {classes[i]: round(float(probas[i]), 4) for i in range(len(classes))}
        
        best_idx = int(np.argmax(probas))
        best_class = classes[best_idx]
        best_conf = float(probas[best_idx])
        
        # Unsupervised Isolation Forest decision score
        # decision_function returns negative values for anomalies, positive for normal
        raw_anomaly = float(self.iso_model.decision_function(scaled_vector)[0])
        # Normalize into 0.0 - 1.0 (where 1.0 is highest anomaly)
        anomaly_score = round(float(np.clip(0.5 - (raw_anomaly * 1.5), 0.0, 1.0)), 4)
        is_anomaly = bool(anomaly_score > 0.65)
        
        # Explainable AI: Feature contributions for this prediction
        # Weight normalized feature deviation by model feature importance
        importances = self.rf_model.feature_importances_
        scaled_row = scaled_vector[0]
        
        contributions = []
        for i, col in enumerate(FEATURE_COLUMNS):
            val = float(features.get(col, 0.0))
            z_score = abs(float(scaled_row[i]))
            impact = float(z_score * importances[i])
            contributions.append({
                "feature": col,
                "name": FEATURE_READABLE_NAMES.get(col, col),
                "value": val,
                "impact": round(impact, 4),
                "importance": round(float(importances[i]), 4)
            })
            
        contributions.sort(key=lambda x: x["impact"], reverse=True)
        top_contributions = contributions[:4]

        return {
            "prediction": best_class,
            "confidence": round(best_conf, 2),
            "probabilities": prob_dict,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "contributing_features": top_contributions
        }

# Global singleton detector
ml_detector = MLThreatDetector()
