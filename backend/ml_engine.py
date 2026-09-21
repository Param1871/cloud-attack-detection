from __future__ import annotations
import os
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

FEATURES = [
    "traffic_anomaly", "cpu_usage", "memory_usage", "bandwidth_usage",
    "transaction_frequency", "security_incidents", "resource_distribution",
    "avg_resource_usage", "scalability_score", "node_degree", "centrality"
]
LABELS = ["BENIGN", "DDoS", "DoS", "PortScan", "BruteForce", "WebAttack"]
MODEL_PATH = Path(os.getenv("MODEL_PATH", "./model.joblib"))

class MLEngine:
    def __init__(self):
        self.model = None
        self.metrics = {}
        self.training_source = "synthetic-demo"
        if MODEL_PATH.exists():
            self.load()
        else:
            self.train_synthetic()

    def _synthetic(self, n=5000, seed=42):
        rng = np.random.default_rng(seed)
        X = pd.DataFrame({f: rng.uniform(0, 1, n) for f in FEATURES})
        score = (
            0.24*X.traffic_anomaly + 0.16*X.cpu_usage + 0.12*X["memory_usage"] +
            0.12*X.bandwidth_usage + 0.08*X.transaction_frequency +
            0.08*X.security_incidents + 0.06*X.resource_distribution +
            0.05*X.avg_resource_usage + 0.04*(1-X.scalability_score) +
            0.03*X.centrality + 0.02*X.node_degree
        )
        y = np.where(score < .30, "BENIGN", np.where(score < .47, "PortScan", np.where(score < .60, "BruteForce", np.where(score < .73, "DoS", np.where(score < .86, "WebAttack", "DDoS")))))
        noise = rng.random(n) < 0.07
        y[noise] = rng.choice(LABELS, noise.sum())
        return X, pd.Series(y, name="label")

    def train_synthetic(self):
        X, y = self._synthetic()
        self._fit(X, y, "synthetic-demo")

    def train_csv(self, path: str, label_col: str = "label"):
        df = pd.read_csv(path)
        missing = [f for f in FEATURES if f not in df.columns]
        if missing or label_col not in df.columns:
            raise ValueError(f"CSV must contain features={FEATURES} and label column='{label_col}'. Missing: {missing}")
        X = df[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0).clip(0, 1)
        y = df[label_col].astype(str)
        self._fit(X, y, "uploaded-csv")

    def _fit(self, X, y, source):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.2, random_state=42, stratify=y)
        self.model = RandomForestClassifier(n_estimators=60, max_depth=12, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        pred = self.model.predict(X_test)
        self.metrics = {
            "accuracy": round(float(accuracy_score(y_test, pred)), 4),
            "precision_weighted": round(float(precision_score(y_test, pred, average="weighted", zero_division=0)), 4),
            "recall_weighted": round(float(recall_score(y_test, pred, average="weighted", zero_division=0)), 4),
            "f1_weighted": round(float(f1_score(y_test, pred, average="weighted", zero_division=0)), 4),
            "samples": int(len(X)), "trees": self.model.n_estimators,
        }
        self.training_source = source
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.save()

    def predict(self, features: dict):
        row = pd.DataFrame([[float(features.get(f, 0)) for f in FEATURES]], columns=FEATURES).clip(0, 1)
        label = str(self.model.predict(row)[0])
        probs = self.model.predict_proba(row)[0]
        classes = list(self.model.classes_)
        confidence = float(probs[classes.index(label)])
        return label, confidence, {c: round(float(p), 4) for c, p in zip(classes, probs)}

    def save(self):
        joblib.dump({"model": self.model, "metrics": self.metrics, "source": self.training_source}, MODEL_PATH)

    def load(self):
        d = joblib.load(MODEL_PATH)
        self.model, self.metrics, self.training_source = d["model"], d["metrics"], d["source"]
