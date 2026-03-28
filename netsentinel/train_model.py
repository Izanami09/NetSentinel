"""
NetSentinel - ML Model Training Pipeline
Trains Random Forest, XGBoost, and Isolation Forest on UNSW-NB15 dataset.
Generates SHAP explanations and saves models for real-time inference.

Usage:
    1. Download UNSW-NB15 from Kaggle:
       https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
       (or the training/testing CSVs from the official UNSW source)
    2. Place CSV files in the data/ directory
    3. Run: python train_model.py
"""

import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# UNSW-NB15 attack categories
ATTACK_CATEGORIES = {
    0: "Normal",
    1: "Fuzzers",
    2: "Analysis",
    3: "Backdoors",
    4: "DoS",
    5: "Exploits",
    6: "Generic",
    7: "Reconnaissance",
    8: "Shellcode",
    9: "Worms",
}

# Features to use (based on UNSW-NB15 feature set)
# These are the most informative features identified in literature
SELECTED_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload",
    "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "stcpb", "dtcpb",
    "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports", "ct_flw_http_mthd", "is_ftp_login",
]


def load_data():
    """Load UNSW-NB15 dataset."""
    print("=" * 60)
    print("📂 Loading UNSW-NB15 Dataset")
    print("=" * 60)

    # Try different file naming conventions
    possible_files = [
        # Official training/testing split
        ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"),
        # Kaggle variant
        ("UNSW-NB15_1.csv", None),
        # Combined
        ("unsw_nb15.csv", None),
    ]

    train_df = None
    test_df = None

    for train_file, test_file in possible_files:
        train_path = os.path.join(DATA_DIR, train_file)
        if os.path.exists(train_path):
            print(f"  Found: {train_file}")
            train_df = pd.read_csv(train_path)
            if test_file:
                test_path = os.path.join(DATA_DIR, test_file)
                if os.path.exists(test_path):
                    print(f"  Found: {test_file}")
                    test_df = pd.read_csv(test_path)
            break

    if train_df is None:
        # Check for any CSV in data dir
        csvs = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
        if csvs:
            print(f"  Found CSVs: {csvs}")
            dfs = []
            for csv_file in csvs:
                dfs.append(pd.read_csv(os.path.join(DATA_DIR, csv_file)))
            train_df = pd.concat(dfs, ignore_index=True)
        else:
            print("\n❌ No dataset found! Please download UNSW-NB15:")
            print("   Option 1: https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15")
            print("   Option 2: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
            print(f"\n   Place CSV files in: {DATA_DIR}/")
            sys.exit(1)

    if test_df is not None:
        df = pd.concat([train_df, test_df], ignore_index=True)
    else:
        df = train_df

    print(f"\n  Total samples: {len(df):,}")
    print(f"  Columns: {list(df.columns[:10])}...")
    return df


def preprocess_data(df: pd.DataFrame):
    """Clean and preprocess the dataset."""
    print("\n" + "=" * 60)
    print("🔧 Preprocessing Data")
    print("=" * 60)

    # Identify label column
    label_col = None
    for col_name in ["label", "Label", "attack_cat", "Attack_cat"]:
        if col_name in df.columns:
            label_col = col_name
            break

    # Binary label
    binary_col = None
    for col_name in ["label", "Label"]:
        if col_name in df.columns:
            binary_col = col_name
            break

    if binary_col is None:
        print("  ⚠️ No label column found. Creating from attack_cat...")
        if "attack_cat" in df.columns:
            df["label"] = (df["attack_cat"].str.strip() != "Normal").astype(int)
            binary_col = "label"
        else:
            print("  ❌ Cannot find label or attack_cat column")
            sys.exit(1)

    # Clean attack_cat if present
    if "attack_cat" in df.columns:
        df["attack_cat"] = df["attack_cat"].fillna("Normal").str.strip()

    print(f"  Label column: {binary_col}")
    print(f"  Class distribution:\n{df[binary_col].value_counts()}")

    # Select features
    available_features = [f for f in SELECTED_FEATURES if f in df.columns]
    print(f"\n  Using {len(available_features)} features out of {len(SELECTED_FEATURES)} selected")

    if len(available_features) < 10:
        # Fallback: use all numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        exclude = ["id", "label", "Label", "attack_cat"]
        available_features = [c for c in numeric_cols if c not in exclude]
        print(f"  Fallback: using {len(available_features)} numeric features")

    X = df[available_features].copy()
    y = df[binary_col].astype(int)

    # Handle missing values
    X = X.fillna(0)

    # Replace infinities
    X = X.replace([np.inf, -np.inf], 0)

    # Encode any remaining categorical columns
    for col in X.select_dtypes(include=["object"]).columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))

    # Scale features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns, index=X.index)

    # Save scaler and feature names
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(available_features, os.path.join(MODEL_DIR, "feature_names.pkl"))

    print(f"  Final shape: X={X_scaled.shape}, y={y.shape}")
    print(f"  Attack ratio: {y.mean():.2%}")

    return X_scaled, y, available_features


def train_models(X: pd.DataFrame, y: pd.Series, feature_names: list):
    """Train RF, XGBoost, and Isolation Forest models."""
    print("\n" + "=" * 60)
    print("🤖 Training Models")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

    results = {}

    # ── 1. Random Forest ──
    print("\n  🌲 Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]

    results["Random Forest"] = evaluate_model(y_test, rf_pred, rf_proba)
    joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.pkl"))
    print(f"     Accuracy: {results['Random Forest']['accuracy']:.4f}")
    print(f"     F1-Score: {results['Random Forest']['f1']:.4f}")

    # ── 2. XGBoost ──
    print("\n  🚀 Training XGBoost...")
    xgb = XGBClassifier(
        n_estimators=100,
        max_depth=10,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42,
    )
    xgb.fit(X_train, y_train)
    xgb_pred = xgb.predict(X_test)
    xgb_proba = xgb.predict_proba(X_test)[:, 1]

    results["XGBoost"] = evaluate_model(y_test, xgb_pred, xgb_proba)
    joblib.dump(xgb, os.path.join(MODEL_DIR, "xgboost.pkl"))
    print(f"     Accuracy: {results['XGBoost']['accuracy']:.4f}")
    print(f"     F1-Score: {results['XGBoost']['f1']:.4f}")

    # ── 3. Isolation Forest (Anomaly Detection) ──
    print("\n  🔍 Training Isolation Forest (Anomaly Detection)...")
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=float(y_train.mean()),  # Set based on actual attack ratio
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_train[y_train == 0])  # Train on normal traffic only
    iso_pred = iso_forest.predict(X_test)
    iso_pred_binary = (iso_pred == -1).astype(int)  # -1 = anomaly = attack

    results["Isolation Forest"] = evaluate_model(y_test, iso_pred_binary)
    joblib.dump(iso_forest, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    print(f"     Accuracy: {results['Isolation Forest']['accuracy']:.4f}")
    print(f"     F1-Score: {results['Isolation Forest']['f1']:.4f}")

    # Save results
    with open(os.path.join(REPORT_DIR, "model_results.json"), "w") as f:
        json.dump(results, f, indent=2)

    # Generate plots
    generate_plots(results, y_test, rf_pred, xgb_pred, rf, xgb, X_test, feature_names)

    # SHAP explanations
    if SHAP_AVAILABLE:
        generate_shap(xgb, X_test, feature_names)

    return results, X_test, y_test


def evaluate_model(y_true, y_pred, y_proba=None) -> dict:
    """Compute evaluation metrics."""
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_proba is not None:
        try:
            metrics["auc_roc"] = float(roc_auc_score(y_true, y_proba))
        except Exception:
            metrics["auc_roc"] = 0.0

    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics["classification_report"] = report
    return metrics


def generate_plots(results, y_test, rf_pred, xgb_pred, rf_model, xgb_model, X_test, feature_names):
    """Generate evaluation plots."""
    print("\n  📊 Generating evaluation plots...")

    # 1. Model Comparison Bar Chart
    fig, ax = plt.subplots(figsize=(10, 6))
    model_names = list(results.keys())
    metrics_to_plot = ["accuracy", "precision", "recall", "f1"]
    x = np.arange(len(model_names))
    width = 0.2

    for i, metric in enumerate(metrics_to_plot):
        values = [results[m][metric] for m in model_names]
        ax.bar(x + i * width, values, width, label=metric.capitalize())

    ax.set_xlabel("Model")
    ax.set_ylabel("Score")
    ax.set_title("NetSentinel — Model Performance Comparison")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(model_names)
    ax.legend()
    ax.set_ylim(0, 1.1)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "model_comparison.png"), dpi=150)
    plt.close()

    # 2. Confusion Matrices
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    for ax, pred, name in zip(axes, [rf_pred, xgb_pred], ["Random Forest", "XGBoost"]):
        cm = confusion_matrix(y_test, pred)
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                    xticklabels=["Normal", "Attack"],
                    yticklabels=["Normal", "Attack"])
        ax.set_title(f"{name} — Confusion Matrix")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "confusion_matrices.png"), dpi=150)
    plt.close()

    # 3. Feature Importance (XGBoost)
    fig, ax = plt.subplots(figsize=(10, 8))
    importances = xgb_model.feature_importances_
    indices = np.argsort(importances)[-20:]  # Top 20
    ax.barh(range(len(indices)), importances[indices], color="#2196F3")
    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels([feature_names[i] for i in indices])
    ax.set_xlabel("Feature Importance")
    ax.set_title("NetSentinel — Top 20 Feature Importances (XGBoost)")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, "feature_importance.png"), dpi=150)
    plt.close()

    print("  ✅ Plots saved to reports/")


def generate_shap(model, X_test, feature_names):
    """Generate SHAP explanations."""
    print("\n  🔮 Generating SHAP Explanations...")

    # Use a sample for speed
    sample_size = min(500, len(X_test))
    X_sample = X_test.iloc[:sample_size]

    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_sample)

        # Save SHAP explainer
        joblib.dump(explainer, os.path.join(MODEL_DIR, "shap_explainer.pkl"))

        # SHAP Summary Plot
        plt.figure(figsize=(12, 8))
        shap.summary_plot(shap_values, X_sample, feature_names=feature_names,
                          show=False, max_display=20)
        plt.title("NetSentinel — SHAP Feature Impact Analysis")
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, "shap_summary.png"), dpi=150, bbox_inches="tight")
        plt.close()

        # SHAP Bar Plot
        plt.figure(figsize=(10, 8))
        shap.summary_plot(shap_values, X_sample, feature_names=feature_names,
                          plot_type="bar", show=False, max_display=20)
        plt.title("NetSentinel — SHAP Mean Absolute Impact")
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, "shap_bar.png"), dpi=150, bbox_inches="tight")
        plt.close()

        print("  ✅ SHAP plots saved to reports/")

    except Exception as e:
        print(f"  ⚠️ SHAP generation failed: {e}")
        print("     Continuing without SHAP plots...")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════╗
    ║     🛡️  NetSentinel — Model Training Pipeline  ║
    ║     AI-Powered Network Threat Detection       ║
    ╚══════════════════════════════════════════════╝
    """)

    df = load_data()
    X, y, features = preprocess_data(df)
    results, X_test, y_test = train_models(X, y, features)

    print("\n" + "=" * 60)
    print("✅ TRAINING COMPLETE!")
    print("=" * 60)
    print(f"\n  📁 Models saved to: {MODEL_DIR}/")
    print(f"  📊 Reports saved to: {REPORT_DIR}/")
    print("\n  Model Performance Summary:")
    for name, metrics in results.items():
        print(f"    {name}:")
        print(f"      Accuracy:  {metrics['accuracy']:.4f}")
        print(f"      Precision: {metrics['precision']:.4f}")
        print(f"      Recall:    {metrics['recall']:.4f}")
        print(f"      F1-Score:  {metrics['f1']:.4f}")
        if "auc_roc" in metrics:
            print(f"      AUC-ROC:   {metrics['auc_roc']:.4f}")
    print("\n  Next step: Run the dashboard with 'streamlit run app.py'")
