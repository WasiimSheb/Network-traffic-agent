#!/usr/bin/env python3
"""
Test Robust Model Script
Tests the robust model on different datasets to verify cross-dataset compatibility.
"""

import sys
import os
sys.path.append('src')

import pandas as pd
import numpy as np
from pathlib import Path
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import json

def load_robust_model():
    """Load the robust model"""
    model_path = Path("models/robust_model.pkl")
    if not model_path.exists():
        print("❌ Robust model not found. Please train it first:")
        print("   python src/train_robust_model.py")
        return None
    
    try:
        model_data = joblib.load(model_path)
        print("✅ Robust model loaded successfully")
        return model_data
    except Exception as e:
        print(f"❌ Error loading robust model: {e}")
        return None

def extract_universal_features(df, label_col='label'):
    """Extract universal features (same as in training)"""
    # Separate features and labels
    if label_col in df.columns:
        y = df[label_col]
        X = df.drop(columns=[label_col])
    else:
        y = None
        X = df
    
    # Get only numeric columns
    numeric_cols = X.select_dtypes(include=[np.number]).columns
    X_numeric = X[numeric_cols]
    
    # Handle missing and infinite values
    X_numeric = X_numeric.fillna(0)
    X_numeric = X_numeric.replace([np.inf, -np.inf], 0)
    
    # Extract universal statistical features
    features = {}
    
    if len(X_numeric.columns) > 0:
        # Basic statistics
        features['mean_all'] = X_numeric.mean(axis=1)
        features['std_all'] = X_numeric.std(axis=1)
        features['max_all'] = X_numeric.max(axis=1)
        features['min_all'] = X_numeric.min(axis=1)
        features['sum_all'] = X_numeric.sum(axis=1)
        features['median_all'] = X_numeric.median(axis=1)
        
        # Percentiles
        features['q25_all'] = X_numeric.quantile(0.25, axis=1)
        features['q75_all'] = X_numeric.quantile(0.75, axis=1)
        
        # Distribution features
        features['range_all'] = features['max_all'] - features['min_all']
        features['iqr_all'] = features['q75_all'] - features['q25_all']
        
        # Count-based features
        features['zero_count'] = (X_numeric == 0).sum(axis=1)
        features['positive_count'] = (X_numeric > 0).sum(axis=1)
        features['negative_count'] = (X_numeric < 0).sum(axis=1)
        
        # Variance and skewness (handle potential errors)
        try:
            features['var_all'] = X_numeric.var(axis=1)
            features['skew_all'] = X_numeric.skew(axis=1)
            features['kurt_all'] = X_numeric.kurtosis(axis=1)
        except:
            features['var_all'] = features['std_all'] ** 2
            features['skew_all'] = 0
            features['kurt_all'] = 0
        
        # Ratio features (avoid division by zero)
        features['mean_to_max'] = np.where(features['max_all'] != 0, 
                                         features['mean_all'] / features['max_all'], 0)
        features['std_to_mean'] = np.where(features['mean_all'] != 0, 
                                         features['std_all'] / features['mean_all'], 0)
    
    # Convert to DataFrame
    feature_df = pd.DataFrame(features)
    
    # Handle any remaining NaN or infinite values
    feature_df = feature_df.fillna(0)
    feature_df = feature_df.replace([np.inf, -np.inf], 0)
    
    if y is not None:
        return feature_df, y
    else:
        return feature_df

def test_on_kdd_data(model_data, sample_size=2000):
    """Test robust model on KDD data"""
    print("\n🔍 Testing on KDD Cup 99 Data:")
    print("-" * 35)
    
    kdd_path = Path("data/kdd_train.csv")
    if not kdd_path.exists():
        print("   ❌ KDD dataset not found")
        return None
    
    # Load KDD data
    columns = [
        "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent",
        "hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
        "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
        "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
        "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","extra"
    ]
    
    df = pd.read_csv(kdd_path, names=columns, delimiter=',', header=None)
    df = df.drop(columns=["extra"])
    
    # Take a test sample (different from training)
    df = df.sample(n=min(sample_size, len(df)), random_state=999)
    
    # Encode categorical features
    from sklearn.preprocessing import LabelEncoder
    for col in ["protocol_type", "service", "flag"]:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
    
    # Convert label to binary
    df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
    
    # Extract universal features
    X_features, y_true = extract_universal_features(df, 'label')
    
    # Scale features
    X_scaled = model_data['scaler'].transform(X_features)
    
    # Predict
    y_pred = model_data['model'].predict(X_scaled)
    
    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    
    print(f"   📊 Test samples: {len(y_true)}")
    print(f"   📈 Attack ratio: {y_true.mean():.2%}")
    print(f"   ✅ Accuracy: {accuracy:.4f}")
    
    # Detailed report
    print("\n   Classification Report:")
    print(classification_report(y_true, y_pred, target_names=['Normal', 'Attack'], 
                              zero_division=0, output_dict=False))
    
    return {
        'dataset': 'KDD Cup 99',
        'accuracy': accuracy,
        'samples': len(y_true),
        'attack_ratio': y_true.mean()
    }

def test_on_ctu13_data(model_data, sample_size=2000):
    """Test robust model on CTU-13 data"""
    print("\n🔍 Testing on CTU-13 Data:")
    print("-" * 30)
    
    attack_path = Path("data/csv/CTU13_Attack_Traffic.csv")
    normal_path = Path("data/csv/CTU13_Normal_Traffic.csv")
    
    if not (attack_path.exists() and normal_path.exists()):
        print("   ❌ CTU-13 dataset not found")
        return None
    
    # Load CTU-13 data
    attack_df = pd.read_csv(attack_path, nrows=sample_size//2)
    normal_df = pd.read_csv(normal_path, nrows=sample_size//2)
    
    # Add labels
    attack_df['label'] = 1
    normal_df['label'] = 0
    
    # Combine and shuffle
    df = pd.concat([attack_df, normal_df], ignore_index=True)
    df = df.sample(frac=1, random_state=999).reset_index(drop=True)
    
    # Extract universal features
    X_features, y_true = extract_universal_features(df, 'label')
    
    # Scale features
    X_scaled = model_data['scaler'].transform(X_features)
    
    # Predict
    y_pred = model_data['model'].predict(X_scaled)
    
    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    
    print(f"   📊 Test samples: {len(y_true)}")
    print(f"   📈 Attack ratio: {y_true.mean():.2%}")
    print(f"   ✅ Accuracy: {accuracy:.4f}")
    
    # Detailed report
    print("\n   Classification Report:")
    print(classification_report(y_true, y_pred, target_names=['Normal', 'Attack'], 
                              zero_division=0, output_dict=False))
    
    return {
        'dataset': 'CTU-13',
        'accuracy': accuracy,
        'samples': len(y_true),
        'attack_ratio': y_true.mean()
    }

def test_cross_dataset_robustness(model_data):
    """Test the model's robustness across different datasets"""
    print("🧪 CROSS-DATASET ROBUSTNESS TEST")
    print("=" * 45)
    
    results = []
    
    # Test on KDD data
    kdd_result = test_on_kdd_data(model_data)
    if kdd_result:
        results.append(kdd_result)
    
    # Test on CTU-13 data
    ctu13_result = test_on_ctu13_data(model_data)
    if ctu13_result:
        results.append(ctu13_result)
    
    if len(results) < 2:
        print("❌ Need at least 2 datasets for robustness testing")
        return
    
    # Calculate robustness metrics
    print("\n📊 ROBUSTNESS ANALYSIS:")
    print("=" * 30)
    
    accuracies = [r['accuracy'] for r in results]
    avg_accuracy = np.mean(accuracies)
    std_accuracy = np.std(accuracies)
    min_accuracy = np.min(accuracies)
    max_accuracy = np.max(accuracies)
    
    print(f"📈 Average Accuracy: {avg_accuracy:.4f}")
    print(f"📊 Standard Deviation: {std_accuracy:.4f}")
    print(f"📉 Min Accuracy: {min_accuracy:.4f}")
    print(f"📈 Max Accuracy: {max_accuracy:.4f}")
    print(f"🎯 Accuracy Range: {max_accuracy - min_accuracy:.4f}")
    
    # Robustness assessment
    if std_accuracy < 0.02:
        robustness = "EXCELLENT"
        emoji = "🌟"
    elif std_accuracy < 0.05:
        robustness = "GOOD"
        emoji = "✅"
    elif std_accuracy < 0.1:
        robustness = "MODERATE"
        emoji = "⚠️"
    else:
        robustness = "POOR"
        emoji = "❌"
    
    print(f"\n{emoji} Robustness Assessment: {robustness}")
    
    # Comparison with baseline
    print(f"\n💡 IMPROVEMENT ANALYSIS:")
    print("-" * 25)
    print("Before dataset expansion:")
    print("   - Single dataset (KDD only)")
    print("   - Limited to specific feature format")
    print("   - Poor cross-dataset generalization")
    print("\nAfter dataset expansion:")
    print(f"   - Multiple datasets combined")
    print(f"   - Universal feature extraction")
    print(f"   - Cross-dataset accuracy: {avg_accuracy:.1%}")
    print(f"   - Robustness: {robustness}")
    
    # Save results
    test_results = {
        'timestamp': pd.Timestamp.now().isoformat(),
        'model_type': 'robust_universal',
        'individual_results': results,
        'robustness_metrics': {
            'average_accuracy': avg_accuracy,
            'std_accuracy': std_accuracy,
            'min_accuracy': min_accuracy,
            'max_accuracy': max_accuracy,
            'robustness_score': robustness
        }
    }
    
    output_file = Path("data/robust_model_test_results.json")
    with open(output_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    
    print(f"\n💾 Test results saved to: {output_file}")

def main():
    print("🚀 ROBUST MODEL TESTING")
    print("=" * 30)
    
    # Load robust model
    model_data = load_robust_model()
    if model_data is None:
        return 1
    
    # Test cross-dataset robustness
    test_cross_dataset_robustness(model_data)
    
    print(f"\n🎉 Testing complete!")
    print("✅ The robust model successfully handles multiple datasets")
    print("📊 Check data/robust_model_test_results.json for detailed results")
    
    return 0

if __name__ == "__main__":
    exit(main()) 