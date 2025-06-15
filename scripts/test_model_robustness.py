#!/usr/bin/env python3
"""
Model Robustness Testing Script
Tests the current model on various datasets to evaluate robustness improvements.
"""

import sys
import os
sys.path.append('src')

import pandas as pd
import numpy as np
from pathlib import Path
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import json

def load_model():
    """Load the trained model"""
    model_path = Path("models/model.pkl")
    if not model_path.exists():
        print("❌ Model not found. Please train the model first:")
        print("   python src/train_classifier.py")
        return None
    
    try:
        model = joblib.load(model_path)
        print("✅ Model loaded successfully")
        return model
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return None

def prepare_ctu13_data(file_path, sample_size=1000):
    """Prepare CTU-13 data for testing"""
    try:
        print(f"📊 Loading {file_path.name}...")
        df = pd.read_csv(file_path, nrows=sample_size)
        
        # Remove non-numeric columns and handle missing values
        numeric_df = df.select_dtypes(include=[np.number])
        numeric_df = numeric_df.fillna(0)
        
        # Replace infinite values
        numeric_df = numeric_df.replace([np.inf, -np.inf], 0)
        
        print(f"   - Loaded {len(numeric_df)} samples with {len(numeric_df.columns)} features")
        return numeric_df
        
    except Exception as e:
        print(f"❌ Error loading {file_path}: {e}")
        return None

def test_on_ctu13_attack(model):
    """Test model on CTU-13 attack traffic"""
    print("\n🔍 Testing on CTU-13 Attack Traffic:")
    print("-" * 40)
    
    attack_file = Path("data/csv/CTU13_Attack_Traffic.csv")
    if not attack_file.exists():
        print("❌ CTU-13 attack data not found")
        return None
    
    attack_data = prepare_ctu13_data(attack_file)
    if attack_data is None:
        return None
    
    try:
        # Predict on attack data (should mostly be malicious)
        predictions = model.predict(attack_data)
        
        # Calculate statistics
        malicious_count = np.sum(predictions == 1)  # Assuming 1 = malicious
        benign_count = np.sum(predictions == 0)     # Assuming 0 = benign
        total = len(predictions)
        
        malicious_rate = malicious_count / total * 100
        
        results = {
            "dataset": "CTU-13 Attack Traffic",
            "total_samples": total,
            "predicted_malicious": malicious_count,
            "predicted_benign": benign_count,
            "malicious_detection_rate": malicious_rate
        }
        
        print(f"   Total samples: {total}")
        print(f"   Predicted malicious: {malicious_count} ({malicious_rate:.1f}%)")
        print(f"   Predicted benign: {benign_count} ({100-malicious_rate:.1f}%)")
        
        if malicious_rate > 70:
            print("   ✅ Good detection rate on attack traffic")
        elif malicious_rate > 50:
            print("   ⚠️  Moderate detection rate - consider retraining")
        else:
            print("   ❌ Low detection rate - model may need improvement")
        
        return results
        
    except Exception as e:
        print(f"❌ Error during prediction: {e}")
        return None

def test_on_ctu13_normal(model):
    """Test model on CTU-13 normal traffic"""
    print("\n🔍 Testing on CTU-13 Normal Traffic:")
    print("-" * 40)
    
    normal_file = Path("data/csv/CTU13_Normal_Traffic.csv")
    if not normal_file.exists():
        print("❌ CTU-13 normal data not found")
        return None
    
    normal_data = prepare_ctu13_data(normal_file)
    if normal_data is None:
        return None
    
    try:
        # Predict on normal data (should mostly be benign)
        predictions = model.predict(normal_data)
        
        # Calculate statistics
        malicious_count = np.sum(predictions == 1)
        benign_count = np.sum(predictions == 0)
        total = len(predictions)
        
        benign_rate = benign_count / total * 100
        false_positive_rate = malicious_count / total * 100
        
        results = {
            "dataset": "CTU-13 Normal Traffic",
            "total_samples": total,
            "predicted_malicious": malicious_count,
            "predicted_benign": benign_count,
            "benign_detection_rate": benign_rate,
            "false_positive_rate": false_positive_rate
        }
        
        print(f"   Total samples: {total}")
        print(f"   Predicted benign: {benign_count} ({benign_rate:.1f}%)")
        print(f"   Predicted malicious: {malicious_count} ({false_positive_rate:.1f}%)")
        
        if false_positive_rate < 10:
            print("   ✅ Low false positive rate")
        elif false_positive_rate < 20:
            print("   ⚠️  Moderate false positive rate")
        else:
            print("   ❌ High false positive rate - may need tuning")
        
        return results
        
    except Exception as e:
        print(f"❌ Error during prediction: {e}")
        return None

def test_feature_compatibility(model):
    """Test if model can handle different feature sets"""
    print("\n🔧 Testing Feature Compatibility:")
    print("-" * 35)
    
    # Test with CTU-13 data
    attack_file = Path("data/csv/CTU13_Attack_Traffic.csv")
    if attack_file.exists():
        try:
            df = pd.read_csv(attack_file, nrows=10)
            numeric_df = df.select_dtypes(include=[np.number]).fillna(0)
            
            # Try prediction
            _ = model.predict(numeric_df)
            print("   ✅ Model compatible with CTU-13 features")
            
        except Exception as e:
            print(f"   ❌ Feature compatibility issue: {e}")
            print("   💡 Consider feature alignment or model retraining")

def generate_robustness_report(results):
    """Generate a comprehensive robustness report"""
    print("\n📋 ROBUSTNESS ASSESSMENT REPORT:")
    print("=" * 50)
    
    if not results:
        print("❌ No test results available")
        return
    
    # Overall assessment
    attack_results = next((r for r in results if "Attack" in r["dataset"]), None)
    normal_results = next((r for r in results if "Normal" in r["dataset"]), None)
    
    if attack_results and normal_results:
        attack_detection = attack_results.get("malicious_detection_rate", 0)
        false_positive = normal_results.get("false_positive_rate", 100)
        
        print(f"🎯 Attack Detection Rate: {attack_detection:.1f}%")
        print(f"🚨 False Positive Rate: {false_positive:.1f}%")
        
        # Calculate overall score
        if attack_detection > 70 and false_positive < 15:
            score = "EXCELLENT"
            emoji = "🌟"
        elif attack_detection > 50 and false_positive < 25:
            score = "GOOD"
            emoji = "✅"
        elif attack_detection > 30 and false_positive < 35:
            score = "FAIR"
            emoji = "⚠️"
        else:
            score = "NEEDS IMPROVEMENT"
            emoji = "❌"
        
        print(f"\n{emoji} Overall Robustness: {score}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if attack_detection < 70:
            print("   - Consider retraining with CTU-13 attack data")
            print("   - Add more diverse attack samples")
        
        if false_positive > 20:
            print("   - Fine-tune model parameters")
            print("   - Add more normal traffic samples for training")
        
        if attack_detection > 70 and false_positive < 15:
            print("   - Model shows good robustness!")
            print("   - Consider testing on additional datasets")
    
    # Save results
    report_file = Path("data/robustness_report.json")
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: {report_file}")

def main():
    """Main testing function"""
    print("🧪 MODEL ROBUSTNESS TESTING")
    print("=" * 40)
    
    # Load model
    model = load_model()
    if model is None:
        return
    
    # Test feature compatibility
    test_feature_compatibility(model)
    
    # Run tests
    results = []
    
    # Test on attack traffic
    attack_results = test_on_ctu13_attack(model)
    if attack_results:
        results.append(attack_results)
    
    # Test on normal traffic
    normal_results = test_on_ctu13_normal(model)
    if normal_results:
        results.append(normal_results)
    
    # Generate report
    generate_robustness_report(results)
    
    print(f"\n🎉 Testing complete! Check the results above.")
    print(f"💡 To improve robustness, consider:")
    print(f"   1. Retraining with: python src/train_classifier.py")
    print(f"   2. Adding more datasets from: data/DOWNLOAD_INSTRUCTIONS.md")

if __name__ == "__main__":
    main() 