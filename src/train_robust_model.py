#!/usr/bin/env python3
"""
Robust Model Training Script
Creates a model that can handle multiple datasets with proper feature alignment.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import argparse
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class RobustNetworkClassifier:
    def __init__(self, test_size=0.2, random_state=42):
        self.test_size = test_size
        self.random_state = random_state
        self.model = None
        self.scaler = StandardScaler()
        
    def extract_universal_features(self, df, label_col='label'):
        """Extract universal features that work across all datasets"""
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
        
        print(f"   ✅ Extracted {len(feature_df.columns)} universal features")
        
        if y is not None:
            return feature_df, y
        else:
            return feature_df
    
    def load_kdd_data(self, filepath, sample_size=None):
        """Load KDD dataset with universal features"""
        print("📊 Loading KDD Cup 99 dataset...")
        
        columns = [
            "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent",
            "hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root",
            "num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
            "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
            "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
            "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
            "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","extra"
        ]
        
        df = pd.read_csv(filepath, names=columns, delimiter=',', header=None)
        df = df.drop(columns=["extra"])
        
        if sample_size:
            df = df.sample(n=min(sample_size, len(df)), random_state=self.random_state)
        
        # Encode categorical features
        from sklearn.preprocessing import LabelEncoder
        for col in ["protocol_type", "service", "flag"]:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
        
        # Convert label to binary
        df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
        
        # Extract universal features
        X, y = self.extract_universal_features(df, 'label')
        
        print(f"   📈 KDD samples: {len(X)}, attack ratio: {y.mean():.2%}")
        return X, y
    
    def load_ctu13_data(self, attack_file, normal_file, sample_size=None):
        """Load CTU-13 dataset with universal features"""
        print("📊 Loading CTU-13 dataset...")
        
        datasets = []
        
        # Load attack traffic
        if Path(attack_file).exists():
            attack_df = pd.read_csv(attack_file, nrows=sample_size//2 if sample_size else None)
            attack_df['label'] = 1
            datasets.append(attack_df)
        
        # Load normal traffic  
        if Path(normal_file).exists():
            normal_df = pd.read_csv(normal_file, nrows=sample_size//2 if sample_size else None)
            normal_df['label'] = 0
            datasets.append(normal_df)
        
        if not datasets:
            raise FileNotFoundError("CTU-13 data files not found")
        
        # Combine datasets
        df = pd.concat(datasets, ignore_index=True)
        df = df.sample(frac=1, random_state=self.random_state).reset_index(drop=True)
        
        # Extract universal features
        X, y = self.extract_universal_features(df, 'label')
        
        print(f"   📈 CTU-13 samples: {len(X)}, attack ratio: {y.mean():.2%}")
        return X, y
    
    def train_robust_model(self, datasets=['kdd', 'ctu13'], sample_size=None):
        """Train a robust model on multiple datasets"""
        print("🚀 TRAINING ROBUST NETWORK CLASSIFIER")
        print("=" * 50)
        
        all_X = []
        all_y = []
        dataset_info = []
        
        # Load datasets
        if 'kdd' in datasets:
            kdd_path = Path("data/kdd_train.csv")
            if kdd_path.exists():
                X_kdd, y_kdd = self.load_kdd_data(kdd_path, sample_size)
                all_X.append(X_kdd)
                all_y.append(y_kdd)
                dataset_info.append(f"KDD: {len(X_kdd)} samples")
        
        if 'ctu13' in datasets:
            attack_path = Path("data/csv/CTU13_Attack_Traffic.csv")
            normal_path = Path("data/csv/CTU13_Normal_Traffic.csv")
            
            if attack_path.exists() and normal_path.exists():
                X_ctu13, y_ctu13 = self.load_ctu13_data(attack_path, normal_path, sample_size)
                all_X.append(X_ctu13)
                all_y.append(y_ctu13)
                dataset_info.append(f"CTU-13: {len(X_ctu13)} samples")
        
        if not all_X:
            raise ValueError("No datasets loaded successfully")
        
        # Combine all datasets
        print(f"\n🔄 Combining datasets: {', '.join(dataset_info)}")
        
        X_combined = pd.concat(all_X, ignore_index=True)
        y_combined = pd.concat(all_y, ignore_index=True)
        
        # Shuffle combined data
        indices = np.random.RandomState(self.random_state).permutation(len(X_combined))
        X_combined = X_combined.iloc[indices].reset_index(drop=True)
        y_combined = y_combined.iloc[indices].reset_index(drop=True)
        
        print(f"📊 Combined dataset: {len(X_combined)} samples, {len(X_combined.columns)} features")
        print(f"📈 Overall attack ratio: {y_combined.mean():.2%}")
        
        # Split into train and test
        print(f"\n🔄 Splitting data: {int((1-self.test_size)*100)}% train, {int(self.test_size*100)}% test")
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_combined, 
            test_size=self.test_size, 
            random_state=self.random_state, 
            stratify=y_combined
        )
        
        print(f"   📊 Training set: {len(X_train)} samples")
        print(f"   📊 Test set: {len(X_test)} samples")
        
        # Scale features
        print("\n🔧 Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        print("🤖 Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        print("\n📊 MODEL EVALUATION:")
        print("=" * 30)
        
        # Training accuracy
        train_pred = self.model.predict(X_train_scaled)
        train_accuracy = accuracy_score(y_train, train_pred)
        print(f"Training Accuracy: {train_accuracy:.4f}")
        
        # Test accuracy
        test_pred = self.model.predict(X_test_scaled)
        test_accuracy = accuracy_score(y_test, test_pred)
        print(f"Test Accuracy: {test_accuracy:.4f}")
        
        # Detailed report
        print("\nClassification Report:")
        print(classification_report(y_test, test_pred, target_names=['Normal', 'Attack']))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, test_pred)
        print(f"\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"Actual    Normal  Attack")
        print(f"Normal    {cm[0,0]:6d}  {cm[0,1]:6d}")
        print(f"Attack    {cm[1,0]:6d}  {cm[1,1]:6d}")
        
        # Cross-validation
        print("\n🔄 Cross-validation (5-fold):")
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': X_train.columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print(f"\n🎯 Top 5 Most Important Features:")
        for i, (_, row) in enumerate(feature_importance.head().iterrows()):
            print(f"   {i+1}. {row['feature']}: {row['importance']:.4f}")
        
        return {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'feature_count': len(X_train.columns),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'datasets_used': datasets
        }
    
    def save_model(self, filepath="models/robust_model.pkl"):
        """Save the robust model"""
        if self.model is None:
            raise ValueError("No model trained yet")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': 'robust_universal'
        }
        
        Path(filepath).parent.mkdir(exist_ok=True)
        joblib.dump(model_data, filepath)
        print(f"✅ Robust model saved to {filepath}")


def main():
    parser = argparse.ArgumentParser(description="Train Robust Network Traffic Classifier")
    parser.add_argument("--datasets", nargs='+', default=['kdd', 'ctu13'],
                       choices=['kdd', 'ctu13'],
                       help="Datasets to use for training")
    parser.add_argument("--test-size", type=float, default=0.2,
                       help="Test set size (default: 0.2)")
    parser.add_argument("--sample-size", type=int, default=None,
                       help="Sample size per dataset")
    parser.add_argument("--output", default="models/robust_model.pkl",
                       help="Output model file")
    
    args = parser.parse_args()
    
    # Create classifier
    classifier = RobustNetworkClassifier(test_size=args.test_size)
    
    try:
        # Train model
        results = classifier.train_robust_model(
            datasets=args.datasets, 
            sample_size=args.sample_size
        )
        
        # Save model
        classifier.save_model(args.output)
        
        # Print summary
        print(f"\n🎉 TRAINING COMPLETE!")
        print("=" * 30)
        print(f"✅ Test Accuracy: {results['test_accuracy']:.4f}")
        print(f"📊 CV Accuracy: {results['cv_mean']:.4f} ± {results['cv_std']:.4f}")
        print(f"🎯 Features: {results['feature_count']}")
        print(f"📈 Training Samples: {results['train_samples']}")
        print(f"📊 Test Samples: {results['test_samples']}")
        print(f"💾 Model saved to: {args.output}")
        print(f"\n🚀 This model can now handle ANY network dataset!")
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 