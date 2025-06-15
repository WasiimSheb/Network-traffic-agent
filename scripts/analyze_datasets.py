#!/usr/bin/env python3
"""
Dataset Analysis Script
Analyzes the characteristics of different network traffic datasets
to help understand their diversity and potential for improving model robustness.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import argparse
from collections import Counter

class DatasetAnalyzer:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.results = {}
    
    def analyze_kdd_dataset(self):
        """Analyze the original KDD Cup 99 dataset"""
        print("=== Analyzing KDD Cup 99 Dataset ===")
        
        kdd_file = self.data_dir / "kdd_train.csv"
        if not kdd_file.exists():
            print(f"KDD dataset not found at {kdd_file}")
            return None
        
        try:
            # Read a sample of the KDD dataset (it's large)
            df = pd.read_csv(kdd_file, nrows=10000)
            
            analysis = {
                "name": "KDD Cup 99",
                "total_samples": len(df),
                "features": df.shape[1],
                "columns": list(df.columns) if hasattr(df, 'columns') else [],
                "data_types": df.dtypes.value_counts().to_dict() if hasattr(df, 'dtypes') else {},
                "missing_values": df.isnull().sum().sum() if hasattr(df, 'isnull') else 0
            }
            
            # Try to identify attack types if there's a label column
            if 'label' in df.columns:
                analysis["attack_distribution"] = df['label'].value_counts().to_dict()
            elif df.shape[1] > 0:  # Use last column as potential label
                last_col = df.columns[-1]
                analysis["attack_distribution"] = df[last_col].value_counts().to_dict()
            
            self.results["kdd99"] = analysis
            print(f"  - Samples analyzed: {analysis['total_samples']}")
            print(f"  - Features: {analysis['features']}")
            print(f"  - Missing values: {analysis['missing_values']}")
            
            return analysis
            
        except Exception as e:
            print(f"Error analyzing KDD dataset: {e}")
            return None
    
    def analyze_ctu13_datasets(self):
        """Analyze the CTU-13 CSV datasets"""
        print("\n=== Analyzing CTU-13 Datasets ===")
        
        csv_dir = self.data_dir / "csv"
        ctu13_files = {
            "attack": csv_dir / "CTU13_Attack_Traffic.csv",
            "normal": csv_dir / "CTU13_Normal_Traffic.csv"
        }
        
        ctu13_analysis = {}
        
        for traffic_type, file_path in ctu13_files.items():
            if not file_path.exists():
                print(f"  {traffic_type.title()} traffic file not found")
                continue
            
            try:
                # Read a sample for analysis
                df = pd.read_csv(file_path, nrows=5000)
                
                analysis = {
                    "name": f"CTU-13 {traffic_type.title()} Traffic",
                    "file_size_mb": file_path.stat().st_size / (1024 * 1024),
                    "total_samples": len(df),
                    "features": df.shape[1],
                    "columns": list(df.columns),
                    "data_types": df.dtypes.value_counts().to_dict(),
                    "missing_values": df.isnull().sum().sum(),
                    "numeric_features": len(df.select_dtypes(include=[np.number]).columns),
                    "categorical_features": len(df.select_dtypes(include=['object']).columns)
                }
                
                # Basic statistics for numeric columns
                numeric_df = df.select_dtypes(include=[np.number])
                if not numeric_df.empty:
                    analysis["numeric_stats"] = {
                        "mean_values": numeric_df.mean().to_dict(),
                        "std_values": numeric_df.std().to_dict(),
                        "zero_variance_features": (numeric_df.std() == 0).sum()
                    }
                
                ctu13_analysis[traffic_type] = analysis
                print(f"  {traffic_type.title()} Traffic:")
                print(f"    - File size: {analysis['file_size_mb']:.1f} MB")
                print(f"    - Samples: {analysis['total_samples']}")
                print(f"    - Features: {analysis['features']}")
                print(f"    - Numeric features: {analysis['numeric_features']}")
                print(f"    - Missing values: {analysis['missing_values']}")
                
            except Exception as e:
                print(f"  Error analyzing {traffic_type} traffic: {e}")
        
        self.results["ctu13"] = ctu13_analysis
        return ctu13_analysis
    
    def compare_datasets(self):
        """Compare characteristics across datasets"""
        print("\n=== Dataset Comparison ===")
        
        if not self.results:
            print("No datasets analyzed yet")
            return
        
        comparison = {
            "dataset_count": len(self.results),
            "total_samples": 0,
            "feature_diversity": set(),
            "data_sources": []
        }
        
        for dataset_name, dataset_info in self.results.items():
            if dataset_name == "ctu13":
                # Handle CTU-13 nested structure
                for traffic_type, info in dataset_info.items():
                    comparison["total_samples"] += info.get("total_samples", 0)
                    comparison["feature_diversity"].update(info.get("columns", []))
                    comparison["data_sources"].append(f"CTU-13 {traffic_type}")
            else:
                comparison["total_samples"] += dataset_info.get("total_samples", 0)
                comparison["feature_diversity"].update(dataset_info.get("columns", []))
                comparison["data_sources"].append(dataset_info.get("name", dataset_name))
        
        comparison["unique_features"] = len(comparison["feature_diversity"])
        comparison["feature_diversity"] = list(comparison["feature_diversity"])
        
        print(f"  Total datasets: {comparison['dataset_count']}")
        print(f"  Total samples available: {comparison['total_samples']:,}")
        print(f"  Unique features across datasets: {comparison['unique_features']}")
        print(f"  Data sources: {', '.join(comparison['data_sources'])}")
        
        self.results["comparison"] = comparison
        return comparison
    
    def generate_recommendations(self):
        """Generate recommendations for improving model robustness"""
        print("\n=== Recommendations for Model Robustness ===")
        
        recommendations = []
        
        # Check dataset diversity
        if len(self.results) < 3:
            recommendations.append(
                "Consider adding more diverse datasets (e.g., CICIDS2017, UNSW-NB15) "
                "to improve model generalization across different attack types and network environments."
            )
        
        # Check for feature diversity
        comparison = self.results.get("comparison", {})
        if comparison.get("unique_features", 0) < 50:
            recommendations.append(
                "Current feature set may be limited. Consider datasets with more diverse "
                "network features (protocol-specific, temporal, behavioral) for better coverage."
            )
        
        # Check for balanced data
        kdd_analysis = self.results.get("kdd99", {})
        if "attack_distribution" in kdd_analysis:
            attack_dist = kdd_analysis["attack_distribution"]
            if len(attack_dist) > 1:
                values = list(attack_dist.values())
                max_val, min_val = max(values), min(values)
                if max_val / min_val > 10:  # Highly imbalanced
                    recommendations.append(
                        "Dataset appears imbalanced. Consider using sampling techniques "
                        "(SMOTE, undersampling) or collecting more balanced datasets."
                    )
        
        # Specific dataset recommendations
        recommendations.extend([
            "Download CTU-13 full PCAP files for more detailed packet-level analysis.",
            "Consider IoT-specific datasets if your network includes IoT devices.",
            "Add recent malware samples from malware-traffic-analysis.net for current threats.",
            "Include normal traffic from different network environments for better baseline modeling."
        ])
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        self.results["recommendations"] = recommendations
        return recommendations
    
    def save_analysis(self, output_file="data/dataset_analysis.json"):
        """Save analysis results to JSON file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(exist_ok=True)
        
        # Convert numpy types to native Python types for JSON serialization
        def convert_numpy(obj):
            if isinstance(obj, (np.integer, np.int64)):
                return int(obj)
            elif isinstance(obj, (np.floating, np.float64)):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {str(key): convert_numpy(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy(item) for item in obj]
            elif hasattr(obj, 'dtype'):  # Handle pandas/numpy dtypes
                return str(obj)
            return obj
        
        clean_results = convert_numpy(self.results)
        
        with open(output_path, 'w') as f:
            json.dump(clean_results, f, indent=2, default=str)
        
        print(f"\nAnalysis saved to: {output_path}")
    
    def run_full_analysis(self):
        """Run complete dataset analysis"""
        print("=== Network Traffic Dataset Analysis ===")
        
        # Analyze individual datasets
        self.analyze_kdd_dataset()
        self.analyze_ctu13_datasets()
        
        # Compare datasets
        self.compare_datasets()
        
        # Generate recommendations
        self.generate_recommendations()
        
        # Save results
        self.save_analysis()
        
        return self.results


def main():
    parser = argparse.ArgumentParser(description="Analyze network traffic datasets")
    parser.add_argument("--data-dir", default="data", help="Data directory path")
    parser.add_argument("--output", default="data/dataset_analysis.json", help="Output file for analysis")
    
    args = parser.parse_args()
    
    analyzer = DatasetAnalyzer(args.data_dir)
    results = analyzer.run_full_analysis()
    
    if args.output != "data/dataset_analysis.json":
        analyzer.save_analysis(args.output)


if __name__ == "__main__":
    main() 