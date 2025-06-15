#!/usr/bin/env python3
"""
Dataset Expansion Script for Network Traffic Analysis
This script helps download and organize various publicly available PCAP datasets
to improve the robustness of network security models.
"""

import os
import sys
import requests
import zipfile
import tarfile
import gzip
import shutil
import argparse
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json
from datetime import datetime

class DatasetExpander:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for different types of data
        self.pcap_dir = self.data_dir / "pcaps"
        self.csv_dir = self.data_dir / "csv"
        self.malware_dir = self.data_dir / "malware"
        self.normal_dir = self.data_dir / "normal"
        
        for dir_path in [self.pcap_dir, self.csv_dir, self.malware_dir, self.normal_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Dataset catalog with download URLs and descriptions
        self.datasets = {
            "ctu13_csv": {
                "name": "CTU-13 CSV Dataset",
                "description": "Processed CTU-13 dataset with botnet, normal and background traffic in CSV format",
                "urls": [
                    "https://raw.githubusercontent.com/imfaisalmalik/CTU13-CSV-Dataset/main/CTU13_Attack_Traffic.csv",
                    "https://raw.githubusercontent.com/imfaisalmalik/CTU13-CSV-Dataset/main/CTU13_Normal_Traffic.csv"
                ],
                "type": "csv",
                "size": "~50MB"
            },
            "malware_traffic_analysis": {
                "name": "Malware Traffic Analysis Samples",
                "description": "Recent malware traffic samples from malware-traffic-analysis.net",
                "urls": [
                    # These would need to be updated with current samples
                    "https://www.malware-traffic-analysis.net/training/host-and-user-ID.html"
                ],
                "type": "pcap",
                "note": "Manual download required due to password protection"
            },
            "cicids2017": {
                "name": "CICIDS2017 Dataset",
                "description": "Intrusion Detection Evaluation Dataset with benign and attack traffic",
                "urls": [
                    "https://www.unb.ca/cic/datasets/ids-2017.html"
                ],
                "type": "csv",
                "note": "Manual download required from official source"
            },
            "unsw_nb15": {
                "name": "UNSW-NB15 Dataset",
                "description": "Network intrusion dataset with nine attack families",
                "urls": [
                    "https://research.unsw.edu.au/projects/unsw-nb15-dataset"
                ],
                "type": "csv",
                "note": "Manual download required from official source"
            }
        }
    
    def download_file(self, url, filename, chunk_size=8192):
        """Download a file with progress indication"""
        try:
            print(f"Downloading {filename} from {url}")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\rProgress: {percent:.1f}%", end='', flush=True)
            
            print(f"\nDownloaded: {filename}")
            return True
            
        except Exception as e:
            print(f"Error downloading {url}: {e}")
            return False
    
    def extract_archive(self, archive_path, extract_to):
        """Extract various archive formats"""
        try:
            if archive_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            elif archive_path.suffix.lower() in ['.tar', '.tar.gz', '.tgz']:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_to)
            elif archive_path.suffix.lower() == '.gz':
                with gzip.open(archive_path, 'rb') as f_in:
                    with open(extract_to / archive_path.stem, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            
            print(f"Extracted: {archive_path}")
            return True
            
        except Exception as e:
            print(f"Error extracting {archive_path}: {e}")
            return False
    
    def download_ctu13_csv(self):
        """Download CTU-13 CSV dataset"""
        print("\n=== Downloading CTU-13 CSV Dataset ===")
        
        urls = self.datasets["ctu13_csv"]["urls"]
        filenames = ["CTU13_Attack_Traffic.csv", "CTU13_Normal_Traffic.csv"]
        
        for url, filename in zip(urls, filenames):
            file_path = self.csv_dir / filename
            if not file_path.exists():
                if self.download_file(url, file_path):
                    print(f"Successfully downloaded {filename}")
                else:
                    print(f"Failed to download {filename}")
            else:
                print(f"{filename} already exists, skipping...")
    
    def generate_sample_pcaps(self):
        """Generate sample PCAP files for testing (synthetic data)"""
        print("\n=== Generating Sample PCAP Files ===")
        
        # This would create synthetic network traffic for testing
        # In a real implementation, you might use scapy to generate packets
        sample_data = {
            "sample_http_traffic.txt": "Sample HTTP traffic data for testing",
            "sample_dns_traffic.txt": "Sample DNS traffic data for testing",
            "sample_malware_traffic.txt": "Sample malware traffic data for testing"
        }
        
        for filename, content in sample_data.items():
            file_path = self.pcap_dir / filename
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"Created sample file: {filename}")
    
    def create_dataset_info(self):
        """Create a JSON file with dataset information"""
        info = {
            "created": datetime.now().isoformat(),
            "datasets": self.datasets,
            "directory_structure": {
                "pcaps": "PCAP files for network traffic analysis",
                "csv": "CSV files with processed network features",
                "malware": "Malware-related traffic samples",
                "normal": "Normal/benign traffic samples"
            },
            "usage_notes": [
                "Always verify dataset licenses before use",
                "Some datasets require manual download due to access restrictions",
                "Consider data privacy and ethical use guidelines",
                "Validate data integrity after download"
            ]
        }
        
        info_file = self.data_dir / "dataset_info.json"
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"Created dataset information file: {info_file}")
    
    def list_available_datasets(self):
        """List all available datasets"""
        print("\n=== Available Datasets ===")
        for key, dataset in self.datasets.items():
            print(f"\n{dataset['name']}:")
            print(f"  Description: {dataset['description']}")
            print(f"  Type: {dataset['type']}")
            if 'size' in dataset:
                print(f"  Size: {dataset['size']}")
            if 'note' in dataset:
                print(f"  Note: {dataset['note']}")
    
    def create_download_instructions(self):
        """Create a file with manual download instructions"""
        instructions = """
# Manual Download Instructions

Some datasets require manual download due to access restrictions or password protection.
Here are the instructions for each:

## 1. Malware Traffic Analysis (malware-traffic-analysis.net)
- Visit: https://www.malware-traffic-analysis.net/
- Browse recent traffic analysis exercises
- Download PCAP files (password: infected)
- Place in data/pcaps/ directory

## 2. CICIDS2017 Dataset
- Visit: https://www.unb.ca/cic/datasets/ids-2017.html
- Register and download the dataset
- Extract CSV files to data/csv/ directory

## 3. UNSW-NB15 Dataset
- Visit: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Download the training and testing sets
- Place CSV files in data/csv/ directory

## 4. CTU-13 Dataset (Full PCAP)
- Visit: https://www.stratosphereips.org/datasets-ctu13
- Download individual scenarios or full dataset (1.9GB)
- Extract PCAP files to data/pcaps/ directory

## 5. Additional Sources
- SecRepo: https://www.secrepo.com/
- Kaggle Security Datasets: https://www.kaggle.com/datasets?search=cybersecurity
- PCAP Repository: https://github.com/markofu/pcaps

## Usage Notes
- Always check dataset licenses
- Verify file integrity after download
- Consider ethical implications of malware samples
- Use appropriate security measures when handling malware
"""
        
        instructions_file = self.data_dir / "DOWNLOAD_INSTRUCTIONS.md"
        with open(instructions_file, 'w') as f:
            f.write(instructions)
        
        print(f"Created download instructions: {instructions_file}")
    
    def run(self, download_auto=True, generate_samples=True):
        """Run the dataset expansion process"""
        print("=== Network Traffic Dataset Expansion ===")
        print(f"Data directory: {self.data_dir.absolute()}")
        
        # List available datasets
        self.list_available_datasets()
        
        # Download automatically available datasets
        if download_auto:
            self.download_ctu13_csv()
        
        # Generate sample files for testing
        if generate_samples:
            self.generate_sample_pcaps()
        
        # Create information files
        self.create_dataset_info()
        self.create_download_instructions()
        
        print(f"\n=== Summary ===")
        print(f"Data directory structure created at: {self.data_dir.absolute()}")
        print("Check DOWNLOAD_INSTRUCTIONS.md for manual download steps")
        print("Review dataset_info.json for detailed information")


def main():
    parser = argparse.ArgumentParser(description="Expand network traffic dataset")
    parser.add_argument("--data-dir", default="data", help="Data directory path")
    parser.add_argument("--no-download", action="store_true", help="Skip automatic downloads")
    parser.add_argument("--no-samples", action="store_true", help="Skip sample generation")
    parser.add_argument("--list-only", action="store_true", help="Only list available datasets")
    
    args = parser.parse_args()
    
    expander = DatasetExpander(args.data_dir)
    
    if args.list_only:
        expander.list_available_datasets()
    else:
        expander.run(
            download_auto=not args.no_download,
            generate_samples=not args.no_samples
        )


if __name__ == "__main__":
    main() 