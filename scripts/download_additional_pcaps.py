#!/usr/bin/env python3
"""
Download Additional PCAP Files
This script downloads publicly available PCAP files from various sources
to expand the dataset for network traffic analysis.
"""

import requests
import os
from pathlib import Path
import zipfile
import tarfile

def download_file(url, filename, chunk_size=8192):
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

def extract_archive(archive_path, extract_to):
    """Extract archive files"""
    try:
        if archive_path.suffix.lower() == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif archive_path.suffix.lower() in ['.tar', '.tar.gz', '.tgz']:
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_to)
        
        print(f"Extracted: {archive_path}")
        return True
        
    except Exception as e:
        print(f"Error extracting {archive_path}: {e}")
        return False

def download_sample_pcaps():
    """Download sample PCAP files from public repositories"""
    
    # Create directories
    data_dir = Path("data")
    pcap_dir = data_dir / "pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    
    # Sample PCAP files from various sources
    pcap_sources = [
        {
            "name": "HTTP Traffic Sample",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap",
            "filename": "http_sample.cap",
            "description": "Basic HTTP traffic sample"
        },
        {
            "name": "DNS Traffic Sample", 
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap",
            "filename": "dns_sample.cap",
            "description": "DNS query and response traffic"
        },
        {
            "name": "FTP Traffic Sample",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ftp.cap",
            "filename": "ftp_sample.cap", 
            "description": "FTP protocol traffic"
        }
    ]
    
    print("=== Downloading Sample PCAP Files ===")
    
    downloaded_files = []
    
    for source in pcap_sources:
        file_path = pcap_dir / source["filename"]
        
        if file_path.exists():
            print(f"{source['filename']} already exists, skipping...")
            downloaded_files.append(file_path)
            continue
        
        print(f"\n{source['name']}: {source['description']}")
        if download_file(source["url"], file_path):
            downloaded_files.append(file_path)
            print(f"✓ Successfully downloaded {source['filename']}")
        else:
            print(f"✗ Failed to download {source['filename']}")
    
    return downloaded_files

def create_pcap_info():
    """Create information file about downloaded PCAPs"""
    
    pcap_info = {
        "downloaded_pcaps": [
            {
                "filename": "http_sample.cap",
                "type": "HTTP Traffic",
                "source": "Wireshark Sample Captures",
                "description": "Contains HTTP GET and POST requests with responses",
                "use_case": "Web traffic analysis, HTTP protocol learning"
            },
            {
                "filename": "dns_sample.cap", 
                "type": "DNS Traffic",
                "source": "Wireshark Sample Captures",
                "description": "DNS queries and responses for various domains",
                "use_case": "DNS analysis, domain resolution patterns"
            },
            {
                "filename": "ftp_sample.cap",
                "type": "FTP Traffic", 
                "source": "Wireshark Sample Captures",
                "description": "FTP login and file transfer session",
                "use_case": "File transfer protocol analysis"
            }
        ],
        "usage_notes": [
            "These are small sample files for testing and learning",
            "For production models, larger and more diverse datasets are recommended",
            "Consider the CTU-13 full dataset for comprehensive botnet analysis",
            "Always validate PCAP integrity before processing"
        ],
        "next_steps": [
            "Process PCAPs with your existing parse_pcap.py script",
            "Extract features using extract_features.py", 
            "Combine with existing datasets for training",
            "Consider downloading larger datasets from the manual instructions"
        ]
    }
    
    import json
    info_file = Path("data/pcap_info.json")
    with open(info_file, 'w') as f:
        json.dump(pcap_info, f, indent=2)
    
    print(f"\nPCAP information saved to: {info_file}")

def main():
    print("=== Additional PCAP Download Script ===")
    
    # Download sample PCAPs
    downloaded_files = download_sample_pcaps()
    
    # Create info file
    create_pcap_info()
    
    print(f"\n=== Summary ===")
    print(f"Downloaded {len(downloaded_files)} PCAP files")
    print("Files saved to: data/pcaps/")
    print("\nNext steps:")
    print("1. Run your existing classify_flows.py on these new PCAPs")
    print("2. Check data/DOWNLOAD_INSTRUCTIONS.md for larger datasets")
    print("3. Consider combining multiple datasets for training")
    
    # Show current data structure
    print(f"\nCurrent data directory structure:")
    data_dir = Path("data")
    for item in data_dir.rglob("*"):
        if item.is_file():
            size_mb = item.stat().st_size / (1024 * 1024)
            print(f"  {item.relative_to(data_dir)} ({size_mb:.1f} MB)")

if __name__ == "__main__":
    main() 