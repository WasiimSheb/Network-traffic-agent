# Network Traffic Analysis Agent

## Overview
This project is an intelligent network traffic analysis agent. It takes a PCAP file as input, extracts network flows, classifies them as benign or malicious using a machine learning model, and generates a professional summary of suspicious activity using a local LLM (Ollama).

## Features
- Parses PCAP files and extracts network flows
- Computes real features (duration, src_bytes, dst_bytes, etc.)
- Classifies each flow as benign or malicious
- Summarizes suspicious flows in clear, analytical language
- Modular and extensible design

## Usage
1. **Install requirements:**
   - Python 3.8+
   - Install dependencies: `pip install -r requirements.txt`
   - Install and run [Ollama](https://ollama.com/) with the `tinyllama` model
2. **Run the agent:**
   ```bash
   python classify_flows.py <yourfile.pcap>
   ```
3. **Output:**
   - Console output with flow classifications
   - LLM-generated summary of suspicious activity

## Requirements
- Python 3.8+
- scikit-learn
- pandas
- pyshark
- joblib
- ollama (with `tinyllama` model)

## Architecture
```
   flowchart TD
    A[User provides PCAP file] --> B[Parse PCAP into flows]
    B --> C[Extract features (duration, src_bytes, dst_bytes, etc.)]
    C --> D[Classify flows with ML model]
    D --> E[Summarize suspicious flows with LLM]
    E --> F[Output report/summary]
```

## Notes
- The model is trained on the KDD Cup 99 dataset. For best results, extract as many real features as possible from your PCAPs.
- This is a prototype and can be extended for more robust, production-grade use. 
