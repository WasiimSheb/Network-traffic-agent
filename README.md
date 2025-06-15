# Network Traffic Analysis Agent

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview
This project is an intelligent network traffic analysis agent. It takes a PCAP file as input, extracts network flows, classifies them as benign or malicious using a machine learning model, and generates a professional summary of suspicious activity using a local LLM (Ollama).

## Table of Contents
- [Features](#features)
- [Usage](#usage)
- [Requirements](#requirements)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

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
   python src/classify_flows.py data/toolsmith.pcap
   ```
3. **Output:**
   - Console output with flow classifications
   - LLM-generated summary of suspicious activity

## Project Structure
```
├── src/
│   ├── classify_flows.py
│   ├── extract_features.py
│   ├── generate_report.py
│   ├── ollama_summary.py
│   ├── parse_pcap.py
│   └── train_classifier.py
├── scripts/
│   ├── expand_dataset.py
│   ├── analyze_datasets.py
│   ├── download_additional_pcaps.py
│   └── dataset_summary.py
├── data/
│   ├── kdd_train.csv
│   ├── toolsmith.pcap
│   ├── csv/
│   │   ├── CTU13_Attack_Traffic.csv
│   │   └── CTU13_Normal_Traffic.csv
│   ├── pcaps/
│   │   └── [additional PCAP files]
│   ├── dataset_info.json
│   ├── dataset_analysis.json
│   └── DOWNLOAD_INSTRUCTIONS.md
├── models/
│   └── model.pkl
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements
- Python 3.8+
- scikit-learn
- pandas
- pyshark
- joblib
- ollama (with `tinyllama` model)
- requests
- matplotlib
- seaborn
- numpy

## Architecture
```
   flowchart TD
    A[User provides PCAP file] --> B[Parse PCAP into flows]
    B --> C[Extract features such as duration src_bytes dst_bytes]
    C --> D[Classify flows with ML model]
    D --> E[Summarize suspicious flows with LLM]
    E --> F[Output report or summary]
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request if you have suggestions or improvements.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Dataset Expansion
The project now includes an expanded dataset for improved model robustness:
- **CTU-13 Dataset**: Botnet attack and normal traffic samples (22+ MB)
- **Additional PCAP samples**: Various protocol samples for testing
- **Dataset analysis tools**: Scripts to analyze and compare datasets

### Expanding Your Dataset
1. **Automatic expansion**: `python scripts/expand_dataset.py`
2. **Manual downloads**: See `data/DOWNLOAD_INSTRUCTIONS.md`
3. **Dataset analysis**: `python scripts/analyze_datasets.py`
4. **Summary overview**: `python scripts/dataset_summary.py`

## Notes
- The model is trained on the KDD Cup 99 dataset and can be enhanced with CTU-13 data
- For best results, extract as many real features as possible from your PCAPs
- The expanded dataset provides 10x more data with diverse attack patterns
- This is a prototype and can be extended for more robust, production-grade use 
