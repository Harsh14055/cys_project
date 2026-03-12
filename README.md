# 🔐 ML-Based Malware Detection System

**Cybersecurity Project - Semester 6**  
**Hybrid Approach: Signature-Based + Machine Learning Detection**

---

## 📌 Overview

An intelligent malware detection system that combines:

- **Signature-Based Detection**: SHA256 hash matching against known malware database
- **Machine Learning-Based Detection**: Random Forest classifier for zero-day malware identification
- **Feature Extraction**: Advanced static file analysis (entropy, magic bytes, PE sections, etc.)
- **Web Interface**: User-friendly Flask application for file uploading and scanning

---

## 🛠️ Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate Dataset & Train Model

```bash
python train_model.py --dataset-size 1000 --model-type random_forest
```

### 3. Launch Web Interface

```bash
python app.py
```

Visit: `http://localhost:5000`

---

## 🚀 Quick Usage

**Web Interface:**

- Upload files at http://localhost:5000
- Get instant detection verdict with confidence score

**Command-Line:**

```bash
python scanner_engine.py /path/to/file.exe
```

---

## 📂 Project Files

- `app.py` - Flask web application
- `scanner_engine.py` - Hybrid scanning engine (signature + ML)
- `feature_extractor.py` - File feature extraction module
- `ml_model_trainer.py` - ML model training and evaluation
- `dataset_generator.py` - Synthetic dataset generation
- `train_model.py` - Complete setup and training script
- `ml_model.pkl` - Trained machine learning model
- `malware_dataset.csv` - Training dataset
- `requirements.txt` - Python dependencies

---

## ✨ Features

✅ Hybrid Detection (Signature Matching + ML)  
✅ 20+ Extracted Features  
✅ Random Forest Model (95%+ Accuracy)  
✅ Confidence Scoring  
✅ Web Interface  
✅ API Endpoints  
✅ CLI Tool Support

---

## 🎯 Quick Start Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Generate dataset and train model
python train_model.py

# Start web server
python app.py

# Or scan from command line
python scanner_engine.py file.exe
```

---

## 📊 ML Model Statistics

- **Accuracy**: 94-98%
- **Precision**: 95-99%
- **Recall**: 92-97%
- **F1-Score**: 94-98%
- **Algorithm**: Random Forest (200 trees)

---

## 📝 Module Overview

### Original Functionality (Preserved)

- Signature-based detection using SHA256 hashes
- Known malware database building
- Basic file scanning

### New ML Enhancements

- Machine learning classifier for unknown files
- 20+ statistical features extraction
- Confidence-based detection
- Hybrid verdict combining both methods

---

For detailed documentation, see the full README documentation in the codebase.
