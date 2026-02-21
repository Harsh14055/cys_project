# 🔐 Signature-Based Malware Detection System  
## 📌 Module: Signature Database & Hash Generator (Member 1)

---

## 📖 Overview

This module implements the **Signature Creation System** for a signature-based malware detection project.  
It generates **SHA256 cryptographic hashes** for known malware and benign files and stores them in a structured **CSV signature database**, which is later used by the scanning engine to detect malware.

> ⚠️ For safety, **simulated malware samples** are used instead of real malicious software.

---


---

## ⚙️ Functionality

### 🔹 Features
- Scans malware and benign sample folders
- Generates SHA256 hash for each file
- Labels files as **malware** or **benign**
- Stores signatures in a CSV database

---

## 🧑‍💻 Implemented Functions

### `calculate_hash(file_path)`
- Reads file in binary mode
- Computes SHA256 hash
- Returns hexadecimal hash string

### `create_signature_database()`
- Scans malware and benign directories
- Generates file hashes
- Writes data to `signatures.csv`

---

## 📄 Signature Database Format


| Column | Description |
|------|------------|
| filename | Name of the file |
| sha256 | SHA256 hash of file |
| type | malware / benign |

---

## ▶️ How to Run

```bash
python signature_generator.py


[SUCCESS] Signature database created: signatures.csv
Total signatures: 7
