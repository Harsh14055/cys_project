import os
import hashlib
import csv

# Base directory for samples
BASE_DIR = "samples"
MALWARE_DIR = os.path.join(BASE_DIR, "malware")
BENIGN_DIR = os.path.join(BASE_DIR, "benign")

OUTPUT_FILE = "signatures.csv"


def calculate_hash(file_path):
    """
    Calculate SHA256 hash of a file
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Cannot read file {file_path}: {e}")
        return None


def create_signature_database():
    """
    Scan malware and benign folders and generate signatures.csv
    """
    signatures = []

    # Scan malware samples
    for filename in os.listdir(MALWARE_DIR):
        file_path = os.path.join(MALWARE_DIR, filename)
        if os.path.isfile(file_path):
            file_hash = calculate_hash(file_path)
            if file_hash:
                signatures.append([filename, file_hash, "malware"])

    # Scan benign samples
    for filename in os.listdir(BENIGN_DIR):
        file_path = os.path.join(BENIGN_DIR, filename)
        if os.path.isfile(file_path):
            file_hash = calculate_hash(file_path)
            if file_hash:
                signatures.append([filename, file_hash, "benign"])

    # Write to CSV
    with open(OUTPUT_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["filename", "sha256", "type"])
        writer.writerows(signatures)

    print(f"[SUCCESS] Signature database created: {OUTPUT_FILE}")
    print(f"Total signatures: {len(signatures)}")


if __name__ == "__main__":
    create_signature_database()