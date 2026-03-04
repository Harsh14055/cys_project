import os
import hashlib
import csv

import os
import hashlib
import csv

# Get current script directory
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

BASE_DIR = os.path.join(CURRENT_DIR, "..", "samples")
MALWARE_DIR = os.path.join(BASE_DIR, "malware")
BENIGN_DIR = os.path.join(BASE_DIR, "benign")

OUTPUT_FILE = os.path.join(CURRENT_DIR, "signatures.csv")


def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:

        while True:
            chunk = f.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def create_signature_database():

    signatures = []

    for filename in os.listdir(MALWARE_DIR):

        path = os.path.join(MALWARE_DIR, filename)

        if os.path.isfile(path):

            file_hash = calculate_hash(path)

            signatures.append([filename, file_hash, "malware"])

    for filename in os.listdir(BENIGN_DIR):

        path = os.path.join(BENIGN_DIR, filename)

        if os.path.isfile(path):

            file_hash = calculate_hash(path)

            signatures.append([filename, file_hash, "benign"])

    with open(OUTPUT_FILE, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow(["filename", "sha256", "type"])

        writer.writerows(signatures)

    print("Signature database generated successfully")


if __name__ == "__main__":
    create_signature_database()