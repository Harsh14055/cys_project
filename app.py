import os
import hashlib
import time
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from scanner_engine import scan_file

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def generate_hashes(file_path):
    """
    Generate MD5 and SHA256 hash of uploaded file
    """

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break

            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan-file", methods=["POST"])
def scan_file_endpoint():

    logs = []

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    logs.append("✓ File uploaded successfully")
    logs.append("🔍 Generating cryptographic hashes...")

    md5_hash, sha256_hash = generate_hashes(file_path)

    logs.append(f"MD5 generated: {md5_hash[:10]}...")
    logs.append(f"SHA256 generated: {sha256_hash[:10]}...")

    logs.append("⚙ Running machine learning detection...")

    # simulate scan delay for better UI experience
    time.sleep(1.5)

    # Run ML detection
    result = scan_file(file_path)

    verdict = result["verdict"]
    confidence = result["confidence"]

    logs.append(f"Prediction: {verdict}")
    logs.append(f"Confidence: {round(confidence * 100, 2)}%")

    # Convert verdict to UI format
    if verdict == "malicious":
        status = "Malicious"
    elif verdict == "benign":
        status = "Benign"
    else:
        status = "Unknown"

    logs.append("✓ Detection completed")

    response = {
        "file_name": file.filename,
        "md5": md5_hash,
        "sha256": sha256_hash,
        "status": status,
        "logs": logs
    }

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)