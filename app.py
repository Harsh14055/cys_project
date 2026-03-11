import os
import hashlib
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from scanner_engine import load_signatures, check_signature

UPLOAD_FOLDER = "uploads"

app = Flask(__name__)
CORS(app)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

signatures = load_signatures()


def generate_hashes(file_path):

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


# ✅ Serve the UI
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan-file", methods=["POST"])
def scan_file():

    logs = []

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)

    file.save(file_path)

    logs.append("File uploaded successfully")
    logs.append("Generating hashes")

    md5_hash, sha256_hash = generate_hashes(file_path)

    logs.append("Checking signature database")

    is_match, filename, file_type = check_signature(sha256_hash, signatures)

    if is_match:
        status = "Malicious" if file_type == "malware" else "Benign"
    else:
        status = "Unknown"

    logs.append("Detection completed")

    return jsonify({
        "file_name": file.filename,
        "md5": md5_hash,
        "sha256": sha256_hash,
        "status": status,
        "logs": logs
    })


if __name__ == "__main__":
    app.run(debug=True)