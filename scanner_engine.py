import os
import hashlib
import csv
import sys

# Configuration
SIGNATURES_DB = "signatures.csv"


def load_signatures():
    """
    Load signatures from signatures.csv into a dictionary
    Returns: {sha256_hash: (filename, type)}
    """
    signatures = {}
    try:
        if not os.path.exists(SIGNATURES_DB):
            print(f"[ERROR] Signature database not found: {SIGNATURES_DB}")
            return signatures
        
        with open(SIGNATURES_DB, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sha256 = row["sha256"].strip()
                filename = row["filename"].strip()
                file_type = row["type"].strip()
                signatures[sha256] = (filename, file_type)
        
        print(f"[✓] Successfully loaded {len(signatures)} signatures from database")
        return signatures
    
    except Exception as e:
        print(f"[ERROR] Failed to load signatures: {e}")
        return signatures


def generate_file_hash(file_path):
    """
    Generate SHA256 hash of a file
    Returns: SHA256 hexdigest or None if error
    """
    sha256 = hashlib.sha256()
    try:
        if not os.path.exists(file_path):
            print(f"[ERROR] File not found: {file_path}")
            return None
        
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        
        file_hash = sha256.hexdigest()
        return file_hash
    
    except Exception as e:
        print(f"[ERROR] Cannot read file {file_path}: {e}")
        return None


def check_signature(file_hash, signatures):
    """
    Check if a file hash matches a known signature
    Returns: (is_match, filename, file_type) or (False, None, None) if not found
    """
    if file_hash in signatures:
        filename, file_type = signatures[file_hash]
        return True, filename, file_type
    return False, None, None


def scan_file(file_path, signatures):
    """
    Scan a file by generating its hash and comparing with database
    Returns: scan result dictionary
    """
    print(f"\n{'='*60}")
    print(f"[*] Scanning: {file_path}")
    print(f"{'='*60}")
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"[✗] File not found: {file_path}")
        return {
            "status": "error",
            "file": file_path,
            "message": "File not found"
        }
    
    # Generate hash
    print("[*] Generating SHA256 hash...")
    file_hash = generate_file_hash(file_path)
    
    if file_hash is None:
        print("[✗] Failed to generate file hash")
        return {
            "status": "error",
            "file": file_path,
            "message": "Failed to generate hash"
        }
    
    print(f"[*] File Hash: {file_hash}")
    
    # Check signature
    print("[*] Checking against signature database...")
    is_match, orig_filename, file_type = check_signature(file_hash, signatures)
    
    if is_match:
        result = {
            "status": "detected",
            "file": file_path,
            "hash": file_hash,
            "type": file_type,
            "matched_signature": orig_filename,
            "message": f"[⚠] MALWARE DETECTED!" if file_type == "malware" else "[✓] Known benign file"
        }
        print(result["message"])
        print(f"    Classification: {file_type.upper()}")
        print(f"    Matched signature: {orig_filename}")
    else:
        result = {
            "status": "unknown",
            "file": file_path,
            "hash": file_hash,
            "message": "[?] File not found in signature database (Unknown/New file)"
        }
        print("[?] File not recognized in database - might be new or legitimate")
    
    print(f"{'='*60}\n")
    return result


def cli_scanner():
    """
    Command-line interface for the scanner
    """
    print("\n" + "="*60)
    print("🔐 SIGNATURE-BASED MALWARE SCANNER")
    print("="*60)
    
    # Load signatures
    signatures = load_signatures()
    
    if not signatures:
        print("[ERROR] No signatures loaded. Exiting.")
        return
    
    while True:
        print("\n[OPTIONS]")
        print("1. Scan a file")
        print("2. Batch scan (multiple files)")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            file_path = input("Enter file path to scan: ").strip()
            if file_path.startswith('"') and file_path.endswith('"'):
                file_path = file_path[1:-1]
            
            result = scan_file(file_path, signatures)
            
            if result["status"] == "detected":
                print(f"RESULT: {result['type'].upper()}")
            elif result["status"] == "unknown":
                print("RESULT: UNKNOWN/POTENTIALLY SAFE")
            else:
                print("RESULT: ERROR")
        
        elif choice == "2":
            folder_path = input("Enter folder path for batch scan: ").strip()
            if folder_path.startswith('"') and folder_path.endswith('"'):
                folder_path = folder_path[1:-1]
            
            if not os.path.isdir(folder_path):
                print(f"[ERROR] Invalid folder path: {folder_path}")
                continue
            
            results = []
            files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
            
            print(f"\n[*] Found {len(files)} files to scan")
            
            for filename in files:
                file_path = os.path.join(folder_path, filename)
                result = scan_file(file_path, signatures)
                results.append(result)
            
            # Summary
            print("\n" + "="*60)
            print("BATCH SCAN SUMMARY")
            print("="*60)
            detected = sum(1 for r in results if r["status"] == "detected" and r.get("type") == "malware")
            unknown = sum(1 for r in results if r["status"] == "unknown")
            benign = sum(1 for r in results if r["status"] == "detected" and r.get("type") == "benign")
            
            print(f"Total files scanned: {len(results)}")
            print(f"Malware detected: {detected}")
            print(f"Benign files: {benign}")
            print(f"Unknown files: {unknown}")
            print("="*60)
        
        elif choice == "3":
            print("\n[✓] Exiting scanner. Stay safe!")
            break
        
        else:
            print("[ERROR] Invalid choice. Please try again.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Command-line file scan mode
        file_to_scan = sys.argv[1]
        signatures = load_signatures()
        result = scan_file(file_to_scan, signatures)
        
        if result["status"] == "detected":
            sys.exit(1 if result["type"] == "malware" else 0)
        else:
            sys.exit(2)  # Unknown file
    else:
        # Interactive CLI mode
        cli_scanner()
