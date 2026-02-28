import os
import csv
from logg_sys import Logger   # <-- matches your renamed file

SIGNATURE_FILE = "signatures.csv"


class AdvancedScanner:
    def __init__(self):
        self.total_files = 0
        self.malware_found = 0
        self.clean_files = 0
        self.infected_files = []
        self.signatures = self.load_signatures()
        self.logger = Logger()

    def load_signatures(self):
        """Load malware signatures from CSV file"""
        signatures = []
        try:
            with open(SIGNATURE_FILE, newline='', encoding="utf-8") as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    if row:
                        signatures.append(row[0].strip())
        except FileNotFoundError:
            print("Error: signatures.csv not found.")
        except Exception as e:
            print("Error loading signatures:", e)

        return signatures

    def scan_file(self, file_path):
        """Scan a single file for malware"""
        self.total_files += 1
        infected = False

        try:
            with open(file_path, "r", errors="ignore") as file:
                for line_number, line in enumerate(file, start=1):
                    for signature in self.signatures:
                        if signature and signature in line:
                            infected = True
                            self.malware_found += 1
                            self.infected_files.append(file_path)

                            message = (
                                f"MALWARE DETECTED | "
                                f"Signature: '{signature}' | "
                                f"Line: {line_number}"
                            )

                            self.logger.log_scan_result(file_path, message)

                            print(f"[!] Malware found in: {file_path}")
                            print(f"    Signature: {signature}")
                            print(f"    Line: {line_number}\n")

                            return  # Stop scanning this file

            if not infected:
                self.clean_files += 1
                self.logger.log_scan_result(file_path, "CLEAN")

        except Exception as e:
            self.logger.log_error(file_path, str(e))

    def scan_directory(self, directory):
        """Recursively scan a directory"""
        if not os.path.exists(directory):
            print("Error: Directory does not exist.")
            return

        for root, dirs, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                self.scan_file(full_path)

    def print_summary(self):
        print("\n===== Scan Summary =====")
        print(f"Total Files Scanned: {self.total_files}")
        print(f"Malware Found: {self.malware_found}")
        print(f"Clean Files: {self.clean_files}")

        if self.infected_files:
            print("\nInfected Files:")
            for file in self.infected_files:
                print(f" - {file}")

        self.logger.log_summary(
            self.total_files,
            self.malware_found,
            self.clean_files
        )


if __name__ == "__main__":
    scanner = AdvancedScanner()
    directory = input("Enter directory path to scan: ").strip()
    scanner.scan_directory(directory)
    scanner.print_summary()