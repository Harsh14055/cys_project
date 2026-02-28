import os
from datetime import datetime


class Logger:
    def __init__(self, log_file="log.txt"):
        self.log_file = log_file
        self._create_log_file()

    def _create_log_file(self):
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write("===== Malware Scanner Log =====\n")
                f.write(f"Log Created: {datetime.now()}\n")
                f.write("=" * 60 + "\n\n")

    def log(self, level, message):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} | {level} | {message}\n")

    def log_scan_result(self, file_path, message):
        self.log("INFO", f"{file_path} --> {message}")

    def log_error(self, file_path, error_message):
        self.log("ERROR", f"{file_path} --> {error_message}")

    def log_summary(self, total, malware, clean):
        self.log("INFO", "\n===== Scan Summary =====")
        self.log("INFO", f"Total Files Scanned: {total}")
        self.log("INFO", f"Malware Found: {malware}")
        self.log("INFO", f"Clean Files: {clean}")
        self.log("INFO", "=" * 60 + "\n")