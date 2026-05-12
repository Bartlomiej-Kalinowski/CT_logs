from pathlib import Path


class Config:
    KEYWORDS = ["mbank", "pko", "ing", "olx"]
    LOG_FILE_PATH = "cert_logs.jsonl"
    SUSPICIOUS_LOG_FILE_PATH = "suspicious_domains.jsonl"
    CSV_DIR = str(Path(__file__).resolve().parent / "csv")
    POLL_URL = "https://certstream.calidog.io/latest.json"
    POLL_INTERVAL = 5

