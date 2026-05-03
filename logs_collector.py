import json
import time
import urllib.request
from datetime import datetime


class LogCollector:
    def __init__(self, config):
        self.cf = config

    def is_suspicious(self, domain):
        return any(keyword in domain.lower() for keyword in self.cf.KEYWORDS)

    def log_domain(self, domain, message):
        entry = {
            "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "domain": domain,
            "message": message,
        }
        with open(self.cf.LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if self.is_suspicious(domain):
            print(f"[!] {domain}", flush=True)

    def poll(self):
        while True:
            try:
                req = urllib.request.Request(
                    self.cf.POLL_URL,
                    headers={"User-Agent": "CT-logs/1.0"},
                )
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read().decode())
                for msg in data.get("messages", []):
                    if msg.get("message_type") == "certificate_update":
                        for domain in msg.get("data", {}).get("leaf_cert", {}).get("all_domains", []):
                            self.log_domain(domain, msg)
            except Exception as e:
                print(f"Error: {e}", flush=True)
            time.sleep(self.cf.POLL_INTERVAL)

