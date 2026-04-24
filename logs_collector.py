import json
from datetime import datetime


class LogCollector:
    def __init__(self, config):
        self.cf = config

    def is_suspicious(self, domain):
        domain = domain.lower()
        return any(keyword in domain for keyword in self.cf.KEYWORDS)

    def write_logs_to_file(self, domain, message):
        entry = {
            "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "domain": domain,
            "message": message,
        }
        with open(self.cf.LOG_FILE_PATH, "a+", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def process_message(self, message, context):
        message_type = message.get("message_type")
        print("Received:", message_type, flush=True)
        if message_type != "certificate_update":
            return

        data = message.get("data", {})
        domains = data.get("leaf_cert", {}).get("all_domains", [])

        for domain in domains:
            if self.is_suspicious(domain):
                pass
            print(f"[!] Potentially suspicious domain found: {domain}", flush=True)
            self.write_logs_to_file(domain, message)
