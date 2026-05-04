import time
import json
import urllib.request
from datetime import datetime


class LogCollector:
    def __init__(self, config):
        self.cf = config
        self.last_seen_domain = None

    def is_suspicious(self, domain):
        """Sprawdza, czy domena zawiera słowa kluczowe z konfiguracji."""
        return any(keyword in domain.lower() for keyword in self.cf.KEYWORDS)

    def save_to_jsonl(self, file_path, data):
        """Pomocnicza metoda do zapisu jednej linii JSON."""
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def log_domain(self, domain, message):
        # Pobieramy dane o wystawcy certyfikatu (często przydatne w analizie phishingu)
        issuer = message.get("data", {}).get("leaf_cert", {}).get("issuer", {}).get("O", "Unknown")

        entry = {
            "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "domain": domain,
            "issuer": issuer,
            "cert_index": message.get("data", {}).get("cert_index"),
            # Zapisujemy tylko niezbędne info z wiadomości, by nie marnować miejsca
            "raw_log_id": message.get("data", {}).get("update_type")
        }

        # 1. Logowanie ogólne (wszystkie zaobserwowane domeny)
        self.save_to_jsonl(self.cf.LOG_FILE_PATH, entry)

        # 2. Logowanie specyficzne dla podejrzanych domen
        if self.is_suspicious(domain):
            # Wzbogacamy log o flagę, co ułatwi późniejszy trening modelu ML
            suspicious_entry = entry.copy()
            suspicious_entry["status"] = "suspicious"

            # Zapis do oddzielnego pliku zdefiniowanego w config (np. suspicious_domains.jsonl)
            self.save_to_jsonl(self.cf.SUSPICIOUS_LOG_FILE_PATH, suspicious_entry)

            print(f"[!] WYKRYTO PODEJRZANĄ DOMENĘ: {domain} (Issuer: {issuer})", flush=True)

    def poll(self):
        print(f"Rozpoczynam zbieranie danych... (Interwał: {self.cf.POLL_INTERVAL}s)", flush=True)
        while True:
            print("--- Nowa próba pobrania danych ---", flush=True)
            try:
                req = urllib.request.Request(
                    self.cf.POLL_URL,
                    headers={"User-Agent": "CT-logs-Student-Project/1.0"},
                )
                print(f"Łączenie z {self.cf.POLL_URL}...", flush=True)
                with urllib.request.urlopen(req, timeout=10) as r:
                    raw_data = r.read()
                    print(f"Pobrano {len(raw_data)} bajtów.", flush=True)
                    data = json.loads(raw_data.decode())

                current_batch = []
                for msg in data.get("messages", []):
                    if msg.get("message_type") == "certificate_update":
                        for domain in msg.get("data", {}).get("leaf_cert", {}).get("all_domains", []):
                            current_batch.append((domain, msg))

                if not current_batch:
                    time.sleep(self.cf.POLL_INTERVAL)
                    continue

                # Logika kursora (Twoja autorska metoda zapobiegająca duplikatom)
                start_index = 0
                if self.last_seen_domain:
                    domain_names = [item[0] for item in current_batch]
                    if self.last_seen_domain in domain_names:
                        reversed_idx = domain_names[::-1].index(self.last_seen_domain)
                        actual_idx = len(domain_names) - 1 - reversed_idx
                        start_index = actual_idx + 1
                    else:
                        # Opcjonalnie: loguj lukę w danych do pliku systemowego
                        start_index = 0

                new_items = current_batch[start_index:]
                for domain, msg in new_items:
                    self.log_domain(domain, msg)

                if new_items:
                    self.last_seen_domain = new_items[-1][0]
                print(f"Przetworzono paczkę. Nowych domen: {len(new_items)}", flush=True)

            except Exception as e:
                print(f"Błąd pętli poll: {e}", flush=True)

            print(f"Czekam {self.cf.POLL_INTERVAL} sekund...", flush=True)
            time.sleep(self.cf.POLL_INTERVAL)