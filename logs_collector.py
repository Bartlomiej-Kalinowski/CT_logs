import time
import json
import urllib.request
import csv
import glob
import os
from datetime import datetime


class LogCollector:
    def __init__(self, config):
        self.cf = config
        self.last_seen_domain = None
        
        self.known_typosquat_domains = set()
        self._load_heuristics_from_csv()

    def _load_heuristics_from_csv(self):
        """Ładuje wszystkie domeny z plików CSV w folderze zdefiniowanym w configu (np. self.cf.CSV_DIR)."""
        if not hasattr(self.cf, 'CSV_DIR') or not os.path.exists(self.cf.CSV_DIR):
            print("[!] Folder z plikami CSV nie został zdefiniowany w configu lub nie istnieje.", flush=True)
            return

        csv_files = glob.glob(os.path.join(self.cf.CSV_DIR, "*.csv"))
        for file_path in csv_files:
            try:
                with open(file_path, mode='r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    headers = next(reader, None)
                    if not headers: 
                        continue
                    
                    # Znajdź indeks kolumny "Domain (IDNA)", ignorując białe znaki
                    headers_cleaned = [h.strip() for h in headers]
                    try:
                        idna_idx = headers_cleaned.index("Domain (IDNA)")
                    except ValueError:
                        print(f"[-] Pomijam {file_path} - brak kolumny 'Domain (IDNA)'", flush=True)
                        continue

                    for row in reader:
                        if len(row) > idna_idx:
                            # Zapisujemy domenę do szybkiego zbioru (set)
                            self.known_typosquat_domains.add(row[idna_idx].strip().lower())
            except Exception as e:
                print(f"[!] Błąd podczas ładowania pliku {file_path}: {e}", flush=True)
        
        print(f"[+] Załadowano {len(self.known_typosquat_domains)} unikalnych wariantów typosquattingu z CSV.", flush=True)

    def is_suspicious(self, domain):
        """
        Sprawdza domeny z plików CSV, ataki homograficzne.
        Zwraca: (Czy_podejrzana: bool, Powód: str)
        """
        domain_lower = domain.lower()

        # 1. Dokładne dopasowanie do wygenerowanych wariantów dnstwister (CSV)
        if domain_lower in self.known_typosquat_domains:
            return True, "dnstwister_exact_match"

        # 2. Ataki homograficzne (Punycode)
        # Jeśli domena zaczyna się od xn--, a zawiera słowa kluczowe po zdekodowaniu, to czerwona flaga.
        # Jako najprostszą heurystykę możemy oflagować każdy certyfikat dla punycode, jeśli chcemy być restrykcyjni,
        # lub sprawdzić obecność naszych marek bezpośrednio w surowym stringu xn--
        if domain_lower.startswith("xn--"):
            for keyword in self.cf.KEYWORDS:
                # To proste przybliżenie - docelowo można dekodować Punycode do Unicode (idna.decode)
                if keyword in domain_lower: 
                    return True, f"punycode_keyword_match_{keyword}"


        return False, "clean"

    def save_to_jsonl(self, file_path, data):
        """Pomocnicza metoda do zapisu jednej linii JSON."""
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def log_domain(self, domain, message):
        issuer = message.get("data", {}).get("leaf_cert", {}).get("issuer", {}).get("O", "Unknown")

        entry = {
            "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "domain": domain,
            "issuer": issuer,
            "cert_index": message.get("data", {}).get("cert_index"),
            "raw_log_id": message.get("data", {}).get("update_type")
        }

        # 1. Logowanie ogólne
        self.save_to_jsonl(self.cf.LOG_FILE_PATH, entry)

        # 2. Weryfikacja heurystyczna
        is_susp, reason = self.is_suspicious(domain)
        
        if is_susp:
            suspicious_entry = entry.copy()
            suspicious_entry["status"] = "suspicious"
            suspicious_entry["reason"] = reason # Logujemy powód wykrycia

            self.save_to_jsonl(self.cf.SUSPICIOUS_LOG_FILE_PATH, suspicious_entry)
            print(f"[!] PODEJRZANA DOMENA: {domain} | Powód: {reason} | (Issuer: {issuer})", flush=True)

    def poll(self):
        print(f"Rozpoczynam zbieranie danych... (Interwał: {self.cf.POLL_INTERVAL}s)", flush=True)
        while True:
            print("--- Nowa próba pobrania danych ---", flush=True)
            try:
                req = urllib.request.Request(
                    self.cf.POLL_URL,
                    headers={"User-Agent": "CT-logs-Student-Project/1.0"},
                )
                with urllib.request.urlopen(req, timeout=10) as r:
                    raw_data = r.read()
                    data = json.loads(raw_data.decode())

                current_batch = []
                for msg in data.get("messages", []):
                    if msg.get("message_type") == "certificate_update":
                        for domain in msg.get("data", {}).get("leaf_cert", {}).get("all_domains", []):
                            current_batch.append((domain, msg))

                if not current_batch:
                    time.sleep(self.cf.POLL_INTERVAL)
                    continue

                start_index = 0
                if self.last_seen_domain:
                    domain_names = [item[0] for item in current_batch]
                    if self.last_seen_domain in domain_names:
                        reversed_idx = domain_names[::-1].index(self.last_seen_domain)
                        actual_idx = len(domain_names) - 1 - reversed_idx
                        start_index = actual_idx + 1
                    else:
                        start_index = 0

                new_items = current_batch[start_index:]
                for domain, msg in new_items:
                    self.log_domain(domain, msg)

                if new_items:
                    self.last_seen_domain = new_items[-1][0]
                print(f"Przetworzono paczkę. Nowych domen: {len(new_items)}", flush=True)

            except Exception as e:
                print(f"Błąd pętli poll: {e}", flush=True)

            time.sleep(self.cf.POLL_INTERVAL)