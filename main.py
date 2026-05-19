import sys
import io
import re
import csv
import glob
import os

# Wymuszenie kodowania UTF-8
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='ignore')

def load_typosquat_domains():                    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_files = glob.glob(os.path.join(script_dir, "*.csv"))
    typosquats = set()
    
    for file_path in csv_files:
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                
                domain_key = None
                if reader.fieldnames:
                    for key in reader.fieldnames:
                        if key and ('Domain (IDNA)' in key or 'Domain' in key):
                            domain_key = key
                            break
                
                if not domain_key:
                    continue
                    
                for row in reader:
                    val = row.get(domain_key)
                    if val:
                        typosquats.add(val.strip().lower())
        except Exception:
            pass
            
    return typosquats

# Ładowanie bazy podczas startu skryptu
EXACT_TYPOSQUATS = load_typosquat_domains()
SUFFIX_TYPOSQUATS = tuple("." + d for d in EXACT_TYPOSQUATS)

KEYWORDS = [
    # Uwierzytelnianie i dostęp
    "login", "signin", "log-in", "logon", "auth", "authenticat",
    "verify", "verification", "secure", "security", "update",
    
    # Zarządzanie kontem i socjotechnika (presja)
    "account", "recover", "recovery", "restore", "unlock",
    "suspend", "suspended", "billing", "refund", "confirm",
    "payment", "invoice", "support",
    
    # Poczta elektroniczna i panele administracyjne
    "webmail", "admin", "cpanel", "owa", "zimbra", "roundcube",
    "postmaster", "mailbox", "message",
    
    # Usługi chmurowe i współdzielenie plików
    "drive", "docs", "shared", "document", "file", "attachment",
    "dropbox", "onedrive", "sharepoint", "we-transfer",
    
    # Marki i finanse (traktowane jako fallback dla list dnstwist)
    "paypal", "apple", "bank", "banking", "wallet", "crypto", 
    "exchange", "binance", "metamask", "netflix", "microsoft"
]

# Dodano końcówki notowane w raportach Spamhaus i badaniach DGA
SUSPICIOUS_TLDS = (
    # Klasyczne tanie TLD
    '.xyz', '.site', '.top', '.online', '.zip', '.icu', '.vip', '.pw',
    '.shop', '.store', '.club', '.live', '.pro', '.click', '.run',
    '.cc', '.ws', '.cfd', '.sbs', '.best', '.work',
    
    # Często nadużywane darmowe strefy/usługi (public suffixes)
    '.pages.dev', '.workers.dev', '.sslip.io', '.nip.io', 
    '.duckdns.org', '.ddns.net', '.herokuapp.com', '.repl.co',
    '.firebaseapp.com', '.web.app'
)

pattern = re.compile('|'.join(KEYWORDS), re.IGNORECASE)

def is_high_risk(domain: str) -> bool:
    # 0. Szybka ścieżka dla baz typosquattingu
    if EXACT_TYPOSQUATS:
        if domain in EXACT_TYPOSQUATS or domain.endswith(SUFFIX_TYPOSQUATS):
            return True

    # 1. Sprawdzenie słów kluczowych
    has_keyword = bool(pattern.search(domain))
    
    # 2. Cechy strukturalne
    is_deep = domain.count('.') >= 3
    is_cheap_tld = domain.endswith(SUSPICIOUS_TLDS)
    is_punycode = 'xn--' in domain
    
    # 3. System punktowy
    score = 0
    if has_keyword: score += 2
    if is_deep: score += 1
    if is_cheap_tld: score += 1
    if is_punycode: score += 3 
        
    return score >= 2

def main():
    while True:
        try:
            line = sys.stdin.readline()
            
            if not line:
                break
                
            domain = line.strip().lower()
            if not domain:
                continue

            if "certpatrol" in domain:
                continue
                
            if is_high_risk(domain):
                print(domain, flush=True)

            
                
        except Exception:
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)