"""
CT Log Domain Risk Filter
==========================
Reads domain names from stdin (one per line), classifies each one as
high-risk or benign, and writes only the high-risk domains to stdout.

Risk classification is based on three independent signals:
  1. Typosquatting database  – exact match or sub-domain of a known
     typosquatting domain loaded from CSV files co-located with this
     script (generated, e.g., by dnstwist).
  2. Phishing keyword match  – the domain label contains a keyword
     commonly seen in phishing or credential-harvesting URLs.
  3. Structural heuristics   – suspicious TLD, deep sub-domain nesting,
     or Punycode encoding (IDN homograph attacks).

Usage:
    cat domains.txt | python main.py
"""

import sys
import io
import re
import csv
import glob
import os

# Force UTF-8 encoding on stdin so non-ASCII domain labels are handled correctly.
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='ignore')

def load_typosquat_domains() -> set:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_files = glob.glob(os.path.join(script_dir, "*.csv"))
    typosquats = set()

    for file_path in csv_files:
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)

                # Identify which column holds the domain name.
                domain_key = None
                if reader.fieldnames:
                    for key in reader.fieldnames:
                        if key and ('Domain (IDNA)' in key or 'Domain' in key):
                            domain_key = key
                            break

                # Skip files that have no recognisable domain column.
                if not domain_key:
                    continue

                for row in reader:
                    val = row.get(domain_key)
                    if val:
                        typosquats.add(val.strip().lower())
        except Exception as e:
            print(f"[WARNING] Could not read {file_path}: {e}", file=sys.stderr)

    return typosquats

# Load the typosquatting database once at startup to avoid repeated I/O.
EXACT_TYPOSQUATS = load_typosquat_domains()
# Pre-build a tuple of ".domain" strings for fast suffix checks via str.endswith().
SUFFIX_TYPOSQUATS = tuple("." + d for d in EXACT_TYPOSQUATS)

# Keywords commonly found in phishing and credential-harvesting domains.
# Organised by theme; a domain matching any of these earns +2 risk points.
KEYWORDS = [
    # Authentication and access
    "login", "signin", "log-in", "logon", "auth", "authenticat",
    "verify", "verification", "secure", "security", "update",

    # Account management and social-engineering pressure tactics
    "account", "recover", "recovery", "restore", "unlock",
    "suspend", "suspended", "billing", "refund", "confirm",
    "payment", "invoice", "support",

    # Webmail clients and administrative panels
    "webmail", "admin", "cpanel", "owa", "zimbra", "roundcube",
    "postmaster", "mailbox", "message",

    # Cloud storage and file-sharing services
    "drive", "docs", "shared", "document", "file", "attachment",
    "dropbox", "onedrive", "sharepoint", "we-transfer",

    # Brand and finance terms (used as a fallback when dnstwist lists are absent)
    "paypal", "apple", "bank", "banking", "wallet", "crypto",
    "exchange", "binance", "metamask", "netflix", "microsoft"
]

# TLDs and public suffixes frequently cited in Spamhaus threat reports and
# academic DGA (Domain Generation Algorithm) research.  A domain ending with
# one of these earns +1 risk point.
SUSPICIOUS_TLDS = (
    # Classic low-cost TLDs with historically high abuse rates
    '.xyz', '.site', '.top', '.online', '.zip', '.icu', '.vip', '.pw',
    '.shop', '.store', '.club', '.live', '.pro', '.click', '.run',
    '.cc', '.ws', '.cfd', '.sbs', '.best', '.work',

    # Commonly abused free hosting / dynamic DNS services (public suffixes)
    '.pages.dev', '.workers.dev', '.sslip.io', '.nip.io',
    '.duckdns.org', '.ddns.net', '.herokuapp.com', '.repl.co',
    '.firebaseapp.com', '.web.app'
)

pattern = re.compile(r'(?<![a-z])(' + '|'.join(KEYWORDS) + r')(?![a-z])', re.IGNORECASE)

def is_high_risk(domain: str) -> bool:
    # Stage 0: fast-path check against the typosquatting database.
    if EXACT_TYPOSQUATS:
        if domain in EXACT_TYPOSQUATS or domain.endswith(SUFFIX_TYPOSQUATS):
            return True

    # Stage 1: keyword presence in any part of the domain string.
    has_keyword = bool(pattern.search(domain))

    # Stage 2: structural risk signals.
    is_deep      = domain.count('.') >= 4  # 5+ labels indicate suspicious sub-domain nesting
    is_cheap_tld = domain.endswith(SUSPICIOUS_TLDS)
    is_punycode  = 'xn--' in domain        # Internationalized label – common in homograph attacks

    # Scoring: accumulate points from all active signals.
    score = 0
    if has_keyword: score += 1
    if is_deep:     score += 1
    if is_cheap_tld: score += 1
    if is_punycode:  score += 1

    return score >= 3

def main():
    while True:
        try:
            line = sys.stdin.readline()

            # Empty string signals EOF; exit the loop cleanly.
            if not line:
                break

            domain = line.strip().lower()
            if not domain:
                continue

            # Skip error messages.
            if "certpatrol" in domain:
                continue

            if is_high_risk(domain):
                # Flush immediately so downstream consumers receive results
                # in real time rather than waiting for the buffer to fill.
                print(domain, flush=True)

        except Exception as e:
            # Log unexpected per-line errors to stderr and keep running.
            print(f"[ERROR] {e}", file=sys.stderr)
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
        sys.exit(0)