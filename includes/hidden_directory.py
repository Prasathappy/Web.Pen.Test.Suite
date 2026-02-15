import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from includes.logging import Logger


class HiddenDirectoryScanner:
    def __init__(self, target_url, wordlist, threads=10, timeout=15):
        self.target_url = target_url.rstrip("/")
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.logger = Logger()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "AdvancedPenTestSuite/1.0"})

    def scan_directory(self, directory):
        url = urljoin(self.target_url, directory.strip())
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code in [200, 301, 302, 403]:  
                self.logger.log(f"Discovered: {url} (Status: {response.status_code})")
                return url
        except requests.RequestException as e:
            self.logger.log(f"Error scanning {url}: {e}", level="error")
        return None

    def scan(self):
        discovered_directories = []
        self.logger.log(f"Starting directory scan on {self.target_url}")

        with open(self.wordlist, "r") as file:
            directories = file.readlines()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self.scan_directory, directories)

        for result in results:
            if result:
                discovered_directories.append(result)

        self.logger.log("Directory scanning completed")
        return discovered_directories
