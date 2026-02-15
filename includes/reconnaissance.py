import socket
import whois
import requests
from bs4 import BeautifulSoup

class Reconnaissance:
    def __init__(self, target_url):
        self.target_url = target_url

    def dns_lookup(self):
        try:
            domain = self.target_url.split("//")[-1].split("/")[0]
            ip = socket.gethostbyname(domain)
            return f"Domain: {domain}, IP: {ip}"
        except socket.error as e:
            return f"DNS Lookup Error: {str(e)}"

    def whois_lookup(self):
        try:
            domain = self.target_url.split("//")[-1].split("/")[0]
            whois_data = whois.whois(domain)
            return f"WHOIS Data: {str(whois_data)}"
        except Exception as e:
            return f"WHOIS Lookup Error: {str(e)}"

    def discover_links(self):
        try:
            response = requests.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [a['href'] for a in soup.find_all('a', href=True)]
            return f"Discovered Links: {', '.join(links)}"
        except Exception as e:
            return f"Link Discovery Error: {str(e)}"

    def server_info(self):
        try:
            response = requests.head(self.target_url, timeout=10)
            return f"Server Info: {response.headers}"
        except Exception as e:
            return f"Server Info Error: {str(e)}"
