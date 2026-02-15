import requests

class SecurityHeaders:
    def __init__(self, target_url):
        self.target_url = target_url

    def fetch_headers(self):
        try:
            response = requests.head(self.target_url, timeout=10)
            return response.headers
        except requests.RequestException as e:
            return {"error": str(e)}

    def analyze_headers(self, headers):
        required_headers = {
            "Content-Security-Policy": "Protects against XSS and data injection attacks.",
            "Strict-Transport-Security": "Enforces secure (HTTPS) connections to the server.",
            "X-Content-Type-Options": "Prevents browsers from interpreting files as a different MIME type.",
            "X-Frame-Options": "Prevents clickjacking attacks.",
            "X-XSS-Protection": "Provides XSS filtering in browsers.",
            "Referrer-Policy": "Controls the information sent with the Referer header."
        }
        analysis = {}
        for header, description in required_headers.items():
            if header in headers:
                analysis[header] = {"present": True, "description": description}
            else:
                analysis[header] = {"present": False, "description": description}
        return analysis

    def scan(self):
        headers = self.fetch_headers()
        if "error" in headers:
            return headers
        return self.analyze_headers(headers)

