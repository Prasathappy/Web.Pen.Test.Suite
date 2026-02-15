from config import VIRUSTOTAL_API_KEY, SHODAN_API_KEY
import requests

class APIIntegration:
    def __init__(self, virustotal_api_key=None, shodan_api_key=None):
        self.virustotal_api_key = virustotal_api_key
        self.shodan_api_key = shodan_api_key

    def integrate_virustotal(self, url):
        if not self.virustotal_api_key:
            raise ValueError("VirusTotal API key is not provided")
        
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": self.virustotal_api_key}
        response = requests.post(api_url, headers=headers, data={"url": url})
        
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if analysis_id:
                # Fetch the detailed analysis report
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)
                if analysis_response.status_code == 200:
                    return analysis_response.json()
                return {"error": f"Failed to retrieve analysis. Status Code: {analysis_response.status_code}"}
        return {"error": f"Failed to initiate analysis. Status Code: {response.status_code}"}

    def integrate_shodan(self, ip):
        if not self.shodan_api_key:
            raise ValueError("Shodan API key is not provided")
        
        api_url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
        response = requests.get(api_url)
        
        if response.status_code == 200:
            return response.json()
        if response.status_code == 403:
            return {"error": "Forbidden: Check your API key or usage limits"}
        return {"error": f"Failed to scan IP. Status Code: {response.status_code}"}
