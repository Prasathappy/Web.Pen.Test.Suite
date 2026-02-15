import argparse
from includes.reconnaissance import Reconnaissance
from includes.vulnerability_scan import AdvancedVulnerabilityScanner
from includes.security_header import SecurityHeaders
from includes.network_scanning import NetworkScanner
from includes.api_integration import APIIntegration
from includes.reporting import ReportGenerator
from includes.logging import Logger
from includes.hidden_directory import HiddenDirectoryScanner
from config import VIRUSTOTAL_API_KEY, SHODAN_API_KEY
from units import banner

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Application Penetration Testing Suite")
    parser.add_argument("-u", "--url", help="Target URL for testing", required=True)
    parser.add_argument("-t", "--task", help="Task to perform (recon, vuln_scan, sec_headers, net_scan, api_scan)", required=True)
    parser.add_argument("-p", "--ports", help="Port range for network scanning (e.g., 1-1000)", default="1-65535")
    parser.add_argument("-o", "--output", help="Output format for report (txt, html, json)", default="txt")
    parser.add_argument("--wordlist", help="Path to the wordlist for directory scanning")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning (default: 10)")
    args = parser.parse_args()

    logger = Logger()
    logger.log("Starting Advanced PenTestSuite")

    target_url = args.url
    task = args.task.lower()
    output_format = args.output
    port_range = args.ports

    try:
        if task == "recon":
            logger.log(f"Performing reconnaissance on {target_url}")
            recon = Reconnaissance(target_url)
            dns_info = recon.dns_lookup()
            whois_info = recon.whois_lookup()
            links = recon.discover_links()
            server_headers = recon.server_info()

            # Collect all the results into a dictionary
            results = {
                "DNS Info": dns_info,
                "WHOIS Info": whois_info,
                "Discovered Links": links,
                "Server Headers": server_headers,
            }

            logger.log("Reconnaissance completed")

        elif task == "vuln_scan":
            logger.log(f"Performing vulnerability scan on {target_url}")
            scanner = AdvancedVulnerabilityScanner(target_url)
    
            sql_results = scanner.sql_injection()
            xss_results = scanner.xss_scan()
            command_injection_results = scanner.command_injection()
            file_inclusion_results = scanner.file_inclusion()
            path_traversal_results = scanner.path_traversal()

            # Ensure no empty sections in the report
            results = {
                "SQL Injection": sql_results if sql_results else ["No vulnerabilities found"],
                "XSS": xss_results if xss_results else ["No vulnerabilities found"],
                "Command Injection": command_injection_results if command_injection_results else ["No vulnerabilities found"],
                "File Inclusion": file_inclusion_results if file_inclusion_results else ["No vulnerabilities found"],
                "Path Traversal": path_traversal_results if path_traversal_results else ["No vulnerabilities found"],
            }

        elif task == "sec_headers":
            logger.log(f"Checking security headers for {target_url}")
            sec_headers = SecurityHeaders(target_url)
            results = sec_headers.scan()
            logger.log("Security headers analysis completed")

        elif task == "net_scan":
            logger.log(f"Starting network scanning on {target_url} with port range {port_range}")

            # Extract domain/IP from the URL
            ip = target_url.split("//")[-1].split("/")[0]
            port_range_split = port_range.split("-")
            if len(port_range_split) != 2:
                logger.log(f"Invalid port range: {port_range}", level="error")
                return

            # Scan ports
            scanner = NetworkScanner(ip, (int(port_range_split[0]), int(port_range_split[1])))
            open_ports = scanner.scan_ports()

            # Check if open_ports is empty or not
            if not open_ports:
                open_ports = ["No open ports found"]

            results = {"Open Ports": open_ports}
            logger.log("Network scanning completed")

        elif task == "api_scan":
            logger.log("Performing API integrations")
            try:
                api = APIIntegration(virustotal_api_key=VIRUSTOTAL_API_KEY, shodan_api_key=SHODAN_API_KEY)

                # VirusTotal integration
                vt_results = api.integrate_virustotal(target_url)
                if "error" in vt_results:
                    vt_summary = vt_results["error"]
                else:
                    vt_summary = vt_results.get("data", {}).get("attributes", {}).get("last_analysis_stats", "No detailed stats available")

                # Shodan integration
                ip = target_url.split("//")[-1].split("/")[0]  # Extract domain/IP
                shodan_results = api.integrate_shodan(ip)
                shodan_summary = shodan_results if "error" in shodan_results else shodan_results.get("data", [])

                results = {
                    "VirusTotal Scan": vt_summary,
                    "Shodan Scan": shodan_summary,
                }
                logger.log("API integrations completed")
            except Exception as e:
                logger.log(f"An error occurred during API scan: {str(e)}", level="error")
                print(f"An error occurred: {str(e)}")

        elif args.task == "dir_scan":
            if not args.wordlist:
                logger.log("Wordlist is required for directory scan.", level="error")
                return

            logger.log("Starting hidden directory scanning")
            scanner = HiddenDirectoryScanner(args.url, args.wordlist, threads=args.threads, timeout=5)
            hidden_dirs = scanner.scan()
            results = {"Hidden Directories": hidden_dirs if hidden_dirs else ["No hidden directories found"]}
            logger.log("Hidden directory scanning completed")


        else:
            logger.log(f"Unknown task: {task}", level="error")
            print("Invalid task. Use one of: recon, vuln_scan, sec_headers, net_scan, api_scan")
            return

        # Generate report
        logger.log("Generating report")
        report = ReportGenerator(results)
        if output_format == "txt":
            report.save_as_text("report.txt")
        elif output_format == "html":
            report.save_as_html("report.html")
        elif output_format == "json":
            report.save_as_json("report.json")
        else:
            logger.log(f"Unknown output format: {output_format}", level="error")
            print("Invalid output format. Use one of: txt, html, json")
            return

        print("Task completed successfully. Report generated.")

    except Exception as e:
        logger.log(f"An error occurred: {str(e)}", level="error")
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    banner.banner()
    main()
