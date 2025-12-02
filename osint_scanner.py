import os
import sys
from dotenv import load_dotenv
import shodan
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import colorama
from colorama import Fore, Style
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import time
import csv
from datetime import datetime

# Initialize colorama
colorama.init()

# Load environment variables
load_dotenv()

class OSINTScanner:
    def __init__(self):
        self.console = Console()
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')
        
        if not self.shodan_api_key:
            self.console.print("[red]Error: Shodan API key not found in .env file[/red]")
            sys.exit(1)
            
        self.shodan_api = shodan.Shodan(self.shodan_api_key)

    def clean_ip(self, ip):
        """Clean and validate IP address"""
        # Remove any CIDR notation
        ip = ip.split('/')[0]
        
        # Validate IP format
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip):
            self.console.print("[red]Error: Invalid IP address format. Please enter a valid IP (e.g., 8.8.8.8)[/red]")
            return None
            
        # Validate each octet
        octets = ip.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                self.console.print("[red]Error: IP address octets must be between 0 and 255[/red]")
                return None
                
        return ip

    def scan_cidr_range(self, cidr):
        """Scan a CIDR range for information"""
        try:
            # Parse CIDR
            network = ipaddress.ip_network(cidr, strict=False)
            total_ips = network.num_addresses
            
            if total_ips > 256:  # Limite pour éviter de surcharger l'API
                self.console.print(f"[yellow]Warning: CIDR range contains {total_ips} IPs. Limiting to first 256 IPs.[/yellow]")
                total_ips = 256
            
            results = []
            processed = 0
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for ip in network.hosts():
                    if processed >= 256:  # Limite de 256 IPs
                        break
                    futures.append(executor.submit(self.check_ip_shodan, str(ip)))
                    time.sleep(0.2)  # Rate limiting
                    processed += 1
                    progress = (processed / total_ips) * 100
                    self.console.print(f"[yellow]Progress: {progress:.1f}% ({processed}/{total_ips})[/yellow]", end="\r")
                
                for future in futures:
                    result = future.result()
                    if result:
                        results.append(result)
            
            return results
            
        except ValueError as e:
            self.console.print(f"[red]Error: Invalid CIDR format - {str(e)}[/red]")
            return None
        except Exception as e:
            self.console.print(f"[red]Error scanning CIDR range: {str(e)}[/red]")
            return None

    def export_to_csv(self, results, cidr):
        """Export scan results to CSV file"""
        if not results:
            return None

        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{cidr.replace('/', '_')}_{timestamp}.csv"

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # Define CSV headers
                fieldnames = ['IP', 'Virtual Hosts', 'Services', 'Vulnerabilities', 
                            'Hosting Provider', 'Web Interfaces', 'Last Update']
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                # Write data rows
                for result in results:
                    # Extract services and web interfaces
                    services = []
                    web_interfaces = []
                    for data in result.get('data', []):
                        if 'product' in data:
                            services.append(f"{data.get('product', '')} ({data.get('port', '')})")
                        if 'http' in data:
                            web_interfaces.append(f"http://{result['ip']}:{data.get('port', '80')}")

                    writer.writerow({
                        'IP': result.get('ip', 'N/A'),
                        'Virtual Hosts': ', '.join(result.get('hostnames', ['N/A'])),
                        'Services': ', '.join(services) or 'N/A',
                        'Vulnerabilities': ', '.join(result.get('vulns', ['N/A'])),
                        'Hosting Provider': result.get('org', 'N/A'),
                        'Web Interfaces': ', '.join(web_interfaces) or 'N/A',
                        'Last Update': result.get('last_update', 'N/A')
                    })

            return filename
        except Exception as e:
            self.console.print(f"[red]Error exporting to CSV: {str(e)}[/red]")
            return None

    def search_shodan(self, query):
        """Search Shodan for information"""
        try:
            results = self.shodan_api.search(query)
            return results
        except Exception as e:
            self.console.print(f"[red]Error searching Shodan: {str(e)}[/red]")
            return None

    def check_ip_shodan(self, ip):
        """Get information about a single IP from Shodan"""
        # Clean and validate IP
        clean_ip = self.clean_ip(ip)
        if not clean_ip:
            return None
            
        try:
            results = self.shodan_api.host(clean_ip)
            return {
                'ip': results.get('ip_str'),
                'ports': results.get('ports', []),
                'hostnames': results.get('hostnames', []),
                'org': results.get('org'),
                'os': results.get('os'),
                'isp': results.get('isp'),
                'last_update': results.get('last_update'),
                'vulns': results.get('vulns', []),
                'data': results.get('data', [])  # Pour les services et interfaces web
            }
        except Exception as e:
            self.console.print(f"[red]Error checking IP on Shodan: {str(e)}[/red]")
            return None

    def display_shodan_results(self, results):
        """Display Shodan search results in a formatted table"""
        if not results or 'matches' not in results:
            self.console.print("[yellow]No results found[/yellow]")
            return

        table = Table(title="Shodan Search Results")
        table.add_column("IP", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Organization", style="green")
        table.add_column("OS", style="yellow")
        table.add_column("Hostnames", style="blue")

        for match in results['matches']:
            table.add_row(
                match.get('ip_str', 'N/A'),
                str(match.get('port', 'N/A')),
                match.get('org', 'N/A'),
                match.get('os', 'N/A'),
                ', '.join(match.get('hostnames', ['N/A']))
            )

        self.console.print(table)

    def display_ip_info(self, info):
        """Display information about a single IP from Shodan"""
        if not info:
            return
        table = Table(title=f"Shodan IP Information: {info.get('ip', 'N/A')}")
        table.add_column("Category", style="cyan")
        table.add_column("Value", style="magenta")
        for key, value in info.items():
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            table.add_row(key, str(value))
        self.console.print(table)

    def display_cidr_scan_results(self, results):
        """Display detailed results for CIDR range scan"""
        if not results:
            self.console.print("[yellow]No results found[/yellow]")
            return

        table = Table(title="CIDR Range Scan Results")
        table.add_column("IP", style="cyan")
        table.add_column("Virtual Hosts", style="blue")
        table.add_column("Services", style="magenta")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("Hosting Provider", style="green")
        table.add_column("Web Interfaces", style="yellow")

        for result in results:
            # Extraire les services et interfaces web
            services = []
            web_interfaces = []
            for data in result.get('data', []):
                if 'product' in data:
                    services.append(f"{data.get('product', '')} ({data.get('port', '')})")
                if 'http' in data:
                    web_interfaces.append(f"http://{result['ip']}:{data.get('port', '80')}")

            table.add_row(
                result.get('ip', 'N/A'),
                ', '.join(result.get('hostnames', ['N/A'])),
                ', '.join(services) or 'N/A',
                ', '.join(result.get('vulns', ['N/A'])),
                result.get('org', 'N/A'),
                ', '.join(web_interfaces) or 'N/A'
            )

        self.console.print(table)
        return results

def main():
    scanner = OSINTScanner()
    
    while True:
        print(f"\n{Fore.CYAN}OSINT Scanner Menu{Style.RESET_ALL}")
        print(f"{Fore.GREEN}1. Search Shodan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}2. Check Single IP on Shodan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}3. Scan CIDR Range{Style.RESET_ALL}")
        print(f"{Fore.RED}4. Exit{Style.RESET_ALL}")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            query = input("Enter your Shodan search query: ")
            results = scanner.search_shodan(query)
            scanner.display_shodan_results(results)
            
        elif choice == '2':
            ip = input("Enter IP address to check: ")
            info = scanner.check_ip_shodan(ip)
            scanner.display_ip_info(info)
            
        elif choice == '3':
            cidr = input("Enter CIDR range (e.g., 192.168.1.0/24): ")
            results = scanner.scan_cidr_range(cidr)
            if results:
                scanner.display_cidr_scan_results(results)
                # Propose l'export CSV
                export = input("\nDo you want to export results to CSV? (y/n): ")
                if export.lower() == 'y':
                    filename = scanner.export_to_csv(results, cidr)
                    if filename:
                        print(f"\n[green]Results exported to {filename}[/green]")
            
        elif choice == '4':
            print(f"{Fore.YELLOW}Goodbye!{Style.RESET_ALL}")
            break
            
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 