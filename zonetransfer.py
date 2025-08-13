############################################################
# DNS Zone Transfer Vulnerability Scanner
# Author: Black1hp
# For authorized security testing only
############################################################


import argparse
import datetime
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from colorama import Fore, Style, init

class DNSZoneTransferScanner:
    def __init__(self, input_file, threads, timeout, verbose):
        self.input_file = input_file
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.domains = []
        self.vulnerable_domains = []
        self.print_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.total_domains = 0
        self.processed_domains = 0

    def load_domains(self):
        with open(self.input_file, 'r') as f:
            self.domains = [line.strip() for line in f if line.strip()]
        self.total_domains = len(self.domains)
        if not self.domains:
            print(f'{Fore.RED}No domains found in input file.{Style.RESET_ALL}')
            return False
        return True

    def scan_domain(self, domain, index):
        with self.print_lock:
            print(f'[{index}/{self.total_domains}] Testing {domain}')
            self.processed_domains += 1

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        try:
            ns_answers = resolver.resolve(domain, 'NS')
            ns_servers = [str(rdata.target).rstrip('.') for rdata in ns_answers]
            if self.verbose:
                with self.print_lock:
                    print(f'{Fore.YELLOW}[INFO] {domain}: Found NS records: {ns_servers}{Style.RESET_ALL}')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoRootServers, Exception) as e:
            if self.verbose:
                with self.print_lock:
                    print(f'{Fore.YELLOW}[WARN] {domain}: Failed to resolve NS records - {str(e)}{Style.RESET_ALL}')
            with self.print_lock:
                print(f'{Fore.RED}[SAFE] {domain}{Style.RESET_ALL}')
            return

        vulnerable = False
        vuln_ns = None
        zone_data = None

        for ns in ns_servers:
            try:
                ns_ip_answers = resolver.resolve(ns, 'A')
                ns_ip = str(ns_ip_answers[0])
                if self.verbose:
                    with self.print_lock:
                        print(f'{Fore.YELLOW}[INFO] {domain}: Resolved {ns} to {ns_ip}{Style.RESET_ALL}')

                xfr = dns.query.xfr(ns_ip, domain, timeout=self.timeout)
                zone = dns.zone.from_xfr(xfr)

                # Validate full transfer: Check if more than just SOA (avoid false positives)
                if len(zone.nodes) > 1:
                    vulnerable = True
                    vuln_ns = ns
                    zone_data = str(zone)
                    if self.verbose:
                        with self.print_lock:
                            print(f'{Fore.GREEN}[INFO] {domain}: Full AXFR succeeded on {ns} with {len(zone.nodes)} records{Style.RESET_ALL}')
                    break
                else:
                    if self.verbose:
                        with self.print_lock:
                            print(f'{Fore.YELLOW}[INFO] {domain}: AXFR returned only SOA or empty on {ns}{Style.RESET_ALL}')

            except (dns.query.TransferError, dns.exception.FormError, dns.exception.Timeout, dns.query.BadResponse, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException, ConnectionRefusedError, OSError, Exception) as e:
                if self.verbose:
                    with self.print_lock:
                        print(f'{Fore.YELLOW}[INFO] {domain}: AXFR failed (possibly partial, refused, or error) on {ns} - {type(e).__name__}: {str(e)}{Style.RESET_ALL}')

        if vulnerable:
            with self.print_lock:
                print(f'{Fore.GREEN}[VULN] {domain} — via {vuln_ns}{Style.RESET_ALL}')
            timestamp = datetime.datetime.now().isoformat()
            log_line = f'{domain} | {vuln_ns} | {timestamp}\n'
            self.vulnerable_domains.append(log_line)
            # Save zone data
            zone_data_dir = 'zone_data'
            os.makedirs(zone_data_dir, exist_ok=True)
            zone_file = os.path.join(zone_data_dir, f'{domain}.txt')
            with open(zone_file, 'w') as zf:
                zf.write(zone_data)
        else:
            with self.print_lock:
                print(f'{Fore.RED}[SAFE] {domain}{Style.RESET_ALL}')

    def run(self):
        if not self.load_domains():
            return

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f'vulnerable_domains_{timestamp}.txt'

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for i, domain in enumerate(self.domains, 1):
                futures.append(executor.submit(self.scan_domain, domain, i))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        with self.print_lock:
                            print(f'{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}')

        # Write vulnerable domains to file (thread-safe, but done after all scans)
        if self.vulnerable_domains:
            with open(output_file, 'w') as f:
                f.writelines(self.vulnerable_domains)
            print(f'\n{Fore.GREEN}Scan complete. Vulnerable domains found: {len(self.vulnerable_domains)}. Details saved to {output_file}{Style.RESET_ALL}')
        else:
            print(f'\n{Fore.YELLOW}Scan complete. No vulnerable domains found.{Style.RESET_ALL}')

def main():
    init(autoreset=True)

    print("""############################################################
# DNS Zone Transfer Vulnerability Scanner
# Author: Black1hp
# For authorized security testing only
############################################################""")

    parser = argparse.ArgumentParser(description='DNS Zone Transfer Vulnerability Scanner')
    parser.add_argument('input_file', help='File containing list of domains (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads for parallel scanning')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for each DNS query in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    scanner = DNSZoneTransferScanner(args.input_file, args.threads, args.timeout, args.verbose)
    scanner.run()

if __name__ == '__main__':
    main()
