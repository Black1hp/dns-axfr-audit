import argparse
import dns.resolver
import dns.zone
import dns.query
import threading
import time
import os
from datetime import datetime
from queue import Queue

# Author: Black1hp

############################################################
# DNS Zone Transfer Vulnerability Scanner
# Author: Black1hp
# For authorized security testing only
############################################################

"""
This script is for authorized security testing and research only.
Unauthorized use against systems you don't own or have permission to test is illegal.
"""

class DNSZoneTransferScanner:
    def __init__(self, domains_file, threads, timeout, verbose, output_dir="./"):
        self.domains_file = domains_file
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_dir = output_dir
        self.vulnerable_domains = []
        self.domains_queue = Queue()
        self.lock = threading.Lock()
        self.total_domains = 0
        self.processed_domains = 0

        # Colors for output
        self.GREEN = "\033[92m"
        self.RED = "\033[91m"
        self.YELLOW = "\033[93m"
        self.ENDC = "\033[0m"

    def _load_domains(self):
        with open(self.domains_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        self.total_domains = len(domains)
        for domain in domains:
            self.domains_queue.put(domain)

    def _resolve_ns(self, domain):
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            ns_list = [str(ns.target).rstrip('.') for ns in ns_records]
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Found NS records for {domain}: {ns_list}")
            return ns_list
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Could not resolve NS for {domain}: {e}")
            return []
        except Exception as e:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] An unexpected error occurred resolving NS for {domain}: {e}")
            return []

    def _attempt_axfr(self, domain, ns_server):
        try:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Attempting AXFR for {domain} on {ns_server}")
            
            # Try to perform zone transfer
            zone_data_iterator = dns.query.xfr(ns_server, domain, timeout=self.timeout)
            zone = dns.zone.from_xfr(zone_data_iterator)
            
            # Check if the zone actually contains records beyond just the SOA record
            if len(zone.nodes) > 1: 
                if self.verbose:
                    with self.lock:
                        print(f"[DEBUG] AXFR successful for {domain} on {ns_server} with {len(zone.nodes)} records.")
                return zone
            else:
                if self.verbose:
                    with self.lock:
                        print(f"[DEBUG] AXFR for {domain} on {ns_server} returned only SOA record or no records (not vulnerable).")
                return None
            
        except dns.exception.FormError as e:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Form error (partial transfer/malformed response) for {domain} from {ns_server}: {e}")
            return None
            
        except dns.query.TransferError as e:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Transfer error for {domain} on {ns_server}: {e}")
            return None
            
        except (dns.exception.Timeout, ConnectionRefusedError, OSError) as e:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Connection/timeout error for {domain} on {ns_server}: {e}")
            return None
            
        except dns.exception.DNSException as e: # Catch broader DNS exceptions
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] DNS Exception during AXFR for {domain} on {ns_server}: {type(e).__name__}: {e}")
            return None
            
        except Exception as e:
            if self.verbose:
                with self.lock:
                    print(f"[DEBUG] Unexpected error during AXFR for {domain} on {ns_server}: {type(e).__name__}: {e}")
            return None

    def _worker(self):
        while not self.domains_queue.empty():
            try:
                domain = self.domains_queue.get_nowait()
            except:
                break
                
            ns_servers = self._resolve_ns(domain)
            is_vulnerable = False
            vulnerable_ns = "N/A"

            with self.lock:
                self.processed_domains += 1
                print(f"\r[{self.processed_domains}/{self.total_domains}] Testing {domain}...", end="", flush=True)

            if not ns_servers:
                with self.lock:
                    spaces = " " * 30
                    print(f"\r[{self.processed_domains}/{self.total_domains}] {self.RED}[SAFE]{self.ENDC} {domain} (No NS records){spaces}")
                self.domains_queue.task_done()
                continue

            for ns_server in ns_servers:
                zone_data = self._attempt_axfr(domain, ns_server)
                if zone_data:
                    is_vulnerable = True
                    vulnerable_ns = ns_server
                    with self.lock:
                        spaces = " " * 30
                        print(f"\r[{self.processed_domains}/{self.total_domains}] {self.GREEN}[VULN]{self.ENDC} {domain} — via {vulnerable_ns}{spaces}")
                        self.vulnerable_domains.append(f"{domain} | {vulnerable_ns} | {datetime.now().isoformat()}")
                        
                        # Create zone_data folder and save raw zone data
                        zone_data_folder = os.path.join(self.output_dir, "zone_data")
                        os.makedirs(zone_data_folder, exist_ok=True)
                        zone_file_path = os.path.join(zone_data_folder, f"{domain}.txt")
                        with open(zone_file_path, 'w') as f:
                            f.write(str(zone_data))
                    break  # Found vulnerable NS, skip remaining for this domain

            if not is_vulnerable:
                with self.lock:
                    spaces = " " * 30
                    print(f"\r[{self.processed_domains}/{self.total_domains}] {self.RED}[SAFE]{self.ENDC} {domain}{spaces}")
            
            self.domains_queue.task_done()

    def scan(self):
        print("############################################################")
        print("# DNS Zone Transfer Vulnerability Scanner")
        print("# Author: Black1hp")
        print("# For authorized security testing only")
        print("############################################################\n")

        self._load_domains()

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        print("\n")  # Move to a new line after progress updates

        if self.vulnerable_domains:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = os.path.join(self.output_dir, f"vulnerable_domains_{timestamp}.txt")
            with open(output_filename, 'w') as f:
                for entry in self.vulnerable_domains:
                    f.write(entry + "\n")
            print(f"Scan complete. Vulnerable domains found: {len(self.vulnerable_domains)}. Details saved to {output_filename}")
        else:
            print("Scan complete. No vulnerable domains found.")

def main():
    parser = argparse.ArgumentParser(description="DNS Zone Transfer Vulnerability Scanner")
    parser.add_argument("domains_file", help="File containing a list of root domains (one per line).")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for parallel scanning.")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout in seconds for each DNS query.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print all debug info, including refused NS servers.")
    
    args = parser.parse_args()

    scanner = DNSZoneTransferScanner(args.domains_file, args.threads, args.timeout, args.verbose)
    scanner.scan()

if __name__ == "__main__":
    main()
