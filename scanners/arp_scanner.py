try:
    from scapy.all import ARP, Ether, srp
    import argparse
    from datetime import datetime
except ImportError:
    print("[!] Error: scapy library not found")
    print("[*] Install with: pip install scapy")
    exit(1)

class ARPScanner:
    def __init__(self, target_network):
        self.target_network = target_network
        self.devices = []
    
    def scan(self, timeout=2, verbose=True):
        """Perform ARP scan on the network"""
        if verbose:
            print(f"[*] Starting ARP scan on {self.target_network}")
            print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Create ARP request packet
        arp_request = ARP(pdst=self.target_network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send packet and receive response
        answered, unanswered = srp(arp_request_broadcast, timeout=timeout, verbose=False)
        
        # Parse responses
        for sent, received in answered:
            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc
            }
            self.devices.append(device_info)
            if verbose:
                print(f"[+] Found Device:")
                print(f"    IP Address : {device_info['ip']}")
                print(f"    MAC Address: {device_info['mac']}")
                print()
        
        if verbose:
            print(f"[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"[*] Total devices found: {len(self.devices)}")
        
        return self.devices
    
    def print_table(self):
        """Print results in table format"""
        if not self.devices:
            print("[!] No devices found")
            return
        
        print("\n" + "="*60)
        print(f"{'IP Address':<20} {'MAC Address':<20}")
        print("="*60)
        for device in self.devices:
            print(f"{device['ip']:<20} {device['mac']:<20}")
        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description='ARP Scanner - Educational Purpose Only',
        epilog='Example: python arp_scanner.py -t 192.168.1.0/24'
    )
    parser.add_argument('-t', '--target', required=True, help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-o', '--timeout', type=int, default=2, help='Timeout in seconds (default: 2)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - only show table')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("="*60)
        print("ARP Scanner - Educational Purpose Only")
        print("WARNING: Use only on networks you own!")
        print("="*60)
        print()
    
    try:
        scanner = ARPScanner(args.target)
        scanner.scan(timeout=args.timeout, verbose=not args.quiet)
        scanner.print_table()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except PermissionError:
        print("\n[!] Error: This script requires administrator/root privileges")
        print("[*] Run as administrator on Windows or use sudo on Linux/Mac")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
