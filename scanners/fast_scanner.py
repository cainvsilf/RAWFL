import socket
import ipaddress
import concurrent.futures
from datetime import datetime
import argparse
import sys

class FastScanner:
    def __init__(self, target_network):
        self.target_network = target_network
        self.active_hosts = []
    
    def ping_host(self, ip, ports=[80, 443, 445, 22, 3389, 8080]):
        """Ultra-fast host check - only verify if alive"""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.05)  # Super fast timeout!
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False
    
    def detailed_scan(self, ip):
        """Detailed scan only for alive hosts"""
        host_info = {
            'ip': str(ip),
            'hostname': None,
            'open_ports': []
        }
        
        # All common ports
        all_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                     3306, 3389, 5000, 5432, 5900, 8080, 8443, 8888]
        
        # Quick parallel port scan
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_port, all_ports)
            host_info['open_ports'] = [p for p in results if p is not None]
        
        # Quick hostname lookup
        try:
            socket.setdefaulttimeout(0.3)
            host_info['hostname'] = socket.gethostbyaddr(str(ip))[0]
        except:
            pass
        finally:
            socket.setdefaulttimeout(None)
        
        return host_info
    
    def scan_network(self, max_workers=200, detailed=False):
        """Fast network scan with optional detailed mode"""
        print(f"[*] Fast scan on {self.target_network}")
        print(f"[*] Mode: {'Detailed' if detailed else 'Quick Discovery'}")
        print(f"[*] Workers: {max_workers}")
        print(f"[*] Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        network = ipaddress.ip_network(self.target_network, strict=False)
        total_ips = sum(1 for _ in network.hosts())
        
        print(f"[*] Scanning {total_ips} IP addresses...\n")
        
        # Phase 1: Quick discovery
        print("[Phase 1] Quick host discovery...")
        alive_hosts = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in network.hosts()}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                if completed % 50 == 0:
                    print(f"  Progress: {completed}/{total_ips} ({completed*100//total_ips}%)")
                
                if future.result():
                    ip = future_to_ip[future]
                    alive_hosts.append(ip)
                    print(f"\n[+] Host ALIVE: {ip}")
        
        print(f"\n[✓] Phase 1 complete: Found {len(alive_hosts)} alive host(s)\n")
        
        # Phase 2: Detailed scan (if requested)
        if detailed and alive_hosts:
            print("[Phase 2] Detailed port scanning...")
            for ip in alive_hosts:
                print(f"\n[*] Scanning {ip}...")
                host_info = self.detailed_scan(ip)
                self.active_hosts.append(host_info)
                
                print(f"    IP: {host_info['ip']}")
                if host_info['hostname']:
                    print(f"    Hostname: {host_info['hostname']}")
                if host_info['open_ports']:
                    print(f"    Open Ports: {', '.join(map(str, host_info['open_ports']))}")
        else:
            # Just add IPs without detailed info
            for ip in alive_hosts:
                self.active_hosts.append({
                    'ip': str(ip),
                    'hostname': None,
                    'open_ports': []
                })
        
        print(f"\n[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Total active hosts: {len(self.active_hosts)}")
        
        return self.active_hosts

def main():
    parser = argparse.ArgumentParser(
        description='Fast Network Scanner - Educational Purpose Only',
        epilog='Example: python fast_scanner.py -t 192.168.1.0/24 -d'
    )
    parser.add_argument('-t', '--target', required=True, help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-w', '--workers', type=int, default=200, help='Number of workers (default: 200)')
    parser.add_argument('-d', '--detailed', action='store_true', help='Perform detailed port scan on alive hosts')
    
    args = parser.parse_args()
    
    print("="*70)
    print("Fast Network Scanner - Educational Purpose Only")
    print("WARNING: Use only on networks you own!")
    print("="*70)
    print()
    
    try:
        scanner = FastScanner(args.target)
        scanner.scan_network(max_workers=args.workers, detailed=args.detailed)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
