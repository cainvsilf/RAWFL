import socket
import ipaddress
import concurrent.futures
from datetime import datetime
import argparse

class NetworkScanner:
    def __init__(self, target_network):
        self.target_network = target_network
        self.active_hosts = []
    
    def scan_port(self, ip, port, timeout=0.1):
        """Scan a single port on a host - OPTIMIZED"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except:
            return False
    
    def quick_check_host(self, ip):
        """Quick check if host is alive"""
        quick_ports = [80, 443, 445, 22, 3389]
        for port in quick_ports:
            if self.scan_port(ip, port, timeout=0.1):
                return True
        return False
    
    def scan_host(self, ip):
        """Scan common ports on a host - OPTIMIZED"""
        # Quick check first
        if not self.quick_check_host(ip):
            return None
        
        host_info = {
            'ip': str(ip),
            'hostname': None,
            'open_ports': []
        }
        
        # Host is up, do detailed scan
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5000, 8080]
        
        # Parallel port scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            port_futures = {executor.submit(self.scan_port, ip, port, 0.15): port for port in common_ports}
            for future in concurrent.futures.as_completed(port_futures):
                if future.result():
                    host_info['open_ports'].append(port_futures[future])
        
        host_info['open_ports'].sort()
        
        # Try to resolve hostname
        try:
            socket.setdefaulttimeout(0.5)
            host_info['hostname'] = socket.gethostbyaddr(str(ip))[0]
        except:
            pass
        finally:
            socket.setdefaulttimeout(None)
        
        return host_info
    
    def scan_network(self, max_workers=100):
        """Scan entire network range"""
        print(f"[*] Starting network scan on {self.target_network}")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        network = ipaddress.ip_network(self.target_network, strict=False)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    self.active_hosts.append(result)
                    self.print_host_info(result)
        
        print(f"\n[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Found {len(self.active_hosts)} active host(s)")
    
    def print_host_info(self, host_info):
        """Print host information"""
        print(f"\n[+] Active Host Found: {host_info['ip']}")
        if host_info['hostname']:
            print(f"    Hostname: {host_info['hostname']}")
        if host_info['open_ports']:
            print(f"    Open Ports: {', '.join(map(str, host_info['open_ports']))}")

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(
        description='Network Scanner - Educational Purpose Only',
        epilog='Example: python network_scanner.py -t 192.168.1.0/24'
    )
    parser.add_argument('-t', '--target', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-w', '--workers', type=int, default=50, help='Number of concurrent workers (default: 50)')
    
    args = parser.parse_args()
    
    print("="*60)
    print("Network Scanner - Educational Purpose Only")
    print("WARNING: Use only on networks you own!")
    print("="*60)
    
    if args.target:
        target = args.target
    else:
        local_ip = get_local_ip()
        # Suggest network based on local IP
        suggested_network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        print(f"\n[*] Your local IP: {local_ip}")
        print(f"[*] Suggested network: {suggested_network}")
        target = input("\nEnter target network (or press Enter to use suggested): ").strip()
        if not target:
            target = suggested_network
    
    try:
        scanner = NetworkScanner(target)
        scanner.scan_network(max_workers=args.workers)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
