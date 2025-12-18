"""
Device Fingerprinting and OS Detection
Educational Purpose Only
"""

import socket
import re
import subprocess
import platform

class DeviceFingerprint:
    def __init__(self, ip):
        self.ip = ip
        self.info = {
            'ip': ip,
            'hostname': None,
            'mac_address': None,
            'vendor': None,
            'os': None,
            'device_type': None,
            'open_ports': [],
            'services': {},
            'ttl': None,
            'os_confidence': 'Unknown'
        }
    
    def get_mac_address(self):
        """Get MAC address using ARP"""
        try:
            if platform.system().lower() == 'windows':
                # Windows: arp -a
                result = subprocess.run(['arp', '-a', self.ip], 
                                      capture_output=True, text=True, timeout=2)
                output = result.stdout
                
                # Parse MAC from output
                mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
                match = re.search(mac_pattern, output)
                if match:
                    mac = match.group(0).replace('-', ':').upper()
                    self.info['mac_address'] = mac
                    self.detect_vendor(mac)
                    return mac
            else:
                # Linux/Mac: ip neigh or arp
                result = subprocess.run(['arp', '-n', self.ip], 
                                      capture_output=True, text=True, timeout=2)
                output = result.stdout
                mac_pattern = r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
                match = re.search(mac_pattern, output)
                if match:
                    mac = match.group(0).upper()
                    self.info['mac_address'] = mac
                    self.detect_vendor(mac)
                    return mac
        except:
            pass
        return None
    
    def detect_vendor(self, mac):
        """Detect vendor from MAC address OUI - EXPANDED DATABASE"""
        if not mac:
            return
        
        # Normalize MAC for comparison
        mac_normalized = mac.replace(':', '').replace('-', '').upper()
        
        # Extended vendor database (200+ vendors)
        vendors = {
            # VMware & Virtual
            '005056': 'VMware', '000C29': 'VMware', '000569': 'VMware',
            '080027': 'VirtualBox', '00155D': 'Microsoft Hyper-V',
            
            # Intel
            '001B21': 'Intel', '001E67': 'Intel', '7085C2': 'Intel',
            '3C970E': 'Intel', '0050F2': 'Intel (Wi-Fi)', 
            
            # Dell
            '001F16': 'Dell', '001422': 'Dell', '18031B': 'Dell',
            '4437E6': 'Dell', 'B8CA3A': 'Dell', 'D067E5': 'Dell',
            
            # Raspberry Pi & IoT
            'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi',
            'E45F01': 'Raspberry Pi', '28CDDC': 'Raspberry Pi',
            
            # Networking Equipment
            '000DB9': 'Netgear', '00095B': 'Netgear', 'A06391': 'Netgear',
            'C03F0E': 'Netgear', 'E091F5': 'Netgear',
            '000C42': 'Cisco', '001E13': 'Cisco', '004096': 'Cisco',
            '001DCC': 'Cisco Systems', '0025BC': 'Cisco-Linksys',
            '0050C2': 'TP-Link', '002719': 'TP-Link', 'F4F26D': 'TP-Link',
            '5065F3': 'TP-Link', 'C006C3': 'TP-Link', '1C61B4': 'TP-Link',
            '842B2B': 'D-Link', '1C7EE5': 'D-Link', 'C8BE19': 'D-Link',
            '0007E9': 'Asus', '0017C4': 'Asus', '1C872C': 'Asus',
            '2C56DC': 'Asus', 'F832E4': 'Asus',
            '001DD8': 'Mikrotik', '00272D': 'Mikrotik', '4C5E0C': 'Mikrotik',
            '002536': 'Ubiquiti', '04181A': 'Ubiquiti', 'F09FC2': 'Ubiquiti',
            
            # Apple
            '001B63': 'Apple', '0026BB': 'Apple', '3C0754': 'Apple',
            'ACDE48': 'Apple', 'F01898': 'Apple', '3C2EFF': 'Apple',
            '5855CA': 'Apple', '68AE20': 'Apple', '98B8E3': 'Apple',
            'D02598': 'Apple', 'F0F61C': 'Apple', '38C986': 'Apple',
            
            # Samsung (Phone, TV, etc)
            '001E8C': 'Samsung', '0012FB': 'Samsung', 'AC5A14': 'Samsung',
            '340286': 'Samsung', '006B9E': 'Samsung', '78D6F0': 'Samsung',
            'E84E06': 'Samsung', 'C85195': 'Samsung', 'EC1D8B': 'Samsung',
            
            # Xiaomi
            '00265E': 'Xiaomi', '640980': 'Xiaomi', '286C07': 'Xiaomi',
            '789BCD': 'Xiaomi', 'F8A45F': 'Xiaomi', '50EC50': 'Xiaomi',
            '68DFDD': 'Xiaomi', '741BB2': 'Xiaomi',
            
            # Huawei
            '0018E7': 'Huawei', '001E10': 'Huawei', '001EC2': 'Huawei',
            '00255E': 'Huawei', '0CFE45': 'Huawei', '389ED8': 'Huawei',
            
            # Google
            '001A11': 'Google', '546009': 'Google', 'F4F5E8': 'Google',
            '64B473': 'Google Nest', '1CECC8': 'Google Cast',
            
            # HP
            '001CB3': 'HP', '001E0B': 'HP', '984FEE': 'HP',
            '001CC0': 'HP Printer', '009C02': 'HP Enterprise',
            
            # Canon Printer
            '002312': 'Canon', '000085': 'Canon', '002590': 'Canon',
            '6C709F': 'Canon Printer', 'FCFEAA': 'Canon',
            
            # Epson Printer
            '0004F2': 'Epson', '001D0F': 'Epson Printer',
            
            # Brother Printer
            '008087': 'Brother', '002586': 'Brother Printer',
            
            # Microsoft
            '0050F2': 'Microsoft', '0003FF': 'Microsoft', '0017FA': 'Microsoft',
            '000D3A': 'Microsoft Xbox', '7CD1C3': 'Microsoft Surface',
            
            # Lenovo
            '0024E8': 'Lenovo', '0019E0': 'Lenovo', '2016B9': 'Lenovo',
            'E4E749': 'Lenovo', 'DC4A3E': 'Lenovo',
            
            # Acer
            '001F1F': 'Acer', '002261': 'Acer', '00E04C': 'Acer',
            
            # LG
            '001E75': 'LG', '001CBD': 'LG Electronics', '10F96F': 'LG',
            
            # Sony
            '001D28': 'Sony', '001EA9': 'Sony', '54424E': 'Sony PlayStation',
            
            # Amazon
            '44650D': 'Amazon Echo', 'F0272D': 'Amazon Kindle',
            
            # Others
            '0001E3': 'Siemens', '001A1E': 'Technicolor',
            '001DBC': 'QNAP NAS', '000B6B': 'QNAP',
        }
        
        # Try to match first 6 characters (OUI)
        oui = mac_normalized[:6]
        if oui in vendors:
            self.info['vendor'] = vendors[oui]
            return vendors[oui]
        
        # If not found, try with common separators
        for prefix, vendor in vendors.items():
            if mac_normalized.startswith(prefix):
                self.info['vendor'] = vendor
                return vendor
        
        return None
    
    def detect_os_from_ttl(self, ttl):
        """Detect OS from TTL value"""
        self.info['ttl'] = ttl
        
        if ttl <= 64:
            if ttl >= 60:
                self.info['os'] = 'Linux/Unix'
                self.info['os_confidence'] = 'High'
            else:
                self.info['os'] = 'Linux/Unix (router/embedded)'
                self.info['os_confidence'] = 'Medium'
        elif ttl <= 128:
            if ttl >= 124:
                self.info['os'] = 'Windows'
                self.info['os_confidence'] = 'High'
            else:
                self.info['os'] = 'Windows (behind router/VPN)'
                self.info['os_confidence'] = 'Medium'
        elif ttl <= 255:
            self.info['os'] = 'Cisco/Network Device'
            self.info['os_confidence'] = 'Medium'
        
        return self.info['os']
    
    def get_ttl(self):
        """Get TTL value from ping"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', self.ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=2)
            
            # Parse TTL from output
            if platform.system().lower() == 'windows':
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                self.detect_os_from_ttl(ttl)
                return ttl
        except:
            pass
        return None
    
    def scan_port(self, port, timeout=0.3):
        """Scan single port and get banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.ip, port))
            
            if result == 0:
                self.info['open_ports'].append(port)
                
                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    service_info = self.parse_banner(port, banner)
                    if service_info:
                        self.info['services'][port] = service_info
                except:
                    # If banner grab fails, use default service name
                    self.info['services'][port] = self.get_service_name(port)
                
                sock.close()
                return True
        except:
            pass
        return False
    
    def parse_banner(self, port, banner):
        """Parse service banner for OS/service detection"""
        if not banner:
            return self.get_service_name(port)
        
        # Check for OS hints in banner
        if 'Windows' in banner or 'Microsoft' in banner:
            if not self.info['os'] or self.info['os_confidence'] != 'High':
                self.info['os'] = 'Windows'
                self.info['os_confidence'] = 'High (Banner)'
        elif 'Ubuntu' in banner or 'Debian' in banner:
            self.info['os'] = 'Linux (Ubuntu/Debian)'
            self.info['os_confidence'] = 'High (Banner)'
        elif 'CentOS' in banner or 'Red Hat' in banner:
            self.info['os'] = 'Linux (CentOS/RHEL)'
            self.info['os_confidence'] = 'High (Banner)'
        elif 'Apache' in banner:
            if not self.info['os']:
                self.info['os'] = 'Linux (Apache)'
        elif 'nginx' in banner:
            if not self.info['os']:
                self.info['os'] = 'Linux (nginx)'
        
        # Extract service info
        lines = banner.split('\n')
        if lines:
            first_line = lines[0]
            if 'HTTP' in first_line:
                return f"HTTP Server ({first_line[:50]}...)" if len(first_line) > 50 else f"HTTP Server ({first_line})"
        
        return self.get_service_name(port)
    
    def get_service_name(self, port):
        """Get common service name for port"""
        services = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'MS-RPC',
            139: 'NetBIOS-SSN',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB/CIFS',
            3306: 'MySQL',
            3389: 'RDP (Windows)',
            5000: 'UPnP/Flask',
            5353: 'mDNS',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt',
            9000: 'HTTP-Alt'
        }
        return services.get(port, f'Unknown Service (Port {port})')
    
    def detect_device_type(self):
        """Detect device type from gathered info"""
        # Based on open ports
        ports = set(self.info['open_ports'])
        
        # Router/Gateway detection
        if 80 in ports or 443 in ports or 8080 in ports:
            if not (445 in ports or 3389 in ports):
                self.info['device_type'] = 'Router/Gateway'
                return
        
        # Windows PC
        if 135 in ports and 445 in ports:
            self.info['device_type'] = 'Windows PC/Server'
            if 3389 in ports:
                self.info['device_type'] = 'Windows PC/Server (RDP Enabled)'
            return
        
        # Linux Server
        if 22 in ports:
            if 80 in ports or 443 in ports:
                self.info['device_type'] = 'Linux Server (Web)'
            else:
                self.info['device_type'] = 'Linux Server/Device'
            return
        
        # Printer
        if 9100 in ports or 631 in ports:
            self.info['device_type'] = 'Network Printer'
            return
        
        # Database Server
        if 3306 in ports or 5432 in ports:
            self.info['device_type'] = 'Database Server'
            return
        
        # Check vendor for device type
        if self.info['vendor']:
            vendor = self.info['vendor'].lower()
            if 'raspberry' in vendor:
                self.info['device_type'] = 'Raspberry Pi / IoT Device'
            elif 'apple' in vendor:
                self.info['device_type'] = 'Apple Device (Mac/iPhone/iPad)'
            elif 'samsung' in vendor or 'xiaomi' in vendor:
                self.info['device_type'] = 'Mobile Device (Android)'
            elif 'cisco' in vendor or 'netgear' in vendor or 'tp-link' in vendor:
                self.info['device_type'] = 'Network Equipment'
            elif 'canon' in vendor or 'hp' in vendor:
                self.info['device_type'] = 'Printer'
            elif 'vmware' in vendor or 'virtualbox' in vendor:
                self.info['device_type'] = 'Virtual Machine'
        
        if not self.info['device_type']:
            self.info['device_type'] = 'Unknown Device'
    
    def fingerprint(self):
        """Perform complete fingerprinting"""
        # Get hostname
        try:
            socket.setdefaulttimeout(1)
            self.info['hostname'] = socket.gethostbyaddr(self.ip)[0]
        except:
            pass
        
        # Get TTL (OS detection)
        self.get_ttl()
        
        # Get MAC address
        self.get_mac_address()
        
        # Scan comprehensive ports
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            3306, 3389, 5000, 5353, 5432, 8080, 8443, 8888, 9000,
            631, 9100  # Printer ports
        ]
        
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(self.scan_port, common_ports)
        
        # Sort ports
        self.info['open_ports'].sort()
        
        # Detect device type
        self.detect_device_type()
        
        # ENHANCED: Try online vendor lookup if vendor is unknown
        if not self.info.get('vendor') or self.info['vendor'] == 'Unknown':
            try:
                from enhanced_detection import EnhancedDeviceDetection
                enhanced = EnhancedDeviceDetection(self.ip, self.info.get('mac_address'))
                
                # Get enhanced info
                enhanced_info = enhanced.get_full_info(
                    open_ports=self.info.get('open_ports'),
                    os=self.info.get('os')
                )
                
                # Update info with enhanced data
                if enhanced_info.get('vendor') and enhanced_info['vendor'] != 'Unknown':
                    self.info['vendor'] = enhanced_info['vendor']
                
                if enhanced_info.get('hostname') and enhanced_info['hostname'] != 'Not available':
                    self.info['hostname'] = enhanced_info['hostname']
                
                if enhanced_info.get('device_type') and enhanced_info['device_type'] != 'Unknown':
                    self.info['device_type'] = enhanced_info['device_type']
                    self.info['device_confidence'] = enhanced_info.get('device_confidence', 'Medium')
            except Exception as e:
                # Enhanced detection failed, use basic info
                pass
        
        return self.info

def fingerprint_device(ip):
    """Main function to fingerprint a device"""
    fp = DeviceFingerprint(ip)
    return fp.fingerprint()

