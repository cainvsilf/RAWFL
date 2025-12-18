from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import socket
import ipaddress
import concurrent.futures
from datetime import datetime
import json
import threading
import time
import subprocess
import platform
from utils.device_fingerprint import fingerprint_device
from scanners.vulnerability_scanner import scan_vulnerabilities

# Load config for GROQ AI
try:
    import config
    print("[+] Configuration loaded")
except:
    print("[!] Could not load config")

# Try to import Real AI
try:
    from utils.real_ai_assistant import RealAIExploitAssistant
    ai_assistant = RealAIExploitAssistant()
    print("[+] Real AI (GROQ) initialized successfully! 🤖")
except Exception as e:
    print(f"[!] Could not load Real AI: {e}")
    print("[*] AI features disabled")
    ai_assistant = None

app = Flask(__name__)
CORS(app)

# Global variables for network scanner
scanner_web = None

# Global variables for monitoring
monitoring_active = False
monitoring_data = []

class NetworkScannerWeb:
    def __init__(self, target_network):
        self.target_network = target_network
        self.active_hosts = []
    
    def ping_host(self, ip, timeout=1):
        """Ping host to check if alive - works for ALL devices"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            
            command = ['ping', param, '1', timeout_param, str(timeout * 1000 if platform.system().lower() == 'windows' else timeout), str(ip)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 1)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port, timeout=0.08):
        """Scan a single port on a host - FAST"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except:
            return False
    
    def quick_check_host(self, ip):
        """Quick check if host is alive - STRICT VALIDATION"""
        is_alive = False
        
        # Method 1: Try PING first (most reliable)
        if self.ping_host(ip, timeout=1):
            is_alive = True
        
        # Method 2: Check common ports (only if ping fails)
        if not is_alive:
            quick_ports = [80, 443, 445, 22, 3389]  # Reduced ports
            open_count = 0
            for port in quick_ports:
                if self.scan_port(ip, port, timeout=0.3):
                    open_count += 1
                    if open_count >= 1:  # At least 1 port must be open
                        is_alive = True
                        break
        
        return is_alive
    
    def scan_host(self, ip):
        """Scan common ports on a host - STRICT VALIDATION"""
        # Quick check first - PING + PORT CHECK
        if not self.quick_check_host(ip):
            return None  # Host tidak aktif
        
        # Do detailed port scan first to verify host is really alive
        common_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3306, 3389, 5000, 5353, 8080, 8443, 8888, 9000]
        open_ports = []
        
        # Parallel port scanning - FAST
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            port_futures = {executor.submit(self.scan_port, ip, port, 0.1): port for port in common_ports}
            for future in concurrent.futures.as_completed(port_futures):
                if future.result():
                    open_ports.append(port_futures[future])
        
        # STRICT VALIDATION: Host must have at least 1 open port to be considered alive
        if len(open_ports) == 0:
            return None  # No ports open = not a real device
        
        # Host is verified alive, create host info
        host_info = {
            'ip': str(ip),
            'hostname': None,
            'open_ports': sorted(open_ports),
            'status': 'up',
            'mac_address': None,
            'vendor': None,
            'device_type': None,
            'os': None
        }
        
        # Try to resolve hostname (in background, don't block)
        try:
            socket.setdefaulttimeout(0.3)
            host_info['hostname'] = socket.gethostbyaddr(str(ip))[0]
        except:
            pass
        finally:
            socket.setdefaulttimeout(None)
        
        # Get device fingerprint (MAC, Vendor, Device Type, OS)
        try:
            fingerprint = fingerprint_device(str(ip))
            if fingerprint:
                host_info['mac_address'] = fingerprint.get('mac_address')
                host_info['vendor'] = fingerprint.get('vendor') or 'Unknown'
                host_info['device_type'] = fingerprint.get('device_type') or 'Unknown'
                host_info['os'] = fingerprint.get('os') or 'Unknown'
        except:
            pass
        
        # FILTER UTAMA: Hanya tampilkan device yang punya hostname
        # Device tanpa hostname = bukan device nyata
        if not host_info['hostname']:
            return None
        
        return host_info
    
    def scan_network(self, max_workers=150, progress_callback=None):
        """Scan entire network range - ULTRA FAST"""
        network = ipaddress.ip_network(self.target_network, strict=False)
        total_hosts = sum(1 for _ in network.hosts())
        scanned = 0
        
        # High workers for maximum speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(future_to_ip, timeout=300):  # 5 min timeout
                try:
                    result = future.result()
                    scanned += 1
                    
                    # Hanya tambahkan host yang aktif (result != None)
                    if result:
                        self.active_hosts.append(result)
                    
                    if progress_callback:
                        progress = (scanned / total_hosts) * 100
                        progress_callback(progress, scanned, total_hosts)
                except concurrent.futures.TimeoutError:
                    print(f"[!] Scan timeout reached")
                    break
                except Exception as e:
                    scanned += 1
                    continue
        
        # Sort by IP address
        self.active_hosts.sort(key=lambda x: tuple(int(part) for part in x['ip'].split('.')))
        
        # Add bandwidth data to each host
        for host in self.active_hosts:
            try:
                bandwidth = bandwidth_monitor.estimate_device_bandwidth(host['ip'])
                host['bandwidth'] = {
                    'download_speed': bandwidth['download_speed'],
                    'upload_speed': bandwidth['upload_speed'],
                    'total_download': bandwidth['total_download'],
                    'total_upload': bandwidth['total_upload'],
                    'connections': bandwidth['connections'],
                    'status': bandwidth['status']
                }
            except:
                host['bandwidth'] = {
                    'download_speed': '0 B/s',
                    'upload_speed': '0 B/s',
                    'total_download': '0 B',
                    'total_upload': '0 B',
                    'connections': 0,
                    'status': 'unknown'
                }
        
        return self.active_hosts

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

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/test-toggle')
def test_toggle():
    """Test page for stealth toggle"""
    return render_template('test_stealth_toggle.html')

@app.route('/test-stats')
def test_stats():
    """Test page for stats update"""
    return render_template('test_stats.html')

@app.route('/simple-test')
def simple_test():
    """Simple test page for debugging"""
    return render_template('simple_test.html')

@app.route('/api/local-ip')
def api_local_ip():
    """Get local IP and suggested network - SMART DETECTION - FAST VERSION"""
    local_ip = get_local_ip()
    hostname = socket.gethostname()
    
    # Suggest /24 network (most common for home/office networks)
    ip_parts = local_ip.split('.')
    suggested_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    # Also provide alternative ranges
    suggested_small = f"{local_ip}/32"  # Just this device
    suggested_medium = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"  # 254 hosts
    suggested_large = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/23"   # 510 hosts
    
    return jsonify({
        'hostname': hostname,
        'local_ip': local_ip,
        'suggested_network': suggested_network,
        'alternatives': {
            'small': suggested_small,
            'medium': suggested_medium,
            'large': suggested_large
        },
        'info': 'For large networks (/20, /16), scanning may take several minutes. Use /24 for faster results.'
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Perform network scan with client isolation detection"""
    data = request.json
    target_network = data.get('target_network')
    
    if not target_network:
        return jsonify({'error': 'Target network is required'}), 400
    
    try:
        # Validate network
        ipaddress.ip_network(target_network, strict=False)
        
        scanner = NetworkScannerWeb(target_network)
        results = scanner.scan_network()
        
        # Detect possible client isolation
        client_isolation_warning = False
        local_ip = get_local_ip()
        
        # If we only found 1-2 hosts (usually just ourselves and maybe gateway)
        # on a large network, it's likely client isolation
        network_size = sum(1 for _ in ipaddress.ip_network(target_network, strict=False).hosts())
        if len(results) <= 2 and network_size > 10:
            client_isolation_warning = True
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_network': target_network,
            'total_hosts': len(results),
            'hosts': results,
            'network_size': network_size,
            'client_isolation_warning': client_isolation_warning,
            'info': 'Client Isolation may be enabled on this network' if client_isolation_warning else None
        })
    except ValueError as e:
        return jsonify({'error': f'Invalid network address: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Removed SSE endpoint - using simple /api/scan instead

@app.route('/api/port-scan', methods=['POST'])
def api_port_scan():
    """Scan specific host for ports"""
    data = request.json
    target_ip = data.get('target_ip')
    port_range = data.get('port_range', 'common')
    
    if not target_ip:
        return jsonify({'error': 'Target IP is required'}), 400
    
    try:
        scanner = NetworkScannerWeb('0.0.0.0/32')
        
        if port_range == 'common':
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        elif port_range == 'all':
            ports = range(1, 1025)  # Common ports
        else:
            # Custom range like "1-100"
            start, end = map(int, port_range.split('-'))
            ports = range(start, end + 1)
        
        open_ports = []
        for port in ports:
            if scanner.scan_port(target_ip, port, timeout=0.5):
                open_ports.append(port)
        
        # Get hostname
        hostname = None
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except:
            pass
        
        return jsonify({
            'success': True,
            'target_ip': target_ip,
            'hostname': hostname,
            'open_ports': open_ports,
            'total_ports_scanned': len(list(ports)),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fingerprint', methods=['POST'])
def api_fingerprint():
    """Perform deep fingerprinting on a specific IP"""
    data = request.json
    target_ip = data.get('target_ip')
    
    if not target_ip:
        return jsonify({'error': 'Target IP is required'}), 400
    
    try:
        # Validate IP
        ipaddress.ip_address(target_ip)
        
        # Perform fingerprinting
        result = fingerprint_device(target_ip)
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            **result
        })
    except ValueError as e:
        return jsonify({'error': f'Invalid IP address: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system-info')
def api_system_info():
    """Get system network information"""
    try:
        hostname = socket.gethostname()
        local_ip = get_local_ip()
        
        return jsonify({
            'hostname': hostname,
            'local_ip': local_ip,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/bypass-scan', methods=['POST'])
def api_bypass_scan():
    """Advanced network discovery - bypass client isolation"""
    try:
        print("[DEBUG] Bypass scan endpoint called")
        
        data = request.get_json()
        duration = int(data.get('duration', 30))  # Default 30 seconds
        methods = data.get('methods', ['passive'])  # passive or all
        
        print(f"[DEBUG] Duration: {duration}, Methods: {methods}")
        
        scanner = AdvancedNetworkDiscovery()
        discovered = {}
        
        if 'passive' in methods or 'all' in methods:
            # Passive methods (safe, undetectable)
            print(f"[*] Running passive discovery for {duration} seconds...")
            
            try:
                # Method 6: mDNS Discovery (5 seconds)
                print("[DEBUG] Running mDNS discovery...")
                mdns_devices = scanner.method6_multicast_discovery()
                discovered.update(mdns_devices)
                print(f"[DEBUG] mDNS found {len(mdns_devices)} devices")
            except Exception as e:
                print(f"[ERROR] mDNS failed: {e}")
            
            try:
                # Method 7: UPnP Discovery (5 seconds)
                print("[DEBUG] Running UPnP discovery...")
                upnp_devices = scanner.method7_upnp_discovery()
                discovered.update(upnp_devices)
                print(f"[DEBUG] UPnP found {len(upnp_devices)} devices")
            except Exception as e:
                print(f"[ERROR] UPnP failed: {e}")
            
            try:
                # Method 5: Broadcast probe (quick)
                print("[DEBUG] Running broadcast probe...")
                broadcast_devices = scanner.method5_broadcast_probe()
                discovered.update(broadcast_devices)
                print(f"[DEBUG] Broadcast found {len(broadcast_devices)} devices")
            except Exception as e:
                print(f"[ERROR] Broadcast failed: {e}")
        
        print(f"[DEBUG] Total discovered: {len(discovered)} devices")
        
        # Enhanced fingerprinting for each device
        print("[DEBUG] Starting enhanced fingerprinting...")
        devices_list = []
        for ip, info in discovered.items():
            try:
                # Run detailed fingerprinting
                print(f"[DEBUG] Fingerprinting {ip}...")
                fingerprint = scanner.fingerprint_device(ip)
                
                device = {
                    'ip': ip,
                    'method': info.get('method', 'Unknown'),
                    'mac': info.get('mac', fingerprint.get('mac', 'N/A')),
                    'hostname': fingerprint.get('hostname', info.get('hostname', 'N/A')),
                    'os': fingerprint.get('os', 'Unknown'),
                    'device_type': fingerprint.get('device_type', info.get('type', 'Unknown')),
                    'vendor': fingerprint.get('vendor', 'N/A'),
                    'open_ports': fingerprint.get('open_ports', []),
                    'services': fingerprint.get('services', []),
                    'server': info.get('server', 'N/A'),
                    'type': fingerprint.get('device_type', info.get('type', 'Unknown')),
                    'timestamp': info.get('timestamp', time.time())
                }
                devices_list.append(device)
                print(f"[DEBUG] {ip}: {fingerprint.get('device_type')} - {fingerprint.get('os')}")
            except Exception as e:
                print(f"[ERROR] Fingerprinting {ip} failed: {e}")
                # Fallback to basic info
                device = {
                    'ip': ip,
                    'method': info.get('method', 'Unknown'),
                    'mac': info.get('mac', 'N/A'),
                    'hostname': info.get('hostname', 'N/A'),
                    'os': 'Unknown',
                    'device_type': info.get('type', 'Unknown'),
                    'vendor': 'N/A',
                    'open_ports': [],
                    'services': [],
                    'server': info.get('server', 'N/A'),
                    'type': info.get('type', 'Unknown'),
                    'timestamp': info.get('timestamp', time.time())
                }
                devices_list.append(device)
        
        print(f"[DEBUG] Returning {len(devices_list)} devices with fingerprints")
        
        result = {
            'success': True,
            'devices': devices_list,
            'total_found': len(devices_list),
            'duration': duration,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        print(f"[DEBUG] Response ready")
        return jsonify(result)
    
    except Exception as e:
        print(f"[ERROR] Bypass scan failed: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/bypass-scan-advanced', methods=['POST'])
def api_bypass_scan_advanced():
    """Advanced bypass with ARP/DNS monitoring (requires admin)"""
    try:
        data = request.get_json()
        duration = int(data.get('duration', 60))  # Default 60 seconds
        
        scanner = AdvancedNetworkDiscovery()
        discovered = {}
        
        print(f"[*] Running advanced passive monitoring for {duration} seconds...")
        print("[*] This requires Administrator privileges!")
        
        try:
            # Method 1: ARP Monitoring (most effective but needs admin)
            arp_devices = scanner.method1_arp_monitoring(duration=duration)
            discovered.update(arp_devices)
        except Exception as e:
            print(f"[!] ARP monitoring failed: {e}")
            # Fall back to non-admin methods
            
            mdns_devices = scanner.method6_multicast_discovery()
            discovered.update(mdns_devices)
            
            upnp_devices = scanner.method7_upnp_discovery()
            discovered.update(upnp_devices)
        
        # Format results
        devices_list = []
        for ip, info in discovered.items():
            device = {
                'ip': ip,
                'method': info.get('method', 'Unknown'),
                'mac': info.get('mac', 'N/A'),
                'hostname': info.get('hostname', 'N/A'),
                'type': info.get('type', 'Unknown')
            }
            devices_list.append(device)
        
        return jsonify({
            'success': True,
            'devices': devices_list,
            'total_found': len(devices_list),
            'duration': duration,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/shodan-lookup', methods=['POST'])
def api_shodan_lookup():
    """Shodan intelligence lookup for IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        api_key = data.get('api_key', None)  # Optional API key
        
        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        shodan = ShodanIntelligence(api_key=api_key)
        result = shodan.search_ip(ip)
        
        return jsonify({
            'success': True,
            'data': result
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/geoip-lookup', methods=['POST'])
def api_geoip_lookup():
    """GeoIP intelligence lookup"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        geoip = GeoIPIntelligence()
        result = geoip.lookup_ip(ip)
        
        return jsonify({
            'success': True,
            'data': result
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/geoip-map', methods=['POST'])
def api_geoip_map():
    """Generate map data for devices"""
    try:
        data = request.get_json()
        devices = data.get('devices', [])
        
        if not devices:
            return jsonify({'success': False, 'error': 'Device list required'}), 400
        
        # Extract IPs
        ip_list = [d.get('ip') for d in devices if d.get('ip')]
        
        geoip = GeoIPIntelligence()
        map_data = geoip.generate_map_data(ip_list)
        
        return jsonify({
            'success': True,
            'map_data': map_data
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/network-topology', methods=['POST'])
def api_network_topology():
    """Generate network topology visualization"""
    try:
        data = request.get_json()
        devices = data.get('devices', [])
        format_type = data.get('format', 'd3')  # d3 or cytoscape
        
        if not devices:
            return jsonify({'success': False, 'error': 'Device list required'}), 400
        
        mapper = NetworkTopologyMapper()
        topology = mapper.discover_topology(devices)
        
        # Format based on request
        if format_type == 'cytoscape':
            formatted = mapper.export_to_cytoscape(topology)
        else:
            formatted = mapper.export_to_d3(topology)
        
        return jsonify({
            'success': True,
            'topology': topology,
            'formatted': formatted
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/aggressive-scan', methods=['POST'])
def api_aggressive_scan():
    """Aggressive network scan - finds MORE devices"""
    try:
        data = request.get_json()
        network = data.get('network', None)
        
        if not network:
            # Auto-detect network
            local_ip = get_local_ip()
            network_prefix = '.'.join(local_ip.split('.')[:3])
            network = f"{network_prefix}.0/24"
        
        print(f"[*] Starting aggressive scan on {network}")
        
        scanner = AggressiveScanner(network)
        raw_devices = scanner.discover_all_methods(timeout=3)
        
        print(f"[*] Raw scan found {len(raw_devices)} potential IPs")
        
        # FILTER: Only keep REAL devices that are responsive
        verified_devices = {}
        for ip, info in raw_devices.items():
            # Skip if not responsive or no useful info
            if info.get('responsive') or info.get('mac') or info.get('open_ports'):
                verified_devices[ip] = info
        
        print(f"[*] Verified {len(verified_devices)} real devices")
        
        # Format for web display with full device info
        devices_list = []
        for ip, info in verified_devices.items():
            # Get device fingerprint
            try:
                fingerprint = fingerprint_device(ip)
                vendor = fingerprint.get('vendor', 'Unknown')
                device_type = fingerprint.get('device_type', 'Unknown')
                os_info = fingerprint.get('os', 'Unknown')
                mac = fingerprint.get('mac_address') or info.get('mac', 'N/A')
            except:
                vendor = 'Unknown'
                device_type = 'Unknown'
                os_info = 'Unknown'
                mac = info.get('mac', 'N/A')
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = info.get('hostname', 'N/A')
            
            # Get bandwidth
            try:
                bandwidth = bandwidth_monitor.estimate_device_bandwidth(ip)
            except:
                bandwidth = {
                    'download_speed': '0 B/s',
                    'upload_speed': '0 B/s',
                    'total_download': '0 B',
                    'total_upload': '0 B',
                    'connections': 0,
                    'status': 'unknown'
                }
            
            device = {
                'ip': ip,
                'mac': mac,
                'mac_address': mac,
                'hostname': hostname,
                'vendor': vendor,
                'device_type': device_type,
                'os': os_info,
                'method': info.get('method', 'Multiple'),
                'methods': info.get('methods', [info.get('method', 'Unknown')]),
                'open_ports': info.get('open_ports', []),
                'status': 'up',
                'bandwidth': bandwidth
            }
            devices_list.append(device)
        
        # Sort by IP
        devices_list.sort(key=lambda x: tuple(int(part) for part in x['ip'].split('.')))
        
        print(f"[*] Aggressive scan complete: {len(devices_list)} devices with full info")
        
        return jsonify({
            'success': True,
            'total_found': len(devices_list),
            'devices': devices_list,
            'network': network,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    except Exception as e:
        print(f"[ERROR] Aggressive scan failed: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/bandwidth-stats', methods=['GET'])
def api_bandwidth_stats():
    """Get current bandwidth statistics"""
    try:
        stats = bandwidth_monitor.get_network_stats()
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/bandwidth-device', methods=['POST'])
def api_bandwidth_device():
    """Get bandwidth usage for specific device"""
    try:
        data = request.get_json()
        device_ip = data.get('ip')
        
        if not device_ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        bandwidth = bandwidth_monitor.estimate_device_bandwidth(device_ip)
        
        return jsonify({
            'success': True,
            'bandwidth': bandwidth,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/bandwidth-top-users', methods=['GET'])
def api_bandwidth_top_users():
    """Get top bandwidth consuming devices"""
    try:
        limit = request.args.get('limit', 10, type=int)
        top_users = bandwidth_monitor.get_top_bandwidth_users(limit=limit)
        
        return jsonify({
            'success': True,
            'top_users': top_users,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/bandwidth-chart', methods=['GET'])
def api_bandwidth_chart():
    """Get bandwidth chart data"""
    try:
        chart_data = bandwidth_monitor.get_bandwidth_chart_data()
        
        return jsonify({
            'success': True,
            'chart_data': chart_data,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/quick-device-info', methods=['POST'])
def api_quick_device_info():
    """Get comprehensive device information from single IP"""
    try:
        data = request.get_json()
        target_ip = data.get('ip')
        
        if not target_ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        print(f"\n[*] Quick device info scan for {target_ip}")
        
        # Import and use QuickDeviceInfo
        from quick_device_info import QuickDeviceInfo
        
        collector = QuickDeviceInfo(target_ip)
        info = collector.collect_all_info()
        
        return jsonify({
            'success': True,
            'ip': target_ip,
            'info': info,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[ERROR] Quick device info failed: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/stealth-scan', methods=['POST'])
def api_stealth_scan():
    """
    Stealth scanning with anti-detection techniques
    Supports both single IP and network range
    """
    try:
        data = request.get_json()
        target = data.get('ip') or data.get('network')
        scan_profile = data.get('profile', 'stealth')  # paranoid, stealth, normal, aggressive
        
        if not target:
            return jsonify({'success': False, 'error': 'IP address or network required'}), 400
        
        # Check if it's a network range or single IP
        is_network = '/' in target
        
        if is_network:
            # Network range stealth scan
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
            
            # Limit to reasonable size for stealth scan
            if len(hosts) > 50:
                return jsonify({
                    'success': False, 
                    'error': f'Network too large ({len(hosts)} hosts). Stealth scan limited to 50 hosts maximum. Use /27 or smaller network.'
                }), 400
            
            # Get profile settings
            temp_scanner = StealthScanner(str(hosts[0]))
            profile = temp_scanner.safe_scan_profile(str(hosts[0]), scan_profile)
            
            # Scan each host with stealth
            all_devices = []
            scan_log = []
            start_time = time.time()
            
            scan_log.append(f"🥷 Starting stealth network scan: {target}")
            scan_log.append(f"Profile: {scan_profile.upper()} ({profile['delay_min']}-{profile['delay_max']}s delay)")
            scan_log.append(f"Hosts to scan: {len(hosts)}")
            scan_log.append("=" * 50)
            
            for idx, host_ip in enumerate(hosts, 1):
                scanner = StealthScanner(str(host_ip))
                
                # Check if host is alive first (stealth ping)
                scan_log.append(f"\n[{idx}/{len(hosts)}] Checking {host_ip}...")
                
                if scanner.fragmented_ping(str(host_ip)):
                    scan_log.append(f"  ✓ Host {host_ip} is ALIVE")
                    
                    # Scan common ports
                    common_ports = [22, 80, 443, 3389, 8080]  # Reduced for network scan
                    randomized_ports = pattern_randomizer.randomize_port_order(common_ports)
                    
                    open_ports = []
                    for port in randomized_ports:
                        import random
                        delay = random.uniform(profile['delay_min'], profile['delay_max'])
                        time.sleep(delay)
                        
                        if scanner.stealth_port_scan(str(host_ip), port):
                            open_ports.append(port)
                            scan_log.append(f"    Port {port} OPEN (delay: {delay:.1f}s)")
                    
                    if open_ports:
                        all_devices.append({
                            'ip': str(host_ip),
                            'status': 'online',
                            'open_ports': open_ports,
                            'hostname': 'Unknown',
                            'vendor': 'Unknown',
                            'device_type': 'Unknown'
                        })
                else:
                    scan_log.append(f"  ✗ Host {host_ip} offline/blocking")
                
                # Session pause (stealth technique)
                if idx % 10 == 0 and idx < len(hosts):
                    pause_time = random.uniform(5, 15)
                    scan_log.append(f"\n⏸️  Session pause: {pause_time:.1f}s (anti-detection)")
                    time.sleep(pause_time)
            
            total_time = time.time() - start_time
            techniques = temp_scanner.evade_ids_patterns()
            
            return jsonify({
                'success': True,
                'target': target,
                'profile': scan_profile,
                'profile_settings': profile,
                'devices': all_devices,
                'total_found': len(all_devices),
                'total_scanned': len(hosts),
                'scan_log': scan_log,
                'evasion_techniques': techniques,
                'total_time': total_time,
                'timestamp': datetime.now().isoformat()
            })
        
        else:
            # Single IP stealth scan
            scanner = StealthScanner(target)
            
            # Get profile settings
            profile = scanner.safe_scan_profile(target, scan_profile)
            
            # Scan common ports with stealth techniques
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
            
            # Randomize port order
            randomized_ports = pattern_randomizer.randomize_port_order(common_ports)
            
            open_ports = []
            scan_log = []
            
            for port in randomized_ports:
                import random
                delay = random.uniform(profile['delay_min'], profile['delay_max'])
                time.sleep(delay)
                
                if scanner.stealth_port_scan(target, port):
                    open_ports.append(port)
                    scan_log.append(f"Port {port} OPEN (delay: {delay:.1f}s)")
                else:
                    scan_log.append(f"Port {port} closed (delay: {delay:.1f}s)")
            
            # Get evasion techniques
            techniques = scanner.evade_ids_patterns()
            
            return jsonify({
                'success': True,
                'target': target,
                'profile': scan_profile,
                'profile_settings': profile,
                'open_ports': open_ports,
                'scan_log': scan_log,
                'evasion_techniques': techniques,
                'total_time': sum([float(log.split('delay: ')[1].split('s')[0]) for log in scan_log if 'delay:' in log]),
                'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[ERROR] Stealth scan failed: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/obfuscate-payload', methods=['POST'])
def api_obfuscate_payload():
    """
    Obfuscate payload to avoid detection
    """
    try:
        data = request.get_json()
        payload = data.get('payload')
        method = data.get('method', 'random')  # base64, hex, multi-layer, polymorphic, random
        
        if not payload:
            return jsonify({'success': False, 'error': 'Payload required'}), 400
        
        obf = TrafficObfuscator()
        
        if method == 'base64':
            result = obf.encode_base64(payload)
            methods_used = ['base64']
        elif method == 'hex':
            result = obf.encode_hex(payload)
            methods_used = ['hex']
        elif method == 'multi-layer':
            result, methods_used = obf.multi_layer_encoding(payload, layers=3)
        elif method == 'polymorphic':
            result, methods_used = obf.polymorphic_payload(payload)
        else:  # random
            result, method_used = obf.random_encoding(payload)
            methods_used = [method_used]
        
        return jsonify({
            'success': True,
            'original': payload,
            'obfuscated': result,
            'methods': methods_used,
            'length_original': len(payload),
            'length_obfuscated': len(str(result)),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/stealth-info', methods=['GET'])
def api_stealth_info():
    """
    Get stealth scanning information and recommendations
    """
    try:
        scanner = StealthScanner("127.0.0.1")
        
        return jsonify({
            'success': True,
            'profiles': {
                'paranoid': {
                    'description': 'Ultra-stealth - very slow but undetectable',
                    'delay': '5-15 seconds',
                    'detection_risk': 'Very Low'
                },
                'stealth': {
                    'description': 'Stealth mode - good balance',
                    'delay': '2-5 seconds',
                    'detection_risk': 'Low'
                },
                'normal': {
                    'description': 'Normal scan - moderate speed',
                    'delay': '0.5-2 seconds',
                    'detection_risk': 'Medium'
                },
                'aggressive': {
                    'description': 'Aggressive - fast but easily detected',
                    'delay': '0.1-0.5 seconds',
                    'detection_risk': 'High'
                }
            },
            'evasion_techniques': scanner.evade_ids_patterns(),
            'anonymization': scanner.anonymize_scan(),
            'anti_forensics': scanner.anti_forensics()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/arp-scan', methods=['POST'])
def api_arp_scan():
    """ARP Scanner - Layer 2 discovery (requires scapy)"""
    try:
        data = request.json
        target_network = data.get('target_network')
        
        if not target_network:
            return jsonify({'success': False, 'error': 'No target network provided'}), 400
        
        try:
            from scanners.arp_scanner import ARPScanner
        except ImportError:
            return jsonify({
                'success': False,
                'error': 'Scapy library not installed. Install with: pip install scapy'
            }), 500
        
        scanner = ARPScanner(target_network)
        scanner.scan(timeout=2, verbose=False)
        
        # Format devices for web response
        devices = []
        for device in scanner.devices:
            devices.append({
                'ip': device['ip'],
                'mac': device['mac'],
                'status': 'up',
                'open_ports': [],
                'hostname': None
            })
        
        return jsonify({
            'success': True,
            'scan_type': 'ARP Scan',
            'target_network': target_network,
            'total_hosts': len(devices),
            'hosts': devices,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/all-scanners', methods=['POST'])
def api_all_scanners():
    """Run ALL scanners and combine results"""
    try:
        data = request.json
        target_network = data.get('target_network')
        
        if not target_network:
            return jsonify({'success': False, 'error': 'No target network provided'}), 400
        
        results = {
            'success': True,
            'target_network': target_network,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scanners': {}
        }
        
        # 1. Network Scanner (Main Scanner)
        try:
            scanner = NetworkScannerWeb(target_network)
            scanner.scan_network()
            results['scanners']['network'] = {
                'name': 'Network Scanner',
                'hosts_found': len(scanner.active_hosts),
                'hosts': scanner.active_hosts,
                'status': 'completed'
            }
        except Exception as e:
            results['scanners']['network'] = {'status': 'failed', 'error': str(e)}
        
        # 2. ARP Scanner (if scapy available)
        try:
            from scanners.arp_scanner import ARPScanner
            arp_scanner = ARPScanner(target_network)
            arp_scanner.scan(timeout=2, verbose=False)
            results['scanners']['arp'] = {
                'name': 'ARP Scanner',
                'hosts_found': len(arp_scanner.devices),
                'hosts': [{'ip': d['ip'], 'mac': d['mac'], 'status': 'up'} for d in arp_scanner.devices],
                'status': 'completed'
            }
        except ImportError:
            results['scanners']['arp'] = {'status': 'skipped', 'error': 'Scapy not installed'}
        except Exception as e:
            results['scanners']['arp'] = {'status': 'failed', 'error': str(e)}
        
        # 3. Stealth Scanner (optional - commented out for speed)
        # Uncomment jika ingin include stealth scan (akan lebih lambat)
        """
        try:
            from scanners.stealth_scanner import StealthScanner
            stealth_scanner = StealthScanner(target_network)
            stealth_results = stealth_scanner.stealth_scan(profile='normal')
            results['scanners']['stealth'] = {
                'name': 'Stealth Scanner',
                'hosts_found': len(stealth_results.get('devices', [])),
                'hosts': stealth_results.get('devices', []),
                'status': 'completed'
            }
        except Exception as e:
            results['scanners']['stealth'] = {'status': 'failed', 'error': str(e)}
        """
        
        # Combine all unique hosts
        all_hosts = {}
        for scanner_type, scanner_data in results['scanners'].items():
            if scanner_data.get('status') == 'completed':
                for host in scanner_data.get('hosts', []):
                    ip = host.get('ip')
                    if ip:
                        if ip not in all_hosts:
                            all_hosts[ip] = host
                        else:
                            # Merge data
                            all_hosts[ip].update({k: v for k, v in host.items() if v})
        
        results['combined_hosts'] = list(all_hosts.values())
        results['total_unique_hosts'] = len(all_hosts)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/device-details')
def device_details():
    """Device details page"""
    return render_template('device_details.html')


@app.route('/test-ai-button')
def test_ai_button():
    """Test page for AI button functionality"""
    return render_template('test_ai_button.html')


@app.route('/api/detailed-port-scan', methods=['POST'])
def api_detailed_port_scan():
    """Deep port scan for single IP - scan ALL ports with service detection"""
    try:
        data = request.json
        target_ip = data.get('target_ip')
        
        if not target_ip:
            return jsonify({'success': False, 'error': 'No target IP provided'}), 400
        
        # Common ports + service detection
        common_ports = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9090, 27017]
        
        open_ports = []
        
        def scan_port_detailed(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    # Try to get service name
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'Unknown'
                    
                    return {
                        'port': port,
                        'service': service,
                        'state': 'open'
                    }
            except:
                pass
            return None
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(scan_port_detailed, common_ports)
            open_ports = [r for r in results if r is not None]
        
        return jsonify({
            'success': True,
            'target_ip': target_ip,
            'open_ports': open_ports,
            'total_ports_scanned': len(common_ports),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerability-scan', methods=['POST'])
def api_vulnerability_scan():
    """Vulnerability scan for single IP"""
    try:
        data = request.json
        target_ip = data.get('target_ip')
        
        if not target_ip:
            return jsonify({'success': False, 'error': 'No target IP provided'}), 400
        
        # Scan open ports first
        open_ports = []
        common_ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 5432, 8080]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                if sock.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        # Get OS info
        os_info = {}
        try:
            fingerprint = fingerprint_device(target_ip)
            if fingerprint:
                os_info = {'os': fingerprint.get('os', 'Unknown')}
        except:
            pass
        
        # Scan vulnerabilities
        vuln_results = scan_vulnerabilities(target_ip, open_ports, {}, os_info)
        
        return jsonify({
            'success': True,
            'target_ip': target_ip,
            'vulnerabilities': vuln_results.get('vulnerabilities', []),
            'risk_level': vuln_results.get('risk_level', 'Unknown'),
            'risk_score': vuln_results.get('risk_score', 0),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/service-detection', methods=['POST'])
def api_service_detection():
    """Service fingerprinting for single IP"""
    try:
        data = request.json
        target_ip = data.get('target_ip')
        
        if not target_ip:
            return jsonify({'success': False, 'error': 'No target IP provided'}), 400
        
        services = []
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        for port, service_name in common_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((target_ip, port)) == 0:
                    # Try to grab banner
                    version = None
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner:
                            lines = banner.split('\n')
                            for line in lines:
                                if 'Server:' in line or 'server:' in line:
                                    version = line.split(':', 1)[1].strip()
                                    break
                    except:
                        pass
                    
                    services.append({
                        'name': service_name,
                        'port': port,
                        'version': version
                    })
                sock.close()
            except:
                pass
        
        return jsonify({
            'success': True,
            'target_ip': target_ip,
            'services': services,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ai-exploit-guidance', methods=['POST'])
def api_ai_exploit_guidance():
    """
    AI-powered exploit guidance untuk vulnerability tertentu
    """
    try:
        data = request.get_json()
        vulnerability = data.get('vulnerability')
        
        if not vulnerability:
            return jsonify({'success': False, 'error': 'Vulnerability data required'}), 400
        
        # Check if Real AI is available
        if not ai_assistant:
            return jsonify({
                'success': False, 
                'error': 'AI assistant not initialized. Please check GROQ API configuration.'
            }), 503
        
        # Use Real AI (GROQ)
        guidance = ai_assistant.generate_exploit_guidance(vulnerability)
        msf_modules = ai_assistant.get_metasploit_modules(vulnerability)
        
        # Combine results
        result = {
            'success': True,
            'vulnerability': vulnerability,
            'ai_guidance': guidance,
            'raw_ai_response': guidance.get('ai_raw_response', ''),  # Send raw AI response
            'metasploit_modules': msf_modules,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ai_type': 'GROQ Real AI'
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pentest-checklist', methods=['POST'])
def api_pentest_checklist():
    """
    Generate penetration testing checklist
    """
    try:
        data = request.get_json()
        target_ip = data.get('target_ip')
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not target_ip:
            return jsonify({'success': False, 'error': 'Target IP required'}), 400
        
        # Check if Real AI is available
        if not ai_assistant:
            return jsonify({
                'success': False, 
                'error': 'AI assistant not initialized. Please check GROQ API configuration.'
            }), 503
        
        # Use Real AI (GROQ)
        checklist = ai_assistant.generate_pentest_checklist(target_ip, vulnerabilities)
        
        return jsonify({
            'success': True,
            'checklist': checklist,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ai_type': 'GROQ Real AI'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    print("="*70)
    print("Network Security Tools - Web Interface")
    print("Educational Purpose Only")
    print("="*70)
    print(f"\n[*] Starting web server...")
    print(f"[*] Local IP: {get_local_ip()}")
    print(f"\n[*] Access the interface at:")
    print(f"    http://localhost:5000")
    print(f"    http://{get_local_ip()}:5000")
    print(f"\n[!] WARNING: Use only on networks you own!")
    print("="*70)
    
    # Disable reloader to prevent crashes
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True, use_reloader=False)
