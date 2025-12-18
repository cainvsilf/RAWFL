import requests
import json
import re
from datetime import datetime, timedelta
import hashlib

class RealVulnDatabase:
    def __init__(self):
        # API endpoints
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.vulners_api = "https://vulners.com/api/v3/search/lucene/"
        self.circl_api = "https://cve.circl.lu/api"  # CIRCL CVE Search (Free, no API key)
        
        # Biar hemat API calls
        self.cache = {}
        self.cache_duration = 3600  # 1 jam
    
    def search_cve_by_cpe(self, product, version=None):
        """Search CVE berdasarkan product name dan version"""
        cache_key = f"{product}:{version}"
        
        # Check cache
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if datetime.now().timestamp() - timestamp < self.cache_duration:
                return cached_data
        
        vulnerabilities = []
        
        # Try CIRCL API (free, no rate limit)
        try:
            circl_vulns = self._search_circl(product, version)
            vulnerabilities.extend(circl_vulns)
        except Exception as e:
            print(f"CIRCL API error: {e}")
        
        # Try Vulners API (free tier available)
        try:
            vulners_vulns = self._search_vulners(product, version)
            vulnerabilities.extend(vulners_vulns)
        except Exception as e:
            print(f"Vulners API error: {e}")
        
        # Cache results
        self.cache[cache_key] = (vulnerabilities, datetime.now().timestamp())
        
        return vulnerabilities
    
    def _search_circl(self, product, version=None):
        """Search using CIRCL CVE API"""
        vulnerabilities = []
        
        try:
            # Search by vendor/product
            url = f"{self.circl_api}/search/{product}"
            if version:
                url += f"/{version}"
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # CIRCL returns results or list of CVEs
                if isinstance(data, dict):
                    # Check if it's a results wrapper
                    if 'results' in data:
                        cve_list = data['results'][:10]
                    else:
                        cve_list = [data]
                elif isinstance(data, list):
                    cve_list = data[:10]
                else:
                    return vulnerabilities
                
                # Parse each CVE
                for cve_data in cve_list:
                    if isinstance(cve_data, dict):
                        vuln = self._parse_circl_cve(cve_data)
                        if vuln:
                            vulnerabilities.append(vuln)
        except Exception as e:
            pass  # Silently fail to offline DB
        
        return vulnerabilities
    
    def _parse_circl_cve(self, cve_data):
        """Parse CVE data from CIRCL format"""
        try:
            cve_id = cve_data.get('id', 'Unknown')
            summary = cve_data.get('summary', 'No description available')
            
            # Get CVSS score
            cvss = cve_data.get('cvss', 0)
            if isinstance(cvss, (int, float)):
                cvss_score = float(cvss)
            else:
                cvss_score = 0
            
            # Determine severity based on CVSS
            if cvss_score >= 9.0:
                severity = 'Critical'
            elif cvss_score >= 7.0:
                severity = 'High'
            elif cvss_score >= 4.0:
                severity = 'Medium'
            elif cvss_score > 0:
                severity = 'Low'
            else:
                severity = 'Info'
            
            return {
                'cve': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'description': summary[:300],  # Limit length
                'published': cve_data.get('Published', ''),
                'modified': cve_data.get('Modified', ''),
                'source': 'CIRCL CVE Database'
            }
        except Exception as e:
            print(f"Parse CIRCL CVE error: {e}")
            return None
    
    def _search_vulners(self, product, version=None):
        """Search using Vulners API (requires free API key, but has fallback)"""
        vulnerabilities = []
        
        # Vulners free search (limited)
        try:
            query = product
            if version:
                query += f" {version}"
            
            # Public endpoint (limited functionality)
            url = f"https://vulners.com/api/v3/search/lucene/"
            payload = {
                "query": query,
                "size": 10,
                "fields": ["id", "title", "description", "cvss", "type"]
            }
            
            # Try without API key (public search)
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('result') == 'OK':
                    search_results = data.get('data', {}).get('search', [])
                    
                    for item in search_results:
                        vuln = self._parse_vulners_result(item)
                        if vuln:
                            vulnerabilities.append(vuln)
        except Exception as e:
            print(f"Vulners search error: {e}")
        
        return vulnerabilities
    
    def _parse_vulners_result(self, item):
        """Parse vulnerability from Vulners result"""
        try:
            doc = item.get('_source', {})
            
            cve_id = doc.get('id', 'Unknown')
            title = doc.get('title', 'No title')
            description = doc.get('description', 'No description')
            
            # Get CVSS
            cvss_data = doc.get('cvss', {})
            if isinstance(cvss_data, dict):
                cvss_score = cvss_data.get('score', 0)
            else:
                cvss_score = 0
            
            # Severity
            if cvss_score >= 9.0:
                severity = 'Critical'
            elif cvss_score >= 7.0:
                severity = 'High'
            elif cvss_score >= 4.0:
                severity = 'Medium'
            elif cvss_score > 0:
                severity = 'Low'
            else:
                severity = 'Info'
            
            return {
                'cve': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'description': f"{title}. {description[:200]}",
                'source': 'Vulners Database'
            }
        except Exception as e:
            print(f"Parse Vulners error: {e}")
            return None
    
    def get_cve_details(self, cve_id):
        """Get detailed information about specific CVE"""
        try:
            # Use CIRCL API for CVE details
            url = f"{self.circl_api}/cve/{cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Get CVE details error: {e}")
        
        return None
    
    def extract_service_info(self, service_banner):
        """Extract product name and version from service banner"""
        patterns = [
            # Apache
            r'Apache[/\s]+([\d.]+)',
            # nginx
            r'nginx[/\s]+([\d.]+)',
            # Microsoft IIS
            r'Microsoft-IIS[/\s]+([\d.]+)',
            # OpenSSH
            r'OpenSSH[_/\s]+([\d.]+[p\d]*)',
            # ProFTPD
            r'ProFTPD[/\s]+([\d.]+\w*)',
            # vsftpd
            r'vsftpd[/\s]+([\d.]+)',
            # MySQL
            r'MySQL[/\s]+([\d.]+)',
            # PostgreSQL
            r'PostgreSQL[/\s]+([\d.]+)',
            # Samba
            r'Samba[/\s]+([\d.]+)',
            # Pure-FTPd
            r'Pure-FTPd[/\s]+([\d.]+)',
        ]
        
        service_banner = str(service_banner)
        
        for pattern in patterns:
            match = re.search(pattern, service_banner, re.IGNORECASE)
            if match:
                product = pattern.split('[')[0].strip('r\'')
                version = match.group(1)
                return {
                    'product': product.lower(),
                    'version': version,
                    'full_string': match.group(0)
                }
        
        return None

# Offline fallback database untuk common vulnerabilities
OFFLINE_CVE_DATABASE = {
    'apache': {
        '2.4.49': [
            {
                'cve': 'CVE-2021-41773',
                'severity': 'Critical',
                'cvss_score': 9.8,
                'description': 'Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49',
                'recommendation': 'Upgrade to Apache 2.4.51 or later immediately',
                'source': 'Offline Database'
            }
        ],
        '2.4.50': [
            {
                'cve': 'CVE-2021-42013',
                'severity': 'Critical',
                'cvss_score': 9.8,
                'description': 'Path Traversal and RCE in Apache HTTP Server 2.4.50 (incomplete fix for CVE-2021-41773)',
                'recommendation': 'Upgrade to Apache 2.4.51 or later',
                'source': 'Offline Database'
            }
        ]
    },
    'openssh': {
        '7.4': [
            {
                'cve': 'CVE-2016-6210',
                'severity': 'High',
                'cvss_score': 7.5,
                'description': 'User Enumeration vulnerability in OpenSSH before 7.4',
                'recommendation': 'Upgrade to OpenSSH 8.0 or later',
                'source': 'Offline Database'
            }
        ]
    },
    'proftpd': {
        '1.3.3c': [
            {
                'cve': 'CVE-2010-4221',
                'severity': 'Critical',
                'cvss_score': 10.0,
                'description': 'Backdoor in ProFTPD 1.3.3c allows remote attackers to execute arbitrary code',
                'recommendation': 'Upgrade to latest ProFTPD version immediately',
                'source': 'Offline Database'
            }
        ]
    },
    'vsftpd': {
        '2.3.4': [
            {
                'cve': 'CVE-2011-2523',
                'severity': 'Critical',
                'cvss_score': 10.0,
                'description': 'Backdoor in vsftpd 2.3.4 allows remote attackers to execute arbitrary commands',
                'recommendation': 'Upgrade vsftpd or switch to SFTP',
                'source': 'Offline Database'
            }
        ]
    },
    'samba': {
        '3.5': [
            {
                'cve': 'CVE-2017-7494',
                'severity': 'Critical',
                'cvss_score': 10.0,
                'description': 'SambaCry - Remote Code Execution in Samba 3.5.0 to 4.6.4',
                'recommendation': 'Upgrade to Samba 4.6.4 or later',
                'source': 'Offline Database'
            }
        ]
    }
}

def get_offline_vulnerabilities(product, version):
    """Get vulnerabilities from offline database"""
    product = product.lower()
    vulnerabilities = []
    
    if product in OFFLINE_CVE_DATABASE:
        # Exact version match
        if version in OFFLINE_CVE_DATABASE[product]:
            vulnerabilities.extend(OFFLINE_CVE_DATABASE[product][version])
        
        # Version range matching (simplified)
        for db_version, vulns in OFFLINE_CVE_DATABASE[product].items():
            if version.startswith(db_version[:3]):  # Match major.minor
                vulnerabilities.extend(vulns)
    
    return vulnerabilities
