# RAWFL - Network Scanner & Vulnerability Assessment Tool

RAWFL is a powerful network scanning and vulnerability assessment tool built with Python and Flask. It provides comprehensive network reconnaissance, device fingerprinting, and security analysis capabilities with an intuitive web interface.

## Features

### Core Functionality
- **Network Scanning**: Fast and efficient network discovery using multiple scanning techniques
- **Port Scanning**: Comprehensive port scanning with service detection
- **Device Fingerprinting**: Advanced OS detection and device identification
- **Vulnerability Assessment**: Real-time vulnerability scanning with CVE database integration
- **ARP Scanning**: Network device discovery using ARP protocol
- **Real-time Monitoring**: Continuous network monitoring and alerts
- **AI-Powered Analysis**: Exploit recommendation and security analysis using GROQ AI

### Scanning Capabilities
- Multi-threaded scanning for improved performance
- Common service detection (HTTP, HTTPS, SSH, FTP, SMB, RDP, MySQL, etc.)
- Operating system fingerprinting
- Banner grabbing for service version detection
- Anonymous access detection
- Misconfiguration identification

### Vulnerability Detection
- CVE database integration
- Real-time vulnerability matching
- Risk scoring and severity classification
- Exploit recommendations
- Security remediation suggestions
- CVSS score integration

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrator/Root privileges (required for ARP scanning)
- Windows/Linux/MacOS

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/cainvsilf/RAWFL.git
cd RAWFL
```

2. Install dependencies:
```bash
pip install -r config/requirements.txt
```

3. Configure API keys (optional for AI features):
```bash
# Create .env file
echo GROQ_API_KEY=your_api_key_here > .env
```

4. Run the application:

**Windows:**
```batch
START.bat
```
or
```powershell
.\START.ps1
```

**Linux/MacOS:**
```bash
python app.py
```

5. Access the web interface:
```
http://localhost:5000
```

## Usage

### Basic Network Scan
1. Open the web interface at `http://localhost:5000`
2. Enter target network (e.g., `192.168.1.0/24`)
3. Click "Start Scan"
4. View results including active hosts, open ports, and services

### Vulnerability Assessment
1. Complete a network scan
2. Click on any discovered device
3. View detailed vulnerability report
4. Review risk scores and recommendations

### ARP Scanning
1. Navigate to ARP Scanner
2. Enter target network or leave blank for local network
3. View MAC addresses and manufacturer information

### AI-Powered Analysis
1. Enable AI features by configuring GROQ API key
2. Perform vulnerability scan
3. Request exploit recommendations
4. Get AI-generated security analysis

## Configuration

### Environment Variables
Create a `.env` file in the root directory:

```env
GROQ_API_KEY=your_groq_api_key
FLASK_ENV=development
```

## Project Structure

```
RAWFL/
├── app.py                  # Main Flask application
├── config.py              # Configuration management
├── START.bat              # Windows startup script
├── START.ps1              # PowerShell startup script
├── STOP.bat               # Windows stop script
├── STOP.ps1               # PowerShell stop script
├── config/
│   └── requirements.txt   # Python dependencies
├── scanners/
│   ├── network_scanner.py        # Network scanning engine
│   ├── arp_scanner.py           # ARP scanning module
│   ├── fast_scanner.py          # Fast scanning utilities
│   └── vulnerability_scanner.py # Vulnerability assessment
├── utils/
│   ├── device_fingerprint.py    # Device identification
│   ├── real_ai_assistant.py     # AI integration
│   └── real_vuln_db.py          # Vulnerability database
├── templates/
│   ├── index.html               # Main interface
│   ├── network_info.html        # Network information
│   └── device_details.html      # Device details view
└── static/
    └── auto-detect.js           # Frontend scripts
```

## Security Features

### Vulnerability Detection
- Port-based vulnerability identification
- Service version analysis
- Default credential detection
- Anonymous access checking
- Misconfiguration detection
- CVE matching with real-time database

### Risk Assessment
- Automated risk scoring (0-100)
- Severity classification (Critical, High, Medium, Low, Info)
- CVSS score integration
- Comprehensive remediation guidelines

## Requirements

### Python Packages
- Flask >= 2.3.0
- flask-cors >= 4.0.0
- scapy >= 2.5.0
- groq (for AI features)
- requests
- ipaddress

### System Requirements
- 4GB RAM minimum
- Network adapter with promiscuous mode support
- Administrator/Root privileges for advanced scanning

## Limitations

- ARP scanning requires administrator privileges
- Some scans may trigger IDS/IPS systems
- Scan accuracy depends on network configuration
- AI features require valid GROQ API key

## Legal Disclaimer

This tool is designed for authorized security testing and educational purposes only. Users must:

- Obtain proper authorization before scanning any network
- Comply with local and international laws
- Use the tool responsibly and ethically
- Not use for malicious purposes

Unauthorized network scanning may be illegal in your jurisdiction. The developers assume no liability for misuse of this tool.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review documentation thoroughly

## Roadmap

### Planned Features
- Web application vulnerability scanning
- Network packet analysis
- Custom exploit module integration
- Enhanced reporting capabilities
- Database storage for scan history
- Multi-target scanning support
- API key management interface


## Version History

### v1.0.0 (Current)
- Initial release
- Network scanning functionality
- Vulnerability assessment
- ARP scanning support
- AI-powered analysis
- Web-based interface
- Real-time monitoring

## License

This project is licensed under the MIT License - see the LICENSE file for details.
