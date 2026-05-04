TOOL_REGISTRY = {

    # ══════════════════════════════════════════════════════════════════════════
    # RECON — Host & network discovery, port scanning, DNS
    # ══════════════════════════════════════════════════════════════════════════

    "nmap": {
        "description": "Network port scanner — open ports, services, versions, OS fingerprinting",
        "use_cases": ["port scanning", "service detection", "OS fingerprinting", "network discovery"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "recon",
        "example": "nmap -sV -sC --open -T4 --top-ports 1000 <target>",
    },
    "nmap-root": {
        "description": "Nmap with sudo for scans that require raw sockets (SYN, UDP, OS detection)",
        "use_cases": ["SYN scan", "UDP scan", "OS fingerprinting"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "recon",
        "command": "sudo nmap",
        "example": "sudo nmap -sS -O -T4 <target>",
    },
    "masscan": {
        "description": "Ultra-fast port scanner — scans entire internet ranges in minutes",
        "use_cases": ["fast port scanning", "large network scanning"],
        "dangerous": False, "requires_root": True, "timeout": 180, "category": "recon",
        "example": "masscan <target> -p1-65535 --rate=1000",
    },
    "rustscan": {
        "description": "Blazing-fast port scanner that feeds results directly into nmap",
        "use_cases": ["fast port scanning", "quick recon"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "recon",
        "target_flag": "-a",
        "target_before_options": True,
        "example": "rustscan -a <target> --ulimit 5000 -- -sV -sC",
    },
    "netdiscover": {
        "description": "Active/passive ARP reconnaissance — discover live hosts on LAN",
        "use_cases": ["host discovery", "LAN scanning", "ARP scanning"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "recon",
        "example": "netdiscover -r <subnet>/24",
    },
    "arp-scan": {
        "description": "ARP scanner — discover all live hosts on local network",
        "use_cases": ["LAN host discovery", "ARP scanning", "local network mapping"],
        "dangerous": False, "requires_root": True, "timeout": 30, "category": "recon",
        "example": "arp-scan --localnet",
    },
    "fping": {
        "description": "Fast parallel ping — check which hosts are alive in a subnet",
        "use_cases": ["host alive check", "ping sweep", "network discovery"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "recon",
        "example": "fping -a -g <subnet>/24 2>/dev/null",
    },
    "hping3": {
        "description": "Custom TCP/IP packet crafter for firewall testing and OS fingerprinting",
        "use_cases": ["packet crafting", "firewall testing", "OS fingerprinting", "traceroute"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "recon",
        "example": "hping3 -S -p 80 <target>",
    },
    "fierce": {
        "description": "DNS reconnaissance — brute force subdomains and map DNS structure",
        "use_cases": ["DNS recon", "subdomain brute force", "zone walking"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "recon",
        "example": "fierce --domain <domain>",
    },
    "dnsrecon": {
        "description": "DNS enumeration — A/MX/NS/SOA records, zone transfer, reverse lookup",
        "use_cases": ["DNS enumeration", "zone transfer", "reverse DNS"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "recon",
        "example": "dnsrecon -d <domain> -t std",
    },
    "dnsenum": {
        "description": "DNS enumeration — subdomains, MX records, zone transfer attempts",
        "use_cases": ["DNS enumeration", "subdomain discovery", "zone transfer testing"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "recon",
        "example": "dnsenum <domain>",
    },
    "subfinder": {
        "description": "Passive subdomain discovery from public sources (crt.sh, VirusTotal, etc.)",
        "use_cases": ["subdomain enumeration", "domain recon", "asset discovery"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "recon",
        "target_flag": "-d",
        "example": "subfinder -d <domain> -silent",
    },
    "amass": {
        "description": "Deep attack surface mapping — subdomains, ASNs, IPs, CIDR blocks",
        "use_cases": ["subdomain enumeration", "OSINT", "deep domain recon", "ASN mapping"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "recon",
        "target_flag": "-d",
        "example": "amass enum -d <domain>",
    },
    "theHarvester": {
        "description": "OSINT — emails, subdomains, IPs, URLs from search engines and public sources",
        "use_cases": ["email harvesting", "OSINT", "subdomain discovery", "employee enumeration"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "recon",
        "example": "theHarvester -d <domain> -b all",
    },
    "whois": {
        "description": "Domain registration info — registrar, contacts, nameservers, expiry",
        "use_cases": ["domain info", "OSINT", "registrar lookup"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "recon",
        "example": "whois <domain>",
    },
    "dmitry": {
        "description": "All-in-one information gatherer — whois, subdomains, emails, open ports",
        "use_cases": ["passive recon", "domain info", "email gathering"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "recon",
        "example": "dmitry -winsepfb <target>",
    },
    "p0f": {
        "description": "Passive OS fingerprinting — identifies OS from captured traffic without sending packets",
        "use_cases": ["passive fingerprinting", "OS detection", "traffic analysis"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "recon",
        "example": "p0f -i eth0 -p",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # WEB — Web application testing
    # ══════════════════════════════════════════════════════════════════════════

    "nikto": {
        "description": "Web server vulnerability scanner — dangerous files, outdated software, misconfigs",
        "use_cases": ["web vulnerability scanning", "web server audit", "HTTP testing"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "example": "nikto -h <target>",
    },
    "gobuster": {
        "description": "Directory/file/DNS/vhost brute forcer for web servers",
        "use_cases": ["directory busting", "file discovery", "vhost discovery", "web fuzzing"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-u",
        "example": "gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt -t 50 -s 200,204,301,302,307,401,403",
    },
    "ffuf": {
        "description": "Fast web fuzzer — directories, parameters, headers, vhosts",
        "use_cases": ["web fuzzing", "directory discovery", "parameter fuzzing", "vhost discovery"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-u",
        "example": "ffuf -u <target>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -fc 404",
    },
    "feroxbuster": {
        "description": "Fast recursive content discovery — finds hidden directories and files recursively",
        "use_cases": ["recursive directory busting", "content discovery", "web fuzzing"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-u",
        "example": "feroxbuster -u <target> -w /usr/share/wordlists/dirb/common.txt -s 200,204,301,302,307,401,403",
    },
    "dirsearch": {
        "description": "Web path scanner — finds directories and files using a built-in wordlist",
        "use_cases": ["directory scanning", "file discovery", "web content enumeration"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-u",
        "example": "dirsearch -u <target>",
    },
    "dirb": {
        "description": "Classic web content scanner using dictionary-based brute force",
        "use_cases": ["directory scanning", "web content discovery"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "example": "dirb <target>",
    },
    "wpscan": {
        "description": "WordPress scanner — plugins, themes, users, vulnerabilities",
        "use_cases": ["WordPress scanning", "CMS testing", "WordPress vulnerabilities"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "--url",
        "always_flags": "--no-update --request-timeout 15 --format json",
        "example": "wpscan --url <target> --enumerate vp,u --no-update --request-timeout 15 --format json",
    },
    "sqlmap": {
        "description": "Automated SQL injection detection and database exploitation",
        "use_cases": ["SQL injection", "database dumping", "web app testing"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-u",
        "example": "sqlmap -u 'http://<target>/page?id=1' --dbs",
    },
    "whatweb": {
        "description": "Web technology fingerprinter — CMS, frameworks, servers, libraries",
        "use_cases": ["technology detection", "web fingerprinting", "CMS identification"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "web",
        "example": "whatweb <target>",
    },
    "wafw00f": {
        "description": "WAF detection — identifies Web Application Firewall type and vendor",
        "use_cases": ["WAF detection", "firewall identification", "web recon"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "web",
        "example": "wafw00f <target>",
    },
    "nuclei": {
        "description": "Template-based vulnerability scanner — thousands of CVE and misconfiguration checks",
        "use_cases": ["vulnerability scanning", "CVE detection", "misconfiguration", "bulk scanning"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-u",
        "always_flags": "-json -silent",
        "example": "nuclei -u <target> -severity critical,high",
    },
    "dalfox": {
        "description": "XSS scanner and parameter analysis tool",
        "use_cases": ["XSS testing", "reflected XSS", "stored XSS", "parameter analysis"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "example": "dalfox url http://<target>/page?q=test",
    },
    "xsser": {
        "description": "Automated XSS detection and exploitation framework",
        "use_cases": ["XSS testing", "cross-site scripting", "payload injection"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "example": "xsser --url 'http://<target>/page?q=XSS'",
    },
    "commix": {
        "description": "Automated command injection detection and exploitation",
        "use_cases": ["command injection", "OS command injection", "web exploitation"],
        "dangerous": True, "requires_root": False, "timeout": 180, "category": "web",
        "example": "commix --url='http://<target>/page?param=value'",
    },
    "arjun": {
        "description": "HTTP parameter discovery — finds hidden GET and POST parameters",
        "use_cases": ["parameter discovery", "hidden parameters", "API testing"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "target_flag": "-u",
        "example": "arjun -u <target>",
    },
    "wfuzz": {
        "description": "Web fuzzer — brute force web apps, parameters, authentication",
        "use_cases": ["web fuzzing", "brute force", "parameter fuzzing", "auth testing"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "example": "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt <target>/FUZZ",
    },
    "hakrawler": {
        "description": "Web crawler — discovers URLs, forms, endpoints from a website",
        "use_cases": ["web crawling", "endpoint discovery", "link extraction"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "stdin_target": True,
        "example": "printf '%s\\n' <target> | hakrawler",
    },
    "katana": {
        "description": "Next-gen web crawler — JavaScript-aware, finds deep endpoints",
        "use_cases": ["web crawling", "JS endpoint discovery", "attack surface mapping"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "target_flag": "-u",
        "example": "katana -u <target> -silent -d 2",
    },
    "waybackurls": {
        "description": "Fetch all URLs for a domain from Wayback Machine archives",
        "use_cases": ["historical URLs", "endpoint discovery", "OSINT", "web recon"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "web",
        "example": "waybackurls <domain>",
    },
    "gau": {
        "description": "Get All URLs — fetches known URLs from AlienVault, Wayback, Common Crawl",
        "use_cases": ["URL discovery", "endpoint enumeration", "web OSINT"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "web",
        "example": "gau <domain>",
    },
    "httpx": {
        "description": "Fast HTTP probing — check live hosts, grab status codes, titles, and tech",
        "use_cases": ["HTTP probing", "live host detection", "tech detection", "web recon"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "stdin_target": True,
        "example": "printf '%s\\n' <domain> | httpx -json -sc -title -td -cl -location",
    },
    "x8": {
        "description": "Hidden HTTP parameter discovery — finds parameters that change server behavior",
        "use_cases": ["parameter discovery", "hidden parameter", "web fuzzing"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "target_flag": "-u",
        "example": "x8 -u <target> -w params.txt",
    },
    "autorecon": {
        "description": "Automated multi-service enumeration tool — runs nmap then service-specific tools",
        "use_cases": ["automated recon", "service enumeration", "CTF", "pentesting"],
        "dangerous": False, "requires_root": False, "timeout": 600, "category": "recon",
        "example": "autorecon <target>",
    },
    "jwt_tool": {
        "description": "JWT testing toolkit — decode, forge, crack JWT tokens",
        "use_cases": ["JWT testing", "token manipulation", "auth bypass", "algorithm confusion"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "web",
        "example": "jwt_tool <token> -T",
    },
    "ssrfmap": {
        "description": "SSRF detection and exploitation — maps internal services via server-side requests",
        "use_cases": ["SSRF testing", "internal service discovery", "cloud metadata"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "web",
        "example": "ssrfmap -r request.txt -p url",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # NETWORK — SMB, LDAP, RPC, SSL/TLS, protocol enumeration
    # ══════════════════════════════════════════════════════════════════════════

    "enum4linux": {
        "description": "SMB/NetBIOS enumeration — users, shares, OS info, password policies",
        "use_cases": ["SMB enumeration", "Windows enumeration", "user listing", "share discovery"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "network",
        "example": "enum4linux -a <target>",
    },
    "enum4linux-ng": {
        "description": "Modern rewrite of enum4linux with JSON output and extra features",
        "use_cases": ["SMB enumeration", "Windows recon", "user enumeration"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "network",
        "example": "enum4linux-ng -A <target>",
    },
    "smbmap": {
        "description": "SMB share mapper — lists accessible shares, permissions, file listing",
        "use_cases": ["SMB shares", "file share discovery", "Windows recon"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "smbmap -H <target>",
    },
    "smbclient": {
        "description": "SMB client — browse and download files from Windows shares",
        "use_cases": ["SMB access", "file share browsing", "file download"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "smbclient -L //<target> -N",
    },
    "netexec": {
        "description": "Network execution tool (CrackMapExec successor) — SMB, WinRM, LDAP, SSH, RDP",
        "use_cases": ["Windows network attacks", "lateral movement", "credential spraying", "SMB"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "network",
        "example": "netexec smb <target> -u user -p password",
    },
    "rpcclient": {
        "description": "MS-RPC client — enumerate users, groups, shares via RPC",
        "use_cases": ["RPC enumeration", "Windows user listing", "domain recon"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "rpcclient -U '' -N <target>",
    },
    "ldapsearch": {
        "description": "LDAP query tool — enumerate Active Directory users, groups, OUs",
        "use_cases": ["LDAP enumeration", "Active Directory recon", "user listing"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "ldapsearch -x -H ldap://<target> -b 'dc=domain,dc=com'",
    },
    "snmpwalk": {
        "description": "SNMP enumeration — device configs, routing tables, processes via OID walking",
        "use_cases": ["SNMP enumeration", "network device info", "OID walking"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "snmpwalk -v2c -c public <target>",
    },
    "onesixtyone": {
        "description": "Fast SNMP scanner — brute force community strings across multiple hosts",
        "use_cases": ["SNMP community string brute force", "SNMP discovery"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "target_before_options": True,
        "example": "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <target>",
    },
    "nbtscan": {
        "description": "NetBIOS scanner — discovers Windows hostnames and MAC addresses",
        "use_cases": ["NetBIOS scanning", "Windows host discovery"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "nbtscan <target>/24",
    },
    "sslscan": {
        "description": "SSL/TLS scanner — cipher suites, certificate info, vulnerabilities (POODLE, BEAST)",
        "use_cases": ["SSL testing", "TLS vulnerabilities", "certificate analysis", "HTTPS audit"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "network",
        "example": "sslscan <target>",
    },
    "testssl": {
        "description": "Comprehensive SSL/TLS tester — checks all ciphers, protocols, and known vulns",
        "use_cases": ["SSL/TLS audit", "HTTPS testing", "cipher enumeration"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "network",
        "example": "testssl.sh <target>",
    },
    "ike-scan": {
        "description": "VPN/IPSec scanner — discovers and fingerprints IKE hosts",
        "use_cases": ["VPN scanning", "IPSec enumeration", "IKE fingerprinting"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "network",
        "example": "ike-scan <target>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ACTIVE DIRECTORY — AD enumeration and attacks
    # ══════════════════════════════════════════════════════════════════════════

    "bloodhound": {
        "description": "Active Directory attack path mapper — visualizes privilege escalation paths",
        "use_cases": ["AD enumeration", "privilege escalation paths", "domain analysis", "attack path"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "active_directory",
        "command": "bloodhound-python",
        "example": "bloodhound-python -u user -p pass -ns <dc_ip> -d domain.local -c all",
    },
    "kerbrute": {
        "description": "Kerberos brute forcer — enumerate valid AD usernames and spray passwords",
        "use_cases": ["Kerberos brute force", "username enumeration", "password spraying", "AD recon"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "active_directory",
        "example": "kerbrute userenum -d domain.local --dc <dc_ip> userlist.txt",
    },
    "impacket-secretsdump": {
        "description": "Dump domain hashes remotely via DRSUAPI or local SAM/NTDS files",
        "use_cases": ["hash dumping", "domain compromise", "DCSync attack", "credential extraction"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "active_directory",
        "example": "impacket-secretsdump domain/user:password@<target>",
    },
    "impacket-psexec": {
        "description": "Remote shell via SMB service creation — classic lateral movement technique",
        "use_cases": ["lateral movement", "remote shell", "pass-the-hash"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "active_directory",
        "example": "impacket-psexec domain/user:password@<target>",
    },
    "impacket-getTGT": {
        "description": "Request a Kerberos TGT for a user — used in pass-the-hash attacks",
        "use_cases": ["Kerberos ticket", "pass-the-hash", "AS-REP roasting"],
        "dangerous": True, "requires_root": False, "timeout": 30, "category": "active_directory",
        "example": "impacket-getTGT domain.local/user:password",
    },
    "impacket-GetNPUsers": {
        "description": "AS-REP roasting — get hashes for users without pre-auth required",
        "use_cases": ["AS-REP roasting", "Kerberos hashes", "offline cracking"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "active_directory",
        "example": "impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip <dc_ip>",
    },
    "evil-winrm": {
        "description": "Windows Remote Management shell — connect to WinRM with credentials or hashes",
        "use_cases": ["WinRM shell", "remote access", "pass-the-hash", "PowerShell remote"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "active_directory",
        "example": "evil-winrm -i <target> -u user -p password",
    },
    "ldapdomaindump": {
        "description": "Dump all AD objects via LDAP into HTML/JSON reports",
        "use_cases": ["AD enumeration", "LDAP dump", "user/group/computer listing"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "active_directory",
        "example": "ldapdomaindump -u 'domain\\user' -p password <dc_ip>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PASSWORDS — Cracking, brute force, wordlist generation
    # ══════════════════════════════════════════════════════════════════════════

    "hydra": {
        "description": "Parallelized login cracker — SSH, FTP, HTTP, RDP, SMB, and 50+ protocols",
        "use_cases": ["brute force login", "credential testing", "password spraying"],
        "dangerous": True, "requires_root": False, "timeout": 300, "category": "passwords",
        "example": "hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> ssh",
    },
    "medusa": {
        "description": "Fast modular brute forcer — alternative to hydra with wider protocol support",
        "use_cases": ["brute force", "credential testing", "protocol attacks"],
        "dangerous": True, "requires_root": False, "timeout": 300, "category": "passwords",
        "example": "medusa -h <target> -u admin -P /usr/share/wordlists/rockyou.txt -M ssh",
    },
    "ncrack": {
        "description": "High-speed network authentication cracker by the nmap team",
        "use_cases": ["brute force", "network authentication cracking"],
        "dangerous": True, "requires_root": False, "timeout": 300, "category": "passwords",
        "example": "ncrack -p 22 --user root -P /usr/share/wordlists/rockyou.txt <target>",
    },
    "john": {
        "description": "John the Ripper — offline password hash cracker (MD5, SHA, NTLM, bcrypt)",
        "use_cases": ["hash cracking", "offline password attack", "password recovery"],
        "dangerous": False, "requires_root": False, "timeout": 600, "category": "passwords",
        "example": "john --wordlist=/usr/share/wordlists/rockyou.txt <hashfile>",
    },
    "hashcat": {
        "description": "GPU-accelerated hash cracker — world's fastest, supports 300+ hash types",
        "use_cases": ["GPU hash cracking", "fast password cracking", "rule-based attacks"],
        "dangerous": False, "requires_root": False, "timeout": 600, "category": "passwords",
        "example": "hashcat -m 0 -a 0 <hashfile> /usr/share/wordlists/rockyou.txt",
    },
    "hashid": {
        "description": "Hash identifier — determine what type of hash you have",
        "use_cases": ["hash identification", "hash type detection"],
        "dangerous": False, "requires_root": False, "timeout": 10, "category": "passwords",
        "example": "hashid '<hash>'",
    },
    "cewl": {
        "description": "Custom wordlist generator — spiders a website and builds a wordlist from its words",
        "use_cases": ["wordlist generation", "custom wordlist", "targeted brute force"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "passwords",
        "example": "cewl http://<target> -d 2 -m 5 -w wordlist.txt",
    },
    "crunch": {
        "description": "Wordlist generator — generates all combinations from a character set",
        "use_cases": ["wordlist generation", "brute force wordlist", "custom passwords"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "passwords",
        "example": "crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # EXPLOITATION — Exploit frameworks and payload generation
    # ══════════════════════════════════════════════════════════════════════════

    "metasploit": {
        "description": "World's most used pentest framework — exploits, payloads, post-exploitation",
        "use_cases": ["exploitation", "post-exploitation", "payload generation"],
        "dangerous": True, "requires_root": True, "timeout": 300, "category": "exploitation",
        "example": "msfconsole -q -x 'use exploit/...; set RHOSTS <target>; run'",
    },
    "msfconsole": {
        "description": "Metasploit Framework console — interactive exploitation and post-exploitation",
        "use_cases": ["exploitation", "post-exploitation", "auxiliary scanning", "payload delivery"],
        "dangerous": True, "requires_root": True, "timeout": 300, "category": "exploitation",
        "example": "msfconsole -q -r script.rc",
    },
    "msfvenom": {
        "description": "Payload generator and encoder — shellcode, ELF, EXE, APK, reverse shells",
        "use_cases": ["payload generation", "shellcode creation", "reverse shell"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "exploitation",
        "example": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=4444 -f elf -o shell",
    },
    "searchsploit": {
        "description": "Exploit-DB offline search — find exploits for any software/CVE",
        "use_cases": ["exploit search", "CVE lookup", "vulnerability research"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "exploitation",
        "example": "searchsploit apache 2.4.49",
    },
    "beef-xss": {
        "description": "Browser Exploitation Framework — hook browsers and execute client-side attacks",
        "use_cases": ["browser exploitation", "XSS exploitation", "client-side attacks"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "exploitation",
        "example": "beef-xss",
    },
    "sqlninja": {
        "description": "SQL injection exploitation on Microsoft SQL Server",
        "use_cases": ["MSSQL exploitation", "SQL injection", "Windows database attacks"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "exploitation",
        "example": "sqlninja -m t -f sqlninja.conf",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # POST EXPLOITATION — Privilege escalation, persistence, lateral movement
    # ══════════════════════════════════════════════════════════════════════════

    "linpeas": {
        "description": "Linux privilege escalation scanner — finds misconfigs, SUID, cron, weak perms",
        "use_cases": ["Linux privesc", "privilege escalation", "post exploitation", "CTF"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "post_exploitation",
        "example": "bash linpeas.sh | tee linpeas_output.txt",
    },
    "winpeas": {
        "description": "Windows privilege escalation scanner — services, registry, credentials",
        "use_cases": ["Windows privesc", "privilege escalation", "post exploitation"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "post_exploitation",
        "example": "winpeas.exe > winpeas_output.txt",
    },
    "pwncat": {
        "description": "Advanced reverse/bind shell with post-exploitation modules built-in",
        "use_cases": ["reverse shell", "post exploitation", "file transfer", "persistence"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "post_exploitation",
        "example": "pwncat-cs -lp 4444",
    },
    "chisel": {
        "description": "TCP/UDP tunnel over HTTP — pivot through firewalls and NAT",
        "use_cases": ["tunneling", "pivoting", "port forwarding", "firewall bypass"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "post_exploitation",
        "example": "chisel server -p 8080 --reverse",
    },
    "proxychains": {
        "description": "Route any TCP tool through SOCKS4/5 or HTTP proxies for pivoting",
        "use_cases": ["proxying", "pivoting", "traffic routing", "anonymity"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "post_exploitation",
        "example": "proxychains nmap -sT <target>",
    },
    "socat": {
        "description": "Bidirectional data relay — port forwarding, reverse shells, file transfer",
        "use_cases": ["port forwarding", "reverse shell", "file transfer", "pivoting"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "post_exploitation",
        "example": "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:'/bin/bash'",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # WIRELESS — WiFi and Bluetooth attacks
    # ══════════════════════════════════════════════════════════════════════════

    "airmon-ng": {
        "description": "Enable/disable monitor mode on wireless interfaces",
        "use_cases": ["WiFi monitoring", "monitor mode", "wireless interface management"],
        "dangerous": False, "requires_root": True, "timeout": 30, "category": "wireless",
        "example": "airmon-ng start wlan0",
    },
    "airodump-ng": {
        "description": "802.11 packet capture — sniff WiFi networks, capture handshakes",
        "use_cases": ["WiFi scanning", "handshake capture", "network discovery", "packet capture"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "wireless",
        "example": "airodump-ng wlan0mon",
    },
    "aireplay-ng": {
        "description": "WiFi packet injection — deauth attacks, ARP replay, WEP cracking",
        "use_cases": ["deauth attack", "WEP cracking", "packet injection"],
        "dangerous": True, "requires_root": True, "timeout": 60, "category": "wireless",
        "example": "aireplay-ng -0 10 -a <bssid> wlan0mon",
    },
    "aircrack-ng": {
        "description": "WiFi password cracker — WEP and WPA/WPA2 handshake cracking",
        "use_cases": ["WiFi cracking", "WPA2 cracking", "WEP cracking", "handshake cracking"],
        "dangerous": True, "requires_root": False, "timeout": 600, "category": "wireless",
        "example": "aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap",
    },
    "wifite": {
        "description": "Automated WiFi attack tool — scans and attacks multiple networks automatically",
        "use_cases": ["automated WiFi attacks", "WPA2 cracking", "WPS attacks"],
        "dangerous": True, "requires_root": True, "timeout": 1800, "category": "wireless",
        "target_flag": "-i", "requires_tty": True,
        "example": "wifite -i <target> --wpa --dict /usr/share/wordlists/rockyou.txt",
    },
    "reaver": {
        "description": "WPS PIN brute force attack to recover WPA/WPA2 passphrases",
        "use_cases": ["WPS attacks", "WPA2 recovery", "WiFi exploitation"],
        "dangerous": True, "requires_root": True, "timeout": 600, "category": "wireless",
        "example": "reaver -i wlan0mon -b <bssid> -vv",
    },
    "bettercap": {
        "description": "All-in-one network attack framework — MITM, sniffing, WiFi, BLE attacks",
        "use_cases": ["MITM attacks", "network sniffing", "WiFi attacks", "BLE hacking"],
        "dangerous": True, "requires_root": True, "timeout": 60, "category": "wireless",
        "target_flag": "-iface",
        "example": "sudo bettercap -iface <target>",
    },
    "kismet": {
        "description": "Wireless network detector and sniffer — passive WiFi and Bluetooth discovery",
        "use_cases": ["WiFi discovery", "passive sniffing", "Bluetooth discovery"],
        "dangerous": False, "requires_root": True, "timeout": 120, "category": "wireless",
        "target_flag": None,
        "example": "kismet",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # SNIFFING & SPOOFING — Network interception and MITM
    # ══════════════════════════════════════════════════════════════════════════

    "wireshark": {
        "description": "Network protocol analyzer — capture and analyze packets in real time",
        "use_cases": ["packet capture", "traffic analysis", "protocol inspection", "MITM analysis"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "sniffing",
        "example": "tshark -i eth0 -w capture.pcap",
    },
    "tcpdump": {
        "description": "Command-line packet capture and analysis tool",
        "use_cases": ["packet capture", "traffic monitoring", "network debugging"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "sniffing",
        "example": "tcpdump -i eth0 -w capture.pcap",
    },
    "responder": {
        "description": "LLMNR/NBT-NS/MDNS poisoner — captures NTLMv2 hashes on Windows networks",
        "use_cases": ["credential capture", "NTLM hashes", "LLMNR poisoning", "network attacks"],
        "dangerous": True, "requires_root": True, "timeout": 120, "category": "sniffing",
        "example": "responder -I eth0 -rdwv",
    },
    "ettercap": {
        "description": "MITM attack suite — ARP poisoning, sniffing, traffic manipulation",
        "use_cases": ["MITM attacks", "ARP poisoning", "credential sniffing"],
        "dangerous": True, "requires_root": True, "timeout": 60, "category": "sniffing",
        "example": "ettercap -T -i eth0 -M arp:remote /<target1>// /<target2>//",
    },
    "arpspoof": {
        "description": "ARP cache poisoning — redirect traffic between hosts for MITM",
        "use_cases": ["ARP poisoning", "MITM setup", "traffic redirection"],
        "dangerous": True, "requires_root": True, "timeout": 60, "category": "sniffing",
        "example": "arpspoof -i eth0 -t <victim> <gateway>",
    },
    "mitm6": {
        "description": "IPv6 MITM attack — exploits Windows IPv6 preference for credential capture",
        "use_cases": ["IPv6 MITM", "Windows credential capture", "DHCPv6 attacks"],
        "dangerous": True, "requires_root": True, "timeout": 120, "category": "sniffing",
        "example": "mitm6 -d domain.local",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CLOUD — AWS, Azure, GCP security testing
    # ══════════════════════════════════════════════════════════════════════════

    "pacu": {
        "description": "AWS exploitation framework — enumerate and attack AWS environments",
        "use_cases": ["AWS hacking", "cloud exploitation", "AWS privilege escalation"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "pacu",
    },
    "scout-suite": {
        "description": "Multi-cloud security auditing — AWS/Azure/GCP misconfiguration scanner",
        "use_cases": ["cloud security audit", "AWS audit", "Azure audit", "GCP audit", "misconfiguration"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "cloud",
        "example": "scout aws --no-browser",
    },
    "prowler": {
        "description": "AWS/Azure/GCP security assessment tool aligned to CIS benchmarks",
        "use_cases": ["cloud compliance", "CIS benchmark", "AWS security audit"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "cloud",
        "example": "prowler aws",
    },
    "trufflehog": {
        "description": "Secrets scanner — finds API keys, credentials in git repos and file systems",
        "use_cases": ["secrets scanning", "credential discovery", "API key leaks", "git scanning"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "trufflehog git https://github.com/<org>/<repo>",
    },
    "cloudmapper": {
        "description": "AWS environment mapper — visualizes AWS account resources and attack surface",
        "use_cases": ["AWS mapping", "cloud asset discovery", "network visualization"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "python3 cloudmapper.py collect --account <account>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # SOCIAL ENGINEERING — Phishing and human-based attacks
    # ══════════════════════════════════════════════════════════════════════════

    "setoolkit": {
        "description": "Social Engineering Toolkit — phishing, credential harvesting, spear phishing",
        "use_cases": ["phishing", "credential harvesting", "social engineering", "spear phishing"],
        "dangerous": True, "requires_root": True, "timeout": 60, "category": "social_engineering",
        "example": "setoolkit",
    },
    "gophish": {
        "description": "Open-source phishing framework — run phishing campaigns with tracking",
        "use_cases": ["phishing campaigns", "email phishing", "awareness testing"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "social_engineering",
        "example": "gophish",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # OSINT — Open-source intelligence gathering
    # ══════════════════════════════════════════════════════════════════════════

    "spiderfoot": {
        "description": "Automated OSINT — correlates data from 200+ sources into target profiles",
        "use_cases": ["deep OSINT", "target profiling", "automated intelligence"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "osint",
        "example": "spiderfoot -s <target> -t all -o spiderfoot_report.html",
    },
    "sherlock": {
        "description": "Username hunter — find social media accounts for a username across 300+ sites",
        "use_cases": ["username OSINT", "social media lookup", "account discovery"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "osint",
        "example": "sherlock <username>",
    },
    "recon-ng": {
        "description": "OSINT framework with modules for gathering intel from web services",
        "use_cases": ["OSINT framework", "web OSINT", "API-based intel gathering"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "osint",
        "example": "recon-ng",
    },
    "maltego": {
        "description": "Visual OSINT and link analysis tool — map relationships between entities",
        "use_cases": ["visual OSINT", "relationship mapping", "entity analysis"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "osint",
        "example": "maltego",
    },
    "metagoofil": {
        "description": "Extract metadata from public documents (PDF, DOC, XLS) for OSINT",
        "use_cases": ["metadata extraction", "document OSINT", "employee names from docs"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "osint",
        "example": "metagoofil -d <domain> -t pdf,doc,xls -o output/",
    },
    "photon": {
        "description": "Fast web crawler for OSINT — extracts URLs, emails, files, keys from websites",
        "use_cases": ["web OSINT", "email extraction", "key discovery", "link crawling"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "osint",
        "example": "python3 photon.py -u http://<target> -o output/",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # FORENSICS — File analysis, memory forensics, data recovery
    # ══════════════════════════════════════════════════════════════════════════

    "volatility": {
        "description": "Memory forensics framework — analyze RAM dumps for processes, network, malware",
        "use_cases": ["memory forensics", "RAM analysis", "malware detection", "incident response"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "forensics",
        "example": "volatility -f memory.dmp imageinfo",
    },
    "binwalk": {
        "description": "Firmware analysis and file extraction — finds embedded files and filesystems",
        "use_cases": ["firmware analysis", "binary analysis", "file extraction", "CTF"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "forensics",
        "example": "binwalk -e <firmware.bin>",
    },
    "foremost": {
        "description": "File carving — recovers deleted files from disk images by file signatures",
        "use_cases": ["file recovery", "data carving", "disk forensics", "deleted files"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "forensics",
        "example": "foremost -i disk.img -o output/",
    },
    "exiftool": {
        "description": "Read/write metadata in files — images, PDFs, audio, video",
        "use_cases": ["metadata extraction", "image OSINT", "file analysis", "EXIF data"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "forensics",
        "example": "exiftool <file>",
    },
    "strings": {
        "description": "Extract human-readable strings from binary files",
        "use_cases": ["binary analysis", "CTF", "malware analysis", "hidden strings"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "forensics",
        "example": "strings <binary> | grep -i password",
    },
    "steghide": {
        "description": "Steganography — hide or extract data inside images and audio files",
        "use_cases": ["steganography", "hidden data extraction", "CTF", "covert channels"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "forensics",
        "example": "steghide extract -sf image.jpg",
    },
    "stegseek": {
        "description": "Fast steghide password cracker — extracts hidden data from images",
        "use_cases": ["steganography cracking", "CTF", "hidden data"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "forensics",
        "example": "stegseek image.jpg /usr/share/wordlists/rockyou.txt",
    },
    "zsteg": {
        "description": "Detect hidden data in PNG and BMP images — LSB steganography",
        "use_cases": ["PNG steganography", "LSB analysis", "CTF image challenges"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "forensics",
        "example": "zsteg -a image.png",
    },
    "pdf-parser": {
        "description": "Parse PDF files to extract objects, streams, and embedded content",
        "use_cases": ["PDF analysis", "malware analysis", "document forensics"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "forensics",
        "example": "pdf-parser.py <file.pdf>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # REVERSE ENGINEERING — Binary analysis and debugging
    # ══════════════════════════════════════════════════════════════════════════

    "ghidra": {
        "description": "NSA reverse engineering suite — disassemble, decompile, and analyze binaries",
        "use_cases": ["reverse engineering", "binary analysis", "decompilation", "malware analysis"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "reverse_engineering",
        "example": "ghidra",
    },
    "radare2": {
        "description": "Advanced binary analysis framework — disassemble, debug, patch binaries",
        "use_cases": ["reverse engineering", "binary analysis", "CTF", "exploit development"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "reverse_engineering",
        "example": "r2 -A <binary>",
    },
    "gdb": {
        "description": "GNU debugger — debug native programs, analyze crashes, exploit development",
        "use_cases": ["debugging", "exploit development", "crash analysis", "CTF"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "reverse_engineering",
        "example": "gdb <binary>",
    },
    "objdump": {
        "description": "Display binary file information — disassemble and inspect object files",
        "use_cases": ["binary disassembly", "ELF inspection", "section analysis"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "reverse_engineering",
        "example": "objdump -d <binary>",
    },
    "ltrace": {
        "description": "Trace library calls made by a process at runtime",
        "use_cases": ["dynamic analysis", "library tracing", "malware analysis"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "reverse_engineering",
        "example": "ltrace <binary>",
    },
    "strace": {
        "description": "Trace system calls made by a process — understand binary behavior",
        "use_cases": ["syscall tracing", "dynamic analysis", "debugging"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "reverse_engineering",
        "example": "strace <binary>",
    },
    "checksec": {
        "description": "Check binary security protections — NX, ASLR, PIE, canary, RELRO",
        "use_cases": ["binary security check", "exploit development", "CTF binary analysis"],
        "dangerous": False, "requires_root": False, "timeout": 10, "category": "reverse_engineering",
        "example": "checksec --file=<binary>",
    },
    "pwntools": {
        "description": "CTF exploit development framework — write exploits in Python",
        "use_cases": ["exploit development", "CTF", "binary exploitation", "ROP chains"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "reverse_engineering",
        "example": "python3 -c 'from pwn import *; ...'",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # MOBILE — Android and iOS security testing
    # ══════════════════════════════════════════════════════════════════════════

    "apktool": {
        "description": "Android APK decompiler — decode, modify, and recompile Android apps",
        "use_cases": ["APK analysis", "Android reverse engineering", "mobile security"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "mobile",
        "example": "apktool d <app.apk>",
    },
    "jadx": {
        "description": "Android DEX to Java decompiler — read Android app source code",
        "use_cases": ["APK decompilation", "Android analysis", "Java source recovery"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "mobile",
        "example": "jadx -d output/ <app.apk>",
    },
    "frida": {
        "description": "Dynamic instrumentation toolkit — hook and modify app behavior at runtime",
        "use_cases": ["runtime manipulation", "SSL pinning bypass", "app hooking", "dynamic analysis"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "mobile",
        "example": "frida -U -f com.target.app --no-pause -l script.js",
    },
    "objection": {
        "description": "Runtime mobile exploration — bypass SSL pinning, dump memory, explore apps",
        "use_cases": ["SSL pinning bypass", "iOS/Android runtime", "mobile pentest"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "mobile",
        "example": "objection -g com.target.app explore",
    },
    "drozer": {
        "description": "Android security assessment framework — test app attack surface",
        "use_cases": ["Android security testing", "intent attacks", "content provider testing"],
        "dangerous": True, "requires_root": False, "timeout": 60, "category": "mobile",
        "example": "drozer console connect",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # BINARY EXPLOITATION — ROP, symbolic execution, CTF binary tools
    # ══════════════════════════════════════════════════════════════════════════

    "angr": {
        "description": "Binary symbolic execution framework — find vulnerabilities via symbolic analysis",
        "use_cases": ["symbolic execution", "binary analysis", "CTF", "vulnerability discovery", "path exploration"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "reverse_engineering",
        "example": "python3 -c \"import angr; p = angr.Project('<binary>'); print(p.arch)\"",
    },
    "ropgadget": {
        "description": "ROP gadget finder — search for ROP/JOP/SYS gadgets in binaries",
        "use_cases": ["ROP chain building", "exploit development", "CTF", "gadget search"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "reverse_engineering",
        "example": "ROPgadget --binary <binary> --rop",
    },
    "ropper": {
        "description": "ROP gadget and binary utility — find gadgets, show file info, disassemble",
        "use_cases": ["ROP chains", "gadget search", "binary analysis", "exploit development"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "reverse_engineering",
        "example": "ropper -f <binary> --search 'pop rdi'",
    },
    "one_gadget": {
        "description": "Find one-gadget ROP exploits in libc — single gadgets that spawn /bin/sh",
        "use_cases": ["one-gadget exploits", "libc exploitation", "CTF", "ROP shortcuts"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "reverse_engineering",
        "example": "one_gadget /lib/x86_64-linux-gnu/libc.so.6",
    },
    "pwninit": {
        "description": "CTF binary setup tool — patches binaries to use target libc and linker",
        "use_cases": ["CTF setup", "libc patching", "binary preparation", "exploit setup"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "reverse_engineering",
        "example": "pwninit --bin <binary> --libc libc.so.6",
    },
    "hashpump": {
        "description": "Hash length extension attack tool — forge hashes for MD5, SHA1, SHA256",
        "use_cases": ["hash length extension", "CTF crypto", "hash forgery", "web exploitation"],
        "dangerous": True, "requires_root": False, "timeout": 30, "category": "reverse_engineering",
        "example": "hashpump -s '<signature>' -d '<data>' -a '<append>' -k <key_length>",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CLOUD / CONTAINER SECURITY — IaC, container, Kubernetes scanners
    # ══════════════════════════════════════════════════════════════════════════

    "checkov": {
        "description": "Infrastructure-as-Code security scanner — Terraform, CloudFormation, K8s, Helm",
        "use_cases": ["IaC security", "Terraform scanning", "CloudFormation audit", "misconfiguration"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "cloud",
        "always_flags": "-o json",
        "example": "checkov -d <target> -o json",
    },
    "terrascan": {
        "description": "Static code analyzer for IaC — Terraform, Kubernetes, Docker, Helm",
        "use_cases": ["IaC scanning", "Terraform security", "Kubernetes security", "compliance"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "terrascan scan -t terraform -d /path/to/code",
    },
    "trivy": {
        "description": "Comprehensive vulnerability scanner — containers, filesystems, IaC, git repos",
        "use_cases": ["container scanning", "CVE detection", "IaC audit", "filesystem scan"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "trivy image -f json <image:tag>",
    },
    "clair": {
        "description": "Container image vulnerability analyzer — static analysis of Docker/OCI images",
        "use_cases": ["container vulnerabilities", "image scanning", "CVE detection"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "clair-scanner --ip <host_ip> <image:tag>",
    },
    "kube-bench": {
        "description": "Kubernetes CIS benchmark checker — audit cluster security configuration",
        "use_cases": ["Kubernetes security", "CIS benchmark", "cluster audit", "compliance"],
        "dangerous": False, "requires_root": True, "timeout": 120, "category": "cloud",
        "example": "kube-bench run --targets master,node",
    },
    "kube-hunter": {
        "description": "Kubernetes penetration testing — hunt for security weaknesses in clusters",
        "use_cases": ["Kubernetes pentest", "cluster vulnerabilities", "K8s security testing"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "cloud",
        "example": "kube-hunter --remote <cluster_ip>",
    },
    "docker-bench-security": {
        "description": "Docker CIS benchmark — checks Docker daemon and container security configs",
        "use_cases": ["Docker security", "CIS benchmark", "container audit", "daemon hardening"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "cloud",
        "example": "docker-bench-security",
    },
    "falco": {
        "description": "Runtime security monitoring — detects anomalous activity in containers/hosts",
        "use_cases": ["runtime monitoring", "threat detection", "container security", "intrusion detection"],
        "dangerous": False, "requires_root": True, "timeout": 60, "category": "cloud",
        "example": "falco -r /etc/falco/falco_rules.yaml",
    },
    "volatility3": {
        "description": "Memory forensics framework v3 — analyze Windows/Linux/macOS RAM dumps",
        "use_cases": ["memory forensics", "RAM analysis", "malware detection", "incident response"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "forensics",
        "example": "python3 vol.py -f memory.dmp windows.pslist",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # WEB — Additional web testing tools
    # ══════════════════════════════════════════════════════════════════════════

    "jaeles": {
        "description": "Web vulnerability scanner — signature-based scanning for web vulnerabilities",
        "use_cases": ["web vulnerability scanning", "signature scanning", "bug bounty", "automation"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "example": "jaeles scan -u http://<target> -s signatures/",
    },
    "dotdotpwn": {
        "description": "Directory traversal fuzzer — test path traversal in HTTP, FTP, TFTP",
        "use_cases": ["path traversal", "directory traversal", "LFI testing", "file inclusion"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "always_flags": "-q -b",
        "example": "dotdotpwn -m http -h <target> -p 443 -d 6 -f /etc/passwd",
    },
    "graphqlmap": {
        "description": "GraphQL injection and exploitation tool — introspection, injection, enumeration",
        "use_cases": ["GraphQL testing", "GraphQL injection", "API security", "introspection"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "web",
        "target_flag": "-u",
        "example": "graphqlmap -u http://<target>/graphql",
    },
    "zaproxy": {
        "description": "OWASP ZAP — automated web application security scanner with proxy",
        "use_cases": ["web app scanning", "DAST", "proxy testing", "automated scanning"],
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-quickurl",
        "example": "zaproxy -cmd -quickurl http://<target> -quickprogress",
    },
    "zap-baseline.py": {
        "description": "OWASP ZAP baseline passive scan script",
        "use_cases": ["web app scanning", "passive scan", "DAST"],
        "command": "zap-baseline.py",
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-t",
        "example": "zap-baseline.py -t https://<target> -r report.html",
    },
    "zap-full-scan.py": {
        "description": "OWASP ZAP full active scan script",
        "use_cases": ["web app scanning", "active scan", "DAST"],
        "command": "zap-full-scan.py",
        "dangerous": False, "requires_root": False, "timeout": 600, "category": "web",
        "target_flag": "-t",
        "example": "zap-full-scan.py -t https://<target> -r report.html",
    },
    "zap-api-scan.py": {
        "description": "OWASP ZAP API scan script for OpenAPI/SOAP/GraphQL",
        "use_cases": ["API scanning", "OpenAPI testing", "DAST"],
        "command": "zap-api-scan.py",
        "dangerous": False, "requires_root": False, "timeout": 300, "category": "web",
        "target_flag": "-t",
        "example": "zap-api-scan.py -t https://<target>/openapi.json -r report.html",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # URL PROCESSING — URL filtering, deduplication, parameter tools
    # ══════════════════════════════════════════════════════════════════════════

    "paramspider": {
        "description": "Parameter spider — mine URLs with parameters from web archives for testing",
        "use_cases": ["parameter discovery", "URL mining", "bug bounty recon", "web archive"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "web",
        "target_flag": "-d",
        "example": "paramspider -d <domain>",
    },
    "anew": {
        "description": "Append new lines to a file — deduplicate URL lists and tool output streams",
        "use_cases": ["URL deduplication", "output filtering", "recon pipeline", "data processing"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "misc",
        "example": "cat urls.txt | anew unique_urls.txt",
    },
    "uro": {
        "description": "URL filtering — remove duplicate URLs sharing the same parameters",
        "use_cases": ["URL deduplication", "attack surface reduction", "recon cleanup"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "misc",
        "example": "cat urls.txt | uro",
    },
    "qsreplace": {
        "description": "Query string replacement — replace parameter values in URL lists for testing",
        "use_cases": ["parameter replacement", "bulk URL manipulation", "fuzzing pipelines"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "misc",
        "example": "cat urls.txt | qsreplace 'FUZZ'",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # BUG BOUNTY — Specialist tools for bug hunting pipelines
    # ══════════════════════════════════════════════════════════════════════════

    "gf": {
        "description": "grep-friendly patterns — filter URLs for SQLi, XSS, SSRF, LFI, redirect, RCE",
        "use_cases": ["URL pattern matching", "bug bounty triage", "parameter filtering", "XSS hunting"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "bug_bounty",
        "example": "cat urls.txt | gf xss",
    },
    "interactsh-client": {
        "description": "Out-of-band interaction server — detect blind SSRF, XXE, command injection",
        "use_cases": ["blind SSRF", "OOB detection", "XXE", "blind injection", "callback testing"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "interactsh-client -v",
    },
    "notify": {
        "description": "Push notifications from tool output — Slack, Discord, Telegram, email",
        "use_cases": ["scan notifications", "alert on finding", "pipeline notification"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "bug_bounty",
        "example": "echo 'found XSS on target.com' | notify",
    },
    "meg": {
        "description": "Fetch many paths for many hosts — bulk endpoint testing with low bandwidth",
        "use_cases": ["bulk path testing", "endpoint probing", "web recon", "path enumeration"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "meg -d 1000 -v /api/v1/ hosts.txt",
    },
    "crlfuzz": {
        "description": "CRLF injection scanner — test for HTTP header injection vulnerabilities",
        "use_cases": ["CRLF injection", "header injection", "response splitting"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "crlfuzz -u 'http://<target>' -v",
    },
    "corsy": {
        "description": "CORS misconfiguration scanner — detects exploitable cross-origin issues",
        "use_cases": ["CORS testing", "cross-origin misconfiguration", "SOP bypass"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "python3 corsy.py -u http://<target>",
    },
    "smuggler": {
        "description": "HTTP request smuggling scanner — detects CL.TE and TE.CL desync vulnerabilities",
        "use_cases": ["request smuggling", "HTTP desync", "CL.TE", "TE.CL"],
        "dangerous": True, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "python3 smuggler.py -u http://<target>",
    },
    "gowitness": {
        "description": "Web screenshot tool — captures screenshots of web targets for visual recon",
        "use_cases": ["visual recon", "screenshot", "web discovery", "bulk screenshots"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "gowitness scan single --url https://<target>",
    },
    "trufflehog": {
        "description": "Secrets scanner — finds API keys, tokens, credentials in git repos",
        "use_cases": ["secrets discovery", "API key leak", "credential exposure", "git scanning"],
        "dangerous": False, "requires_root": False, "timeout": 120, "category": "bug_bounty",
        "example": "trufflehog git https://github.com/<org>/<repo>",
    },
    "gitdumper": {
        "description": "Download exposed .git directories from web servers",
        "use_cases": ["git exposure", "source code disclosure", "web misconfiguration"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "bug_bounty",
        "example": "git-dumper http://<target>/.git/ output/",
    },
    "linkfinder": {
        "description": "JavaScript endpoint extractor — finds hidden endpoints in JS files",
        "use_cases": ["JS analysis", "endpoint discovery", "API surface", "bug bounty recon"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "bug_bounty",
        "example": "python3 linkfinder.py -i http://<target> -d",
    },
    "secretfinder": {
        "description": "Find API keys and secrets in JavaScript files",
        "use_cases": ["JS secrets", "API key discovery", "token leak", "JS analysis"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "bug_bounty",
        "example": "python3 SecretFinder.py -i http://<target>/app.js -o cli",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # MISC — General-purpose utilities
    # ══════════════════════════════════════════════════════════════════════════

    "netcat": {
        "description": "Swiss army knife — reverse shells, port listening, file transfer, debugging",
        "use_cases": ["reverse shell", "port listening", "file transfer", "network debugging"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "misc",
        "example": "nc -lvnp 4444",
    },
    "curl": {
        "description": "HTTP client — make requests, test APIs, inspect headers",
        "use_cases": ["HTTP requests", "API testing", "web probing", "header inspection"],
        "dangerous": False, "requires_root": False, "timeout": 30, "category": "misc",
        "example": "curl -I http://<target>",
    },
    "wget": {
        "description": "File downloader — download files and mirror websites recursively",
        "use_cases": ["file download", "website mirroring", "resource retrieval"],
        "dangerous": False, "requires_root": False, "timeout": 60, "category": "misc",
        "example": "wget -r -l 2 http://<target>",
    },
    "xxd": {
        "description": "Hex dump and reverse — inspect or convert binary files to hex",
        "use_cases": ["hex analysis", "binary inspection", "CTF", "file carving"],
        "dangerous": False, "requires_root": False, "timeout": 10, "category": "misc",
        "example": "xxd <file> | head -50",
    },
}


# ── Helper functions ──────────────────────────────────────────────────────────

_TOOLS_SUMMARY_CACHE: str = ""


def get_tools_summary() -> str:
    """Formatted summary of all tools for the AI system prompt."""
    global _TOOLS_SUMMARY_CACHE
    if _TOOLS_SUMMARY_CACHE:
        return _TOOLS_SUMMARY_CACHE

    lines = []
    categories: dict = {}

    for name, info in TOOL_REGISTRY.items():
        cat = info.get("category", "misc")
        categories.setdefault(cat, []).append((name, info))

    for cat, tools in sorted(categories.items()):
        lines.append(f"\n[{cat.upper().replace('_', ' ')}]")
        for name, info in tools:
            danger = " ⚠ DANGEROUS" if info["dangerous"] else ""
            lines.append(f"  {name}{danger}: {info['description']}")
            lines.append(f"    Use for: {', '.join(info['use_cases'][:3])}")
            lines.append(f"    Example: {info['example']}")

    _TOOLS_SUMMARY_CACHE = "\n".join(lines)
    return _TOOLS_SUMMARY_CACHE


def get_tool(name: str) -> dict:
    return TOOL_REGISTRY.get(name, {})


def get_tools_by_category(category: str) -> dict:
    return {k: v for k, v in TOOL_REGISTRY.items() if v.get("category") == category}


def list_categories() -> list:
    return sorted(set(v.get("category", "misc") for v in TOOL_REGISTRY.values()))
