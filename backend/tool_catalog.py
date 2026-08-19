"""Metadados das ferramentas para UI (não enviados à IA — economia de tokens)."""

TOOL_CATALOG: dict[str, dict[str, str]] = {
    "nmap": {
        "summary": "Scan de portas, serviços e versões",
        "example": "nmap -sV -T4 scanme.nmap.org",
    },
    "masscan": {
        "summary": "Scan ultrarrápido de portas em larga escala",
        "example": "masscan scanme.nmap.org -p1-65535 --rate 1000",
    },
    "zmap": {
        "summary": "Probe de rede em blocos IP",
        "example": "zmap -p 443 192.0.2.0/24",
    },
    "rustscan": {
        "summary": "Descoberta rápida de portas (precursor do nmap)",
        "example": "rustscan -a alvo.com -- -sV",
    },
    "naabu": {
        "summary": "Scanner de portas escrito em Go",
        "example": "naabu -host alvo.com -top-ports 1000",
    },
    "dig": {
        "summary": "Consulta DNS (A, MX, TXT, etc.)",
        "example": "dig alvo.com ANY +short",
    },
    "whois": {
        "summary": "Registro e contatos do domínio",
        "example": "whois alvo.com",
    },
    "dnsenum": {
        "summary": "Enumeração DNS e zone transfer",
        "example": "dnsenum alvo.com",
    },
    "dnsrecon": {
        "summary": "Reconhecimento DNS automatizado",
        "example": "dnsrecon -d alvo.com -t std",
    },
    "dnsx": {
        "summary": "Probe DNS em massa com resolvers",
        "example": "dnsx -l subdomains.txt -a -resp",
    },
    "massdns": {
        "summary": "Resolução DNS de alta performance",
        "example": "massdns -r resolvers.txt -t A subs.txt",
    },
    "fierce": {
        "summary": "Enumeração DNS e adjacentes",
        "example": "fierce --domain alvo.com",
    },
    "ping": {
        "summary": "Teste de conectividade ICMP",
        "example": "ping -c 4 alvo.com",
    },
    "traceroute": {
        "summary": "Rastreia rota de pacotes até o alvo",
        "example": "traceroute alvo.com",
    },
    "amass": {
        "summary": "Mapeamento profundo de subdomínios",
        "example": "amass enum -d alvo.com",
    },
    "subfinder": {
        "summary": "Descoberta passiva de subdomínios",
        "example": "subfinder -d alvo.com -silent",
    },
    "sublist3r": {
        "summary": "OSINT de subdomínios via motores públicos",
        "example": "sublist3r -d alvo.com",
    },
    "theHarvester": {
        "summary": "Coleta e-mails, hosts e subdomínios",
        "example": "theHarvester -d alvo.com -b google",
    },
    "httpx": {
        "summary": "Probe HTTP — status, título, tech",
        "example": "httpx -l urls.txt -title -status-code",
    },
    "gau": {
        "summary": "URLs históricas de certificados e arquivos",
        "example": "gau alvo.com",
    },
    "waybackurls": {
        "summary": "URLs arquivadas no Wayback Machine",
        "example": "waybackurls alvo.com",
    },
    "uncover": {
        "summary": "Busca hosts em bases Shodan/Censys",
        "example": "uncover -q alvo.com",
    },
    "shuffledns": {
        "summary": "Bruteforce de subdomínios com wordlist",
        "example": "shuffledns -d alvo.com -w subs.txt",
    },
    "nuclei": {
        "summary": "Scan de vulnerabilidades por templates",
        "example": "nuclei -u https://alvo.com -severity critical,high -jsonl",
    },
    "ffuf": {
        "summary": "Fuzzer web — diretórios, parâmetros, vhosts",
        "example": "ffuf -u https://alvo.com/FUZZ -w dirs.txt",
    },
    "feroxbuster": {
        "summary": "Fuzzer recursivo de diretórios web",
        "example": "feroxbuster -u https://alvo.com -w dirs.txt",
    },
    "gobuster": {
        "summary": "Bruteforce de dirs/DNS/vhosts",
        "example": "gobuster dir -u https://alvo.com -w dirs.txt",
    },
    "dirsearch": {
        "summary": "Scanner de paths e arquivos web",
        "example": "dirsearch -u https://alvo.com -e php,html",
    },
    "nikto": {
        "summary": "Scanner de vulnerabilidades web clássico",
        "example": "nikto -h https://alvo.com",
    },
    "sqlmap": {
        "summary": "Detecção e exploração de SQL injection",
        "example": "sqlmap -u 'https://alvo.com/page?id=1' --batch",
    },
    "katana": {
        "summary": "Crawler web rápido (ProjectDiscovery)",
        "example": "katana -u https://alvo.com -d 3",
    },
    "dalfox": {
        "summary": "Scanner de XSS parametrizado",
        "example": "dalfox url 'https://alvo.com/search?q=test'",
    },
    "whatweb": {
        "summary": "Fingerprint de tecnologias web",
        "example": "whatweb https://alvo.com",
    },
    "wafw00f": {
        "summary": "Detecta WAF/proxy na frente do site",
        "example": "wafw00f https://alvo.com",
    },
    "wpscan": {
        "summary": "Scan de segurança WordPress",
        "example": "wpscan --url https://alvo.com --no-update",
    },
    "arjun": {
        "summary": "Descobre parâmetros HTTP ocultos",
        "example": "arjun -u https://alvo.com/api",
    },
    "sslscan": {
        "summary": "Analisa ciphers e certificados TLS",
        "example": "sslscan alvo.com",
    },
    "testssl.sh": {
        "summary": "Auditoria completa SSL/TLS",
        "example": "testssl.sh alvo.com",
    },
    "tlsx": {
        "summary": "Probe TLS em massa",
        "example": "tlsx -u alvo.com -san -cn",
    },
    "openssl": {
        "summary": "Utilitário criptográfico e certificados",
        "example": "openssl s_client -connect alvo.com:443",
    },
    "hydra": {
        "summary": "Bruteforce de login em serviços",
        "example": "hydra -l admin -P pass.txt ssh://alvo.com",
    },
    "john": {
        "summary": "Crack de hashes offline",
        "example": "john --wordlist=pass.txt hashes.txt",
    },
    "hashcat": {
        "summary": "Crack de hashes GPU/CPU",
        "example": "hashcat -m 0 hashes.txt pass.txt",
    },
    "ncrack": {
        "summary": "Bruteforce de autenticação em rede",
        "example": "ncrack -U users.txt -P pass.txt ssh://alvo.com",
    },
    "medusa": {
        "summary": "Bruteforce paralelo de logins",
        "example": "medusa -h alvo.com -u admin -P pass.txt -M ssh",
    },
    "patator": {
        "summary": "Fuzzer/bruteforce multi-protocolo",
        "example": "patator http_fuzz url=https://alvo.com/login",
    },
    "nxc": {
        "summary": "Swiss-army knife Windows/SMB/AD",
        "example": "nxc smb 192.168.1.0/24",
    },
    "enum4linux": {
        "summary": "Enumeração SMB/LDAP Windows",
        "example": "enum4linux -a 192.168.1.10",
    },
    "smbmap": {
        "summary": "Lista shares e permissões SMB",
        "example": "smbmap -H 192.168.1.10",
    },
    "kerbrute": {
        "summary": "Bruteforce e enumeração Kerberos",
        "example": "kerbrute userenum -d corp.local users.txt",
    },
    "certipy": {
        "summary": "Abuso de certificados AD (ESC)",
        "example": "certipy find -u user@corp.local -p pass -dc-ip 10.0.0.1",
    },
    "responder": {
        "summary": "Captura hashes LLMNR/NBT-NS",
        "example": "responder -I eth0",
    },
    "impacket-secretsdump": {
        "summary": "Dump de secrets SAM/LSA/NTDS",
        "example": "impacket-secretsdump corp/user:pass@192.168.1.10",
    },
    "evil-winrm": {
        "summary": "Shell WinRM pós-exploração",
        "example": "evil-winrm -i 192.168.1.10 -u admin -p pass",
    },
    "wlan-scan": {
        "summary": "Lista redes Wi-Fi visíveis (Windows nativo)",
        "example": "wlan-scan",
    },
    "wlan-interfaces": {
        "summary": "Mostra adaptador Wi-Fi do host",
        "example": "wlan-interfaces",
    },
    "aircrack-ng": {
        "summary": "Suite Wi-Fi — crack WPA/WEP",
        "example": "aircrack-ng -w wordlist.txt capture.cap",
    },
    "airodump-ng": {
        "summary": "Captura pacotes e BSSIDs Wi-Fi",
        "example": "airodump-ng wlan0mon",
    },
    "wifite": {
        "summary": "Automação de ataques Wi-Fi",
        "example": "wifite --kill",
    },
    "searchsploit": {
        "summary": "Busca exploits no Exploit-DB",
        "example": "searchsploit apache 2.4",
    },
    "trivy": {
        "summary": "Scan de vulns em containers/imagens",
        "example": "trivy image nginx:latest",
    },
    "scout": {
        "summary": "Auditoria multi-cloud (ScoutSuite)",
        "example": "scout aws",
    },
    "tshark": {
        "summary": "Análise de tráfego de rede (CLI Wireshark)",
        "example": "tshark -r capture.pcap -Y http",
    },
    "tcpdump": {
        "summary": "Captura pacotes em interface",
        "example": "tcpdump -i eth0 port 443 -c 50",
    },
    "binwalk": {
        "summary": "Extrai firmware e arquivos embutidos",
        "example": "binwalk -e firmware.bin",
    },
    "foremost": {
        "summary": "Recuperação de arquivos por carving",
        "example": "foremost -i disk.img",
    },
    "vol": {
        "summary": "Análise de memória RAM (Volatility)",
        "example": "vol -f mem.raw windows.info",
    },
    "yara": {
        "summary": "Detecção por regras de malware",
        "example": "yara rules.yar suspicious.bin",
    },
    "radare2": {
        "summary": "Engenharia reversa e disassembly",
        "example": "r2 -A binary.exe",
    },
    "fls": {
        "summary": "Lista arquivos em imagem forense (Sleuth Kit)",
        "example": "fls -r disk.img",
    },
    "bulk_extractor": {
        "summary": "Extrai e-mails, URLs e dados de disco",
        "example": "bulk_extractor -o out/ disk.img",
    },
    "autorecon": {
        "summary": "Recon automatizado multi-estágio",
        "example": "autorecon alvo.com",
    },
    "curl": {
        "summary": "Requisições HTTP e download",
        "example": "curl -I https://alvo.com",
    },
    "wget": {
        "summary": "Download de arquivos via HTTP/FTP",
        "example": "wget -qO- https://alvo.com",
    },
    "nc": {
        "summary": "Netcat — conexão TCP/UDP raw",
        "example": "nc -zv alvo.com 80 443",
    },
    "snmpwalk": {
        "summary": "Enumeração SNMP de dispositivos",
        "example": "snmpwalk -v2c -c public alvo.com",
    },
    "socat": {
        "summary": "Relay bidirecional entre sockets",
        "example": "socat TCP-LISTEN:8080,fork TCP:alvo.com:80",
    },
    "mitm6": {
        "summary": "Ataque IPv6 DHCP/DNS em redes AD",
        "example": "mitm6 -d corp.local",
    },
}

_DEFAULT = {
    "summary": "Ferramenta de segurança disponível no Kali",
    "example": "{tool} --help",
}


def get_tool_info(tool_id: str) -> dict[str, str]:
    if tool_id in TOOL_CATALOG:
        return TOOL_CATALOG[tool_id]
    return {
        "summary": _DEFAULT["summary"],
        "example": _DEFAULT["example"].format(tool=tool_id),
    }


def enrich_categories(
    categories: list[dict], *, presence: dict[str, bool] | None = None
) -> list[dict]:
    enriched = []
    for cat in categories:
        tools = []
        for tool_id in cat.get("tools", []):
            meta = get_tool_info(tool_id)
            row = {
                "id": tool_id,
                "summary": meta["summary"],
                "example": meta["example"],
            }
            if presence is not None:
                row["available"] = bool(presence.get(str(tool_id).lower(), False))
            tools.append(row)
        enriched.append(
            {
                "id": cat["id"],
                "name": cat["name"],
                "tools": tools,
            }
        )
    return enriched
