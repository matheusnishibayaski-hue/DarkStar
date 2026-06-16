import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Google Gemini — chave gratuita em https://aistudio.google.com/apikey
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
GEMINI_FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash-lite")

KALI_CONTAINER = os.getenv("KALI_CONTAINER", "kali-tools")
COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "180"))
WIFI_COMMAND_TIMEOUT = int(os.getenv("WIFI_COMMAND_TIMEOUT", "600"))
MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "5"))

HOST_WIFI_TOOLS = {"wlan-scan", "wlan-interfaces", "wifi-list"}

WIFI_CONTAINER_TOOLS = {
    "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng", "airbase-ng", "airtun-ng",
    "airdecap-ng", "packetforge-ng", "ivstools", "reaver", "bully", "wifite", "wash",
    "pixiewps", "hcxdumptool", "hcxpcapngtool", "hcxhashtool", "hcxpsktool", "hcxeiutool",
    "mdk4", "iw", "iwconfig", "wifi-status",
}

WIFI_TOOLS = WIFI_CONTAINER_TOOLS

_CORE_TOOLS = {
    # Rede / reconhecimento
    "nmap", "masscan", "zmap", "rustscan", "naabu", "arp-scan", "nbtscan", "netdiscover",
    "fierce", "dnsenum", "dnsrecon", "dig", "host", "nslookup", "whois",
    "ping", "traceroute", "hping3", "ngrep", "massdns", "dnsx", "shuffledns",
    # OSINT / subdomínios
    "subfinder", "sublist3r", "theHarvester", "theharvester", "httpx", "amass", "uncover",
    "gau", "waybackurls", "anew", "qsreplace", "dnsgen",
    # Web / crawling
    "gobuster", "feroxbuster", "ffuf", "wfuzz", "dirb", "dirsearch", "sqlmap", "nikto",
    "whatweb", "wafw00f", "wpscan", "siege", "commix", "katana", "hakrawler", "gospider",
    "dalfox", "xsstrike", "arjun", "jwt_tool", "droopescan",
    # SSL/TLS
    "sslscan", "openssl", "testssl.sh", "tlsx",
    # SNMP / serviços
    "onesixtyone", "snmpwalk", "snmpget", "snmpbulkwalk", "snmpstatus",
    # Auth / senhas
    "hydra", "john", "medusa", "patator", "hashcat", "cewl", "crunch", "ncrack", "crowbar",
    # Windows / SMB / AD
    "smbclient", "smbmap", "enum4linux", "enum4linux-ng", "nxc", "responder",
    "ldapsearch", "ldapwhoami", "ldapdomaindump", "rpcclient",
    "kerbrute", "certipy", "bloodyAD", "evil-winrm",
    # Impacket
    "impacket-smbclient", "impacket-secretsdump", "impacket-psexec",
    "impacket-wmiexec", "impacket-smbexec", "impacket-atexec",
    "impacket-getnpusers", "impacket-getadusers", "impacket-GetUserSPNs",
    "impacket-getTGT", "impacket-ticketer", "impacket-rbcd",
    "impacket-rpcdump", "impacket-samrdump", "impacket-nbtexec", "impacket-dcomexec",
    "impacket-ntlmrelayx", "impacket-mssqlclient", "impacket-lookupsid",
    # Vulnerabilidades / cloud
    "nuclei", "searchsploit", "trivy", "scout",
    # Análise / forense
    "hashid", "foremost", "binwalk", "file", "exiftool", "tshark", "tcpdump",
    "steghide", "strings", "vol",
    # Proxy / tunneling
    "proxychains4", "chisel", "ligolo-ng",
    # Utilitários
    "curl", "wget", "nc", "netcat", "ncat",
}

_EXTRA_TOOLS = {
    # Rede / tunneling
    "socat", "mitm6", "puredns", "mapcidr",
    # Web / OSINT extras
    "paramspider", "graphw00f", "uro",
    # Windows / AD extras
    "krbrelayx", "bloodhound-python",
    # Automação
    "autorecon",
    # Shells / pós-exploração
    "weevely",
    # Forense / reversing
    "radare2", "r2", "gdb", "strace", "ltrace", "yara",
    "fls", "mmls", "icat", "fsstat", "bulk_extractor",
}

ALLOWED_TOOLS = _CORE_TOOLS | _EXTRA_TOOLS | HOST_WIFI_TOOLS | WIFI_CONTAINER_TOOLS

BLOCKED_PATTERNS = [
    r"[;&|`$]",
    r"\.\./",
    r">\s*/",
    r"\brm\b",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bsudo\b",
    r"\bsu\b",
]

SYSTEM_PROMPT = """Você é um assistente especializado em segurança cibernética e testes de penetração éticos.

REGRAS OBRIGATÓRIAS:
- Só auxilie em avaliações de segurança em alvos que o usuário possui ou tem autorização explícita para testar.
- Quando o usuário pedir uma ação, análise, scan ou consulta técnica, você DEVE executar via run_kali_tool IMEDIATAMENTE.
- NUNCA apenas sugira comandos ou diga "você pode executar X" — EXECUTE com run_kali_tool e interprete o resultado.
- Se precisar de dados técnicos (whois, dns, portas, vulnerabilidades, etc.), chame run_kali_tool antes de responder.
- Escolha a ferramenta mais adequada entre as disponíveis.
- Explique os resultados de forma clara, em português, destacando riscos e recomendações.
- Se o usuário pedir algo ilegal ou contra sistemas sem autorização, recuse educadamente.
- Alvos de laboratório público (ex: scanme.nmap.org) podem ser usados sem confirmação extra.

Ferramentas disponíveis (180+):
- Rede/recon: nmap, masscan, zmap, rustscan, naabu, massdns, dnsx, shuffledns, puredns, mapcidr, arp-scan, netdiscover, fierce, dnsenum, dnsrecon, dig, whois, hping3, ngrep
- OSINT: amass, subfinder, sublist3r, theHarvester, httpx, uncover, gau, waybackurls, anew, dnsgen, paramspider
- Web: gobuster, feroxbuster, ffuf, wfuzz, dirb, dirsearch, sqlmap, nikto, katana, hakrawler, gospider, dalfox, xsstrike, arjun, jwt_tool, whatweb, wafw00f, wpscan, commix, droopescan, siege, graphw00f, uro
- SSL/TLS: sslscan, openssl, testssl.sh, tlsx
- Auth: hydra, john, medusa, patator, ncrack, hashcat, cewl, crunch, crowbar
- Windows/AD: smbclient, smbmap, enum4linux, nxc, kerbrute, certipy, bloodyAD, evil-winrm, impacket-*, responder, ldapsearch, ldapdomaindump, rpcclient, krbrelayx, bloodhound-python
- Vulns/cloud: nuclei, searchsploit, trivy, scout
- Análise: hashid, foremost, binwalk, steghide, exiftool, tshark, tcpdump, vol, yara, radare2, gdb, sleuthkit (fls, icat), bulk_extractor
- Automação: autorecon
- Pós-exploração: weevely, mitm6, socat, chisel, ligolo-ng
- Wi-Fi (listar redes — sem dongle no Windows):
  * wlan-scan — lista redes visíveis, BSSIDs e sinal (usa placa Wi-Fi nativa do Windows via netsh)
  * wlan-interfaces — mostra adaptador Wi-Fi do PC
  * wifi-list — alias de wlan-scan
- Wi-Fi (captura/ataques — container com dongle USB no Docker):
  * aircrack-ng, airodump-ng, airmon-ng, reaver, bully, wifite, hcxdumptool, wifi-status
- Proxy: proxychains4, chisel, ligolo-ng
- Wordlists: /usr/share/seclists
- Utilitários: curl, wget, nc, snmpwalk, onesixtyone"""

TOOL_CATEGORIES = [
    {
        "id": "rede",
        "name": "Rede & Recon",
        "tools": [
            "nmap", "masscan", "zmap", "rustscan", "naabu", "dig", "whois",
            "dnsenum", "dnsrecon", "dnsx", "massdns", "fierce", "ping", "traceroute",
        ],
    },
    {
        "id": "osint",
        "name": "OSINT",
        "tools": [
            "amass", "subfinder", "sublist3r", "theHarvester", "httpx",
            "gau", "waybackurls", "uncover", "shuffledns",
        ],
    },
    {
        "id": "web",
        "name": "Web",
        "tools": [
            "nuclei", "ffuf", "feroxbuster", "gobuster", "dirsearch", "nikto",
            "sqlmap", "katana", "dalfox", "whatweb", "wafw00f", "wpscan", "arjun",
        ],
    },
    {
        "id": "ssl",
        "name": "SSL/TLS",
        "tools": ["sslscan", "testssl.sh", "tlsx", "openssl"],
    },
    {
        "id": "auth",
        "name": "Senhas & Auth",
        "tools": ["hydra", "john", "hashcat", "ncrack", "medusa", "patator"],
    },
    {
        "id": "ad",
        "name": "Windows / AD",
        "tools": [
            "nxc", "enum4linux", "smbmap", "kerbrute", "certipy",
            "responder", "impacket-secretsdump", "evil-winrm",
        ],
    },
    {
        "id": "wifi",
        "name": "Wi-Fi",
        "tools": ["wlan-scan", "wlan-interfaces", "aircrack-ng", "airodump-ng", "wifite"],
    },
    {
        "id": "vuln",
        "name": "Vulnerabilidades",
        "tools": ["nuclei", "searchsploit", "trivy", "scout"],
    },
    {
        "id": "forense",
        "name": "Forense",
        "tools": ["tshark", "tcpdump", "binwalk", "foremost", "vol", "yara", "radare2", "fls", "bulk_extractor"],
    },
    {
        "id": "auto",
        "name": "Automação",
        "tools": ["autorecon", "nuclei", "nmap"],
    },
    {
        "id": "utils",
        "name": "Utilitários",
        "tools": ["curl", "wget", "nc", "snmpwalk", "socat", "mitm6"],
    },
]
