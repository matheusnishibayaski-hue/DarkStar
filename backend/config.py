import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# OpenRouter — chave em https://openrouter.ai/keys
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Aliases novos (preferidos) com retrocompatibilidade GEMINI_*
PRIMARY_MODEL = (
    os.getenv("OPENROUTER_PRIMARY_MODEL")
    or os.getenv("GEMINI_MODEL")
    or "google/gemini-2.5-flash"
)
FALLBACK_MODEL = (
    os.getenv("OPENROUTER_FALLBACK_MODEL")
    or os.getenv("GEMINI_FALLBACK_MODEL")
    or "deepseek/deepseek-chat-v3.2"
)
GEMINI_MODEL = PRIMARY_MODEL
GEMINI_FALLBACK_MODEL = FALLBACK_MODEL

# Servidor / segurança local
UVICORN_HOST = os.getenv("UVICORN_HOST", "127.0.0.1")
UVICORN_PORT = int(os.getenv("UVICORN_PORT", "8000"))
CHAT_API_TOKEN = os.getenv("CHAT_API_TOKEN", "").strip()
_cors_raw = os.getenv(
    "CORS_ORIGINS",
    "http://127.0.0.1:8000,http://localhost:8000",
)
CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]

KALI_CONTAINER = os.getenv("KALI_CONTAINER", "kali-tools")
COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "180"))
WIFI_COMMAND_TIMEOUT = int(os.getenv("WIFI_COMMAND_TIMEOUT", "600"))
MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "5"))
MAX_HEALING_ATTEMPTS = int(os.getenv("MAX_HEALING_ATTEMPTS", "2"))
MAX_HISTORY_MESSAGES = int(os.getenv("MAX_HISTORY_MESSAGES", "10"))
MAX_AUTONOMOUS_ROUNDS = int(os.getenv("MAX_AUTONOMOUS_ROUNDS", "10"))
MAX_AUTONOMOUS_TOOLS = int(os.getenv("MAX_AUTONOMOUS_TOOLS", "25"))
OUTPUT_TOKEN_LIMIT = int(os.getenv("OUTPUT_TOKEN_LIMIT", "3000"))
SUMMARY_HEAD_LINES = int(os.getenv("SUMMARY_HEAD_LINES", "30"))
SUMMARY_TAIL_LINES = int(os.getenv("SUMMARY_TAIL_LINES", "15"))
LOG_DIR = BASE_DIR / "backend" / "logs"
RECON_DIR = BASE_DIR / "backend" / "recon"
RECON_TTL_DAYS = int(os.getenv("RECON_TTL_DAYS", "30"))

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

SYSTEM_PROMPT = """Assistente de pentest ético. Só teste alvos autorizados.

REGRAS:
- Execute via run_kali_tool — nunca só sugira comandos.
- Escolha a ferramenta adequada; interprete resultados em português.
- Comandos sem ; | & ou redirecionamentos. Wordlists: /usr/share/seclists
- Laboratórios públicos (scanme.nmap.org) ok sem confirmação extra."""

AUTONOMOUS_SYSTEM_PROMPT = """Você é um agente autônomo de pentest em MODO AUTO-PILOT.

ALVO AUTORIZADO: {target}
OBJETIVO DA MISSÃO: {objective}

REGRAS DO MODO AUTÔNOMO:
- Você controla o fluxo completo: recon → enumeração → análise → verificação do objetivo.
- NÃO peça confirmação ao usuário. Tome decisões técnicas e execute via run_kali_tool.
- Após cada execução, analise o output e decida o próximo passo lógico em direção ao objetivo.
- Use ferramentas adequadas: subfinder/amass para subdomínios, httpx para probing, nuclei para vulns, nmap para portas, etc.
- Quando o objetivo for atingido OU não houver passos úteis restantes, chame finish_mission com um resumo completo.
- Responda em português nos resumos e conclusões.
- Só opere em alvos que o usuário possui ou tem autorização explícita.

Ferramentas disponíveis (180+): nmap, subfinder, amass, httpx, nuclei, ffuf, gobuster, sqlmap, dig, whois, masscan, feroxbuster, katana, wafw00f, sslscan, e demais da whitelist Kali.

Wordlists: /usr/share/seclists"""

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
