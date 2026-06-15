KALI_TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_kali_tool",
        "description": (
            "Executa uma ferramenta de segurança no ambiente isolado via Docker. "
            "150+ ferramentas: nmap, masscan, amass, nuclei, ffuf, feroxbuster, "
            "katana, dalfox, dirsearch, sqlmap, hydra, nxc, kerbrute, certipy, "
            "impacket-*, enum4linux, wpscan, subfinder, gau, trivy, chisel, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Comando completo a executar (ex: nmap -sV 192.168.1.1)",
                },
                "reason": {
                    "type": "string",
                    "description": "Breve explicação do porquê este comando é necessário",
                },
            },
            "required": ["command", "reason"],
        },
    },
}
