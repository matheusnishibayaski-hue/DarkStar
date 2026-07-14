# Chat IA Kali

Assistente de chat com interface de terminal para **testes de penetração éticos**. O usuário descreve o que precisa em linguagem natural; a IA (Google Gemini) interpreta o pedido, escolhe a ferramenta adequada e **executa comandos reais** em um ambiente Kali Linux isolado via Docker — em vez de apenas sugerir comandos.

> **Aviso legal:** use este projeto **somente** em sistemas, redes ou aplicações que você possui ou para os quais tem **autorização explícita por escrito**. O uso não autorizado é ilegal.

---

## Sumário

- [Visão geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Fluxo de uma conversa](#fluxo-de-uma-conversa)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e execução](#instalação-e-execução)
- [Configuração (`.env`)](#configuração-env)
- [Interface web](#interface-web)
- [API REST](#api-rest)
- [Motor de execução e segurança](#motor-de-execução-e-segurança)
- [Ferramentas disponíveis](#ferramentas-disponíveis)
- [Wi-Fi: duas camadas de execução](#wi-fi-duas-camadas-de-execução)
- [Container Docker Kali](#container-docker-kali)
- [Agente de IA (Gemini)](#agente-de-ia-gemini)
- [Solução de problemas](#solução-de-problemas)
- [Desenvolvimento manual](#desenvolvimento-manual)

---

## Visão geral

O **Chat IA Kali** combina três peças:

| Camada | Tecnologia | Função |
|--------|------------|--------|
| **Frontend** | HTML, CSS, JavaScript vanilla | Interface estilo terminal com histórico de conversas e seletor de ferramentas |
| **Backend** | Python + FastAPI + Uvicorn | API REST, servir arquivos estáticos, orquestrar IA e execução |
| **Ambiente de ferramentas** | Docker (Debian + 180+ ferramentas de segurança) | Executar `nmap`, `nuclei`, `sqlmap`, `aircrack-ng` etc. de forma isolada |

A IA recebe um *system prompt* que a instrui a **sempre executar** ferramentas via function calling (`run_kali_tool`) quando o usuário pedir scans, análises ou consultas técnicas — nunca apenas recomendar comandos.

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│  Navegador (frontend/)                                          │
│  index.html · styles.css · app.js                               │
│  - Terminal interativo                                          │
│  - Histórico em localStorage                                    │
│  - Seletor de ferramenta (auto ou fixa)                         │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP (fetch)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Backend FastAPI (backend/main.py)                              │
│  GET  /              → index.html                               │
│  GET  /static/*      → CSS/JS                                   │
│  GET  /api/health    → status Docker + Wi-Fi                      │
│  GET  /api/tools     → categorias de ferramentas                │
│  POST /api/chat      → conversa com IA + execuções              │
└───────────────┬─────────────────────────┬───────────────────────┘
                │                         │
                ▼                         ▼
┌───────────────────────────┐  ┌────────────────────────────────┐
│  Agente Gemini            │  │  Executor (backend/executor/)  │
│  backend/ai/agent.py      │  │  kali.py · wifi_scan.py        │
│  - Function calling       │  │  - Validação whitelist         │
│  - Loop até 5 iterações   │  │  - docker exec kali-tools      │
│  - Fallback de modelo     │  │  - Wi-Fi nativo Windows (netsh)│
└───────────────────────────┘  └───────────────┬────────────────┘
                                               │
                                               ▼
                               ┌───────────────────────────────┐
                               │  Container Docker kali-tools  │
                               │  docker/Dockerfile            │
                               │  180+ ferramentas pré-instal. │
                               └───────────────────────────────┘
```

---

## Fluxo de uma conversa

1. **Usuário digita** uma mensagem no prompt do terminal (ex.: *"Faça um scan de portas em scanme.nmap.org"*).

2. **Frontend** (`app.js`) envia `POST /api/chat` com:
   - `message`: texto atual
   - `history`: mensagens anteriores (user/assistant)
   - `preferred_tool`: `"auto"` ou nome de uma ferramenta fixa (ex.: `"nmap"`)

3. **Backend** repassa para `chat()` em `backend/ai/agent.py`.

4. **Gemini** analisa o pedido com o `SYSTEM_PROMPT` (definido em `backend/config.py`). Se precisar de dados técnicos, chama a função `run_kali_tool(command, reason)`.

5. **Executor** (`backend/executor/kali.py`):
   - Valida o comando (whitelist + padrões bloqueados)
   - Se for ferramenta Wi-Fi do host (`wlan-scan`, `wlan-interfaces`, `wifi-list`) → executa no Windows via `netsh`
   - Caso contrário → `docker exec --user root kali-tools bash -c "<comando>"`

6. **Resultado** volta para a IA em texto formatado (`format_result_for_llm`); a IA pode executar mais ferramentas (até `MAX_TOOL_ITERATIONS`, padrão 5) ou gerar a resposta final em português.

7. **Resposta** inclui:
   - `message`: texto interpretado pela IA
   - `tool_executions`: lista com comando, stdout, stderr, exit code, sucesso/bloqueio

8. **Frontend** renderiza a resposta e blocos expansíveis `[ok]` / `[exit N]` / `[blocked]` para cada execução.

---

## Estrutura do projeto

```
Chat IA Kali/
├── backend/
│   ├── main.py              # FastAPI: rotas, health check, static files
│   ├── config.py              # .env, whitelist, system prompt, categorias
│   ├── ai/
│   │   └── agent.py           # Integração Gemini + function calling
│   └── executor/
│       ├── kali.py            # Validação e docker exec
│       ├── wifi_scan.py       # Scan Wi-Fi nativo (Windows/Linux host)
│       └── result.py          # ExecutionResult e formatação para LLM
├── frontend/
│   ├── index.html             # Shell do terminal
│   ├── styles.css             # Tema verde terminal (JetBrains Mono)
│   └── app.js                 # Chat, histórico, seletor de ferramentas
├── docker/
│   ├── Dockerfile             # Imagem com 180+ ferramentas
│   ├── docker-compose.yml     # Serviço kali-tools (privileged, host network)
│   ├── wifi-entrypoint.sh     # Desbloqueia rfkill e mantém container vivo
│   └── wifi-status.sh         # Diagnóstico de interfaces wireless
├── scripts/
│   └── docker-check.ps1       # Helper com timeout para comandos Docker no Windows
├── start.bat                  # Script principal de inicialização (Windows)
├── requirements.txt           # Dependências Python
├── .env.example               # Modelo de variáveis de ambiente
└── .env                       # Suas chaves (não versionar)
```

---

## Pré-requisitos

| Requisito | Versão / observação |
|-----------|---------------------|
| **Windows** | Ambiente principal (IIS em `inetpub`; script `start.bat` para Windows) |
| **Python** | 3.10 ou superior |
| **Docker Desktop** | Para ferramentas Kali (opcional no modo `start.bat servidor`) |
| **Chave Google Gemini** | Gratuita em [Google AI Studio](https://aistudio.google.com/apikey) |
| **Dongle USB Wi-Fi** | Apenas para ataques/captura no container (monitor mode) |

---

## Instalação e execução

### Modo completo (recomendado)

Duplo clique ou no terminal:

```bat
start.bat
```

O script executa **6 etapas**:

1. **Configuração Python** — cria `.env` a partir de `.env.example`, cria `venv`, instala `requirements.txt`
2. **Docker** — verifica se o engine responde; inicia Docker Desktop se necessário (até ~8 min de espera)
3. **Container Kali** — `docker compose up -d --build` em `docker/` (primeira build pode levar vários minutos)
4. **Aguarda container** — verifica se `kali-tools` está running
5. **Verifica ferramentas** — testa `which nmap` dentro do container
6. **Servidor web** — `uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload`

Acesse: **http://localhost:8000**

### Modos alternativos

| Comando | Descrição |
|---------|-----------|
| `start.bat servidor` | Sobe só o chat, sem Docker. Wi-Fi nativo (`wlan-scan`) funciona; ferramentas Kali não |
| `start.bat nodocker` | Alias de `servidor` |
| `start.bat repair` | Reinicia Docker Desktop e limpa cache (`builder prune`, `system prune`) |

---

## Configuração (`.env`)

Copie `.env.example` para `.env` (o `start.bat` faz isso automaticamente):

```env
# Google Gemini — chave gratuita em https://aistudio.google.com/apikey
GEMINI_API_KEY=sua_chave_aqui

# flash-lite tem mais cota no plano gratuito
GEMINI_MODEL=gemini-2.5-flash-lite
GEMINI_FALLBACK_MODEL=gemini-2.5-flash-lite

# Container Docker
KALI_CONTAINER=kali-tools

# Timeout de comandos normais (segundos)
COMMAND_TIMEOUT=180

# Timeout de ferramentas Wi-Fi no container (segundos)
WIFI_COMMAND_TIMEOUT=600

# Máximo de chamadas run_kali_tool por mensagem do usuário
MAX_TOOL_ITERATIONS=5
```

**Importante:** cada mensagem no chat pode gerar **2–6 chamadas** à API Gemini (ferramentas + resposta). Se a cota esgotar (erro 429), aguarde alguns minutos ou use `gemini-2.5-flash-lite`.

---

## Interface web

A UI imita um terminal Linux com tema verde fosforescente.

### Barra superior

| Botão | Função |
|-------|--------|
| **tool:auto** | Abre painel para escolher ferramenta fixa ou deixar em `auto` |
| **hist** | Histórico de conversas (persistido no `localStorage` do navegador) |
| **+** | Nova conversa |

### Prompt

```
kali@ai:~$ <sua mensagem>
```

- Mensagens do usuário aparecem como linhas de comando
- Respostas da IA começam com `# `
- Execuções de ferramentas aparecem como blocos clicáveis: `[ok]`, `[exit 1]`, `[blocked]`

### Persistência

Chave no navegador: `chat-ia-kali-sessions`

Cada sessão guarda: `id`, `title`, `messages`, `preferredTool`, timestamps.

---

## API REST

### `GET /api/health`

Verifica saúde do sistema.

**Resposta exemplo:**

```json
{
  "status": "ok",
  "docker": true,
  "kali_container": true,
  "kali_error": "",
  "wifi_ready": true,
  "wifi_interfaces": ["Wi-Fi"],
  "wifi_message": "Placa nativa: Wi-Fi · 12 rede(s) visível(is)"
}
```

- No **Windows**, Wi-Fi usa `netsh wlan show interfaces`
- Com container ativo no **Linux**, lista interfaces via `iw dev` dentro do Docker

### `GET /api/tools`

Retorna categorias e ferramentas para o seletor da UI (definidas em `TOOL_CATEGORIES` em `config.py`).

### `POST /api/chat`

**Corpo:**

```json
{
  "message": "scan de portas em scanme.nmap.org",
  "history": [
    { "role": "user", "content": "..." },
    { "role": "assistant", "content": "..." }
  ],
  "preferred_tool": "auto"
}
```

**Resposta:**

```json
{
  "message": "Interpretação dos resultados em português...",
  "tool_executions": [
    {
      "command": "nmap -sV scanme.nmap.org",
      "reason": "Identificar serviços e versões nas portas abertas",
      "stdout": "...",
      "stderr": "",
      "exit_code": 0,
      "success": true,
      "blocked": false
    }
  ]
}
```

---

## Motor de execução e segurança

Toda execução passa por `validate_command()` em `backend/executor/kali.py`.

### Whitelist de ferramentas

Apenas binários listados em `ALLOWED_TOOLS` (`config.py`) são permitidos — mais de **180 ferramentas**, incluindo:

- Rede/recon: `nmap`, `masscan`, `dig`, `whois`, `rustscan`, …
- OSINT: `subfinder`, `amass`, `theHarvester`, `httpx`, …
- Web: `nuclei`, `ffuf`, `sqlmap`, `nikto`, …
- AD/Windows: `nxc`, `impacket-*`, `kerbrute`, `responder`, …
- Wi-Fi host: `wlan-scan`, `wlan-interfaces`, `wifi-list`
- Wi-Fi container: `aircrack-ng`, `airodump-ng`, `wifite`, …

### Padrões bloqueados

Comandos que correspondem a estes padrões são **rejeitados** (`blocked: true`):

- Shell injection: `;`, `&`, `|`, `` ` ``, `$`
- Path traversal: `../`
- Redirecionamento perigoso: `> /`
- Comandos destrutivos/admin: `rm`, `mkfs`, `dd`, `shutdown`, `reboot`, `chmod`, `chown`, `sudo`, `su`

### Limites

| Limite | Valor padrão |
|--------|--------------|
| Tamanho máximo do comando | 500 caracteres |
| Timeout comandos normais | 180 s |
| Timeout ferramentas Wi-Fi | 600 s |
| Tamanho máximo stdout capturado | 50 000 caracteres |
| Tamanho máximo stderr capturado | 10 000 caracteres |

### Isolamento Docker

Comandos Kali rodam como:

```bash
docker exec --user root kali-tools bash -c "<comando>"
```

O container é **privileged**, com `network_mode: host`, capacidades `NET_ADMIN`/`NET_RAW`/`SYS_ADMIN` e acesso USB — necessário para monitor mode e dongles Wi-Fi.

---

## Ferramentas disponíveis

As categorias exibidas na UI (`TOOL_CATEGORIES`):

| Categoria | Exemplos |
|-----------|----------|
| Rede & Recon | nmap, masscan, dig, whois, dnsenum |
| OSINT | amass, subfinder, theHarvester, httpx |
| Web | nuclei, ffuf, sqlmap, nikto, wpscan |
| SSL/TLS | sslscan, testssl.sh, tlsx |
| Senhas & Auth | hydra, john, hashcat, ncrack |
| Windows / AD | nxc, enum4linux, kerbrute, impacket-secretsdump |
| Wi-Fi | wlan-scan, aircrack-ng, airodump-ng, wifite |
| Vulnerabilidades | nuclei, searchsploit, trivy |
| Forense | tshark, binwalk, vol, radare2 |
| Automação | autorecon |
| Utilitários | curl, wget, nc, snmpwalk |

Wordlists: `/usr/share/seclists` (SecLists) dentro do container.

---

## Wi-Fi: duas camadas de execução

### 1. Host Windows (sem dongle no Docker)

Ferramentas: `wlan-scan`, `wlan-interfaces`, `wifi-list`

Executadas via **`netsh wlan`** no próprio Windows:

- Adaptador Wi-Fi ativo
- Redes visíveis (SSID, BSSID, sinal)
- Perfis salvos no PC

Funcionam mesmo com `start.bat servidor` (sem Docker).

### 2. Container Docker (captura / monitor mode)

Ferramentas: `aircrack-ng`, `airodump-ng`, `airmon-ng`, `reaver`, `wifite`, `hcxdumptool`, `wifi-status`, etc.

Requisitos:

- Docker com container `kali-tools` rodando
- Dongle USB Wi-Fi compatível com monitor mode
- USB repassado ao container (`/dev/bus/usb`)
- Entrypoint desbloqueia rfkill (`wifi-entrypoint.sh`)

Diagnóstico dentro do container:

```bash
docker exec kali-tools wifi-status
```

---

## Container Docker Kali

### Build e execução manual

```bash
cd docker
docker compose up -d --build
```

### Imagem (`docker/Dockerfile`)

Base: **Debian Bookworm slim**, com instalação em camadas:

1. **APT** — nmap, masscan, sqlmap, hydra, john, aircrack-ng, tshark, etc.
2. **Binários** — ffuf, feroxbuster, nuclei, subfinder, httpx, rustscan, kerbrute, chisel, trivy, …
3. **Git** — nikto, testssl.sh, searchsploit, dirsearch, wifite, autorecon, SecLists, …
4. **Python/Ruby pip** — impacket, nxc, certipy-ad, wpscan, evil-winrm, volatility3, …

O container **não executa um shell interativo** — fica vivo com `sleep infinity` após desbloquear rádios Wi-Fi.

### Compose (`docker/docker-compose.yml`)

```yaml
services:
  kali-tools:
    build: .
    container_name: kali-tools
    privileged: true
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW, SYS_ADMIN]
    devices:
      - /dev/bus/usb:/dev/bus/usb
```

---

## Agente de IA (Gemini)

Arquivo: `backend/ai/agent.py`

### Comportamento

- Usa **Google GenAI SDK** (`google-genai`) com function calling validado
- `automatic_function_calling` está **desabilitado** — o loop é manual para registrar cada execução
- Se a IA responder sem executar ferramenta na primeira tentativa, um **nudge** força: *"Execute o comando AGORA com run_kali_tool"*
- **Ferramenta preferida:** se o usuário selecionar ex.: `nmap`, a mensagem é prefixada com instrução para usar essa ferramenta obrigatoriamente

### Tratamento de erros

| Erro | Mensagem ao usuário |
|------|---------------------|
| API key inválida | Link para gerar nova chave |
| Cota esgotada (429) | Sugestão de `flash-lite`, aguardar, reduzir uso |
| Sem `GEMINI_API_KEY` | Instrução para configurar `.env` |

### Fallback de modelo

Se o modelo principal retornar 429, tenta `GEMINI_FALLBACK_MODEL` após 2 segundos.

---

## Solução de problemas

### Docker não responde

- Abra o **Docker Desktop** e aguarde o ícone estabilizar
- Rode `start.bat repair`
- Ou suba só o chat: `start.bat servidor`

### Erro "input/output error" ou blob corrompido

1. Feche o Docker Desktop (Quit na bandeja)
2. Reabra e aguarde
3. **Settings → Troubleshoot → Clean/Purge data**
4. Verifique espaço em disco em `C:`
5. Execute `start.bat repair` e depois `start.bat`

### Container `kali-tools` não está rodando

```bat
cd docker
docker compose up -d --build
```

Ou use o health check: `GET http://localhost:8000/api/health`

### Chave Gemini inválida ou cota esgotada

- Gere chave em https://aistudio.google.com/apikey
- Use `GEMINI_MODEL=gemini-2.5-flash-lite` no `.env`
- Aguarde alguns minutos entre sessões intensas

### Comando bloqueado (`[blocked]`)

A ferramenta não está na whitelist ou o comando contém padrão proibido. Verifique `ALLOWED_TOOLS` e `BLOCKED_PATTERNS` em `backend/config.py`.

### Wi-Fi no container sem interface

- Confirme dongle USB conectado
- `docker exec kali-tools wifi-status`
- Container precisa estar `privileged` com USB mapeado

### Build Docker muito lenta

Normal na primeira execução (download de dezenas de ferramentas). Builds subsequentes usam cache.

---

## Desenvolvimento manual

Sem `start.bat`:

```bash
# Ambiente virtual
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt

# Configuração
copy .env.example .env
# Edite GEMINI_API_KEY

# Container (opcional)
cd docker && docker compose up -d --build

# Servidor
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Dependências Python

| Pacote | Uso |
|--------|-----|
| `fastapi` | Framework web |
| `uvicorn` | Servidor ASGI |
| `google-genai` | Cliente Gemini |
| `python-dotenv` | Carregar `.env` |
| `pydantic` | Validação de request/response |

---

## Exemplos de uso

| Pedido no chat | O que acontece |
|----------------|----------------|
| *"Liste redes Wi-Fi ao redor"* | Executa `wlan-scan` via `netsh` no Windows |
| *"Scan SYN nas top 1000 portas de scanme.nmap.org"* | `nmap` dentro do container Kali |
| *"Busque subdomínios de example.com"* | `subfinder` ou `amass` |
| *"Teste vulnerabilidades web em https://alvo.com"* | `nuclei` ou combinação recon + scan |
| Selecionar **tool:nmap** + *"scanme.nmap.org"* | Força uso do nmap independente da escolha da IA |

---

## Licença e responsabilidade

Este software é fornecido para **fins educacionais e testes autorizados**. Os autores não se responsabilizam pelo uso indevido. Respeite leis locais (LGPD, Marco Civil, CFAA equivalentes) e obtenha autorização antes de testar qualquer sistema de terceiros.
