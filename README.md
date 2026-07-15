# Chat IA Kali

Assistente de chat com interface de terminal para **testes de penetração éticos**. O usuário descreve o que precisa em linguagem natural; a IA interpreta o pedido, escolhe a ferramenta adequada e **executa comandos reais** em um ambiente Kali Linux isolado via Docker — em vez de apenas sugerir comandos.

A IA é alimentada via **OpenRouter** (modelos Gemini e DeepSeek), com seletor de custo/qualidade na interface, modo **Auto-Pilot** para missões autônomas, dashboards visuais de resultados, relatórios Markdown e execução vectorizada sem shell.

> **Aviso legal:** use este projeto **somente** em sistemas, redes ou aplicações que você possui ou para os quais tem **autorização explícita por escrito**. O uso não autorizado é ilegal.

---

## Sumário

- [Visão geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Fluxo de uma conversa](#fluxo-de-uma-conversa)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e execução](#instalação-e-execução)
- [Configuração (`.env`)](#configuração-env)
- [Interface web](#interface-web)
- [Seletor de modelos (Gemini / DeepSeek)](#seletor-de-modelos-gemini--deepseek)
- [Modo Auto-Pilot](#modo-auto-pilot)
- [API REST](#api-rest)
- [Motor de execução e segurança](#motor-de-execução-e-segurança)
- [Logs, resumo de output e relatórios](#logs-resumo-de-output-e-relatórios)
- [Ferramentas disponíveis](#ferramentas-disponíveis)
- [Wi-Fi: duas camadas de execução](#wi-fi-duas-camadas-de-execução)
- [Container Docker Kali](#container-docker-kali)
- [Agente de IA (OpenRouter)](#agente-de-ia-openrouter)
- [Solução de problemas](#solução-de-problemas)
- [Desenvolvimento manual](#desenvolvimento-manual)
- [Testes](#testes)
- [Exemplos de uso](#exemplos-de-uso)
- [Changelog](#changelog)
- [Licença e responsabilidade](#licença-e-responsabilidade)

---

## Visão geral

O **Chat IA Kali** combina quatro camadas:

| Camada | Tecnologia | Função |
|--------|------------|--------|
| **Frontend** | HTML, CSS, JavaScript vanilla | Terminal interativo, sidebar, seletor de ferramentas/modelos, dashboards |
| **Backend** | Python + FastAPI + Uvicorn | API REST, orquestração IA + execução + relatórios |
| **IA** | OpenRouter (SDK OpenAI) | Gemini / DeepSeek com function calling |
| **Ferramentas** | Docker (180+ tools de segurança) | `nmap`, `nuclei`, `sqlmap`, `aircrack-ng` etc. |

A IA recebe um *system prompt* compacto que a instrui a **sempre executar** ferramentas via function calling (`run_kali_tool`) quando o usuário pedir scans, análises ou consultas técnicas — nunca apenas recomendar comandos.

---

## Funcionalidades

### Chat interativo
- Interface estilo terminal Linux (tema verde fosforescente, scanlines, JetBrains Mono)
- Histórico de conversas na sidebar (persistido em `localStorage`)
- Seletor de ferramenta fixa ou modo `auto`
- Histórico de comandos no prompt (↑ / ↓)
- Barra de status inferior (Docker, Kali, ferramenta, modelo, mensagens)
- Toasts de feedback e botão scroll ↓

### Execução real de ferramentas
- 180+ ferramentas na whitelist
- Execução **vectorizada** no Docker (sem `bash -c`)
- Wi-Fi nativo no Windows (`netsh`) ou no container (monitor mode)
- Flags não-interativas automáticas (`--batch`, `-y`, etc.)
- Logs completos em disco; resumo inteligente enviado à IA

### Visualização de resultados
- **Dashboard Nmap:** tabela Porta / Estado / Serviço / Versão
- **Dashboard Nuclei/vulns:** cards coloridos por severidade
- Log bruto oculto por padrão quando há dashboard; botão **Ver Log Completo**
- Link para log persistido (`/api/logs/{id}`)

### Relatórios e Auto-Pilot
- Botão **report** gera relatório Markdown da sessão
- **Auto-Pilot:** informe alvo + objetivo; o agente executa múltiplas ferramentas em loop e entrega relatório final

### Economia de tokens
- System prompt enxuto
- Histórico limitado (`MAX_HISTORY_MESSAGES`)
- Output truncado/resumido antes de ir à IA (`summarize.py`)
- Catálogo de ferramentas só na UI (`tool_catalog.py`) — não infla o prompt

### Seletor de modelos
- Três tiers: **Economia**, **Equilibrado**, **Raciocínio**
- Alternância **Gemini ↔ DeepSeek** por tier
- Fallback automático em erro de cota

---

## Arquitetura

```
┌──────────────────────────────────────────────────────────────────────┐
│  Navegador (frontend/)                                               │
│  index.html · styles.css · js/main.js (+ módulos ES)               │
│  - Terminal + sidebar + painéis                                      │
│  - Seletor de ferramenta e modelo                                    │
│  - Dashboards nmap/nuclei · relatório · Auto-Pilot                   │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ HTTP (fetch)
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Backend FastAPI (backend/main.py)                                   │
│  GET  /              → index.html                                    │
│  GET  /static/*      → CSS/JS                                        │
│  GET  /api/health    → status Docker + Wi-Fi                         │
│  GET  /api/tools     → categorias + metadados UI                     │
│  GET  /api/models    → catálogo Gemini/DeepSeek                      │
│  GET  /api/logs/{id} → log completo da execução                      │
│  POST /api/chat      → conversa com IA + execuções                   │
│  POST /api/autonomous→ modo Auto-Pilot                               │
│  POST /api/generate-report → relatório Markdown                      │
└──────────────┬─────────────────────────────┬─────────────────────────┘
               │                             │
               ▼                             ▼
┌────────────────────────────┐   ┌─────────────────────────────────────┐
│  Agente IA (OpenRouter)    │   │  Executor (backend/executor/)       │
│  backend/ai/agent.py       │   │  kali.py · wifi_scan.py             │
│  backend/ai/autopilot.py   │   │  summarize.py · logs.py · result.py │
│  - Function calling        │   │  - Whitelist + execução vectorizada │
│  - Fallback de modelo      │   │  - Resumo de output para IA         │
└────────────────────────────┘   └──────────────────┬──────────────────┘
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

1. **Usuário digita** uma mensagem (ex.: *"Faça um scan de portas em scanme.nmap.org"*).

2. **Frontend** envia `POST /api/chat` com:
   - `message`, `history`, `preferred_tool`
   - `model` e `fallback_model` (do seletor pill)

3. **Backend** repassa para `chat()` em `backend/ai/agent.py`.

4. **IA** analisa com o `SYSTEM_PROMPT`. Se precisar de dados técnicos, chama `run_kali_tool(command, reason)`.

5. **Executor** (`backend/executor/kali.py`):
   - Faz parse com `shlex` → lista de argumentos
   - Valida binário na whitelist + bloqueio de `..` nos args
   - Wi-Fi host (`wlan-scan`, etc.) → `netsh` no Windows
   - Demais → `docker exec kali-tools <bin> <arg1> <arg2> ...` (sem shell)

6. **Output** é salvo em `backend/logs/{uuid}.log`; um **resumo** vai para a IA; stdout/stderr **completos** vão ao frontend.

7. A IA pode executar mais ferramentas (até `MAX_TOOL_ITERATIONS`, padrão 5) ou responder em português.

8. **Frontend** renderiza resposta, dashboards e blocos `[ok]` / `[exit N]` / `[blocked]`.

---

## Estrutura do projeto

```
Chat IA Kali/
├── backend/
│   ├── main.py                 # Entry FastAPI (~60 linhas): monta app + routers
│   ├── config.py               # .env, whitelist, system prompts
│   ├── schemas.py              # Modelos Pydantic (requests/responses)
│   ├── deps.py                 # Auth helpers, versão APP_VERSION
│   ├── middleware.py           # Rate limit + guard de API token
│   ├── routes/                 # auth, system, chat, autonomous
│   ├── security/               # Sessões, rate limit, registro de missões
│   ├── models_catalog.py       # Tiers Gemini/DeepSeek para UI
│   ├── tool_catalog.py         # Resumo + exemplo por ferramenta (só UI)
│   ├── ai/
│   │   ├── agent.py            # Chat OpenRouter + function calling + relatório
│   │   └── autopilot.py        # Modo Auto-Pilot autônomo
│   ├── executor/
│   │   ├── kali.py             # Validação, execução vectorizada, flags
│   │   ├── wifi_scan.py        # Scan Wi-Fi nativo (Windows/Linux host)
│   │   ├── result.py           # ExecutionResult e formatação para LLM
│   │   ├── summarize.py        # Truncamento/resumo de output longo
│   │   └── logs.py             # Persistência de logs em disco
│   ├── data/                   # Sessões persistidas (gitignored)
│   └── logs/                   # Logs de execução (gitignored)
├── frontend/
│   ├── index.html              # Shell do terminal + painéis
│   ├── styles.css              # Tema terminal, dashboards, scrollbars
│   ├── js/
│   │   ├── main.js             # Entry point — wiring dos módulos
│   │   ├── chat.js             # Envio de mensagens + relatório + cancel
│   │   ├── autopilot.js        # Modo Auto-Pilot
│   │   ├── mission.js          # Cancel compartilhado (chat + pilot)
│   │   ├── chat-view.js        # Renderização do terminal
│   │   ├── ui.js               # Toasts, sidebar, overlays, health
│   │   ├── sessions.js         # Store localStorage + sidebar de conversas
│   │   ├── tools-panel.js      # Seletor de ferramentas + modelos IA
│   │   ├── auth.js             # Login por sessão + cancelamento
│   │   ├── api.js              # fetch + SSE + token
│   │   ├── exec.js             # Blocos de execução + dashboards nmap/nuclei
│   │   ├── stream.js           # Logs ao vivo [live]
│   │   └── constants.js        # Chaves localStorage, prompts, ajuda
├── docker/
│   ├── Dockerfile              # Imagem com 180+ ferramentas
│   ├── docker-compose.yml      # Serviço kali-tools (privileged, host network)
│   ├── wifi-entrypoint.sh      # Desbloqueia rfkill e mantém container vivo
│   └── wifi-status.sh          # Diagnóstico de interfaces wireless
├── scripts/
│   └── docker-check.ps1        # Helper com timeout para Docker no Windows
├── start.bat                   # Script principal de inicialização (Windows)
├── start.sh                    # Inicialização Linux/macOS
├── requirements.txt            # Dependências Python
├── .env.example                # Modelo de variáveis de ambiente
└── .env                        # Suas chaves (não versionar)
```

---

## Pré-requisitos

| Requisito | Versão / observação |
|-----------|---------------------|
| **Windows** | Ambiente principal (`start.bat`); Linux/macOS via `./start.sh` |
| **Python** | 3.10 ou superior |
| **Docker Desktop** | Para ferramentas Kali (opcional com `start.bat servidor`) |
| **Chave OpenRouter** | Em [openrouter.ai/keys](https://openrouter.ai/keys) |
| **Dongle USB Wi-Fi** | Apenas para captura/monitor mode no container |

---

## Instalação e execução

### Modo completo (recomendado)

**Windows:**

```bat
start.bat
```

**Linux / macOS:**

```bash
chmod +x start.sh
./start.sh
```

O script executa **6 etapas**:

1. **Configuração Python** — cria `.env` a partir de `.env.example`, cria `venv`, instala `requirements.txt`
2. **Docker** — verifica engine; inicia Docker Desktop se necessário (até ~8 min)
3. **Container Kali** — `docker compose up -d --build` em `docker/`
4. **Aguarda container** — verifica se `kali-tools` está running
5. **Verifica ferramentas** — testa `which nmap` dentro do container
6. **Servidor web** — `uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload` (host lido do `.env`)

Acesse: **http://127.0.0.1:8000** (ou `http://localhost:8000`)

### Modos alternativos

| Comando | Descrição |
|---------|-----------|
| `start.bat servidor` | Sobe só o chat, sem Docker. Wi-Fi nativo funciona; ferramentas Kali não |
| `start.bat nodocker` | Alias de `servidor` |
| `start.bat repair` | Reinicia Docker Desktop e limpa cache |
| `./start.sh servidor` | Linux/macOS — só o chat, sem Docker |
| `./start.sh repair` | Linux/macOS — limpa cache Docker (builder/system prune) |

---

## Configuração (`.env`)

Copie `.env.example` para `.env` (o `start.bat` faz isso automaticamente):

```env
# OpenRouter — chave em https://openrouter.ai/keys
OPENROUTER_API_KEY=sk-or-v1-...

# Modelo principal e fallback (IDs OpenRouter)
GEMINI_MODEL=google/gemini-2.5-flash
GEMINI_FALLBACK_MODEL=deepseek/deepseek-chat-v3.2

# Container Docker
KALI_CONTAINER=kali-tools
COMMAND_TIMEOUT=180
WIFI_COMMAND_TIMEOUT=600

# Limites de IA e execução
MAX_TOOL_ITERATIONS=5
MAX_HISTORY_MESSAGES=10
MAX_AUTONOMOUS_ROUNDS=10
MAX_AUTONOMOUS_TOOLS=25

# Economia de tokens no output das ferramentas
OUTPUT_TOKEN_LIMIT=3000
SUMMARY_HEAD_LINES=30
SUMMARY_TAIL_LINES=15
```

**Dica de custo:** use tier **Economia** (Flash-Lite ou DeepSeek V3.2) no seletor da UI para scans simples; reserve **Raciocínio** (Pro / R1) para análises complexas.

Logs persistidos em `backend/logs/` (não versionados).

---

## Interface web

### Layout

| Área | Descrição |
|------|-----------|
| **Sidebar** | Conversas salvas, botão novo chat, link de atalhos |
| **Barra superior** | Título da sessão + botões de ação |
| **Terminal** | Histórico de mensagens e execuções |
| **Prompt** | Entrada de comando + seletor de modelo (pill) |
| **Barra de status** | Docker, Kali, ferramenta, modelo, contadores |

### Barra superior

| Botão | Atalho | Função |
|-------|--------|--------|
| **tools:auto** | `Ctrl+T` | Painel grande de ferramentas (grid 3 colunas) |
| **pilot** | `Ctrl+P` | Modo Auto-Pilot |
| **report** | `Ctrl+R` | Gera e baixa relatório Markdown |
| **?** | `Ctrl+/` | Ajuda com atalhos |
| **+** | `Ctrl+N` | Nova conversa |

### Painel de ferramentas

- Modal amplo (~94% da largura, até 1280px)
- Abas por categoria (Rede, OSINT, Web, Wi-Fi, etc.)
- Busca por nome, categoria ou descrição
- Cards com resumo, exemplo de comando e botão **usar** (preenche o prompt)
- Card **auto** em destaque — IA escolhe a ferramenta

### Prompt

```
kali@ai:~$ <sua mensagem>                    [Flash ▾]
```

- Mensagens do usuário aparecem como linhas de comando
- Respostas da IA começam com `# `
- Execuções: blocos clicáveis `[ok]`, `[exit 1]`, `[blocked]`
- Dashboards automáticos para nmap e nuclei

### Atalhos de teclado

| Atalho | Ação |
|--------|------|
| `M` | Abrir/fechar sidebar |
| `Esc` | Fechar painéis |
| `Ctrl+K` | Focar no prompt |
| `↑` / `↓` | Histórico de comandos da sessão |
| `Ctrl+T` | Ferramentas |
| `Ctrl+P` | Auto-Pilot |
| `Ctrl+R` | Relatório |
| `Ctrl+N` | Novo chat |
| `Ctrl+/` | Ajuda |

### Persistência

| Chave localStorage | Conteúdo |
|--------------------|----------|
| `chat-ia-kali-sessions` | Conversas (id, title, messages, preferredTool) |
| `chat-ia-kali-model` | Modelo selecionado (id, provider, fallback) |

---

## Seletor de modelos (Gemini / DeepSeek)

Botão pill ao lado do prompt abre menu estilo dropdown com três tiers:

| Tier | Gemini | DeepSeek | Uso |
|------|--------|----------|-----|
| **Economia** | Flash-Lite | V3.2 | Scans rápidos, menor custo |
| **Equilibrado** | Flash | Chat | Uso geral do dia a dia |
| **Raciocínio** | Pro | R1 | Análises profundas, relatórios |

- Checkmark no modelo ativo
- Badges **G** (Gemini) e **DS** (DeepSeek)
- Escolha persistida no navegador
- Enviada em `POST /api/chat` e `POST /api/autonomous`
- Fallback cruzado automático (ex.: Gemini → DeepSeek do mesmo tier)

Catálogo definido em `backend/models_catalog.py`; exposto via `GET /api/models`.

---

## Modo Auto-Pilot

Missões autônomas multi-etapa sem intervenção manual.

1. Clique **pilot** ou `Ctrl+P`
2. Informe **alvo** (IP, domínio, URL) e **objetivo** (ex.: *"mapear portas abertas e identificar serviços web"*)
3. O agente (`backend/ai/autopilot.py`):
   - Executa ferramentas em loop (até `MAX_AUTONOMOUS_ROUNDS` / `MAX_AUTONOMOUS_TOOLS`)
   - Analisa resultados entre rodadas
   - Encerra via `finish_mission` quando o objetivo foi atingido ou não há mais passos úteis
4. Retorna mensagem final + execuções + **relatório Markdown** (download automático)

**Endpoint:** `POST /api/autonomous`

```json
{
  "target": "scanme.nmap.org",
  "objective": "Identificar portas abertas e serviços",
  "model": "google/gemini-2.5-flash",
  "fallback_model": "deepseek/deepseek-chat-v3.2"
}
```

---

## API REST

### `GET /api/health`

```json
{
  "status": "ok",
  "version": "2.0.0",
  "docker": true,
  "kali_container": true,
  "kali_error": "",
  "wifi_ready": true,
  "wifi_interfaces": ["Wi-Fi"],
  "wifi_message": "Placa nativa: Wi-Fi · 12 rede(s) visível(is)"
}
```

### `GET /api/tools`

Retorna categorias enriquecidas com `summary` e `example` de cada ferramenta (UI).

### `GET /api/models`

Retorna tiers, modelos Gemini/DeepSeek, defaults e fallbacks.

### `GET /api/logs/{log_id}`

Retorna log completo da execução (text/plain).

### `POST /api/chat`

**Corpo:**

```json
{
  "message": "scan de portas em scanme.nmap.org",
  "history": [
    { "role": "user", "content": "..." },
    { "role": "assistant", "content": "..." }
  ],
  "preferred_tool": "auto",
  "model": "google/gemini-2.5-flash",
  "fallback_model": "deepseek/deepseek-chat-v3.2"
}
```

**Resposta:**

```json
{
  "message": "Interpretação dos resultados...",
  "tool_executions": [
    {
      "command": "nmap -sV scanme.nmap.org",
      "reason": "Identificar serviços e versões",
      "stdout": "...",
      "stderr": "",
      "exit_code": 0,
      "success": true,
      "blocked": false,
      "log_file_id": "a1b2c3d4e5f6",
      "tool": "nmap"
    }
  ]
}
```

### `POST /api/autonomous`

Ver [Modo Auto-Pilot](#modo-auto-pilot).

### `POST /api/generate-report`

Gera relatório Markdown a partir do histórico e execuções da sessão.

**Corpo:**

```json
{
  "history": [...],
  "tool_executions": [...],
  "title": "Relatório de Pentest"
}
```

**Resposta:** arquivo `relatorio-pentest.md` (download).

---

## Motor de execução e segurança

Toda execução passa por `validate_command(args: list[str])` em `backend/executor/kali.py`.

### Execução vectorizada (v2.0)

| Antes | Depois |
|-------|--------|
| `docker exec ... bash -c "<string>"` | `docker exec ... <binário> <arg1> <arg2> ...` |
| Validação por regex em string | Whitelist do binário + bloqueio de `..` nos argumentos |
| Risco de shell injection | Argumentos isolados via `shlex`; sem interpretação shell |

### Whitelist

Apenas binários em `ALLOWED_TOOLS` (`config.py`) — **180+ ferramentas**, incluindo:

- Rede/recon: `nmap`, `masscan`, `dig`, `whois`, `rustscan`, …
- OSINT: `subfinder`, `amass`, `theHarvester`, `httpx`, …
- Web: `nuclei`, `ffuf`, `sqlmap`, `nikto`, …
- AD/Windows: `nxc`, `impacket-*`, `kerbrute`, `responder`, …
- Wi-Fi host: `wlan-scan`, `wlan-interfaces`, `wifi-list`
- Wi-Fi container: `aircrack-ng`, `airodump-ng`, `wifite`, …

### Flags não-interativas automáticas

| Ferramenta | Flag inserida |
|------------|---------------|
| sqlmap | `--batch` |
| apt / apt-get | `-y` |
| dpkg | `--force-confdef --force-confold` |
| hydra | `-I` |
| nikto | `-ask no` |
| wpscan | `--no-update` |
| ffuf | `-noninteractive` |

Todas as execuções Docker usam `stdin=subprocess.DEVNULL`.

### Limites

| Limite | Valor padrão |
|--------|--------------|
| Tamanho máximo do comando | 500 caracteres |
| Timeout comandos normais | 180 s |
| Timeout ferramentas Wi-Fi | 600 s |
| Iterações de ferramenta por mensagem | 5 |
| Histórico enviado à IA | 10 mensagens |

---

## Logs, resumo de output e relatórios

### Logs persistidos

- Cada execução gera UUID de 12 caracteres
- Log completo em `backend/logs/{id}.log`
- Frontend exibe link **Log #{id}** → `GET /api/logs/{id}`

### Resumo para a IA (`summarize.py`)

Quando output excede `OUTPUT_TOKEN_LIMIT`:

1. Mantém primeiras **N linhas** (`SUMMARY_HEAD_LINES`, padrão 30)
2. Extrai linhas críticas via regex (`[CRITICAL]`, `[CVE-`, `open/tcp`, etc.)
3. Mantém últimas **N linhas** (`SUMMARY_TAIL_LINES`, padrão 15)
4. Prefixo: `[Output truncado para economia. Resumo técnico abaixo:]`

Apenas o **resumo** vai para a IA; o frontend recebe stdout/stderr **completos**.

### Relatório Markdown (`generate_report`)

Estrutura gerada pela IA:

1. Resumo Executivo
2. Resumo Técnico (tabela de comandos)
3. Tabela de Vulnerabilidades / Achados
4. Recomendações de Mitigação
5. Anexo — referências aos logs persistidos

Disparado pelo botão **report** ou retornado pelo Auto-Pilot.

---

## Ferramentas disponíveis

Categorias na UI (`TOOL_CATEGORIES` + metadados em `tool_catalog.py`):

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

Executadas via **`netsh wlan`** no Windows. Funcionam com `start.bat servidor` (sem Docker).

### 2. Container Docker (captura / monitor mode)

Ferramentas: `aircrack-ng`, `airodump-ng`, `airmon-ng`, `reaver`, `wifite`, `hcxdumptool`, etc.

Requisitos: container `kali-tools` running, dongle USB compatível, USB repassado, entrypoint desbloqueia rfkill.

Diagnóstico:

```bash
docker exec kali-tools wifi-status
```

---

## Container Docker Kali

### Build manual

```bash
cd docker
docker compose up -d --build
```

### Imagem (`docker/Dockerfile`)

Base **Debian Bookworm slim** com instalação em camadas:

1. **APT** — nmap, masscan, sqlmap, hydra, john, aircrack-ng, tshark, etc.
2. **Binários** — ffuf, feroxbuster, nuclei, subfinder, httpx, rustscan, kerbrute, chisel, trivy, …
3. **Git** — nikto, testssl.sh, searchsploit, dirsearch, wifite, autorecon, SecLists, …
4. **Python/Ruby pip** — impacket, nxc, certipy-ad, wpscan, evil-winrm, volatility3, …

O container fica vivo com `sleep infinity` após desbloquear rádios Wi-Fi.

### Compose

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

## Agente de IA (OpenRouter)

Arquivo: `backend/ai/agent.py`

### Integração

- Cliente **OpenAI SDK** apontando para `https://openrouter.ai/api/v1`
- Chave: `OPENROUTER_API_KEY` no `.env`
- Modelos referenciados como IDs OpenRouter (`google/gemini-2.5-flash`, `deepseek/deepseek-chat-v3.2`, etc.)

### Comportamento

- Function calling manual (loop controlado para registrar cada execução)
- **Nudge** se a IA responder sem executar: *"Execute o comando AGORA com run_kali_tool"*
- **Ferramenta preferida:** prefixo força uso da ferramenta selecionada na UI
- Histórico truncado a `MAX_HISTORY_MESSAGES`

### Tratamento de erros

| Erro | Ação |
|------|------|
| API key inválida | Mensagem com link para OpenRouter |
| Cota esgotada (429) | Fallback automático após 2 s |
| Sem `OPENROUTER_API_KEY` | Instrução para configurar `.env` |

---

## Solução de problemas

### Docker não responde

- Abra o **Docker Desktop** e aguarde estabilizar
- Rode `start.bat repair`
- Ou: `start.bat servidor` (só chat)

### Container `kali-tools` não está rodando

```bat
cd docker
docker compose up -d --build
```

Ou verifique: `GET http://localhost:8000/api/health`

### Chave OpenRouter inválida ou cota esgotada

- Gere chave em [openrouter.ai/keys](https://openrouter.ai/keys)
- Use tier **Economia** no seletor da UI
- Configure fallback diferente no `.env`

### Comando bloqueado (`[blocked]`)

Ferramenta fora da whitelist ou argumento com `..`. Verifique `ALLOWED_TOOLS` em `backend/config.py`.

### Modal de ferramentas pequeno / CSS desatualizado

Hard refresh: `Ctrl+Shift+R` (cache bust via `?v=` no HTML).

### Wi-Fi no container sem interface

- Dongle USB conectado
- `docker exec kali-tools wifi-status`
- Container `privileged` com USB mapeado

### Build Docker lenta

Normal na primeira execução. Builds subsequentes usam cache.

---

## Desenvolvimento manual

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

copy .env.example .env
# Edite OPENROUTER_API_KEY

cd docker && docker compose up -d --build   # opcional

python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Dependências Python

| Pacote | Uso |
|--------|-----|
| `fastapi` | Framework web |
| `uvicorn` | Servidor ASGI |
| `openai` | Cliente OpenRouter (API compatível) |
| `python-dotenv` | Carregar `.env` |
| `pydantic` | Validação de request/response |

---

## Testes

Suite unitária e de integração (sem Docker nem chamadas à OpenRouter):

```bash
python -m unittest discover -s tests -v
```

| Arquivo | Cobertura |
|---------|-----------|
| `tests/test_core.py` | Whitelist kali, recon DB, Smart Healing |
| `tests/test_integration.py` | Health, auth token, recon TTL, stream hub SSE |
| `tests/test_sse.py` | `/api/chat/stream` e `/api/autonomous/stream` (agente mockado) |
| `tests/test_security.py` | Sessão HttpOnly, rate limit, cancelamento, **persistência em disco** |
| `tests/test_kali_mock.py` | Cancelamento Docker com `subprocess` mockado |

CI: GitHub Actions (`.github/workflows/tests.yml`) roda a suite com `requirements-lock.txt` em push/PR para `main`/`master`.

---

## Exemplos de uso

| Pedido / ação | O que acontece |
|---------------|----------------|
| *"Liste redes Wi-Fi ao redor"* | `wlan-scan` via `netsh` no Windows |
| *"Scan SYN nas top 1000 portas de scanme.nmap.org"* | `nmap` no container + dashboard na UI |
| *"Busque subdomínios de example.com"* | `subfinder` ou `amass` |
| Selecionar **nmap** + botão **usar** | Fixa ferramenta e preenche exemplo no prompt |
| **pilot** → alvo + objetivo | Auto-Pilot executa loop e baixa relatório |
| **report** após sessão | Download de `relatorio-pentest.md` |
| Pill **Economia → DeepSeek V3.2** | Chat usa modelo mais barato |

---

## Changelog

### v3.6 — Polimento pós-v3.5 (2026-07-15)

#### Correções e docs
- README alinhado: host padrão **`127.0.0.1`** (não `0.0.0.0`)
- Removidos imports não usados (`backend/main.py`, `autopilot.js`)

#### Testes
- **`test_sessions_survive_store_reload`** — sessões persistidas em disco sobrevivem reload do store
- **`test_chat_stream_cancelled_stopped_reason`** — SSE `done` com `stopped_reason: cancelled`

#### DevOps
- **`./start.sh repair`** — limpeza de cache Docker (paridade com `start.bat repair`)

---

### v3.5 — Arquitetura modular e cancel no chat (2026-07-15)

#### Backend
- `backend/main.py` enxuto (~60 linhas) — routers em `backend/routes/` (`auth`, `system`, `chat`, `autonomous`)
- `backend/schemas.py`, `backend/deps.py`, `backend/middleware.py` — separação de responsabilidades
- **Sessões persistidas** em `backend/data/sessions.json` (sobrevivem restart do servidor)
- **Cancel no chat normal** — `mission_id` em `POST /api/chat/stream` interrompe execução Docker ativa

#### Frontend ES modules
- `frontend/js/chat.js` — envio de mensagens + relatório + cancel via `mission.js`
- `frontend/js/autopilot.js` — modo Auto-Pilot isolado
- `frontend/js/mission.js` — controle compartilhado chat/auto-pilot
- `frontend/js/ui.js`, `frontend/js/chat-view.js` — UI e renderização do terminal
- `frontend/js/main.js` — wiring fino (~250 linhas)

#### DevOps e testes
- **`start.sh`** — inicialização Linux/macOS (espelho simplificado do `start.bat`)
- **`tests/test_kali_mock.py`** — cancelamento com `subprocess` mockado
- **`tests/auth_patch.py`** — helper de mock para testes de auth pós-refactor

---

### v3.4 — Segurança, cancelamento e deps pinadas (2026-07-15)

#### Auth por sessão HttpOnly
- `POST /api/auth/login` — troca `CHAT_API_TOKEN` por cookie `kali_session`
- `GET /api/auth/session`, `POST /api/auth/logout`
- Retrocompatível com header `X-Chat-Token` e `?token=` no EventSource

#### Rate limiting
- Rotas caras (`/api/chat*`, `/api/autonomous*`) limitadas por IP
- Config: `RATE_LIMIT_REQUESTS=30`, `RATE_LIMIT_WINDOW_SEC=60`

#### Cancelar Auto-Pilot
- Cliente envia `mission_id`; botão **cancel** na barra do terminal
- `POST /api/missions/{id}/cancel` — interrompe missão e mata processo Docker ativo

#### Dependências
- `requirements.txt` com versões pinadas (deps diretas)
- `requirements-lock.txt` — freeze completo para CI

---

### v3.3 — CI, testes SSE e modularização frontend (2026-07-15)

#### GitHub Actions
- `.github/workflows/tests.yml` — suite roda em push/PR para `main`/`master`

#### Testes SSE
- `tests/test_sse.py` — `/api/chat/stream` e `/api/autonomous/stream` com agente mockado

#### Frontend ES modules (continuação)
- `frontend/js/sessions.js` — store localStorage, sidebar, histórico de conversas
- `frontend/js/tools-panel.js` — painel de ferramentas, seletor de modelos, objetivos rápidos

---

### v3.2 — Frontend modular e streaming Auto-Pilot (2026-07-15)

#### Frontend ES modules
- Entry point: `frontend/js/main.js` (ES modules no HTML)
- Módulos: `constants.js`, `api.js`, `exec.js`, `stream.js`
- SSE compartilhado via `consumeChatStream` / `createToolStreamHandlers`

#### Auto-Pilot com logs ao vivo
- `POST /api/autonomous/stream` — eventos `mission_start`, `round_start`, `tool_start`, `tool_done`, `done`
- Blocos `[live]` no chat durante execução autônoma

#### Recon DB — TTL
- **`RECON_TTL_DAYS=30`** — entradas expiradas removidas automaticamente em `get_recon_data`

#### Testes de integração
- `tests/test_integration.py` — health, auth token, recon TTL, stream hub
- Executar tudo: `python -m unittest discover -s tests -v`

---

### v3.1 — Hardening e qualidade (2026-07-15)

#### Segurança local
- **`UVICORN_HOST=127.0.0.1`** por padrão (`start.bat` lê do `.env`)
- **`CHAT_API_TOKEN`** opcional — protege `/api/*` via header `X-Chat-Token`
- **CORS** restrito a localhost por padrão (`CORS_ORIGINS`)
- **`GET /api/client-config`** — frontend detecta se auth é necessária

#### Smart Healing limitado
- **`MAX_HEALING_ATTEMPTS=2`** — evita loop caro de retentativas
- Módulo `backend/ai/healing.py`

#### Recon DB mais preciso
- Ignora domínios genéricos (`example.com`, `localhost`, etc.)
- Persiste recon apenas para alvos presentes **no comando** executado

#### Configuração
- Aliases **`OPENROUTER_PRIMARY_MODEL`** / **`OPENROUTER_FALLBACK_MODEL`**
- Retrocompatível com `GEMINI_MODEL` / `GEMINI_FALLBACK_MODEL`

#### Testes
- `tests/test_core.py` — 10 testes unitários (validação kali, recon, healing)
- Executar: `python -m unittest tests.test_core -v`

---

### v3.0.0 — Tríade de Performance (2026-07-15)

**Foco:** Streaming em tempo real, auto-correção de comandos, memória local de reconhecimento.

Esta release implementa a **Tríade de Performance** para uso local: logs das ferramentas aparecem linha a linha no terminal web enquanto executam; falhas disparam **Smart Healing** automático pela IA; e descobertas sobre cada alvo são persistidas em JSON para contexto em conversas futuras.

#### 1. Streaming de logs em tempo real (SSE)

**Arquivos novos:** `backend/executor/stream_hub.py` — registry thread-safe de execuções ativas

**Arquivos alterados:** `backend/executor/kali.py`, `backend/executor/logs.py`, `backend/ai/agent.py`, `backend/main.py`, `frontend/js/stream.js`, `frontend/styles.css`

**Fluxo integrado:**
1. Agente pré-registra `execution_id` no hub e emite `tool_start` via `POST /api/chat/stream`
2. Frontend abre `EventSource` em `GET /api/logs/stream/{execution_id}`
3. Docker escreve stdout/stderr → hub → SSE → terminal web em tempo real
4. Ao final, log completo salvo em `backend/logs/{id}.log` e bloco substituído pelo dashboard final

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/logs/stream/{execution_id}` | SSE linha a linha da execução |
| POST | `/api/chat/stream` | Chat com eventos SSE (`tool_start`, `tool_done`, `done`) |

`POST /api/chat` (JSON clássico) permanece disponível.

#### 2. Auto-correção de comandos (Smart Healing)

**Arquivos:** `backend/ai/agent.py`, `backend/ai/autopilot.py`

Quando `run_kali_tool` retorna `exit_code != 0` ou `success == false` (e não foi bloqueado pela whitelist):

1. Resultado do erro é enviado à IA como mensagem `tool`
2. Mensagem adicional é injetada automaticamente pedindo correção imediata
3. O loop de `MAX_TOOL_ITERATIONS` continua — a IA corrige e reexecuta **sem nova mensagem do usuário**

Funciona também no **Auto-Pilot**.

#### 3. Banco de reconhecimento local (Recon DB)

**Arquivo novo:** `backend/executor/recon_db.py`  
**Diretório:** `backend/recon/{alvo_normalizado}.json` (gitignored)

| Função | Descrição |
|--------|-----------|
| `save_recon_data(alvo, chave, valor)` | Salva/atualiza campo no JSON do alvo |
| `get_recon_data(alvo)` | Lê JSON completo do alvo |
| `extract_targets(texto)` | Extrai IPs e domínios de mensagens |
| `extract_recon_from_output(stdout, stderr)` | Portas abertas, CVEs, achados nuclei |
| `build_recon_context(targets)` | Texto para injetar no prompt |

**Integração com a IA:**
- **Início do chat:** se o usuário menciona IP/domínio, contexto anterior é injetado no prompt
- **Após execução bem-sucedida:** portas, CVEs e vulnerabilidades são mergeados no JSON do alvo
- **Auto-Pilot:** recon do alvo da missão incluído no system prompt

#### Configuração v3.0

Nenhuma variável nova obrigatória. Diretórios criados automaticamente:
- `backend/logs/` — logs completos (já existia)
- `backend/recon/` — memória de alvos (novo)

#### Checklist de validação v3.0

- [ ] Reiniciar servidor (`start.bat` ou uvicorn reload)
- [ ] Hard refresh no browser (`Ctrl+Shift+R`)
- [ ] Enviar mensagem com scan → ver badge `[live]` e linhas aparecendo em tempo real
- [ ] Provocar erro (comando inválido) → IA tenta corrigir automaticamente
- [ ] Scan em `scanme.nmap.org` → verificar `backend/recon/scanme.nmap.org.json`
- [ ] Nova conversa mencionando o mesmo alvo → contexto de recon no prompt (portas salvas)

---

### v2.1 — UX, modelos e OpenRouter (2026-07-15)

#### Migração para OpenRouter
- Substituído Google Gemini SDK direto por **OpenRouter** via SDK OpenAI
- Chave: `OPENROUTER_API_KEY` (substitui `GEMINI_API_KEY`)
- Modelos configuráveis: Gemini e DeepSeek via IDs OpenRouter
- Fallback automático em erro 429 / cota

#### Seletor de modelos na UI
- Menu estilo pill/dropdown no prompt
- Três tiers: **Economia**, **Equilibrado**, **Raciocínio**
- Alternância Gemini ↔ DeepSeek por tier
- Persistência em `localStorage`
- Novo endpoint: `GET /api/models`
- Campos `model` e `fallback_model` em `/api/chat` e `/api/autonomous`

#### Interface e navegação
- Sidebar com conversas, tela welcome, barra de status inferior
- Atalhos: `Ctrl+T/P/R/N/K+/`, `M` para menu, `Esc` para fechar painéis
- Toasts, histórico ↑↓ no prompt, botão scroll ↓
- Painel **tools** ampliado (~94% largura, grid 3 colunas)
- Abas por categoria, busca, cards com resumo/exemplo e botão **usar**
- Scrollbars customizados (tema terminal, scanlines, thumb verde)
- Catálogo de ferramentas enriquecido (`tool_catalog.py`) — metadados só na UI

#### Economia de tokens (refinamento)
- System prompt enxuto
- `MAX_HISTORY_MESSAGES=10`
- `OUTPUT_TOKEN_LIMIT=3000`, resumo 30+15 linhas

#### Modo Auto-Pilot
- `backend/ai/autopilot.py` — missões autônomas multi-etapa
- `POST /api/autonomous` — alvo + objetivo → loop de ferramentas + relatório
- Botão **pilot** na barra superior
- Limites: `MAX_AUTONOMOUS_ROUNDS`, `MAX_AUTONOMOUS_TOOLS`

---

### v2.0.0 — Mega prompt (2026-07-14)

**Foco:** Segurança rigorosa, redução de custo, UX profissional.

#### 1. Segurança — Execução vectorizada no Docker

| Antes | Depois |
|-------|--------|
| `docker exec ... bash -c "<string>"` | `docker exec ... <binário> <arg1> <arg2> ...` |
| Validação por regex (`;`, `\|`, `&`, etc.) | Whitelist do binário + bloqueio de `..` nos args |
| `validate_command(command: str)` | `validate_command(args: list[str])` via `shlex` |

**Benefício:** elimina shell injection clássica via `bash -c`.

**Arquivos:** `backend/executor/kali.py`, `backend/config.py`

#### 2. Custo — Resumo inteligente de output

- Logs completos em `backend/logs/{uuid}.log`
- `ExecutionResult` com `log_file_id`, `tool`, `truncated_for_llm`
- `summarize.py` — truncamento + extração de linhas críticas
- Apenas resumo vai à IA; frontend recebe output completo
- Nova rota: `GET /api/logs/{log_id}`

**Arquivos novos:** `backend/executor/summarize.py`, `backend/executor/logs.py`

#### 3. UX/UI — Dashboards visuais

- Parser **Nmap:** tabela Porta / Estado / Serviço / Versão
- Parser **Nuclei/vulns:** cards por severidade (Critical/High vermelho, Medium amarelo, Info azul)
- Log bruto oculto quando há dashboard; botão **Ver Log Completo**
- Link **Log #{id}** para `/api/logs/{id}`

**Arquivos:** `frontend/js/main.js`, `frontend/index.html`, `frontend/styles.css`

#### 4. Profissionalismo — Relatórios Markdown

- `generate_report()` em `backend/ai/agent.py`
- `POST /api/generate-report`
- Botão **report** na barra superior
- Estrutura: Resumo Executivo → Técnico → Vulnerabilidades → Mitigação → Anexo logs

#### 5. Técnica — Tratamento de não-interatividade

- `apply_non_interactive_flags()` — `--batch`, `-y`, `-I`, etc.
- `stdin=subprocess.DEVNULL` em todas execuções Docker

#### API v2.0 — campos e rotas novas

**`ToolExecutionResponse` expandido:**

```json
{
  "log_file_id": "a1b2c3d4e5f6",
  "tool": "nmap"
}
```

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/logs/{log_id}` | Log completo |
| POST | `/api/generate-report` | Relatório `.md` |

**Health:** campo `version: "2.0.0"`

#### Configuração v2.0

```env
OUTPUT_TOKEN_LIMIT=5000
```

Logs em `backend/logs/` (`.gitignore`)

#### Checklist de validação v2.0

- [ ] Reiniciar servidor: `start.bat`
- [ ] Testar `nmap scanme.nmap.org` — dashboard Nmap na UI
- [ ] Testar output longo (nuclei) — truncamento na IA, log completo em `/api/logs/{id}`
- [ ] Tentar `; rm -rf /` — deve falhar na whitelist
- [ ] Clicar **report** — baixar `relatorio-pentest.md`
- [ ] Verificar `backend/logs/` após execuções

---

## Licença e responsabilidade

Este software é fornecido para **fins educacionais e testes autorizados**. Os autores não se responsabilizam pelo uso indevido. Respeite leis locais (LGPD, Marco Civil, CFAA equivalentes) e obtenha autorização antes de testar qualquer sistema de terceiros.
