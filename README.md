# Chat IA Kali

**Versão estável 1.0.0** — assistente local de pentest com IA que **executa ferramentas reais** no Kali Linux (Docker), não apenas sugere comandos.

Você descreve o objetivo em linguagem natural; a IA (via [OpenRouter](https://openrouter.ai)) interpreta, escolhe a ferramenta, roda no container isolado e devolve análise, dashboards visuais e relatórios Markdown. Inclui modo **Auto-Pilot** para missões autônomas multi-etapa, streaming de logs ao vivo, cancelamento de execuções e auth por sessão HttpOnly.

> **Uso exclusivamente autorizado.** Teste somente sistemas, redes ou aplicações que você possui ou para os quais tem **permissão explícita por escrito**. Uso não autorizado é ilegal. Você é responsável por escopo, conformidade (LGPD, Marco Civil, CFAA equivalentes) e cada comando executado.

---

## Sumário

- [Início rápido](#início-rápido)
- [Escopo v1.0](#escopo-v10)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Interface](#interface)
- [Modos de uso](#modos-de-uso)
- [IA, modelos e economia de tokens](#ia-modelos-e-economia-de-tokens)
- [Motor de execução](#motor-de-execução)
- [Dados persistidos](#dados-persistidos)
- [API REST](#api-rest)
- [Solução de problemas](#solução-de-problemas)
- [Testes e validação](#testes-e-validação)
- [Release e versionamento](#release-e-versionamento)
- [Changelog](#changelog)
- [Licença](#licença)

---

## Início rápido

```bat
# Windows — Docker + Kali + servidor
start.bat

# Linux / macOS
chmod +x start.sh && ./start.sh

# Sem Docker (chat + Wi-Fi nativo Windows; sem ferramentas Kali)
start.bat servidor          # ou: ./start.sh servidor
```

1. Na primeira execução, `.env` é criado a partir de `.env.example`.
2. Edite **`OPENROUTER_API_KEY`** (obrigatório) em [openrouter.ai/keys](https://openrouter.ai/keys).
3. Abra **http://127.0.0.1:8000**
4. Confirme: `GET /api/health` → `"version": "1.0.0"`, `"status": "ok"`.

**Recomendado:** defina `CHAT_API_TOKEN` no `.env` para proteger a API local.

**Testes:** `python -m unittest discover -s tests -v` (29 testes, sem Docker/OpenRouter)

---

## Escopo v1.0

Release **1.0.0** encerra o ciclo como **ferramenta local single-user**. Evoluções grandes (playbooks YAML, timeline de missão) ficam reservadas para uma eventual v2.

| Incluído | Excluído (por enquanto) |
|----------|-------------------------|
| Chat + Auto-Pilot + relatórios Markdown | Multi-usuário, RBAC, dashboard consultoria |
| Execução Kali Docker, whitelist, cancel | Mitigação automática, SIEM, SOC |
| Auth sessão, rate limit, bind `127.0.0.1` | ML customizado, multi-agentes paralelos |
| Windows (`start.bat`) e Linux/macOS (`start.sh`) | Labs GNS3 / EVE-NG / VMs dinâmicas |

---

## Funcionalidades

| Área | Detalhe |
|------|---------|
| **Chat** | Terminal web (tema fosforescente), sidebar de conversas (`localStorage`), histórico ↑↓, toasts, barra de status |
| **Ferramentas** | 180+ binários na whitelist; painel com categorias, busca e exemplos; modo `auto` ou ferramenta fixa |
| **Execução** | Vectorizada (`docker exec bin arg1 arg2…`, sem shell); flags não-interativas; timeout configurável |
| **Streaming** | Logs stdout/stderr ao vivo via SSE; blocos `[live]` durante execução |
| **Dashboards** | Parser Nmap (tabela portas) e Nuclei/vulns (cards por severidade) |
| **Smart Healing** | Até `MAX_HEALING_ATTEMPTS` retentativas automáticas após falha de comando |
| **Recon DB** | Memória local por alvo (`backend/recon/`), TTL configurável, contexto injetado em chats futuros |
| **Auto-Pilot** | Alvo + objetivo → loop autônomo de ferramentas + relatório `.md` |
| **Cancel** | Botão **cancel** interrompe chat stream e Auto-Pilot; mata processo Docker ativo |
| **Relatórios** | Botão **report** ou fim do Auto-Pilot → Markdown estruturado |
| **Modelos** | Tiers Economia / Equilibrado / Raciocínio; Gemini ↔ DeepSeek; fallback em 429 |
| **Segurança** | Sessão HttpOnly, rate limit, CORS localhost, optional `CHAT_API_TOKEN` |

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (frontend/)                                       │
│  index.html · styles.css · js/main.js + 12 módulos ES6      │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP / SSE
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Backend FastAPI (backend/main.py → routes/)                │
│  auth · system · chat · autonomous                          │
│  middleware: rate limit + API token guard                   │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────┐  ┌─────────────────────────────┐
│  IA (backend/ai/)        │  │  Executor (backend/executor/)│
│  agent · autopilot       │  │  kali · logs · summarize     │
│  healing · sse           │  │  recon_db · stream_hub       │
│  OpenRouter + tools      │  │  wifi_scan (host Windows)    │
└──────────────────────────┘  └──────────────┬──────────────┘
                                             │ docker exec
                                             ▼
                              ┌─────────────────────────────┐
                              │  Container kali-tools         │
                              │  docker/Dockerfile (180+ tools)│
                              └─────────────────────────────┘
```

### Fluxo de uma mensagem (chat)

1. Frontend envia `POST /api/chat/stream` com `message`, `history`, `preferred_tool`, `model`, `mission_id`.
2. `agent.py` chama OpenRouter com function calling (`run_kali_tool`).
3. `kali.py` valida whitelist → executa no Docker ou Wi-Fi host → salva log → resume output para IA.
4. Eventos SSE: `tool_start`, linhas ao vivo, `tool_done`, `done` (ou `error`).
5. Frontend renderiza resposta, dashboards e blocos `[ok]` / `[exit N]` / `[blocked]`.
6. Iterações até `MAX_TOOL_ITERATIONS`; Smart Healing em falhas; Recon DB atualizado em sucesso.

---

## Estrutura do repositório

```
Chat IA Kali/
├── backend/
│   ├── main.py              # Entry FastAPI (~60 linhas)
│   ├── config.py            # .env, whitelist, prompts
│   ├── schemas.py · deps.py · middleware.py
│   ├── routes/              # auth, system, chat, autonomous
│   ├── security/            # sessions, rate_limit, missions
│   ├── ai/                  # agent, autopilot, healing, sse
│   ├── executor/            # kali, logs, summarize, recon_db, …
│   ├── data/                # sessões (gitignored)
│   └── logs/ · recon/       # gitignored
├── frontend/
│   ├── index.html · styles.css
│   └── js/                  # main, chat, autopilot, mission, ui, …
├── docker/                  # Dockerfile, compose, scripts Wi-Fi
├── tests/                   # 29 testes + auth_patch helper
├── scripts/docker-check.ps1 # Docker com timeout (Windows)
├── start.bat · start.sh
├── requirements.txt · requirements-lock.txt
└── .env.example
```

---

## Instalação

### Pré-requisitos

| Item | Observação |
|------|------------|
| Python 3.10+ | Criado automaticamente em `venv/` |
| Docker Desktop | Opcional (`start.bat servidor` pula Docker) |
| Chave OpenRouter | Obrigatória para IA |
| Dongle USB Wi-Fi | Só para monitor mode no container |

### Modo completo (`start.bat` / `./start.sh`)

1. Cria `.env` e `venv`, instala dependências
2. Verifica/inicia Docker (Windows: até ~8 min)
3. `docker compose up -d --build` em `docker/`
4. Aguarda container `kali-tools` e testa `nmap`
5. Sobe Uvicorn lendo `UVICORN_HOST` / `UVICORN_PORT` do `.env`

### Comandos alternativos

| Comando | Efeito |
|---------|--------|
| `start.bat servidor` / `./start.sh servidor` | Só servidor; Wi-Fi Windows ok; Kali off |
| `start.bat repair` / `./start.sh repair` | Reinicia Docker (Win) ou `docker system prune` (Unix) |

### Desenvolvimento manual

```bash
python -m venv venv
# Windows: venv\Scripts\activate  |  Unix: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edite OPENROUTER_API_KEY
cd docker && docker compose up -d --build   # opcional
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Dependências: `fastapi`, `uvicorn`, `openai` (OpenRouter), `python-dotenv`, `pydantic`.

---

## Configuração

Copie `.env.example` → `.env`. Variáveis principais:

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `OPENROUTER_API_KEY` | — | **Obrigatória.** Chave OpenRouter |
| `OPENROUTER_PRIMARY_MODEL` | `google/gemini-2.5-flash` | Modelo principal |
| `OPENROUTER_FALLBACK_MODEL` | `deepseek/deepseek-chat-v3.2` | Fallback em erro/cota |
| `UVICORN_HOST` | `127.0.0.1` | Use `0.0.0.0` só em LAN confiável |
| `UVICORN_PORT` | `8000` | Porta do servidor |
| `CHAT_API_TOKEN` | vazio | Se definido, protege `/api/*` (sessão HttpOnly) |
| `KALI_CONTAINER` | `kali-tools` | Nome do container |
| `COMMAND_TIMEOUT` | `180` | Timeout geral (s) |
| `WIFI_COMMAND_TIMEOUT` | `600` | Timeout Wi-Fi (s) |
| `MAX_TOOL_ITERATIONS` | `5` | Ferramentas por mensagem de chat |
| `MAX_HEALING_ATTEMPTS` | `2` | Retentativas Smart Healing |
| `MAX_AUTONOMOUS_ROUNDS` | `10` | Rodadas Auto-Pilot |
| `MAX_AUTONOMOUS_TOOLS` | `25` | Comandos totais Auto-Pilot |
| `MAX_HISTORY_MESSAGES` | `10` | Mensagens enviadas à IA |
| `OUTPUT_TOKEN_LIMIT` | `3000` | Limite antes de resumir output |
| `RECON_TTL_DAYS` | `30` | Expiração cache recon |
| `SESSION_TTL_HOURS` | `24` | TTL cookie de sessão |
| `RATE_LIMIT_REQUESTS` | `30` | Requisições por janela |
| `RATE_LIMIT_WINDOW_SEC` | `60` | Janela rate limit |

**Produção local recomendada:** `CHAT_API_TOKEN` forte + `UVICORN_HOST=127.0.0.1`. Não exponha na internet sem TLS, reverse proxy e auth robusta.

---

## Interface

### Layout

| Área | Conteúdo |
|------|----------|
| Sidebar | Conversas, novo chat, ajuda |
| Barra superior | `tools` · `pilot` · `cancel` · `report` · `?` · `+` |
| Terminal | Mensagens, execuções, dashboards |
| Prompt | Entrada + pill de modelo |
| Status bar | Docker, Kali, ferramenta, modelo, contadores |

### Atalhos

| Atalho | Ação |
|--------|------|
| `M` | Sidebar |
| `Esc` | Fechar painéis |
| `Ctrl+K` | Focar prompt |
| `↑` / `↓` | Histórico da sessão |
| `Ctrl+T` | Ferramentas |
| `Ctrl+P` | Auto-Pilot |
| `Ctrl+R` | Relatório |
| `Ctrl+N` | Novo chat |
| `Ctrl+/` | Ajuda |

Persistência no navegador: `chat-ia-kali-sessions` (conversas), `chat-ia-kali-model` (modelo ativo).

---

## Modos de uso

### Chat interativo

Digite no prompt ou use o painel **tools** para fixar ferramenta e preencher exemplo. A IA executa via `run_kali_tool` quando o pedido exige dados técnicos.

**Streaming (padrão):** `POST /api/chat/stream` — preferido; suporta logs ao vivo e cancel.

**Clássico:** `POST /api/chat` — resposta JSON única (sem SSE).

### Cancelamento

Durante chat ou Auto-Pilot, o botão **cancel** envia `AbortController` no cliente e `POST /api/missions/{mission_id}/cancel` no servidor, matando o processo Docker registrado.

### Auto-Pilot

1. `Ctrl+P` → informe **alvo** e **objetivo**
2. Agente roda loop (`autopilot.py`) até objetivo, limite de rodadas ou cancel
3. Relatório Markdown baixado automaticamente ao concluir

**Endpoint:** `POST /api/autonomous/stream` (SSE) ou `POST /api/autonomous` (JSON).

### Relatório de sessão

Botão **report** → `POST /api/generate-report` com histórico e execuções da sessão → download `relatorio-pentest.md`.

Estrutura: Resumo Executivo → Técnico → Vulnerabilidades → Mitigação → Anexo logs.

### Exemplos práticos

| Ação | Resultado |
|------|-----------|
| *"Liste redes Wi-Fi"* | `wlan-scan` via `netsh` (Windows host) |
| *"Scan SYN em scanme.nmap.org"* | `nmap` no container + dashboard |
| *"Subdomínios de example.com"* | `subfinder` / `amass` |
| **pilot** + alvo lab | Missão autônoma + relatório |
| Tier **Economia** | Modelo mais barato (Flash-Lite / DeepSeek V3.2) |

---

## IA, modelos e economia de tokens

Integração via SDK OpenAI apontando para `https://openrouter.ai/api/v1`. Function calling manual com loop controlado; *nudge* se a IA responder sem executar ferramenta.

### Tiers (`GET /api/models`)

| Tier | Gemini | DeepSeek | Uso |
|------|--------|----------|-----|
| Economia | Flash-Lite | V3.2 | Scans rápidos |
| Equilibrado | Flash | Chat | Dia a dia |
| Raciocínio | Pro | R1 | Análises profundas |

Escolha na UI → enviada como `model` e `fallback_model` nos POSTs. Fallback cruzado automático em HTTP 429.

### Economia

- System prompt compacto; catálogo de ferramentas só na UI (`tool_catalog.py`)
- Histórico truncado (`MAX_HISTORY_MESSAGES`)
- Output de ferramentas resumido (`summarize.py`) antes de ir à IA; frontend recebe stdout/stderr completos
- Logs completos em `backend/logs/`; link **Log #{id}** na UI

---

## Motor de execução

Arquivo central: `backend/executor/kali.py`.

### Segurança

| Mecanismo | Detalhe |
|-----------|---------|
| Execução vectorizada | `docker exec kali-tools nmap -sV alvo` — sem `bash -c` |
| Whitelist | Binário deve estar em `ALLOWED_TOOLS` (`config.py`) |
| Path traversal | `..` bloqueado nos argumentos |
| Tamanho | Comando ≤ 500 caracteres |
| stdin | `DEVNULL` em todas execuções Docker |
| Flags auto | `--batch` (sqlmap), `-y` (apt), `-I` (hydra), etc. |

Comando bloqueado aparece como `[blocked]` na UI.

### Wi-Fi — duas camadas

| Camada | Ferramentas | Onde roda |
|--------|-------------|-----------|
| Host Windows | `wlan-scan`, `wlan-interfaces`, `wifi-list` | `netsh` local; funciona sem Docker |
| Container | `aircrack-ng`, `airodump-ng`, `wifite`, … | Requer dongle USB, `privileged`, USB mapeado |

Diagnóstico container: `docker exec kali-tools wifi-status`

### Docker Kali

```bash
cd docker && docker compose up -d --build
```

Imagem Debian Bookworm slim: APT + binários Go + repos Git + pip (Impacket, nxc, nuclei templates, SecLists). Compose: `privileged`, `network_mode: host`, caps `NET_ADMIN`/`NET_RAW`, USB `/dev/bus/usb`.

Categorias na UI: Rede, OSINT, Web, SSL, Senhas, AD, Wi-Fi, Vuln, Forense, Automação, Utilitários.

---

## Dados persistidos

| Caminho | Conteúdo | Versionado |
|---------|----------|------------|
| `backend/logs/{id}.log` | Output completo de cada execução | Não |
| `backend/recon/{alvo}.json` | Portas, CVEs, achados por alvo | Não |
| `backend/data/sessions.json` | Sessões auth HttpOnly | Não |
| `localStorage` (browser) | Conversas e modelo | N/A |

Recon: extraído após execuções bem-sucedidas; injetado no prompt quando o usuário menciona o mesmo alvo. Entradas expiradas removidas por `RECON_TTL_DAYS`.

---

## API REST

Base: `http://127.0.0.1:8000`. Com `CHAT_API_TOKEN`, rotas `/api/*` exigem cookie `kali_session` (via `POST /api/auth/login`) ou header `X-Chat-Token`.

### Referência

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/health` | Status Docker, Kali, Wi-Fi, `version` |
| GET | `/api/client-config` | `authRequired`, host, port |
| GET | `/api/tools` | Categorias + metadados UI |
| GET | `/api/models` | Tiers Gemini/DeepSeek |
| GET | `/api/logs/{id}` | Log completo (text/plain) |
| GET | `/api/logs/stream/{id}` | SSE linha a linha |
| GET | `/api/auth/session` | Estado da sessão |
| POST | `/api/auth/login` | `{ "token" }` → cookie HttpOnly |
| POST | `/api/auth/logout` | Revoga sessão |
| POST | `/api/chat/stream` | Chat SSE (**recomendado**) |
| POST | `/api/chat` | Chat JSON clássico |
| POST | `/api/autonomous/stream` | Auto-Pilot SSE |
| POST | `/api/autonomous` | Auto-Pilot JSON |
| POST | `/api/generate-report` | Relatório Markdown |
| POST | `/api/missions/{id}/cancel` | Cancela missão / mata Docker |

### Payloads principais

**Chat / stream:**

```json
{
  "message": "scan de portas em scanme.nmap.org",
  "history": [{ "role": "user", "content": "..." }],
  "preferred_tool": "auto",
  "model": "google/gemini-2.5-flash",
  "fallback_model": "deepseek/deepseek-chat-v3.2",
  "mission_id": "uuid-opcional-para-cancel"
}
```

**Auto-Pilot:**

```json
{
  "target": "scanme.nmap.org",
  "objective": "Mapear portas abertas e serviços web",
  "mission_id": "uuid-opcional"
}
```

**Health (exemplo):**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "docker": true,
  "kali_container": true,
  "wifi_ready": true
}
```

**SSE — eventos chat:** `tool_start`, `tool_done`, `done`, `error`. Auto-Pilot adiciona `mission_start`, `round_start`. Campo `stopped_reason` em `done` pode ser `completed`, `cancelled`, `objective_met`, etc.

---

## Solução de problemas

| Sintoma | Ação |
|---------|------|
| Docker não responde | Abrir Docker Desktop; `start.bat repair` ou `./start.sh repair` |
| Kali off | `cd docker && docker compose up -d --build`; ver `/api/health` |
| IA não responde | Verificar `OPENROUTER_API_KEY`; tier Economia; saldo OpenRouter |
| `[blocked]` | Ferramenta fora da whitelist ou `..` nos args |
| CSS/JS antigo | Hard refresh `Ctrl+Shift+R` |
| Wi-Fi container vazio | Dongle USB; `docker exec kali-tools wifi-status` |
| Build Docker lenta | Normal na 1ª vez; cache nas seguintes |
| 401 nas APIs | Login com `CHAT_API_TOKEN` ou header `X-Chat-Token` |
| 429 | Rate limit; aguardar `Retry-After` |

---

## Testes e validação

### Automatizados (29 testes)

```bash
python -m unittest discover -s tests -v
```

| Arquivo | Cobertura |
|---------|-----------|
| `test_core.py` | Whitelist, recon, healing |
| `test_integration.py` | Health, auth, recon TTL, stream hub |
| `test_sse.py` | Chat/autonomous stream, cancel SSE |
| `test_security.py` | Sessão, rate limit, persistência disco |
| `test_kali_mock.py` | Cancel Docker (subprocess mock) |

CI: `.github/workflows/tests.yml` em push/PR para `main`/`master` com `requirements-lock.txt`.

### Checklist manual (release)

**Infra:** `start.bat`/`start.sh` ok · Docker · container `kali-tools` · `/api/health` → `1.0.0`

**Funcional:** chat · execução nmap lab · **cancel** · whitelist bloqueia · log em `backend/logs/`

**Auto-Pilot / report:** missão lab · download `.md`

**Segurança:** `CHAT_API_TOKEN` · login · sessão sobrevive restart

**UI:** hard refresh · sidebar · status bar Docker/Kali

---

## Release e versionamento

| Campo | Valor |
|-------|-------|
| Release estável | **1.0.0** |
| API | `/api/health` → `"version": "1.0.0"` |
| Testes | 29 |

```bash
git tag -a v1.0.0 -m "Chat IA Kali 1.0.0"
git push origin main --tags
```

**Não versionar:** `.env`, `venv/`, `backend/data/`, `backend/logs/`, `backend/recon/`

---

## Changelog

### 1.0.0 — Release estável (2026-07-15)

Versão pública consolidada após ciclo interno v2→v3. Ferramenta local single-user pronta para uso contínuo: chat stream, Auto-Pilot, cancel, auth sessão, 29 testes, `start.bat` + `start.sh`.

### Histórico resumido (desenvolvimento)

| Versão | Destaques |
|--------|-----------|
| **v3.6** | README/host fix, testes sessão + cancel SSE, `start.sh repair` |
| **v3.5** | Backend routers modular, frontend ES6 (`chat.js`, `autopilot.js`, `mission.js`), sessões em disco, cancel no chat |
| **v3.4** | Auth HttpOnly, rate limit, cancel Auto-Pilot, deps pinadas, CI |
| **v3.3** | Testes SSE, `sessions.js`, `tools-panel.js` |
| **v3.2** | SSE compartilhado, Auto-Pilot stream, recon TTL |
| **v3.1** | Hardening `127.0.0.1`, `CHAT_API_TOKEN`, CORS, Smart Healing limitado |
| **v3.0** | Streaming ao vivo, Smart Healing, Recon DB |
| **v2.1** | Migração OpenRouter, seletor modelos, sidebar, Auto-Pilot |
| **v2.0** | Execução vectorizada, summarize, dashboards nmap/nuclei, relatórios |

---

## Licença

### Uso ético

Software fornecido para **fins educacionais e testes autorizados**. Autores não se responsabilizam por uso indevido.

### MIT License

```
MIT License

Copyright (c) 2026 Chat IA Kali

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

O aviso de uso ético permanece válido independentemente da licença MIT.
