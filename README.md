# Chat IA Kali

**Versão estável 1.1.0** — assistente local de pentest com IA que **executa ferramentas reais** no Kali Linux (Docker), não apenas sugere comandos.

Você descreve o objetivo em linguagem natural; a IA (via [OpenRouter](https://openrouter.ai)) interpreta, escolhe a ferramenta, roda no container isolado e devolve análise, dashboards visuais e **relatórios assertivos** (PoC, CVSS, evidências, bundle ZIP). Inclui modo **Auto-Pilot** com metodologia por fases, **Attack Surface Graph**, pipeline de verificação automática, triagem no Intel e auth por sessão HttpOnly.

> **Uso exclusivamente autorizado.** Teste somente sistemas, redes ou aplicações que você possui ou para os quais tem **permissão explícita por escrito**. Uso não autorizado é ilegal. Você é responsável por escopo, conformidade (LGPD, Marco Civil, CFAA equivalentes) e cada comando executado.

---

## Sumário

- [Início rápido](#início-rápido)
- [Escopo v1.1](#escopo-v11)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Interface](#interface)
- [Modos de uso](#modos-de-uso)
- [Assertividade e relatório comercial](#assertividade-e-relatório-comercial)
- [Playbooks](#playbooks)
- [IA, modelos e economia de tokens](#ia-modelos-e-economia-de-tokens)
- [Motor de execução](#motor-de-execução)
- [Segurança e hardening](#segurança-e-hardening)
- [Dados persistidos](#dados-persistidos)
- [API REST](#api-rest)
- [Solução de problemas](#solução-de-problemas)
- [Testes e validação](#testes-e-validação)
- [Observabilidade](#observabilidade)
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
4. Confirme: `GET /api/health` → `"version": "1.1.0"`, `"status": "ok"`.

**Recomendado:** defina `CHAT_API_TOKEN` no `.env` para proteger a API local.

**Testes:** `python -m unittest discover -s tests -v` (**188** testes, cobertura alta, sem Docker/OpenRouter) · E2E: `npm install && npx playwright test -c e2e/playwright.config.js`

---

## Escopo v1.1

Release **1.1.0** fecha o ciclo operacional **scan → recon → artefato → relatório** com auditoria, playbooks, timeline e testes E2E.

| Incluído | Excluído (por enquanto) |
|----------|-------------------------|
| Chat + Auto-Pilot + relatórios enriquecidos | Multi-usuário, RBAC, dashboard consultoria |
| Execução Kali Docker, whitelist, cancel, scope lock + **aviso** | Mitigação automática, SIEM, SOC |
| **Auditoria** JSONL, **playbooks**, **timeline** | ML customizado, multi-agentes paralelos |
| Auth sessão, rate limit, bind `127.0.0.1` | Labs GNS3 / EVE-NG / VMs dinâmicas |
| Intel hub (alvos + triagem + relatórios), mapa Kaspersky separado, file manager, admin de dados | — |
| **UI atual:** triagem por conversa, PDF, Piloto por perfil de scan, modo offensive, assistente Kali no chat | Painel Intel clássico na toolbar (API engagements/surface permanecem) |
| **Pós-1.1.0:** observabilidade, metodologia, teto de assertividade, extractors nmap/nikto, **188 testes** | Prometheus/Grafana, load tests |

---

## Funcionalidades

| Área | Detalhe |
|------|---------|
| **Chat** | Assistente **Kali** (tom consultivo), Markdown, execução real via tools; sidebar recolhível, histórico ↑↓, toasts, status bar |
| **Ferramentas** | 180+ binários na whitelist; painel com categorias, busca; modo `auto` ou ferramenta fixa |
| **Logs / relatório** | Por conversa: modal **Logs** (`Alt+L`) e **Relatório** (`Alt+R`) com triagem (vulnerabilidade / FP / descartar); PDF manual (**Baixar PDF**) |
| **Relatórios (UI)** | Biblioteca local de PDFs baixados (`Alt+F`, IndexedDB); Piloto gera PDF ao fim da missão |
| **Piloto automático** | Alvo + perfil **Básico / Intermediário / Completo / Personalizado**; objetivo padrão por perfil; PDF ao concluir |
| **Modo offensive** | Switch na barra superior (`offensive`): UI vermelha, `risk_profile: full` no Piloto e catálogo ampliado no scan completo |
| **Intel (backend)** | Achados ligados à `chat_session_id` em `backend/intel_sessions/`; sync a partir das execuções do chat; API `/api/intel-sessions/*` |
| **Mapa** | Modal (`mapa` · `Alt+C`): Kaspersky Cybermap — contexto global, separado do chat |
| **Artefatos Kali** | Saídas em `/tools/output` (volume Docker); API `/api/files` — sem painel dedicado na toolbar atual |
| **Execução** | Vectorizada no Docker; streaming SSE `[live]`; Smart Healing; Recon DB por alvo |
| **Admin de dados** | `GET/POST/DELETE /api/data/*` — purge logs/recon/surface/outputs/audit (via API ou utilitários) |
| **Playbooks** | Presets `recon-web` e `port-scan` — API `POST /api/playbooks/{id}/run` (sem seção na UI do Piloto) |
| **Auditoria** | Log append-only em `backend/audit/`; `GET /api/audit` |
| **Tour guiado** | Spotlight (`F1`, `?`, guia na sidebar) — chat, tools, offensive, pilot, logs, triagem, PDFs, mapa |
| **Attack Surface** | Grafo por alvo com dedup (CVE/template-id), findings, baseline de reteste |
| **Triagem (UI)** | Modal **Relatório** por conversa; classificação manual; PDF reflete achados confirmados |
| **Triagem (API)** | Engagements/surface: risk score, verify, buckets executivo/fila humana — `GET /api/engagements/{alvo}/triage` |
| **Extractors** | Achados de nmap (HttpOnly, banners), nikto, paths — além de Nuclei `[sev]`/CVE; backfill via `repair_surface_from_stored_output` |
| **Cancel** | Botão **cancel** interrompe chat stream e Auto-Pilot; mata processo Docker ativo |
| **Relatórios** | Gate rígido (só confirmados no executivo), CVSS/impacto, remediação, delta reteste, metodologia, limitações, ZIP de entrega |
| **Modelos** | Tiers Economia / Equilibrado / Raciocínio; seletor CRT `llm:`; Gemini ↔ DeepSeek; fallback em 429 |
| **Sons CRT** | Bipes sintetizados (Web Audio API); toggle `snd:on`/`snd:off` na status bar |
| **Segurança** | Sessão HttpOnly, rate limit, CORS localhost, `CHAT_API_TOKEN`, **`ALLOWED_TARGETS`** (scope lock) |
| **Health** | Banner dismissível quando Docker/Kali offline; pills `docker:` / `kali:` na status bar |

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (frontend/)                                       │
│  index.html · styles.css · js/main.js + módulos ES6        │
│  (chat, autopilot, session-report-modal, offensive-mode, files, guided-tour, threatmap, …) │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP / SSE
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Backend FastAPI (backend/main.py → routes/)                │
│  auth · system · chat · autonomous · engagements · files · audit · data · playbooks │
│  middleware: request context · rate limit · auth            │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────┐  ┌─────────────────────────────┐
│  IA (backend/ai/)        │  │  Executor (backend/executor/)│
│  agent · autopilot       │  │  kali · logs · summarize     │
│  phases · findings       │  │  recon_db · surface          │
│  verify · nuclei_json    │  │  files_store · data_cleanup  │
│  cvss · evidence         │  │  wifi_scan                   │
│  risk_score · chains     │  │                              │
│  delivery · report · …   │  │                              │
│  OpenRouter + tools      │  │                              │
└──────────────────────────┘  └──────────────┬──────────────┘
               │                              │ docker exec
               │  observability.py            ▼
               │  (logs JSON · métricas)   ┌─────────────────────────────┐
               └──────────────────────────►│  Container kali-tools         │
                                           │  docker/Dockerfile (180+ tools)│
                                           └─────────────────────────────┘
```

### Fluxo de uma mensagem (chat)

1. Frontend envia `POST /api/chat/stream` com `message`, `history`, `preferred_tool`, `model`, `mission_id`.
2. `agent.py` chama OpenRouter com function calling (`run_kali_tool`).
3. `kali.py` valida whitelist → executa no Docker ou Wi-Fi host → salva log → resume output para IA.
4. Eventos SSE: `tool_start`, linhas ao vivo, `tool_done`, `done` (ou `error`).
5. Frontend renderiza resposta, dashboards e blocos `[ok]` / `[exit N]` / `[blocked]`.
6. Iterações até `MAX_TOOL_ITERATIONS`; Smart Healing em falhas; Recon DB e **Attack Surface** atualizados em sucesso.

### Backend — mapa de módulos

```
main.py ──► middleware (request_id, rate limit, auth)
    │
    ├── routes/* ──► ai/ · playbooks/ · security/ · executor/
    │
    ├── ai/          agent · autopilot · phases · findings · verify
    │                nuclei_json · cvss · evidence · risk_score · chains
    │                delivery · remediation · delta · report · …
    ├── executor/    kali · logs · recon_db · surface · files_store
    │                data_cleanup · stream_hub · wifi_scan · …
    ├── routes/      auth · chat · autonomous · engagements · data · …
    ├── security/    sessions · rate_limit · scope · audit · missions
    ├── config.py    facade (env + reexports)
    │     config_tools.py    ALLOWED_TOOLS · TOOL_CATEGORIES
    │     config_prompts.py  SYSTEM_PROMPT · AUTONOMOUS_*
    └── observability.py     logs JSON · métricas · timing
```

Sem ciclos de import estáticos. API estendida com `/api/engagements` e `/api/surface` (assertividade).

### Acoplamentos mitigados (pós-hardening)

| # | Problema | Mitigação |
|---|----------|-----------|
| 1 | `config.py` God Object | Split em `config_tools` + `config_prompts`; facade estável |
| 2 | `agent.py` orquestra tudo | `report.py` + `openrouter_common.py` extraídos |
| 3 | `kali.py` ciclo de vida repetido | `_finalize_stream_result` |
| 4 | Autopilot importava privados do agent | Imports públicos + `openrouter_common` |
| 5 | Auth/config por valor (patch frágil em testes) | Mantido; helper `tests/auth_patch.py` |

---

## Estrutura do repositório

```
Chat IA Kali/
├── backend/
│   ├── main.py              # Entry FastAPI
│   ├── config.py            # .env + facade (reexporta tools/prompts)
│   ├── config_tools.py · config_prompts.py
│   ├── observability.py     # logs JSON, request ID, métricas
│   ├── schemas.py · deps.py · middleware.py
│   ├── routes/              # auth, system, chat, autonomous, engagements, files, audit, data, playbooks
│   ├── security/            # sessions, rate_limit, missions, scope, audit
│   ├── playbooks/           # recon-web.yaml, port-scan.yaml, loader.py
│   ├── ai/                  # agent, autopilot, phases, verify, nuclei_json, cvss,
│   │                        # evidence, risk_score, chains, delivery, report, …
│   ├── executor/            # kali, logs, summarize, recon_db, surface, files_store,
│   │                        # data_cleanup, stream_hub, wifi_scan, …
│   ├── audit/               # eventos JSONL (gitignored)
│   ├── data/                # sessões auth (gitignored)
│   ├── logs/ · recon/ · surface/ · outputs/   # gitignored (evidence/ e delivery/ em outputs/)
├── frontend/
│   ├── index.html · styles.css
│   └── js/                  # main, chat, autopilot, session-report-modal, offensive-mode,
│                            # files (PDFs), guided-tour, threatmap, session-logs-modal, …
├── docker/                  # Dockerfile, compose (+ volume outputs)
├── e2e/                     # Playwright smoke tests
├── tests/                   # 188 testes unitários + auth_patch helper
├── scripts/docker-check.ps1 # Docker com timeout (Windows)
├── start.bat · start.sh
├── package.json             # ESLint + Playwright (dev)
├── requirements.txt · requirements-dev.txt · pyproject.toml
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
| `start.bat quick` / `start.bat menu` | Só sobe o servidor + menu interativo (**R** reinicia uvicorn, **K** reinicia Kali, **Q** sai) |
| `start.bat restricted` / `./start.sh restricted` | Docker perfil B (sem Wi-Fi, hardening agressivo) |

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
| `OPENROUTER_FALLBACK_MODEL` | `deepseek/deepseek-v3.2` | Fallback em erro/cota |
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
| `ALLOWED_TARGETS` | vazio | Scope lock: lista de alvos permitidos (vazio = sem restrição + aviso na UI) |
| `RISK_PROFILE` | `safe-active` | Auto-Pilot: `passive` / `safe-active` / `full` (bloqueia tools agressivas) |
| `VERIFY_MAX_FINDINGS` | `40` | Teto do pipeline PoC (high/critical sempre entram; máx 80) |
| `REPORT_BRAND_NAME` | `Chat IA Kali` | Marca padrão nos relatórios HTML/Markdown |
| `TRUST_PROXY` | off | Se `true`, usa `X-Forwarded-For` para IP (só atrás de proxy confiável) |
| `LOG_LEVEL` | `INFO` | Nível dos logs JSON (`DEBUG`/`INFO`/`WARNING`/`ERROR`) |
| `OUTPUTS_DIR` | `backend/outputs` | Pasta host dos artefatos (montada em `/tools/output` no Kali) |
| `MAX_FILE_DOWNLOAD_MB` | `50` | Limite de download no file manager |
| `SESSION_TTL_HOURS` | `24` | TTL cookie de sessão |
| `RATE_LIMIT_REQUESTS` | `30` | Requisições por janela |
| `RATE_LIMIT_WINDOW_SEC` | `60` | Janela rate limit |

**Produção local recomendada:** `CHAT_API_TOKEN` forte + `UVICORN_HOST=127.0.0.1`. Não exponha na internet sem TLS, reverse proxy e auth robusta.

---

## Interface

### Layout (tema CRT)

Interface estilo terminal fosforescente (`kali@pentest:~$`), scanlines, boot sequence na sessão nova e relógio na status bar.

| Área | Conteúdo |
|------|----------|
| **Sidebar** | Conversas, `$` novo chat, guia (`F1`); **recolhível** no desktop (`M` ou `‹`/`›`) — vira rail estreita (~52px) com ícones e iniciais das sessões; no mobile vira gaveta overlay |
| **Barra superior** | `tools` · `pilot` · switch **`offensive`** · `stop` · **`relatórios`** · **`mapa`** · `?` · `+` |
| **Prompt** | Entrada + ícones **logs** / **relatório** + seletor `llm:` (tiers Economia / Equilibrado / Raciocínio) |
| **Status bar** | `docker:` · `kali:` · relógio · status · **`snd:on`/`snd:off`** |
| **Health banner** | Aviso dismissível quando Docker ou container Kali estão offline |
| **Scope banner** | Aviso persistente quando `ALLOWED_TARGETS` está vazio |
| **Terminal** | Mensagens (Markdown), execuções `[live]`, dashboards Nmap/Nuclei |

### Logs e relatório (por conversa)

| Recurso | Atalho | Função |
|---------|--------|--------|
| **Logs** | `Alt+L` | Execuções da conversa ativa |
| **Relatório** | `Alt+R` | Triagem de achados + **Baixar PDF** |
| **Relatórios** | `Alt+F` | Biblioteca de PDFs no navegador |

### Modo offensive e Piloto

Switch **offensive** na barra (tema vermelho, catálogo ampliado no Piloto). **Piloto** (`Alt+P`): alvo + tipo de scan; PDF ao concluir a missão.

A API `/api/engagements/*` (hub Intel antigo na UI) segue disponível para fluxos comerciais avançados.

### Mapa de ameaças (`mapa` · `Alt+C`)

Modal **separado** do Intel com [Kaspersky Cybermap](https://cybermap.kaspersky.com/pt). Modos **live** e **globe**; arraste o globo; link para mapa completo.

### Fluxo consultoria (resumo)

```
Chat / Piloto → execuções + extractors → achados por conversa (intel_sessions)
        → triagem no modal Relatório → PDF (POST /api/generate-report)
Engagements API (opcional) → surface.json → PoC / verify → relatório comercial .md/.html/.zip
```

### Artefatos no container (`/tools/output`)

Peça à IA para salvar com caminho explícito; download via `GET /api/files`:

```text
nmap -oA /tools/output/scanme scanme.nmap.org
```

### Tour guiado e onboarding

| Recurso | Quando |
|---------|--------|
| **Tour guiado** (`F1`, `?`, **guia** na sidebar) | Spotlight: chat, tools, offensive, pilot, logs, triagem, PDFs, mapa |
| **Onboarding** (primeira visita) | 3 passos: health Docker/Kali, escopo `ALLOWED_TARGETS`, primeiro comando sugerido |
| **Atalhos avançados** | No fim do tour — abre `man kali-ai` com lista completa de teclas |

### Sons CRT (`snd:on` / `snd:off`)

Efeitos sintetizados via **Web Audio API** (sem arquivos `.mp3`). Feedback em envio de mensagem, fim de execução (`[ok]` / `[exit N]` / `[blocked]`), toasts e abertura de painéis. Desligado com `prefers-reduced-motion` ou pelo botão na status bar. Preferência em `localStorage` (`chat-ia-kali-sound`).

### Atalhos

| Atalho | Ação |
|--------|------|
| `Alt+T` | Ferramentas |
| `Alt+P` | Piloto automático |
| `Alt+L` | Logs da conversa |
| `Alt+C` | Mapa Kaspersky |
| `Alt+F` | Biblioteca de relatórios PDF |
| `Alt+R` | Relatório / triagem da conversa |
| `Alt+N` | Novo chat |
| `Alt+H` / `F1` | Tour guiado |
| `Alt+K` / `Ctrl+K` | Focar prompt |
| `M` | Recolher/expandir sidebar (desktop) ou gaveta (mobile) |
| `Esc` | Fechar painéis / sair do tour |
| `↑` / `↓` | Histórico da sessão |
| `snd` (status bar) | Ligar/desligar sons CRT |

Alternativas: `Ctrl+Shift+T/P/E/N`. Usar `Alt+*` evita conflito com o navegador (Ctrl+T abre aba, Ctrl+R recarrega).

**Persistência no navegador:** `chat-ia-kali-sessions`, `chat-ia-kali-model`, `chat-ia-kali-sound`, `chat-ia-kali-sidebar-collapsed`, `chat-ia-kali-pilot-offensive`.

---

## Modos de uso

### Chat interativo

Digite no prompt ou use o painel **tools** para fixar ferramenta e preencher exemplo. A IA executa via `run_kali_tool` quando o pedido exige dados técnicos.

**Streaming (padrão):** `POST /api/chat/stream` — preferido; suporta logs ao vivo e cancel.

**Clássico:** `POST /api/chat` — resposta JSON única (sem SSE).

### Cancelamento

Durante chat ou Auto-Pilot, o botão **cancel** envia `AbortController` no cliente e `POST /api/missions/{mission_id}/cancel` no servidor, matando o processo Docker registrado.

### Auto-Pilot (metodologia + assertividade)

1. `Alt+P` → **alvo** + **tipo de scan** (ou Personalizado com ferramentas marcadas)
2. Ative **`offensive`** na barra se precisar do catálogo completo no scan Completo
3. **Iniciar missão com IA** — fases automáticas + Attack Surface no backend
4. PDF ao encerrar; triagem em **Relatório** (`Alt+R`) → **Baixar PDF** quando quiser reexportar

| Fase | O que faz | Ferramentas típicas |
|------|-----------|---------------------|
| `recon` | Hosts / subdomínios / OSINT | subfinder, amass, dig, whois, httpx |
| `enumerate` | Portas, serviços, URLs | nmap, httpx, gobuster, ffuf, whatweb |
| `vuln_scan` | Candidatos a vulnerabilidade | nuclei **`-jsonl`**, nikto, sslscan, wpscan |
| `verify` | Confirma ou descarta candidatos | curl, httpx, nuclei, nmap |
| `report` | Resumo → `finish_mission` | (sem novas tools) |

**Perfis de risco** (`RISK_PROFILE` ou body `risk_profile`):

| Perfil | Uso |
|--------|-----|
| `passive` | Só OSINT — sem nmap/nuclei/brute |
| `safe-active` (**padrão**) | Scans ativos sem sqlmap/hydra/metasploit |
| `full` | Whitelist completa (ainda limitado por `ALLOWED_TARGETS`) |

Eventos SSE: `phase_change`, `verify_start`, `verify_done`, `verify_summary`.

**Endpoint:** `POST /api/autonomous/stream` (SSE) ou `POST /api/autonomous` (JSON).

---

## Assertividade e relatório comercial

Pipeline pensado para **consultoria solo**: máximo de automação mecânica, revisão humana só na fila crítica.

### Ciclo de um finding

```
candidate → PoC pass 1 → confirmed | false_positive | inconclusive
inconclusive → PoC pass 2 → confirmed | false_positive | discarded | inconclusive (WAF)
WAF/inconclusivo → PoC pass 3 (UA alternativo) → fila humana ou fechamento
```

| Status | No executivo do cliente? |
|--------|--------------------------|
| `confirmed` (gate rígido) | **Sim** — high, ou medium + template/CVE + PoC/multi-fonte |
| `confirmed` (confiança baixa) | Não — vai para **fila humana** na triagem |
| `false_positive` | Não — anexo técnico |
| `discarded` | Não — anexo técnico |
| `inconclusive` / WAF | Não — **fila humana** (revisar antes de entregar) |

### O que o pipeline extrai e prova

| Camada | Detalhe |
|--------|---------|
| **Nuclei JSON** | `-jsonl` → `template-id`, `matched-at`, `curl-command`, CVSS do template |
| **Dedup** | Correlação por CVE → template-id → título; merge de fontes (`sources`) |
| **PoC tipado** | `nuclei -id <template>`; pass 2 pode usar `curl-command` do JSON |
| **CVE × versão** | Versões do `nmap -sV` no surface; correlação heurística (sem NVD online) |
| **Evidências** | Arquivo por finding: `outputs/evidence/{alvo}/{id}.txt` |
| **CVSS / impacto / esforço** | Por achado confirmado |
| **Risk score** | 0–100 + faixa (Crítico / Alto / Médio / Baixo) |
| **Cadeias A+B** | Hipóteses compostas (ex.: exposição + HSTS + CVE) — sinal, não confirmação |
| **Delta reteste** | Baseline vs confirmados atuais (corrigidos / novos / abertos) |

### Gate executivo (rígido)

Entra no sumário para o cliente apenas se:
- `confidence: high`, **ou**
- `confidence: medium` **e** (`template_id` ou CVE) **e** PoC registrado **ou** `sources ≥ 2`

### Estrutura do relatório (`GET /api/engagements/{alvo}/report`)

1. Escopo e **limitações** (o que a automação não cobre)
2. Metodologia (PTES / OWASP WSTG)
3. **Resumo executivo** (derivado dos confirmados — não do chat)
4. Comandos executados
5. Achados confirmados (CVSS, impacto, esforço, PoC, pacote de evidência)
6. Fila humana (se houver)
7. Hipóteses de cadeia
8. Delta de reteste
9. Remediações por achado
10. Anexo — FP e descartados
11. Recon · artefatos · logs · disclaimer

### Entrega ao cliente

| Formato | Como |
|---------|------|
| **Markdown** | `?format=md` ou botão **report** da sessão |
| **HTML / PDF** | `?format=html` ou **triage → .html** → imprimir (Ctrl+P) |
| **ZIP bundle** | `?format=zip` ou **triage → .zip** — `relatorio.md`, `relatorio.html`, `evidencias/`, `delta.json`, `surface.json`, `meta.json` |

### Engajamento (metadados)

```json
POST /api/engagements
{
  "target": "lab.cliente.com",
  "objective": "Pentest externo web",
  "client": "Empresa XYZ",
  "scope_notes": "Apenas *.cliente.com em produção",
  "risk_profile": "safe-active",
  "brand_name": "Sua Marca Consultoria"
}
```

`POST /api/engagements/{alvo}/baseline` congela confirmados para o **próximo reteste**.

### O que ainda exige você

- Credenciais / testes autenticados
- Impacto de negócio e validação de críticos
- IDOR, lógica de aplicação, cadeias complexas
- Revisão da **fila humana** antes de enviar ao cliente

---

### Relatório de sessão (chat / piloto)

- **Triagem:** ícone de relatório na barra do prompt → classificar achados → **Baixar PDF** no rodapé do modal  
- **Geração:** `POST /api/generate-report` com histórico, `tool_executions`, `chat_session_id`, `surface_target`  
- Se houver Attack Surface para o alvo, usa o motor assertivo; senão, fallback por extractors nos logs  
- **Piloto:** PDF automático ao fim da missão; cópias em **Relatórios** (`Alt+F`)

### Exemplos práticos

| Ação | Resultado |
|------|-----------|
| *"Liste redes Wi-Fi"* | `wlan-scan` via `netsh` (Windows host) |
| *"Scan SYN em scanme.nmap.org"* | `nmap` no container + dashboard |
| *"Subdomínios de example.com"* | `subfinder` / `amass` |
| **pilot** + alvo lab | Missão por perfil de scan → PDF + triagem no modal Relatório |
| **Relatório** (`Alt+R`) | Sync achados · classificar · Baixar PDF |
| Tier **Economia** | Modelo mais barato (Flash-Lite / DeepSeek V3.2) |

---

## Playbooks

Presets em `backend/playbooks/*.yaml` (schema em `playbook.schema.json` — **não** é Ansible). Na UI ficam na seção **Roteiros fixos (opcional)** do Auto-Pilot; também disponíveis via API.

Ao final de cada playbook: atualiza o **Attack Surface Graph** e dispara o **pipeline PoC** (mesmo motor do Auto-Pilot).

| ID | Descrição |
|----|-----------|
| `recon-web` | `subfinder` → `httpx` no alvo |
| `port-scan` | `nmap -sV -oA /tools/output/nmap-{alvo}` |

Placeholders nos YAML:

| Placeholder | Uso |
|-------------|-----|
| `{target}` | Alvo original (domínio/IP) |
| `{target_safe}` | Nome sanitizado para arquivos em `/tools/output/` |

```bash
GET /api/playbooks
POST /api/playbooks/port-scan/run   # body: { "target": "scanme.nmap.org" }
```

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
| **Scope lock** | Com `ALLOWED_TARGETS` no `.env`, comandos só rodam se o alvo estiver na lista (`backend/security/scope.py`) |
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

Imagem Debian Bookworm slim: APT + binários Go + repos Git + pip (Impacket, nxc, nuclei templates, SecLists). Compose: `privileged`, `network_mode: host`, caps `NET_ADMIN`/`NET_RAW`, USB `/dev/bus/usb`, volume **`../backend/outputs:/tools/output`** para artefatos persistentes.

Categorias na UI: Rede, OSINT, Web, SSL, Senhas, AD, Wi-Fi, Vuln, Forense, Automação, Utilitários.

---

## Segurança e hardening

### Checklist rápido

- [ ] `.env` nunca commitado (`OPENROUTER_API_KEY`, `CHAT_API_TOKEN`)
- [ ] `ALLOWED_TARGETS` definido para alvos autorizados (recomendado mesmo em lab)
- [ ] `CHAT_API_TOKEN` ativo se exposto além de localhost
- [ ] Rotacionar token após compartilhar ambiente
- [ ] Revisar trilha em `backend/audit/` ou `GET /api/audit`
- [ ] Artefatos sensíveis em `backend/outputs/` fora de backups públicos

### Escopo (`ALLOWED_TARGETS`)

- **Vazio:** sem restrição — UI exibe banner de aviso (modo lab).
- **Preenchido:** comandos, Auto-Pilot e playbooks só aceitam alvos na lista.

```env
ALLOWED_TARGETS=scanme.nmap.org,10.0.0.0/24,lab.local
```

### Auditoria

Cada execução gera evento append-only em `backend/audit/events-YYYY-MM-DD.jsonl`:

- timestamp, ferramenta, comando, alvos, status, `mission_id`, `log_file_id`
- segredos redigidos automaticamente

### Admin de dados (`/api/data`)

Categorias de purge (`POST /api/data/purge` com `confirm: true`):

| Categoria | Remove |
|-----------|--------|
| `logs` | Arquivos em `backend/logs/` |
| `recon` | Cache `backend/recon/{alvo}.json` |
| `surface` | Attack Surface `backend/surface/{alvo}.json` |
| `outputs` | Artefatos gerais em `backend/outputs/` (exceto evidence/delivery se categorias separadas) |
| `evidence` | Pacotes de prova `outputs/evidence/` |
| `delivery` | ZIPs de entrega `outputs/delivery/` |
| `audit` | JSONL em `backend/audit/` |

Opcional: filtrar por `target` em recon/surface. Exclusões individuais via `DELETE` por recurso.

### File manager

- Anti path-traversal (`files_store.py`)
- Whitelist de extensões
- Limite de download: `MAX_FILE_DOWNLOAD_MB` (padrão 50)

### Docker — perfis

| Perfil | Como subir | Privileges | Uso |
|--------|------------|------------|-----|
| **A — Wi-Fi / completo** (padrão) | `start.bat` / `./start.sh` ou `docker compose up -d` | `privileged`, host network, USB, caps NET_* + SYS_ADMIN | Lab com monitor mode / aircrack |
| **B — Restrito** | `start.bat restricted` / `./start.sh restricted` ou `docker compose -f docker-compose.restricted.yml up -d` | user `1000` (não-root), sem privileged, `no-new-privileges`, `cap_drop: ALL` + NET_RAW/NET_ADMIN, `read_only` + tmpfs | Scans/recon sem Wi-Fi |

**Ambos os perfis:** `mem_limit`, `cpus`, `pids_limit`, `healthcheck` (`nmap --version`).

Trade-off do perfil A: privilégios elevados ≈ controle próximo ao host — use só em lab dedicado.

### Autenticação

- `CHAT_API_TOKEN` protege `/api/*` (exceto health, client-config, login)
- Sessões HttpOnly com TTL (`SESSION_TTL_HOURS`)
- Rate limit: `RATE_LIMIT_REQUESTS` / `RATE_LIMIT_WINDOW_SEC`

---

## Dados persistidos

| Caminho | Conteúdo | Versionado |
|---------|----------|------------|
| `backend/logs/{id}.log` | Output completo de cada execução | Não |
| `backend/recon/{alvo}.json` | Portas, CVEs, achados por alvo (cache legado para chat) | Não |
| `backend/surface/{alvo}.json` | Attack Surface Graph (fases, findings, baseline, engajamento) | Não |
| `backend/outputs/evidence/` | Pacotes de prova por finding (`{id}.txt`) | Não |
| `backend/outputs/delivery/` | ZIPs de entrega gerados | Não |
| `backend/outputs/` | Demais artefatos (`/tools/output` no Kali) | Não |
| `backend/audit/` | Trilha de auditoria (JSONL por dia) | Não |
| `backend/data/sessions.json` | Sessões auth HttpOnly | Não |
| `localStorage` (browser) | Conversas, modelo e preferência de som | N/A |

Recon: extraído após execuções bem-sucedidas; injetado no prompt quando o usuário menciona o mesmo alvo. Entradas expiradas removidas por `RECON_TTL_DAYS`.

Surface: atualizado a cada execução (chat, Auto-Pilot, playbook); extractors para nmap/nikto além de Nuclei; alimenta triagem, verify e relatório comercial. Backfill: `repair_surface_from_stored_output(alvo)`.

**Não versionar:** além dos paths acima, `backend/surface/*.json` e `backend/outputs/**` (exceto `.gitkeep`).

---

## API REST

Base: `http://127.0.0.1:8000`. Com `CHAT_API_TOKEN`, rotas `/api/*` exigem cookie `kali_session` (via `POST /api/auth/login`) ou header `X-Chat-Token`.

### Referência

| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/health` | Status Docker, Kali, Wi-Fi, `version` |
| GET | `/api/metrics` | Contadores leves (requests, erros, tools, LLM); requer auth se `CHAT_API_TOKEN` |
| GET | `/api/client-config` | `authRequired`, host, port |
| GET | `/api/tools` | Categorias + metadados UI |
| GET | `/api/models` | Tiers Gemini/DeepSeek |
| GET | `/api/recon` | Lista alvos com recon em cache |
| GET | `/api/recon/{target}` | Detalhe recon (portas, CVEs, achados) |
| GET | `/api/surface` | Lista Attack Surface Graphs |
| GET | `/api/surface/{target}` | Grafo completo (hosts, ports, urls, findings) |
| POST | `/api/engagements` | Cria engajamento (cliente, escopo, marca, perfil) |
| GET | `/api/engagements/{target}` | Estado + surface + gate + delta |
| PATCH | `/api/engagements/{target}` | Atualiza cliente/escopo/marca/objetivo |
| PATCH | `/api/engagements/{target}/phase` | Força fase (debug/manual) |
| GET | `/api/engagements/{target}/triage` | Buckets: executive / human_queue / archive |
| GET | `/api/engagements/{target}/delta` | Delta vs baseline (corrigidos/novos/abertos) |
| POST | `/api/engagements/{target}/baseline` | Congela confirmados como baseline |
| GET | `/api/engagements/{target}/report` | Relatório `?format=md\|html\|zip` (HTML→PDF; ZIP=bundle) |
| GET | `/api/engagements/{target}/risk` | Risk score 0–100 do engajamento |
| POST | `/api/engagements/{target}/findings/{id}` | Marca finding (`confirmed` / `false_positive` / `discarded` / …) |
| POST | `/api/engagements/{target}/verify` | Pipeline PoC (`?max_findings=`) |
| GET | `/api/files` | Lista artefatos em `OUTPUTS_DIR` |
| GET | `/api/files/{path}` | Download de artefato (path validado, anti-traversal, limite MB) |
| GET | `/api/audit` | Trilha de auditoria (JSONL, `?limit=&date=`) |
| GET | `/api/data/summary` | Resumo de storage (logs, recon, surface, outputs, audit, …) |
| GET | `/api/data/logs` | Lista logs de execução (`?limit=`) |
| POST | `/api/data/purge` | Purge por categoria — body: `{ "categories": [...], "target": "opcional", "confirm": true }` |
| DELETE | `/api/data/logs/{id}` | Exclui log de execução (+ entrada na auditoria) |
| DELETE | `/api/data/recon/{target}` | Exclui cache recon do alvo |
| DELETE | `/api/data/surface/{target}` | Exclui Attack Surface / engajamento do alvo |
| DELETE | `/api/data/files/{path}` | Exclui artefato em `OUTPUTS_DIR` |
| DELETE | `/api/data/audit` | Purge auditoria (`?all=true` ou `?date=YYYY-MM-DD`) |
| GET | `/api/playbooks` | Lista playbooks pré-definidos |
| POST | `/api/playbooks/{id}/run` | Executa playbook em alvo autorizado |
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
  "fallback_model": "deepseek/deepseek-v3.2",
  "mission_id": "uuid-opcional-para-cancel"
}
```

**Auto-Pilot:**

```json
{
  "target": "scanme.nmap.org",
  "objective": "Mapear portas abertas e serviços web",
  "mission_id": "uuid-opcional",
  "risk_profile": "safe-active"
}
```

**Health (exemplo):**

```json
{
  "status": "ok",
  "version": "1.1.0",
  "docker": true,
  "kali_container": true,
  "scope_lock_enabled": false,
  "scope_warning": true,
  "wifi_ready": true
}
```

**SSE — eventos chat:** `tool_start`, `tool_done`, `done`, `error`. Auto-Pilot adiciona `mission_start`, `round_start`, `phase_change`. Campo `stopped_reason` em `done` pode ser `completed`, `cancelled`, `objective_met`, etc.

---

## Solução de problemas

| Sintoma | Ação |
|---------|------|
| Docker não responde | Abrir Docker Desktop; `start.bat repair` ou `./start.sh repair` |
| Kali off | `cd docker && docker compose up -d --build`; ver `/api/health` |
| IA não responde | Verificar `OPENROUTER_API_KEY`; tier Economia; saldo OpenRouter |
| `[blocked]` | Ferramenta fora da whitelist ou `..` nos args |
| CSS/JS antigo | Hard refresh `Ctrl+Shift+R` (cache-bust em `?v=` nos assets) |
| Arquivos vazios em **files** | Recrie o container após alterar `docker-compose.yml` (`docker compose up -d --build`) |
| Mapa Kaspersky sem interação | Use botão **mapa** ou `Alt+C` (modal separado) · modo **globe**; arraste o globo |
| Sem som | Clique na página uma vez (política do browser); verifique `snd:on` |
| Wi-Fi container vazio | Dongle USB; `docker exec kali-tools wifi-status` |
| Build Docker lenta | Normal na 1ª vez; cache nas seguintes |
| 401 nas APIs | Login com `CHAT_API_TOKEN` ou header `X-Chat-Token` |
| 429 | Rate limit; aguardar `Retry-After` |

---

## Testes e validação

### Automatizados (188 testes unitários)

```bash
python -m unittest discover -s tests -v
# Com cobertura (CI fail_under ≥ 95%):
coverage run -m unittest discover -s tests -q && coverage report
```

### E2E (Playwright)

```bash
npm install
npx playwright install chromium
# Com servidor rodando em 127.0.0.1:8000:
npx playwright test -c e2e/playwright.config.js
```

| Arquivo | Cobertura |
|---------|-----------|
| `test_core.py` | Whitelist, recon, healing, **scope lock** |
| `test_integration.py` | Health, auth, recon TTL, stream hub, **files API** |
| `test_sse.py` | Chat/autonomous stream, cancel SSE |
| `test_security.py` | Sessão, rate limit, persistência disco |
| `test_audit.py` | Auditoria JSONL e API |
| `test_playbooks.py` | Playbooks YAML e scope |
| `test_openapi.py` | Contrato OpenAPI v1.1 |
| `test_observability.py` | Request ID, métricas, logs JSON, imports P0, block/path traversal |
| `test_autopilot_unit.py` | Auto-Pilot cancel/finish com mocks |
| `test_security_proxy.py` | TRUST_PROXY, audit client_ip, files traversal, OpenRouter helpers |
| `test_agent_unit.py` | Chat agent mockado, cancel, relatório, concorrência de missões |
| `test_kali_mock.py` | Cancel mata processo Docker |
| `test_coverage_*.py` | Cobertura restante (executor, rotas, agent, autopilot) |
| `test_methodology.py` | Fases, risk profile, Attack Surface, API engagements |
| `test_verify_pipeline.py` | PoC, scoring, fechamento assertivo, seções do relatório |
| `test_assertiveness.py` | Dedup, remediação, delta, WAF, triage/export API |
| `test_max_assertiveness.py` | Nuclei JSON, CVSS, gate rígido, evidências, ZIP, risk/chains |
| `test_data_cleanup.py` | API `/api/data`, purge, exclusão logs/recon/surface/arquivos |
| `test_tool_findings_extract.py` | Extractors nmap/nikto/HttpOnly/banners → surface |

### Matriz por módulo

| Módulo | Cobertura | Arquivos de teste |
|--------|-----------|-------------------|
| `security/` (scope, auth, proxy, audit) | Alta | `test_security*`, `test_audit`, `test_core` |
| `executor/` (kali, files, stream) | Alta | `test_kali_mock`, `test_observability`, `test_integration`, `test_coverage_*` |
| `ai/` (agent, autopilot, healing) | Alta | `test_agent_unit`, `test_autopilot_unit`, `test_core`, `test_coverage_*` |
| `routes/` + OpenAPI | Alta | `test_integration`, `test_openapi`, `test_playbooks` |
| `observability` | Alta | `test_observability` + E2E `observability.spec.js` |
| Frontend (smoke) | Básica | `e2e/smoke.spec.js` |

### CI/CD

Pipeline em `.github/workflows/tests.yml` (qualquer etapa falha → workflow falha):

| Job | O que faz |
|-----|-----------|
| `lint` | `ruff check` + `ruff format --check` |
| `security` | Bandit (high/critical) + Semgrep (OWASP + secrets) |
| `unit` | unittest + coverage (≥ 95%) |
| `docker-config` | Valida sintaxe compose A/B (**bloqueante**) |
| `e2e` | Playwright smoke + observabilidade (aguarda `/api/health`) |
| `docker-build` | Build imagem Kali restrita (continue-on-error — pesado/flaky) |

Comandos locais equivalentes:

```bash
pip install -r requirements-dev.txt
ruff check backend tests && ruff format --check backend tests
bandit -r backend -ll -ii
python -m coverage run -m unittest discover -s tests -q && coverage report
```

### Checklist manual (release)

**Infra:** `start.bat`/`start.sh` ok · Docker · container `kali-tools` · `/api/health` → `1.1.0`

**Funcional:** chat · execução nmap lab · **cancel** · whitelist bloqueia · log em `backend/logs/`

**Auto-Pilot / assertividade:** missão lab · **intel** (hub + verify) · export `.html` e `.zip` · revisar fila humana

**Segurança:** `CHAT_API_TOKEN` · login · sessão sobrevive restart · purge dados via Intel → Limpar dados

**UI:** hard refresh · sidebar recolhível (rail) · status bar Docker/Kali · **intel** hub · **files** · **mapa** · tour guiado · sons CRT

---

## Observabilidade

Módulo central: `backend/observability.py`.

| Campo / métrica | Onde | Interpretação |
|-----------------|------|---------------|
| Header `X-Request-ID` | Resposta HTTP (gerado ou propagado) | Correlacionar uma requisição nos logs |
| `request_id` / `correlation_id` | Logs JSON no stderr | Filtrar uma sessão/missão |
| `duration_ms` + `path` | Middleware HTTP | Latência por endpoint |
| `op=tool_execution` / `llm_call` / `docker_exec` | Logs timing | Tempo de ferramenta, IA e Docker |
| `GET /api/metrics` | Contadores em memória | `requests_total`, `errors_total`, `tool_executions_total`, `llm_calls_total`, `cancellations_total`, `docker_ops_total` |

Exemplo de log:

```json
{"ts":"2026-07-16T17:00:00+00:00","level":"INFO","module":"chat_ia_kali","message":"request_completed","request_id":"a1b2c3d4e5f67890","correlation_id":"a1b2c3d4e5f67890","duration_ms":12.4,"path":"/api/health","method":"GET","status_code":200}
```

Variável opcional: `LOG_LEVEL` (padrão `INFO`). Segredos são redigidos nos logs.

---

## Release e versionamento

| Campo | Valor |
|-------|-------|
| Release estável | **1.1.0** |
| API | `/api/health` → `"version": "1.1.0"` |
| Testes | 188 unit · 5 E2E |
| Documentação | Este README |

```bash
git tag -a v1.1.0 -m "Chat IA Kali 1.1.0"
git push origin main --tags
```

**Não versionar:** `.env`, `venv/`, `node_modules/`, `backend/data/`, `backend/logs/`, `backend/recon/`, `backend/audit/`, `backend/outputs/*`, `test-results/`

---

## Changelog

### Pós-1.1.0 — UI conversa, Piloto e relatório (2026-07)

| Área | O que entrou |
|------|----------------|
| **Chat** | Persona assistente Kali; menos “runner de comandos” seco |
| **Piloto** | Modal só com alvo + tipo de scan (básico/intermediário/completo/personalizado); PDF ao fim |
| **Offensive** | Switch na barra principal; tema vermelho; `risk_profile: full` no Piloto |
| **Relatório** | Modal amplo por conversa; triagem sem auto-download; rodapé **Baixar PDF** |
| **Relatórios** | `Alt+F` = biblioteca IndexedDB de PDFs (não artefatos `/tools/output` na UI) |
| **Dev** | `start.bat quick` / menu **R/K/Q** via `start.ps1` |
| **Tour** | `guided-tour.js` alinhado à toolbar atual |

### Pós-1.1.0 — UI Intel, dados e persistência (2026-07-16)

| Área | O que entrou |
|------|----------------|
| **Intel hub** | Lista de alvos + detalhe/triagem; subpainéis logs, timeline, audit, limpar dados |
| **Mapa separado** | Modal próprio (`mapa` / `Alt+C`) — fora do Intel |
| **Files** | Modal simples agrupado por pasta; busca e exclusão |
| **Auto-Pilot** | Fluxo alvo → objetivo → missão IA; playbooks em seção opcional |
| **Sidebar** | Rail recolhível (~52px) com ícones; `M` / `‹`/`›` / ☰ |
| **Tour guiado** | Spotlight interativo (`guided-tour.js`) + onboarding primeira visita |
| **Extractors** | Achados nmap/nikto/HttpOnly/banners em `surface.py`; backfill de logs |
| **API dados** | `/api/data/*` — summary, purge, delete logs/recon/surface/files/audit |
| **Modelo DeepSeek** | ID atualizado para `deepseek/deepseek-v3.2` |
| **Testes** | +`test_data_cleanup`, +`test_tool_findings_extract` → **188** testes |

Módulos frontend: `targets-hub.js`, `data-admin.js`, `guided-tour.js`, `logs-panel.js`, `row-actions.js`. Backend: `routes/data.py`, `executor/data_cleanup.py`.

### Pós-1.1.0 — Teto prático de assertividade (2026-07-16)

| Área | O que entrou |
|------|----------------|
| **Nuclei JSON** | `-jsonl` → template-id, matched-at, curl-command, CVSS do template |
| **Gate rígido** | Executivo: high, ou medium+template/CVE+PoC/multi-fonte |
| **PoC** | Até 3 passes; pass 3 WAF com UA alternativo |
| **CVSS / impacto / esforço** | Por achado; versão nmap no surface |
| **Evidências** | `outputs/evidence/{alvo}/{id}.txt` |
| **Risk score + cadeias** | Score 0–100; hipóteses A+B no relatório/triagem |
| **Relatório comercial** | Escopo, metodologia, executivo estruturado, limitações, disclaimer |
| **Entrega ZIP** | `?format=zip` → md+html+evidências+delta+surface |
| **UI triage** | Risk, chains, export `.zip` |

Módulos: `ai/nuclei_json.py`, `ai/cvss.py`, `ai/evidence.py`, `ai/risk_score.py`, `ai/chains.py`, `ai/delivery.py`.

### Pós-1.1.0 — Assertividade e triagem (2026-07-16)

Dedup, PoC tipado, remediação, delta, triage UI, playbooks→verify — base do teto acima.

### Pós-1.1.0 — Metodologia Auto-Pilot (2026-07-16)

**Attack Surface Graph** + **fases** + **pipeline PoC**:

- Fases: `recon` → `enumerate` → `vuln_scan` → `verify` → `report`
- Perfis: `passive` / `safe-active` / `full` (`RISK_PROFILE`)
- Pipeline: candidato → PoC → `confirmed` / `false_positive` / `inconclusive` → re-PoC → `discarded` (exceto fila WAF)
- API base: `/api/surface`, `/api/engagements`, `/api/engagements/{t}/verify`
- SSE: `phase_change`, `verify_*`

Objetivo: ~90%+ operacional + máxima assertividade; você revisa só a fila humana e críticos.

### Pós-1.1.0 — Robustez e qualidade (2026-07-16)

Ciclo de hardening pós-release **1.1.0**: correções P0, refatoração do backend, observabilidade, Docker endurecido, CI ampliado e suíte de testes levada a **~100% de cobertura** no `backend/`. Mapa de módulos e acoplamentos: seção [Arquitetura](#arquitetura).

#### Correções críticas

| Arquivo | Problema | Impacto |
|---------|----------|---------|
| `ai/agent.py` | Faltava import de `get_stream_hub` | Execução real de ferramentas quebrava em runtime |
| `ai/autopilot.py` | Faltavam `normalize_target`, `build_recon_context`, `resolve_model` | Modo Autônomo falhava ao iniciar |

#### Refatoração do backend

| Mudança | Motivo |
|---------|--------|
| `config.py` vira **facade**; whitelist em `config_tools.py`, prompts em `config_prompts.py` | Reduzir God Object; imports estáveis para rotas e executor |
| Novo `ai/openrouter_common.py` | Helpers OpenRouter (retry 429, mensagens de erro) compartilhados por chat e Auto-Pilot |
| Novo `ai/report.py` | Geração de relatório Markdown extraída de `agent.py` |
| `kali.py` → `_finalize_stream_result` | Unificar fechamento de stream, log e auditoria (menos duplicação) |
| Autopilot deixa de importar símbolos privados do agent | Acoplamento circular mitigado |

#### Observabilidade

Novo módulo `backend/observability.py` + middleware `request_context_guard`:

- Header **`X-Request-ID`** (propagado ou gerado) e `correlation_id` em logs
- Logs **JSON estruturados** no stderr (`request_completed`, `tool_execution`, `llm_call`, etc.)
- Timing por operação: HTTP, ferramenta, chamada LLM, `docker exec`
- **`GET /api/metrics`** — contadores em memória (`requests_total`, `errors_total`, `tool_executions_total`, `llm_calls_total`, `cancellations_total`, `docker_ops_total`, memória/CPU quando disponível)
- Variáveis: `LOG_LEVEL`, `TRUST_PROXY` (ver [Observabilidade](#observabilidade) e [Configuração](#configuração))

#### Segurança

| Item | Detalhe |
|------|---------|
| `TRUST_PROXY` | `X-Forwarded-For` só quando explicitamente habilitado (evita spoof em bind local) |
| Auditoria | Eventos passam a registrar `client_ip` do contexto da requisição |
| Docker perfil B | Container não-root (`uid 1000`), `no-new-privileges`, `cap_drop: ALL`, rootfs read-only + tmpfs |

#### Docker

| Perfil | Alteração |
|--------|-----------|
| **A** (padrão) | `mem_limit`, `cpus`, `pids_limit`, **healthcheck** (`nmap --version`) |
| **B** (restrito) | Novo `docker-compose.restricted.yml`; subcomando `start.bat restricted` / `./start.sh restricted` |
| **Dockerfile** | Usuário `kaliuser` (uid 1000) para perfil B; app ainda usa `docker exec --user root` nas ferramentas |

#### CI/CD e qualidade

Pipeline `.github/workflows/tests.yml` reorganizado:

| Job | Função |
|-----|--------|
| `lint` | Ruff (`check` + `format --check`) |
| `security` | Bandit + Semgrep |
| `unit` | unittest + **coverage ≥ 95%** (`pyproject.toml`) |
| `docker-config` | Valida compose A e B (**bloqueante**) |
| `e2e` | Playwright (`smoke` + `observability`) |
| `docker-build` | Build imagem restrita (`continue-on-error`) |

Ferramentas: `requirements-dev.txt` (Ruff, coverage, Bandit, etc.), `pyproject.toml` (Ruff + coverage).

#### Testes

| Antes | Depois |
|-------|--------|
| ~70 testes, ~71% cobertura | **188 testes**, cobertura alta no `backend/` |

Novos grupos principais: `test_observability`, `test_agent_unit`, `test_autopilot_unit`, `test_security_proxy`, `test_coverage_*` (executor, rotas, agent, gaps finais), `e2e/observability.spec.js`. Rate limit flaky corrigido (recriação do limiter entre cenários).

**Fora de escopo** (deliberado): DDD/hexagonal completo, pytest, Prometheus/Grafana, load tests, build Kali bloqueante no CI.

#### Documentação

- `.env.example` e este README atualizados (`TRUST_PROXY`, observabilidade, perfis Docker, mapa de módulos, matriz de testes, contagens)

---

### 1.1.0 — Release operacional (2026-07-15)

**Segurança:** auditoria JSONL (`GET /api/audit`), aviso de escopo aberto, limite download files, seção de hardening neste README.

**Utilidade:** timeline de missão, playbooks `recon-web`/`port-scan`, relatório com recon + artefatos, ligação recon ↔ files.

**UX:** onboarding 60s, abas audit/timeline no Intel, playbooks no Auto-Pilot, toolbar mobile.

**Engenharia:** E2E Playwright no CI, ESLint, `frontend/js/api/routes.js`, testes audit/playbooks/OpenAPI.

### 1.0.0 — Release estável (2026-07-15)

Chat com execução real Kali via Docker, Auto-Pilot, Intel, file manager, sons CRT, scope lock opcional, 29 testes iniciais.

**Pós-1.0.0 — UI CRT e painéis (2026-07):** tema terminal, Markdown, health banner, seletor `llm:`, Intel (recon + threats), file manager, sons CRT, scope lock — 34 testes na base 1.0.

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
