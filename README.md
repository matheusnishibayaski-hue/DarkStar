# DarkStar · Argus

Assistente **local** de pentest com IA. Você descreve o alvo em português; a **Argus** interpreta, escolhe ferramentas e **executa de verdade** num Kali Linux em Docker — depois devolve análise, logs e relatório PDF.

> **Só em alvos autorizados.** Uso sem permissão é ilegal. Você é responsável pelo escopo.

---

## Como o projeto funciona

O DarkStar é a interface. A Argus é o agente de IA. Juntos formam um loop fechado: pedido → decisão → execução real → evidência → relatório.

### Peças

| Camada | Papel |
|--------|--------|
| **Frontend** (`frontend/`) | Chat, Piloto, logs, triagem, PDF, mapa e controles (ferramentas, offensive, master key) |
| **Backend** (`backend/`) | FastAPI: auth, chat SSE, Auto-Pilot, surface/findings, relatórios |
| **IA** (`backend/ai/`) | Chama o LLM via OpenRouter com *function calling* (`run_kali_tool`) |
| **Executor** (`backend/executor/`) | Valida whitelist/escopo e roda o comando no Docker Kali |
| **Kali** (`docker/`) | Container `kali-tools` com 180+ ferramentas (nmap, nuclei, httpx, …) |

```
┌──────────────┐     HTTP / SSE      ┌─────────────────┐
│  DarkStar UI │ ──────────────────► │  FastAPI        │
│  chat/Piloto │ ◄────────────────── │  rotas + auth   │
└──────────────┘   texto + live log  └────────┬────────┘
                                              │
                         ┌────────────────────┼────────────────────┐
                         ▼                    ▼                    ▼
                  OpenRouter (LLM)     Attack Surface        Docker Kali
                  escolhe tool         findings / PoC        nmap, nuclei…
                         │                    ▲                    │
                         └────── resultado ───┴──── stdout/stderr ─┘
                                              │
                                              ▼
                                    Triagem → PDF / ZIP
```

### Fluxo de uma mensagem no chat

1. Você envia o pedido (ex.: *“scan de portas em scanme.nmap.org”*).
2. O backend monta o histórico curto + system prompt e chama o modelo no OpenRouter.
3. Se a IA precisar de dados reais, ela pede `run_kali_tool` com o binário e os argumentos.
4. O executor checa: ferramenta na whitelist, sem `..` nos paths, alvo em `ALLOWED_TARGETS` (se definido), e perfil de risco (B vs full).
5. O comando roda no container (`docker exec`), **sem** `bash -c` — execução vectorizada.
6. O stdout volta em streaming (`[live]`); o log completo fica em `backend/logs/`.
7. A IA lê um resumo do output e responde; se precisar, pede outra tool (até o limite de iterações).
8. Achados relevantes alimentam o **Attack Surface** do alvo (portas, URLs, CVEs, candidatos a vuln).

### Fluxo do Piloto (missão automática)

O Piloto não é um chat solto: é uma missão por **fases**:

`recon` → `enumerate` → `vuln_scan` → `verify` → `report`

- Você escolhe **alvo** + perfil (Básico / Intermediário / Completo / Personalizado).
- Em cada fase a IA escolhe ferramentas tipicas (subfinder, nmap, nuclei, etc.).
- Candidatos passam por um pipeline de **PoC/verify** (confirmado, falso positivo, inconclusivo).
- Só achados que passam no **gate** entram no resumo executivo do relatório.
- Ao terminar, a UI gera/baixa o **PDF**; você ainda pode triar manualmente no modal Relatório.

### Segurança embutida no caminho crítico

- Escopo: `ALLOWED_TARGETS` limita o que pode ser escaneado.
- Whitelist: só binários conhecidos rodam no Kali.
- Perfil **B** (padrão sem master key): ferramentas agressivas bloqueadas.
- Perfil **full** (com `MASTER_KEY` + modo offensive): catálogo ampliado, ainda limitado por escopo.
- Bind em `127.0.0.1`; `CHAT_API_TOKEN` opcional para proteger a API.
- Auditoria append-only em `backend/audit/`.

### O que fica salvo

| Onde | Conteúdo |
|------|----------|
| `backend/logs/` | Output bruto de cada execução |
| `backend/surface/` | Grafo do alvo (hosts, ports, findings, baseline) |
| `backend/outputs/` | Artefatos Kali (`/tools/output` no container) |
| Navegador | Conversas, modelo escolhido, preferências de UI |

Nada disso vai para a nuvem além das chamadas ao OpenRouter (prompts + resumos de output). A execução das tools é **local**, no seu Docker.

### Camadas opcionais (já no código)

| Recurso | Para quê | Docs |
|---------|----------|------|
| **MCP** | Cursor/Claude Desktop usam o mesmo motor (surface, tools, Kali) | [`docs/MCP.md`](docs/MCP.md) |
| **Intelligence Hub** | Histórico de alvos, sugestões de próximos checks, threat model | [`docs/INTELLIGENCE.md`](docs/INTELLIGENCE.md) |
| **Threat intel** | Enriquece CVEs com CISA KEV + EPSS no risk score | `.env` → `THREAT_INTEL_ENABLED` |

Ative no `.env` (`MCP_ENABLED`, `INTELLIGENCE_ENABLED`, etc.). Compliance na API é **indicativo**, não certificação.

---

## Instalação

### Pré-requisitos

- **Python 3.10+**
- **Docker Desktop** (para ferramentas Kali; opcional se for só chat)
- Conta e chave em [OpenRouter](https://openrouter.ai/keys)

### Windows (recomendado)

```bat
start.bat
```

Cria `.env` e `venv`, sobe o Kali e inicia o servidor → **http://127.0.0.1:8000**

### Linux / macOS

```bash
chmod +x start.sh && ./start.sh
```

### Só o servidor (sem Docker)

```bat
start.bat servidor
```

```bash
./start.sh servidor
```

UI e chat sobem; scans Kali ficam indisponíveis até o container existir.

### Variantes do start

| Comando | Efeito |
|---------|--------|
| `start.bat` / `./start.sh` | Completo: venv + Docker Kali + servidor |
| `… servidor` | Só servidor (sem Docker) |
| `… restricted` | Kali perfil B (mais hardened, sem Wi-Fi) |
| `… repair` | Tenta recuperar o Docker Desktop / engine |
| `… quick` / `… menu` | Menu: reiniciar servidor (R), Kali (K) ou sair (Q) |

### Manual

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Unix:    source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # edite OPENROUTER_API_KEY
cd docker && docker compose up -d --build
cd .. && python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

---

## Configuração mínima

No `.env` (a partir de `.env.example`):

| Variável | Obrigatório | Função |
|----------|-------------|--------|
| `OPENROUTER_API_KEY` | **Sim** | Chave da IA |
| `ALLOWED_TARGETS` | Recomendado | Alvos permitidos (vazio = lab, com aviso) |
| `CHAT_API_TOKEN` | Recomendado | Protege a API local |
| `MASTER_KEY` | Opcional | Desbloqueia perfil full / offensive |
| `THREAT_INTEL_ENABLED` | Opcional | KEV/EPSS nos findings |
| `MCP_ENABLED` | Opcional | Expõe `/api/mcp/*` e stdio |
| `UVICORN_HOST` / `UVICORN_PORT` | Não | Padrão `127.0.0.1:8000` |

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

---

## Uso rápido

1. Chat: *scan leve em scanme.nmap.org*.
2. Ou **Piloto** → alvo + tipo de scan.
3. Logs na sidebar; **Relatório** para triar e baixar PDF.
4. **F1** = tour da interface.

| Atalho | Ação |
|--------|------|
| `Alt+P` | Piloto |
| `Alt+T` | Ferramentas |
| `Alt+L` / `Alt+R` | Logs / Relatório da conversa |
| `Alt+N` | Novo chat |
| `Esc` | Fecha painéis |

Health: `GET http://127.0.0.1:8000/api/health` → deve retornar `"status": "ok"`.

---

## Problemas comuns

| Sintoma | O que fazer |
|---------|-------------|
| Docker/Kali off | Docker Desktop aberto; `start.bat repair` ou `cd docker && docker compose up -d` |
| IA não responde | `OPENROUTER_API_KEY` e saldo OpenRouter |
| Comando `[blocked]` | Fora da whitelist, fora do escopo, ou perfil B sem master key |
| UI antiga | Hard refresh `Ctrl+F5` |
| 401 na API | Defina `CHAT_API_TOKEN` e faça login |

Testes: `python -m unittest discover -s tests -v`

---

## Licença

MIT — com obrigação de uso ético e autorizado.

Mais detalhe: [`docs/MCP.md`](docs/MCP.md), [`docs/INTELLIGENCE.md`](docs/INTELLIGENCE.md), [`docs/POSITIONING.md`](docs/POSITIONING.md).