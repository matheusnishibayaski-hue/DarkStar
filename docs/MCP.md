# Servidor MCP (Model Context Protocol)

O Chat IA Kali expõe seu motor de pentest — Attack Surface Graph, whitelist de
ferramentas e execução no container Kali — como um servidor **MCP**
(https://modelcontextprotocol.io), para uso por Cursor, Claude Desktop e
outros agentes compatíveis.

Duas camadas de transporte compartilham a mesma lógica (`backend/mcp_service.py`):

- **HTTP** — `backend/routes/mcp.py`, montado em `/api/mcp/*`.
- **stdio** — `backend/mcp_server.py`, invocado via `python -m backend.mcp_server`.

Controlado pela variável `MCP_ENABLED` (padrão `true`). Quando desabilitado,
as rotas HTTP retornam `404`.

## Segurança

- `run_kali_tool` passa pela **mesma validação** de whitelist (`ALLOWED_TOOLS`,
  ~180 binários) e trava de escopo (`ALLOWED_TARGETS`) usada pelo chat e pelo
  Auto-Pilot. Comandos fora do escopo autorizado são bloqueados antes de
  qualquer execução — nunca chegam ao Docker.
- As rotas HTTP herdam a autenticação de `/api/*` (`CHAT_API_TOKEN` / sessão),
  aplicada pelo middleware `api_token_guard`.
- O transporte stdio roda como processo local confiável (iniciado pelo próprio
  cliente MCP, ex. Cursor) — sem exposição de rede.

## Tools

| Tool | Descrição | Parâmetros |
|------|-----------|------------|
| `list_surface_targets` | Lista alvos com Attack Surface Graph registrado. | — |
| `get_surface_graph` | Grafo completo (hosts, portas, urls, serviços, findings) de um alvo. | `target` |
| `get_surface_triage` | Executivo, fila humana, arquivo, cadeias de ataque e risk score. | `target` |
| `get_risk_score` | Score 0–100 + faixa, com boost de CISA KEV/EPSS. | `target` |
| `list_allowed_tools` | Whitelist de binários permitidos + categorias da UI. | — |
| `run_kali_tool` | Executa um comando no container Kali (whitelist + scope lock). | `command`, `reason` |
| `enrich_target_threat_intel` | Enriquece findings com CVE via CISA KEV + FIRST EPSS. | `target` |
| `suggest_next_checks` | Sugere próximos checks (Intelligence Hub). | `target`, `industry?`, `limit?` |

## Resources

| URI | Conteúdo |
|-----|----------|
| `targets://list` | Lista de alvos com engajamento registrado. |
| `tools://whitelist` | Binários permitidos + categorias. |
| `surface://{alvo}` | Attack Surface Graph completo do alvo. |

## Endpoints HTTP (`/api/mcp/*`)

```
GET  /api/mcp/info                 → metadados do servidor (nome, versão, protocolo)
GET  /api/mcp/tools                → lista de tools (schema JSON de cada uma)
GET  /api/mcp/tools/{name}         → schema de uma tool específica
POST /api/mcp/tools/{name}         → executa a tool ({"arguments": {...}})
GET  /api/mcp/resources            → lista de resources disponíveis
GET  /api/mcp/resources/{uri}      → lê um resource (ex.: surface://exemplo.com)
POST /api/mcp/rpc                  → endpoint JSON-RPC 2.0 genérico
```

### Exemplo — JSON-RPC via HTTP

```bash
curl -s http://127.0.0.1:8000/api/mcp/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_risk_score","arguments":{"target":"scanme.nmap.org"}}}'
```

### Exemplo — chamada REST direta

```bash
curl -s http://127.0.0.1:8000/api/mcp/tools/list_allowed_tools -X POST -d '{}'
```

## Configuração no Cursor / Claude Desktop (stdio)

Adicione ao arquivo de configuração MCP do cliente (ex. `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "chat-ia-kali": {
      "command": "python",
      "args": ["-m", "backend.mcp_server"],
      "cwd": "/caminho/para/Chat IA Kali"
    }
  }
}
```

O processo herda o `.env` do projeto — mesmas configurações de escopo,
whitelist e container Kali usadas pela aplicação web.

## Threat Intelligence (CISA KEV + EPSS)

Módulo `backend/ai/threat_intel.py`. Controlado por `THREAT_INTEL_ENABLED`
(padrão `true`) e `THREAT_INTEL_CACHE_TTL` (padrão `21600` segundos / 6h).

- **CISA KEV** (Known Exploited Vulnerabilities): catálogo público de CVEs com
  exploração ativa confirmada. Um CVE presente no catálogo eleva
  automaticamente a severidade do finding para no mínimo `high` e marca
  `cisa_kev_flag: true` no Attack Surface Graph.
- **FIRST EPSS**: score (`epss_score`) e percentil (`epss_percentile`) de
  probabilidade de exploração em campo nos próximos 30 dias.

Esses campos entram automaticamente:

- No **Attack Surface Graph** (`backend/surface/{alvo}.json`), a cada finding
  com CVE processado (ingestão de execução ou merge de duplicatas).
- No **risk score** (`backend/ai/risk_score.py`): CVEs em KEV recebem peso
  ×1,25; EPSS ≥ 0,5 recebe peso ×1,15.
- No **relatório comercial** (`backend/ai/report.py`): alerta de KEV e
  percentual EPSS no detalhamento de cada achado executivo.

Para forçar o enriquecimento de um alvo já testado, use a tool MCP
`enrich_target_threat_intel` ou chame diretamente
`backend.ai.threat_intel.enrich_surface_with_threat_intel(target)`.
