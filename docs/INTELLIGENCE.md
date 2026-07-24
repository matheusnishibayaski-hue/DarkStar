# Intelligence Hub + Threat Model

Camada local de inteligência do Chat IA Kali **2.0**.

## O que faz

- **Record** — grava snapshot do Attack Surface (`backend/surface/{alvo}.json`)
- **Patterns** — agrega CVE / template-id / títulos
- **Suggest** — próximos checks com `rationale` (heurístico, sem claim de acurácia)
- **Threat model** — assets por industry + `infer_attack_chains` + `scan_plan`
- **Storage** — `json` (default em testes) ou **PostgreSQL** (`INTELLIGENCE_STORAGE=postgres` + `DATABASE_URL`)

## Config

```env
INTELLIGENCE_ENABLED=true
INTELLIGENCE_STORAGE=postgres   # ou json
DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/ChatIA
INTELLIGENCE_TTL_DAYS=90
```

## API

```bash
# Gravar a partir do surface existente
curl -s -X POST http://127.0.0.1:8000/api/intelligence/record \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","industry":"generic"}'

curl -s "http://127.0.0.1:8000/api/intelligence/suggest/scanme.nmap.org?limit=5"

curl -s -X POST http://127.0.0.1:8000/api/intelligence/threat-model \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","industry":"ecommerce"}'
```

Com `CHAT_API_TOKEN`, use cookie de sessão ou header `X-Chat-Token`.

## Gancho

Ao final de playbooks (`backend/playbooks/loader.py`), `try_record_from_surface(target)` roda em best-effort.

## MCP

Tool `suggest_next_checks` no servidor MCP.
