# Arquitetura — Chat IA Kali v1.1.0

Documento técnico pós-hardening. Sem mudança de contratos de API/SSE/UI.

## Diagrama de dependências (atual)

```
frontend (ES6)
    │ HTTP / SSE
    ▼
main.py ──► middleware (request_id, rate limit, auth)
    │
    ├── routes/* ──► ai/agent · ai/autopilot · playbooks · security · executor
    │
    ├── ai/
    │     agent.py          orquestração chat
    │     autopilot.py      modo autônomo
    │     openrouter_common.py   helpers OpenRouter
    │     report.py         relatório Markdown
    │     healing.py · sse.py
    │
    ├── executor/
    │     kali.py           whitelist + docker exec + finalize
    │     logs · recon_db · files_store · stream_hub · summarize · wifi_scan
    │
    ├── security/
    │     sessions · rate_limit · scope · audit · missions
    │
    ├── config.py           env + reexports
    │     config_tools.py   ALLOWED_TOOLS · TOOL_CATEGORIES
    │     config_prompts.py SYSTEM_PROMPT · AUTONOMOUS_*
    │
    └── observability.py    logs JSON · métricas · timing
```

**Ciclos estáticos:** nenhum.

## Top acoplamentos (após mitigação)

| # | Problema | Severidade | Mitigação aplicada |
|---|----------|------------|--------------------|
| 1 | `config.py` God Object | Média | Split em `config_tools` + `config_prompts`; facade estável |
| 2 | `agent.py` orquestra tudo | Média | `report.py` + `openrouter_common.py` extraídos |
| 3 | `kali.py` ciclo de vida repetido | Média | `_finalize_stream_result` |
| 4 | Autopilot importava privados do agent | Alta | Imports públicos + `openrouter_common` |
| 5 | Auth/config por valor (patch frágil) | Baixa | Mantido; `auth_patch` cobre targets |

## Observabilidade

| Métrica / campo | Onde | Uso |
|-----------------|------|-----|
| `X-Request-ID` | middleware | correlacionar request |
| `request_id` / `correlation_id` | logs JSON | filtrar missão |
| `duration_ms` | HTTP / tool / llm / docker | latência |
| `GET /api/metrics` | contadores memória | requests, erros, tools, LLM, cancel, docker |

## Docker — perfis

| Perfil | Arquivo | Hardening |
|--------|---------|-----------|
| A Wi-Fi | `docker-compose.yml` | privileged + host net; mem/cpu/pids + healthcheck |
| B Restrito | `docker-compose.restricted.yml` | user 1000, no-new-privileges, cap_drop ALL, read_only, limits |

## Matriz de cobertura de testes (estimada)

| Módulo | Nível | Arquivos de teste |
|--------|-------|-------------------|
| security (scope, auth, proxy, audit) | Alto | `test_security*`, `test_audit`, `test_core` |
| executor (kali, files, stream) | Médio-Alto | `test_kali_mock`, `test_observability`, `test_integration` |
| ai (agent, autopilot, healing) | Médio | `test_agent_unit`, `test_autopilot_unit`, `test_core` |
| routes / OpenAPI | Médio | `test_integration`, `test_openapi`, `test_playbooks` |
| observability | Alto | `test_observability` + E2E `observability.spec.js` |
| frontend UI smoke | Básico | `e2e/smoke.spec.js` |

Baseline CI: coverage ≥ 50% (típico local ~66%).

## Fora de escopo (consciente)

- Hexagonal/DDD completo, microserviços, pytest migration
- Testes de carga / Prometheus / Grafana
- Multi-usuário / RBAC
