# Dashboard & histórico

Painel no shell DarkStar (sidebar → **dashboard**) com métricas, trends Chart.js e export.

## Persistência

- Tabelas `scan_history` e `vulnerability_tracking` (SQLAlchemy).
- Usa `DATABASE_URL` (Postgres) quando definido; senão SQLite em `backend/data/dashboard.db`.
- Scans são gravados ao final do **Piloto** (`run_autonomous`), na CLI e em jobs de schedule (`monitor`/`full`).

## API

| Método | Path |
|--------|------|
| GET | `/api/dashboard/metrics?days=30` |
| GET | `/api/dashboard/vulnerability-trend?days=30` |
| GET | `/api/dashboard/top-issues?limit=10` |
| GET | `/api/dashboard/scan-history?days=30&target=` |
| GET | `/api/dashboard/summary?days=30` |
| GET | `/api/dashboard/export?format=json\|csv\|pdf&days=30` |

Auth: mesmo middleware do restante (`CHAT_API_TOKEN` / roles).

## UI

1. Abra http://127.0.0.1:8000  
2. Sidebar → **dashboard**  
3. Escolha período 7/30/90/365 e exporte se precisar  

Trends vazios no início são normais até rodar pelo menos um scan (Piloto ou CLI).
