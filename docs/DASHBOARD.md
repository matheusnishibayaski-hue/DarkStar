# Dashboard & histórico

Painel no **Workspace** da conversa (sidebar → **workspace** → aba dashboard). Métricas, trends Chart.js e export — **somente da conversa ativa**.

## Escopo por conversa

- Cada scan gravado inclui `chat_session_id` (Piloto / chat).
- APIs exigem `session_id`. Sem isso → 422; não há agregado global.
- Ao apagar um chat, `DELETE /api/dashboard/session/{id}` remove os scans daquela conversa (o frontend chama automaticamente).

## Persistência

- Tabelas `scan_history` (com `chat_session_id`) e `vulnerability_tracking` (SQLAlchemy).
- Usa `DATABASE_URL` (Postgres) quando definido; senão SQLite em `backend/data/dashboard.db`.

## API

| Método | Path |
|--------|------|
| GET | `/api/dashboard/metrics?days=30&session_id=` |
| GET | `/api/dashboard/vulnerability-trend?days=30&session_id=` |
| GET | `/api/dashboard/top-issues?limit=10&session_id=` |
| GET | `/api/dashboard/scan-history?days=30&session_id=&target=` |
| GET | `/api/dashboard/summary?days=30&session_id=` |
| GET | `/api/dashboard/export?format=json\|csv\|pdf&days=30&session_id=` |
| DELETE | `/api/dashboard/session/{session_id}` |

Auth: mesmo middleware do restante (`CHAT_API_TOKEN` / roles).

## UI

1. Abra http://127.0.0.1:8000  
2. Selecione/crie um chat  
3. Sidebar → **workspace** → aba **dashboard**  
4. Período 7/30/90/365 e export  

Trends vazios são normais até rodar um scan **nessa** conversa (Piloto ou CLI com session, se aplicável).
