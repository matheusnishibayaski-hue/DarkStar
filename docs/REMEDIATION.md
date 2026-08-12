# Remediação inteligente (wizard)

Planos step-by-step gerados por LLM a partir de findings de pentest (host/URL/CVE/evidência), com fallback no mapa estático de `backend/ai/remediation.py`. UI: overlay no shell (triagem → **fix**), não página HTML isolada.

## Fluxo

1. Na triagem, clique **fix** num finding.
2. `POST /api/remediation/generate` usa o provider atual (`get_llm_provider().complete`) ou o mapa estático se a LLM falhar.
3. O overlay mostra causa raiz, passos, before/after opcional, comando de verificação (só texto — **não** executado no host) e referências.
4. Marcar passos / **marcar resolvido** persiste em `backend/data/remediation_track.json`.

## API

| Método | Path | Função |
|--------|------|--------|
| POST | `/api/remediation/generate` | gera plano (`finding`, `code_context` opcional) |
| POST | `/api/remediation/verify` | checagem leve de sintaxe (Python); não roda `test_command` |
| POST | `/api/remediation/track` | inicia tracking |
| PATCH | `/api/remediation/track/{finding_id}` | atualiza status / passos |
| GET | `/api/remediation/stats` | estatísticas do tracker |
| GET | `/api/remediation/alternatives/{id}` | 501 (omitido no MVP) |

Auth: mesmo middleware do restante (`CHAT_API_TOKEN` / roles).

Body de generate (exemplo):

```json
{
  "finding": {
    "id": "f1",
    "title": "Missing HSTS",
    "severity": "medium",
    "host": "lab.test",
    "evidence": "No Strict-Transport-Security header"
  }
}
```

## Escopo MVP

- Seed com `remediation_for` (PDF/report continua igual).
- Sem botão “Create Fix PR” (não há repo do alvo).
- `code_context` / `project_info` opcionais; prompts focam em evidência + tipo.
- Verify: só `ast.parse` para Python; outras linguagens → `syntax_valid: true` + nota.

## Módulos

- `backend/ai/remediation.py` — mapa estático + re-exports
- `backend/ai/remediation_ai.py` — Advisor / Verifier / Tracker
- `backend/routes/remediation.py` — rotas
- `frontend/js/remediation-wizard.js` — overlay
