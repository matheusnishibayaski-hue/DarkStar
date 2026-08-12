# GitHub Integration

Integração **sync** com a API do GitHub para comentários em PR, issues e commit status.

## Setup

1. Crie um PAT (classic) com escopos `repo` (comentários/issues/status) ou use o `GITHUB_TOKEN` do Actions.
2. Configure:

```env
GITHUB_TOKEN=ghp_...
```

Ou variável de ambiente / secret do Actions.

3. Confira:

```bash
python -c "from backend.integrations.github import GitHubClient; print(GitHubClient().is_available())"
```

## API local

Rotas (protegidas pelo middleware usual — `CHAT_API_TOKEN` / roles):

| Method | Path | Descrição |
|--------|------|-----------|
| GET | `/api/github/status` | `{ "available": true/false }` |
| POST | `/api/github/comment-pr` | Comenta no PR |
| POST | `/api/github/create-issue` | Cria issue a partir de um finding |
| POST | `/api/github/update-status` | Commit status (`pending`/`success`/`failure`/`error`) |

Exemplo:

```bash
curl -s -X POST http://127.0.0.1:8000/api/github/comment-pr \
  -H "Content-Type: application/json" \
  -H "X-Chat-Token: $CHAT_API_TOKEN" \
  -d '{
    "repo_url": "owner/repo",
    "pr_number": 12,
    "target": "scanme.nmap.org",
    "findings": [{"title":"Missing HSTS","severity":"medium","host":"scanme.nmap.org","remediation":"Enable HSTS"}]
  }'
```

Webhook inbound **não** está no MVP (evita superfície sem assinatura). Use Actions `workflow_dispatch` ou a CLI.

## CLI

```bash
python -m backend.cli autonomous \
  --target scanme.nmap.org \
  --github-repo owner/repo \
  --pr 12 \
  -o report.json
```

## Actions

Ver [CLI.md](CLI.md). Templates:

- `darkstar-pentest.yml` — dispatch manual; PR comment só se `pr_number` for informado
- `darkstar-scheduled.yml` — dispatch (cron comentado); issue se critical

Para branch protection: use o check context `DarkStar Security` após um run manual, ou integre o exit code do CLI no seu pipeline.

## Labels

ASCII: `security`, `darkstar`, `severity/critical|high|medium|low`, `tool/<name>`.

## Notas

- Findings são estilo **pentest** (host/URL/CVE), não AppSec file:line.
- Sem `GITHUB_TOKEN`, a API responde **501** e a CLI ignora o comentário com aviso.
- Offline/air-gapped: deixe o token vazio; o restante do DarkStar continua local.
