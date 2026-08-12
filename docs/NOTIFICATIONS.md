# Notificações multicanal

Canais sync (urllib/SMTP), sem SDKs extras: Slack, Discord, Telegram, Email, Jira.

## Configuração (`.env`)

```env
# Slack (ou ALERT_WEBHOOK_URL legado)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CHANNEL=#security

DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=security@example.com
EMAIL_TO=team@example.com

JIRA_URL=https://your.atlassian.net
JIRA_USER=user@example.com
JIRA_TOKEN=
JIRA_PROJECT=SEC
```

Só canais com variáveis preenchidas ficam ativos.

## Routing

- `critical` / `high` → todos os canais configurados (automático)
- `medium` / `low` / `info` → exige `channels` explícito na API (evita spam)

## API

| Método | Path |
|--------|------|
| GET | `/api/notifications/channels` |
| POST | `/api/notifications/send` |
| POST | `/api/notifications/test/{channel}` |
| POST | `/api/notifications/alert-finding` |

Exemplo:

```bash
curl -s -X POST http://127.0.0.1:8000/api/notifications/send \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","message":"hello","severity":"info","channels":["slack"]}'
```

## Integração automática

- `maybe_alert_delta` (delta/risco) também dispara `NotificationManager`
- CLI `autonomous` notifica se `critical > 0`
