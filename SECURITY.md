# Segurança — Chat IA Kali

Este documento descreve práticas recomendadas para uso seguro do Chat IA Kali em ambiente de laboratório.

## Checklist rápido

- [ ] `.env` nunca commitado (contém `OPENROUTER_API_KEY`, opcionalmente `CHAT_API_TOKEN`)
- [ ] `ALLOWED_TARGETS` definido para alvos autorizados (recomendado mesmo em lab)
- [ ] `CHAT_API_TOKEN` ativo se exposto além de localhost
- [ ] Rotacionar token após compartilhar ambiente
- [ ] Revisar trilha de auditoria em `backend/audit/` ou `GET /api/audit`
- [ ] Artefatos sensíveis em `backend/outputs/` fora de backups públicos

## Escopo de alvos (`ALLOWED_TARGETS`)

- **Vazio:** sem restrição — a UI exibe aviso persistente (modo lab).
- **Preenchido:** comandos e auto-pilot só aceitam alvos na lista (IPs, domínios, sufixos).

Exemplo no `.env`:

```env
ALLOWED_TARGETS=scanme.nmap.org,10.0.0.0/24,lab.local
```

## Auditoria

Execuções de ferramentas geram eventos append-only em `backend/audit/events-YYYY-MM-DD.jsonl`:

- timestamp, ferramenta, comando, alvos extraídos, status, `mission_id`, `log_file_id`
- segredos redigidos automaticamente

Consulta via API: `GET /api/audit?limit=100`

## File manager

- Anti path-traversal em `backend/executor/files_store.py`
- Whitelist de extensões
- Limite de download: `MAX_FILE_DOWNLOAD_MB` (padrão 50)

## Docker — perfis

### Perfil atual (padrão) — Wi-Fi e monitor mode

O `docker-compose.yml` usa `privileged: true`, `network_mode: host` e caps `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN` para ferramentas wireless (`aircrack-ng`, `airodump-ng`, etc.).

**Use apenas em máquina de lab dedicada.**

### Perfil restrito (sem Wi-Fi)

Para scans de rede/web sem wireless, comente `privileged` e `network_mode: host` e use rede bridge:

```yaml
services:
  kali-tools:
    # privileged: true
    # network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    # Remover SYS_ADMIN se não necessário
```

Reinicie o container após alterações.

## Autenticação

- `CHAT_API_TOKEN` protege `/api/*` (exceto health, client-config, login)
- Sessões via cookie com TTL (`SESSION_TTL_HOURS`)
- Rate limit: `RATE_LIMIT_REQUESTS` por janela (`RATE_LIMIT_WINDOW_SEC`)

## Relatório de uso ético

Execute **somente** em sistemas que você possui ou tem autorização explícita por escrito. O projeto é single-user e local por design (`UVICORN_HOST=127.0.0.1`).
