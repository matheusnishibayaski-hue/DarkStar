# Playbooks

Arquivos YAML com schema próprio do Chat IA Kali (não são playbooks Ansible).

| Placeholder | Uso |
|-------------|-----|
| `{target}` | Alvo original (domínio/IP) — use em `-d`, último arg de scan, etc. |
| `{target_safe}` | Alvo sanitizado para nomes de arquivo em `/tools/output/` |

Validação no editor: `playbook.schema.json` (via `.vscode/settings.json` ou comentário `$schema` no topo de cada arquivo).

API: `GET /api/playbooks`, `POST /api/playbooks/{id}/run` com `{"target": "..."}`.
