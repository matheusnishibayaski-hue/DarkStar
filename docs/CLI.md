# DarkStar CLI

Modo linha de comando para pipelines e automação local.

## Instalação

```bash
pip install -r requirements.txt
```

Requer o mesmo ambiente do app (`.env`, Docker/Kali para scans reais).

## Comandos

### Autonomous (Piloto)

```bash
python -m backend.cli autonomous \
  --target scanme.nmap.org \
  --risk-profile safe-active \
  --scan-profile intermediate \
  --output json \
  --output-file report.json
```

Dry-run (só valida escopo):

```bash
python -m backend.cli autonomous --target scanme.nmap.org --dry-run
```

Comentar em PR após o scan (requer `GITHUB_TOKEN`):

```bash
python -m backend.cli autonomous \
  --target scanme.nmap.org \
  --github-repo owner/repo \
  --pr 42 \
  -o report.json
```

Também: `python -m backend …` (mesmo CLI).

### Chat

```bash
python -m backend.cli chat -m "scan leve de portas em scanme.nmap.org" --output text
```

### Health

```bash
python -m backend.cli health --check all --output json
```

Checks: `docker`, `kali`, `ai`, `config` (via Docker CLI — sem SDK).

### List tools

```bash
python -m backend.cli list-tools --category rede --output json
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK — sem critical/high (ou dry-run ok) |
| 1 | High findings (sem critical) |
| 2 | Critical findings |
| 100 | Execution error |
| 102 | Scope validation failed (`ALLOWED_TARGETS`) |

Útil para branch protection / falha controlada em CI.

## Saídas

- **json** — relatório estruturado (`findings`, counts, `risk`, `markdown_report`)
- **sarif** — SARIF 2.1.0 mínimo (locations = host/URL, não file:line)

## GitHub Actions (template seguro)

Workflows:

- [`.github/workflows/darkstar-pentest.yml`](../.github/workflows/darkstar-pentest.yml)
- [`.github/workflows/darkstar-scheduled.yml`](../.github/workflows/darkstar-scheduled.yml)

**Só `workflow_dispatch`.** Não rodam em push/PR automaticamente. O alvo deve ser informado no input ou no secret `DARKSTAR_TARGET`. URLs `github.com` são recusadas.

Secrets úteis:

| Secret | Uso |
|--------|-----|
| `OPENROUTER_API_KEY` | IA (modo online) |
| `DARKSTAR_TARGET` | Alvo default se o input vier vazio |
| `DARKSTAR_ALLOWED_TARGETS` | Opcional — espelha `ALLOWED_TARGETS` |

Ver também [GITHUB-INTEGRATION.md](GITHUB-INTEGRATION.md).
