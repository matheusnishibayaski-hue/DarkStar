# Changelog

## [1.1.0] — 2026-07-15

### Segurança
- Auditoria imutável (JSONL append-only) com rota `GET /api/audit`
- Aviso de escopo aberto quando `ALLOWED_TARGETS` está vazio
- Limite de download no file manager (`MAX_FILE_DOWNLOAD_MB`, padrão 50 MB)
- Documentação de hardening em `SECURITY.md`

### Utilidade
- Timeline de missão no painel Intel
- Playbooks pré-definidos (`recon-web`, `port-scan`) com `GET/POST /api/playbooks`
- Relatório enriquecido com recon cacheado e artefatos em `/tools/output`
- Ligação recon ↔ files (botão artefatos, filtro por alvo)

### UX
- Onboarding de primeiro uso (3 passos)
- Banner de aviso de escopo
- Abas audit e timeline no Intel
- Playbooks no overlay Auto-Pilot
- Toolbar mobile com menu overflow

### Engenharia
- Camada `frontend/js/api/routes.js`
- ESLint básico no frontend
- Testes: auditoria, playbooks, OpenAPI
- E2E Playwright (3 fluxos) no CI

## [1.0.0] — 2026-07

- Chat com execução real de ferramentas Kali via Docker
- Auto-Pilot autônomo
- Painel Intel (recon + ameaças Kaspersky)
- File manager `/tools/output`
- Sons CRT, tema terminal fosforescente
- Scope lock opcional (`ALLOWED_TARGETS`)
