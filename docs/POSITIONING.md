# Posicionamento — Chat IA Kali 2.0

## Onde estamos

Assistente **local** de pentest com execução real no Kali Docker, Auto-Pilot por fases, Attack Surface, verify/PoC, **gate rígido** e relatório comercial — agora com MCP, threat intel (KEV/EPSS), Intelligence Hub e threat plan heurístico.

## Peers (qualidade, não stars)

| Peer | Força deles | Nosso eixo |
|------|-------------|------------|
| PentAGI | Multi-agente / plataforma | Assertividade + entrega consultoria |
| HexStrike | MCP + muitas tools | MCP + missão→gate→PDF fechado |
| CAI | Framework de agentes | App opinada ponta a ponta |
| PentestGPT | Orquestração LLM | Execução isolada + evidência |

## Somos / não somos

**Somos:** pipeline scan → evidência → gate → relatório, com escopo e whitelist.

**Não somos:** multi-tenant SaaS, certificação automática de compliance, multi-agente teatral.

## Compliance

`/api/compliance/*` é **indicativo**. Não é auditoria nem certificação.

## Demo de qualidade

1. Lab autorizado (`scanme.nmap.org`)
2. Pilot ou chat → surface
3. Triagem / PDF
4. `POST /api/intelligence/record` + suggest
5. MCP `list_tools` / `suggest_next_checks`
