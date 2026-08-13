# DarkStar · Argus

### O assistente de pentest que **não só fala** — ele **executa**.

Você digita em português.  
A **Argus** entende.  
O **Kali** roda de verdade no seu PC.  
No fim: análise, evidência e **PDF pronto**.

Isso não é mais um chat que “sugere comandos”.  
É uma **cabine de pentest com IA** — local, rápida e feita para quem entrega resultado.

> Use só em alvos **autorizados**. Sem permissão = ilegal. A responsabilidade é sua.

---

## Por que as pessoas ficam surpresas

### 1. Ele realmente executa (não é teatro)

Enquanto muita ferramenta de “IA + pentest” só **descreve** o que você deveria fazer, o DarkStar:

- escolhe a ferramenta
- monta o comando
- **roda no Kali Linux** (Docker no seu computador)
- mostra a saída **ao vivo**
- explica o resultado em português

Você pede o objetivo.  
Ela faz o caminho técnico.

#### Exemplos fáceis de entender

| Você digita… | O que acontece de verdade |
|--------------|---------------------------|
| *“scan leve de portas nesse site”* | A Argus sobe o `nmap` no Kali e te devolve portas abertas — não um tutorial. |
| *“acha subdomínios desse domínio”* | Roda ferramentas reais de recon e lista o que encontrou. |
| *“isso aqui é o quê?”* (colando saída) | Explica em português o que o scan mostrou. |

Diferença simples: **não é GPS descrevendo a rua — é o carro andando.**

---

### 2. Tem um “Piloto automático” de missão

Cansado de digitar passo a passo?

Abra o **PILOTO**, informe o alvo e o nível do scan.

A Argus segue sozinha um roteiro completo:

**descobrir → mapear → procurar falhas → tentar confirmar → gerar relatório**

É como ter um analista júnior que não para até fechar a missão — e ainda te devolve o PDF.

#### Exemplos fáceis de entender

| Situação | Como o Piloto ajuda |
|----------|---------------------|
| **Você tem 1 hora antes da call** | Coloca o alvo, escolhe “básico” e deixa rodando enquanto prepara a reunião. |
| **Lab de madrugada** | Dorme (ou faz café). A missão continua: recon → scan → verificação. |
| **Cliente pediu “visão geral rápida”** | Missão intermediária + PDF no fim — sem montar checklist na mão. |
| **Quer controle fino** | Perfil personalizado: você marca as tools; a Argus orquestra. |

É o modo “piloto automático do avião”: você define destino e altitude — o sistema voa o trecho.

---

### 3. O relatório não é “achismo da IA”

Aqui vem o diferencial que mais impressiona quem já queimou a mão com falso positivo:

- candidato a vulnerabilidade passa por **verificação**
- o que for fraco ou duvidoso **não entra** no resumo executivo automaticamente
- **Baixar PDF** abre a **triagem**: um achado por vez, em português claro
- em cada item: **opinião da Argus** (heurística imediata) + **segunda opinião da IA** (não marca sozinha)
- a **prévia** e o **PDF** são o mesmo relatório: testes resumidos (sem ANSI), KPIs, gráficos, achados explicados e plano de correção
- os dois trazem cobertura **indicativa ISO 27001 / SOC 2** (não é certificação)

**Menos vergonha na frente do cliente. Mais confiança no PDF.**

#### Exemplos fáceis de entender

| Situação | O que o DarkStar evita |
|----------|------------------------|
| **Scanner gritou “crítico!” e era bobagem** | O achado fica na fila; a Argus mostra chance de alarme falso e o motivo — você decide. |
| **IA “achou” vulnerabilidade só no texto** | Sem evidência / PoC, não passa no filtro (gate). |
| **Cliente pergunta “tem prova?”** | Você tem log, comando e classificação — não só opinião. |
| **Retrabalho humilhante** | Menos “desculpa, era falso positivo” depois de enviar o relatório. |
| **IA marcou “vuln” e era porta/info/WAF** | A triagem puxa de novo o que parece falso positivo (score ≥ 55), mesmo já “confirmado”. |
| **Cliente pede ISO / SOC 2** | O PDF tem tabela por controle + disclaimer: *indicativo do engajamento, não substitui auditoria*. |

Pense num detector de metal no aeroporto: **apita fácil**, mas alguém ainda confere a mala antes de acusar.

---

### 4. Roda na sua máquina — e pode ficar **100% offline**

O DarkStar não te prende a um SaaS misterioso.

- servidor local no seu PC  
- tools no Kali isolado  
- conversas e logs com você  

E tem o detalhe que muda o jogo: o switch **offline**.

Com ele ligado + Ollama, a IA também fica **dentro da sua máquina**.  
Nada de prompt indo para a nuvem. Nada de depender de Wi‑Fi.

> O DarkStar permite pentest assistido por IA em lugares onde a internet **não pode existir** — tipo um submarino, uma rede de usina, um hospital isolado ou o lab do cliente sem cabo para fora — **sem enviar um único byte para a nuvem**.

#### Exemplos fáceis de entender

| Situação | Por que o offline importa |
|----------|---------------------------|
| **Cliente “nada sai daqui”** | Você abre o notebook, liga o offline e trabalha. A conversa com a IA não atravessa a porta. |
| **Rede sem internet** | Não tem Wi‑Fi, não tem 4G — e mesmo assim a Argus continua pensando e o Kali continua executando. |
| **Ambiente sensível** | Dados de alvo, comandos e achados ficam no PC. Sem “upload escondido” para nuvem de IA. |
| **Demo / prova de conceito** | Mostra o produto funcionando em sala fechada, sem depender de API externa. |

Resumo em uma frase:

**Online** quando quiser o melhor da nuvem (ChatGPT, Claude, Gemini, Grok, DeepSeek…).  
**Offline** quando o mundo lá fora não pode ver — ou simplesmente não existe conexão.

Um clique. Modo local. Sem drama.

---

### 5. Segurança embutida (não é “IA solta na internet”)

O projeto nasceu com freio de mão:

- só ferramentas permitidas (whitelist)
- lista de alvos autorizados
- perfil restrito por padrão
- arsenal completo só com master key + modo offensive
- auditoria do que foi executado

Poderoso? Sim.  
Irresponsável? Não.

#### Exemplos fáceis de entender

| Situação | O que o freio evita |
|----------|---------------------|
| **IA “resolveu” testar outro domínio** | Se não está na lista de alvos, o comando pode ser bloqueado. |
| **Alguém pediu ferramenta perigosa sem key** | Perfil B segura o arsenal agressivo até você desbloquear. |
| **Estagiário na máquina** | Sem master key, o poder fica limitado — você controla o volume. |
| **“Quem rodou isso?”** | Auditoria registra a trilha. Não fica no “foi a IA, juro”. |

É cinto de segurança: **não te impede de dirigir** — impede o carro de sair voando no primeiro erro.

---

### 6. Feito para o dia a dia de quem pentesta de verdade

- chat natural em português (seletor de modelo no compositor)
- onboarding na primeira visita + tour guiado (**F1**)
- barra de status: Docker, Kali, LLM e privilégio (perfil B / full)
- painel de ferramentas, logs, mapa e dashboard — tudo da **conversa ativa**
- **relatórios**: prévia HTML ao vivo (= PDF) — testes em linguagem clara, não dump de terminal
- triagem na hora do download, com opinião automática + segunda leitura da IA
- workspace por **cliente** (sidebar → CLIENTE) e agenda de reteste
- **PILOTO** com básico / intermediário / completo / personalizado; **PARAR** cancela a missão
- atalhos de teclado (Alt+P, Alt+T, Alt+R, Alt+N…)

Abre, pede, executa, revisa, entrega.

#### Exemplos fáceis de entender

| Momento do dia | O que você usa |
|----------------|----------------|
| **Chegou agora e não conhece a tela** | Aperta **F1** — tour guiado. |
| **Quer repetir o mesmo tipo de scan** | Fixa a tool no painel ou roda o Piloto. |
| **Precisa provar o que rolou ontem** | Abre **relatórios** — prévia, PDFs salvos e carteira dos alvos. |
| **Entrega amanhã** | Clica **Baixar PDF**, lê as duas opiniões, valida o que ainda está pendente, gera o arquivo. |
| **Dois clientes no mesmo PC** | Sidebar → **CLIENTE**: troca o workspace; conversas e relatórios não se misturam. |
| **Reteste periódico** | No Piloto, marque **repetir** e informe os dias. A missão de agora roda na hora; a seguinte entra sozinha. |
| **Quer fluir sem mouse** | Atalhos: Piloto, tools, relatório, novo chat. |

Menos “ferramenta de demo”.  
Mais **bancada de trabalho**.

---
## Em uma imagem mental

```
Você fala o objetivo
        ↓
Argus decide o que fazer
        ↓
Kali executa de verdade
        ↓
Evidência + triagem (modal no download)
        ↓
PDF (ISO 27001 / SOC 2 indicativo) · dashboard · alertas · remediação · (opcional) GitHub
```

**DarkStar** = a cabine  
**Argus** = a copiloto  
**Kali** = a caixa de ferramentas  

Você manda. O sistema trabalha.

---

## O que você consegue fazer (de verdade)

- Pedir scans e enumerações em linguagem natural  
- Rodar missão automática com o Piloto (e **PARAR** se precisar)  
- Ver logs ao vivo e histórico completo  
- Triar achados **antes** do PDF: *é um problema real* / *alarme falso* / *ainda não sei* (ou pular o resto), com opinião da Argus e segunda opinião da IA  
- Ver a **prévia ao vivo** e baixar o **mesmo** PDF (testes resumidos, 8 seções, gráficos, correção, ISO/SOC 2 indicativo)  
- Isolar workspaces por **cliente** (sidebar → CLIENTE: criar, trocar, excluir)  
- Agendar reteste no Piloto (a cada N dias) ou via API (`monitor` / `remind` / `full`)  
- Ver **delta** vs baseline e importar Nessus CSV / Nuclei JSONL (API)  
- Automatizar por **CLI** (`autonomous`, `chat`, `health`, `list-tools`) e **GitHub Actions** (só quando você disparar)  
- Gerar saída **JSON** ou **SARIF** na CLI para CI  
- Abrir o **workspace** da conversa (ferramentas, logs, relatórios, mapa, dashboard) — tudo filtrado pelo chat ativo  
- Receber **alertas** (Slack, Discord, Telegram, e-mail, Jira) em achados críticos / delta  
- Persistir conversas, PDFs, intel e agenda no **SQLite local** ou Postgres (`DATABASE_URL`)  
- Trocar de modelo de IA no compositor (nuvem) ou ligar **04 offline** com Ollama  
- Desbloquear perfil avançado com master key + modo **03 offensive**  
- Integrar com Cursor/Claude via MCP (para quem quer ir além)

Se você é consultor solo, lab de estudo ou time pequeno: isso aqui foi feito para o seu fluxo.

---

## Automação, métricas, alertas e remediação

Além do chat e do Piloto no navegador, o DarkStar cobre o ciclo **depois** da execução — sem virar SaaS e sem vazar alvo por engano.

As **5 etapas** da camada de consultoria/automação:

1. **CLI** — pipeline e lab sem UI  
2. **GitHub** — comentário em PR / issue / commit status, só quando você pedir  
3. **Dashboard** — métricas e histórico da conversa  
4. **Alertas** — Slack, Discord, Telegram, e-mail, Jira  
5. **Remediação** — plano no PDF/prévia; API de wizard IA opcional  

No mesmo pacote: workspaces por cliente, agenda, delta, PDF da conversa (= prévia) e PDF comercial white-label por alvo, import de scanner, papéis locais e persistência no banco.

### 1. CLI (pipelines e lab sem UI)

Comandos: `autonomous`, `chat`, `health`, `list-tools`.

```bash
# Ative o venv do projeto, depois:
python -m backend.cli autonomous --target scanme.nmap.org --dry-run
python -m backend.cli autonomous --target scanme.nmap.org -o report.json
python -m backend.cli health
python -m backend.cli list-tools
```

Saídas: **json** (findings + risco) ou **sarif** (SARIF 2.1.0 mínimo — host/URL, não file:line).  
Exit codes pensados para CI: `0` ok · `1` high · `2` critical · `100` erro · `102` fora de escopo.

Detalhes: [`docs/CLI.md`](docs/CLI.md)

### 2. GitHub (entrega no PR / issue — sob demanda)

Com `GITHUB_TOKEN` no `.env`, a CLI ou a API podem **comentar no PR**, abrir issue ou atualizar commit status (`DarkStar Security`).  
**Não é automático** no chat/Piloto: só roda se você passar `--github-repo` + `--pr`, chamar a API ou disparar o workflow.

Templates Actions (somente `workflow_dispatch` — sem push/PR automático; alvo via input ou secret `DARKSTAR_TARGET`):

- [`.github/workflows/darkstar-pentest.yml`](.github/workflows/darkstar-pentest.yml) — scan manual; comenta no PR se informar o número  
- [`.github/workflows/darkstar-scheduled.yml`](.github/workflows/darkstar-scheduled.yml) — reteste; abre issue se houver critical  

```bash
python -m backend.cli autonomous \
  --target SEU_ALVO_AUTORIZADO \
  --github-repo owner/repo \
  --pr 12 \
  -o report.json
```

Detalhes: [`docs/GITHUB-INTEGRATION.md`](docs/GITHUB-INTEGRATION.md)

### 3. Workspace da conversa (página, sem modal)

Sidebar → **workspace**: **ferramentas · logs · relatórios · mapa · dashboard**.  
Tudo é da **conversa ativa** — apagar o chat zera intel/logs/scans ligados a ele. Dashboard não é visão global MSSP.

**Aba relatórios** (entrega do engajamento, num só lugar):

1. **Prévia HTML ao vivo** — o mesmo documento do PDF, atualizado com o chat.  
   KPIs (testes, achados, confirmados, FPs, risco) e gráficos de barras: risco residual, gravidade, triagem, ISO/SOC 2 indicativo, tipos de achado e ferramentas.  
   **Testes realizados** vêm resumidos (ferramenta, OK/FALHA, uma frase, bullets). Sem código ANSI nem logo de scanner. Falha (wordlist ausente, alvo sem resposta, comando errado) aparece em português. O log limpo fica em detalhe.  
   Cada achado vem em linguagem simples (o que é, analogia, impacto) + evidência.  
   **Como corrigir** traz quem faz, por quê, passo a passo e como validar.  
2. **Baixar PDF** — se ainda houver o que validar, abre o **modal de triagem** (um achado por vez, sem jargão).  
   - Fila: pendentes (`candidate` / `inconclusive`) **e** confirmados com heurística de falso positivo ≥ 55 (segunda olhada).  
   - **Opinião da Argus (automática)** — veredito, chance de alarme falso (%) e motivos a favor/contra. Sai na hora; a decisão continua sendo sua.  
   - **Segunda opinião (IA)** — pede no card visível (~8s), não atrasa a abertura da fila e **não marca** o achado sozinha. Os dois blocos usam a mesma escala: chance de alarme falso (0–100). Logs de teste (`OK — nmap`, etc.) ficam com FP alto mesmo se a IA chutar “problema real”. Se a IA falhar/offline, a heurística permanece.  
   - **É um problema real** · **É alarme falso** · **Ainda não sei** · **Pular o resto e gerar o PDF mesmo assim** · Cancelar (não baixa).  
   - No fim da fila o “pular” some: só **Gerar o PDF agora**.  
   - Fila vazia → PDF imediato. “Ainda não sei” vai para o **anexo**, fora do risco residual.  
   - Marcar alarme falso grava o padrão na **SQLite/Postgres** (`fp_suppress_patterns`) para o próximo scan.  
3. **Carteira** — cards dos alvos desta conversa: risco, confirmados/pendentes/FPs, delta (“novos / corrigidos / ainda abertos”) e próximo scan.  
4. **PDFs salvos** desta conversa.

O PDF da conversa **copia a prévia** (8 seções). Gravidade usa o tipo do achado e a tag do scanner (`[high]` XSS não vira “leve”).  
O PDF **comercial por alvo** (`GET /api/engagements/{alvo}/report`) é o outro layout: capa/rodapé white-label (`CONSULTING_NAME`, logo, cor) e sumário executivo (LLM com fallback).  
ISO/IEC 27001 e SOC 2 no relatório são mapeamento **indicativo** por palavras-chave. **Não substitui** certificação nem atestado SOC 2.

Aba **dashboard**: tendência de severidade, top issues, histórico de scans e export JSON/CSV/PDF — só desta conversa.

Detalhes: [`docs/DASHBOARD.md`](docs/DASHBOARD.md) · [`docs/REMEDIATION.md`](docs/REMEDIATION.md)

### 4. Notificações multicanal

Quando o delta/risco sobe (e canais estiverem configurados), o sistema pode avisar em:

- Slack / Discord (webhook)  
- Telegram  
- E-mail (SMTP)  
- Jira (issue)

Regra: **critical/high** disparam os canais ativos; médio/baixo só se você pedir na API (evita spam).  
A CLI `autonomous` também notifica se houver critical. API `/api/notifications/*` para teste e envio manual.

Detalhes: [`docs/NOTIFICATIONS.md`](docs/NOTIFICATIONS.md)

### 5. Remediação (no relatório + API)

O PDF/prévia já traz o plano **Como corrigir** (mapa estático por tipo: XSS, SQLi, HSTS, CVE…).  
Há também API de wizard IA (`POST /api/remediation/generate`) com tracker em `backend/data/remediation_track.json` — o overlay existe no shell, mas o workspace atual **não** tem um botão **fix** na lista de achados.

O comando de verificação do wizard é **só texto** (não executa no host).

Detalhes: [`docs/REMEDIATION.md`](docs/REMEDIATION.md)

### 6. Consultoria local (cliente, agenda, delta)

Feito para quem atende **vários alvos no mesmo PC**, sem portal do cliente e sem multi-tenant na nuvem.

- **CLIENTE** na sidebar — criar (modal + slug), trocar e excluir workspace. Conversas, relatórios e intel ficam separados por cliente. A marca (`CONSULTING_*` / logo do cliente) vale no **PDF comercial por alvo**.  
- **Backup/restore** do cliente (`tar.gz` via API).  
- **Agenda** (`SCHEDULE_ENABLED`, ligada por padrão):  
  - **Piloto** — checkbox “Repetir este teste automaticamente” + intervalo em **dias**. A primeira rodada é agora; as seguintes executam o **mesmo** alvo e tipo de scan (`job_type: repeat`).  
  - API `POST /api/schedules` também aceita `monitor` (nmap leve), `remind` (webhook) e `full` (só avisa para você iniciar o Piloto).  
  - A carteira em Relatórios mostra o próximo horário. 
- **Delta** — compara o baseline com o estado atual: novos, corrigidos, ainda abertos, portas que abriram.  
- **Import** — Nessus CSV ou Nuclei JSONL para o Attack Surface (`POST /api/engagements/{alvo}/import`).  
- **Papel local** (`OPERATOR_ROLE`): `admin` / `analyst` / `viewer` (viewer só lê).  
- **Retenção** (`RETENTION_DAYS`) — limpa artefatos velhos.  
- CVEs enriquecidos com **CISA KEV** e **FIRST EPSS** quando o threat intel está ligado.

### 7. Persistência (não perde o lab no F5)

Sem `DATABASE_URL` → **SQLite** em `backend/data/dashboard.db`.  
Com Postgres → a mesma URL serve dashboard, conversas, intel, clientes, agenda e PDFs.

Fica no banco: chats, relatórios baixados, sessão de intel da conversa, jobs da agenda, histórico de scans e padrões de falso positivo aprendidos na triagem.  
Apagar um chat remove o que era daquela conversa.

---

## Como instalar (simples)

### Você precisa de:

1. **Python 3.10+**
2. **Docker Desktop** (para o Kali real)
3. Uma IA:
   - chave no [OpenRouter](https://openrouter.ai/keys) **ou**
   - [Ollama](https://ollama.com) local (`ollama pull llama3.1:8b`)

### Windows (mais fácil)

```bat
start.bat
```

Abra: **http://127.0.0.1:8000**

Na primeira vez, o script prepara quase tudo sozinho e a Argus mostra um **guia de 3 passos**.  
Coloque sua chave no arquivo `.env` (`OPENROUTER_API_KEY`) se for usar modo online.

Sidebar (sistema): **01 workspace** · **02 master key** · **03 offensive** · **04 offline** · **05 som** · **06 ajuda**.

### Linux / macOS

```bash
chmod +x start.sh && ./start.sh
```

### Sem Docker agora? (só interface/chat)

```bat
start.bat servidor
```

### Quer IA 100% local? (o modo “submarino”)

1. Instale o [Ollama](https://ollama.com) e baixe um modelo (`ollama pull llama3.1:8b`)  
2. Abra o DarkStar  
3. Ligue o switch **04 offline** na barra lateral  

A partir daí: Argus + Kali **só no seu PC**.  
Útil em lab sem internet, cliente restrito — ou qualquer lugar onde a nuvem não pode entrar.

---

## Primeiro teste (lab autorizado)

1. Abra http://127.0.0.1:8000  
2. Aperte **F1** para o tour (opcional)  
3. Digite algo como:  
   *“faz um scan leve de portas em scanme.nmap.org”*  
4. Ou clique **PILOTO** e deixe a missão rodar  
5. Workspace → **relatórios**: veja a prévia (testes resumidos + gráficos) e clique **Baixar PDF** (a triagem mostra as duas opiniões se ainda houver o que validar)  
6. (Opcional) Abas **dashboard** / **logs** / **mapa** · botão **PARAR** se a missão estiver rodando  
7. (Opcional) Sidebar → **CLIENTE** para separar conversas por workspace  
8. (Opcional) Pelo venv: `python -m backend.cli autonomous --target scanme.nmap.org --dry-run`  

Se a mágica acontecer na sua tela… bem-vindo ao DarkStar.

---

## Atalhos

Use **Alt** + tecla (evita conflito com Ctrl+T / Ctrl+R do navegador).

| Tecla | Ação |
|-------|------|
| **Alt+P** | Piloto |
| **Alt+T** | Workspace · ferramentas |
| **Alt+R** ou **Alt+F** | Workspace · relatórios |
| **Alt+L** | Workspace · logs |
| **Alt+C** | Workspace · mapa |
| **Alt+N** | Novo chat |
| **Alt+K** ou **Ctrl+K** | Focar o prompt |
| **F1** / **Alt+H** / **?** | Tour guiado |
| **M** | Recolher/expandir a sidebar |
| **Esc** | Fechar painéis |

Ctrl+Shift+T / P / E / N são alternativas. **Enter** envia; **↑** / **↓** no prompt percorre o histórico da sessão.

---

## Configuração rápida (`.env`)

| O que | Para quê |
|-------|----------|
| `OPENROUTER_API_KEY` | IA na nuvem (modo online) |
| `ALLOWED_TARGETS` | Só esses alvos podem ser testados |
| `CHAT_API_TOKEN` | Protege a API local |
| `MASTER_KEY` | Libera perfil completo / offensive |
| `AI_PROVIDER=ollama` | Começa já em modo local |
| `GITHUB_TOKEN` | Comentários em PR / issues / status (opcional) |
| `DATABASE_URL` | Postgres (dashboard, conversas, intel, agenda, PDFs); sem isso → SQLite local |
| `CONSULTING_NAME` / `CONSULTING_LOGO_PATH` | White-label da capa do PDF comercial por alvo |
| `OPERATOR_ROLE` | `admin` (padrão) · `analyst` · `viewer` (só leitura) |
| `SCHEDULE_ENABLED` | Agenda de reteste em background |
| `RETENTION_DAYS` | Limpa artefatos antigos (0 = não limpa) |
| `COMPLIANCE_ENABLED` | Mapper indicativo ISO 27001 / SOC 2 |
| `MCP_ENABLED` | Servidor MCP em `/api/mcp/*` (Cursor/Claude) |
| `INTELLIGENCE_ENABLED` | Hub local de padrões / próximas checagens |
| `THREAT_INTEL_ENABLED` | Enriquece CVE com CISA KEV + EPSS |
| `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` | Alertas em canal |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Alertas Telegram |
| `SMTP_*` / `EMAIL_*` | Alertas por e-mail |
| `JIRA_URL` + `JIRA_USER` + `JIRA_TOKEN` | Abrir issue no Jira |
| `ALERT_WEBHOOK_URL` / `ALERT_ON_CRITICAL` | Webhook legado + gatilho de crítico |

Lista completa comentada: [`.env.example`](.env.example)

---

## Testes e cobertura

O CI ([`.github/workflows/tests.yml`](.github/workflows/tests.yml)) roda no **Ubuntu / Python 3.11**. A suíte unitária cobre **100% dos statements** de `backend/` (sem omitir módulos de código). O limiar é `fail_under = 100` no [`pyproject.toml`](pyproject.toml). Pastas de dado (`outputs/`, `audit/`, `logs/`, `recon/`, `data/`) ficam de fora — não são código.

Não precisa de Docker, Kali, rede nem chave de IA: os testes usam mocks.

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
coverage run -m unittest discover -s tests
coverage report
```

Lint (o mesmo do GitHub): `ruff check backend tests` e `ruff format --check backend tests`.  
E2E opcional: `npm ci` + `npx playwright test -c e2e/playwright.config.js` com a API no ar.

---

## Se travar em algo

| Problema | Solução rápida |
|----------|----------------|
| Não abre | Confira se o `start.bat` / `start.sh` está rodando |
| Kali off | Docker Desktop aberto + `start.bat repair` |
| IA muda | Chave OpenRouter / saldo, ou Ollama no offline |
| Comando bloqueado | Fora do escopo ou perfil restrito |
| Tela antiga | `Ctrl+F5` (cache do frontend) |
| `No module named 'github'` / CLI estranha | Use o venv: `.\venv\Scripts\Activate.ps1` (Windows) |
| GitHub responde 501 | `GITHUB_TOKEN` vazio ou inválido |
| Dashboard / carteira vazios | Rode um scan **nesta** conversa; carteira lê alvos e achados do chat |
| Alertas não chegam | Configure o canal no `.env` e teste `/api/notifications/test/{channel}` |
| API recusa POST | `OPERATOR_ROLE=viewer` só lê; use `analyst` ou `admin` |
| PDF sem a sua marca | `CONSULTING_*` vale no PDF **comercial por alvo** (`/api/engagements/.../report`), não na prévia da conversa |
| Segunda opinião da IA some | Chave OpenRouter / Ollama no **04 offline**; a opinião automática da Argus continua valendo |
| PDF com códigos `[34m` / logo do nuclei | `Ctrl+F5` e gere o PDF de novo — testes agora saem resumidos e limpos |
| `coverage report` falha no CI | Instale `coverage==7.8.0` (está em `requirements-dev.txt`); o limiar é 100% do `backend/` |

---

## Licença

MIT — com uso ético e autorizado.

Quer ir mais fundo?  
[`docs/MCP.md`](docs/MCP.md) · [`docs/INTELLIGENCE.md`](docs/INTELLIGENCE.md) · [`docs/POSITIONING.md`](docs/POSITIONING.md) · [`docs/CLI.md`](docs/CLI.md) · [`docs/GITHUB-INTEGRATION.md`](docs/GITHUB-INTEGRATION.md) · [`docs/DASHBOARD.md`](docs/DASHBOARD.md) · [`docs/NOTIFICATIONS.md`](docs/NOTIFICATIONS.md) · [`docs/REMEDIATION.md`](docs/REMEDIATION.md)

---

### DarkStar não é “mais um chat de hacking”.

É o ponto em que a conversa vira execução…  
a execução vira evidência…  
e a evidência vira entrega.

**Você pede. A Argus age. O relatório fecha.**
