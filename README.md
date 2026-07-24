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
- você revisa, classifica e só então entrega

**Menos vergonha na frente do cliente. Mais confiança no PDF.**

#### Exemplos fáceis de entender

| Situação | O que o DarkStar evita |
|----------|------------------------|
| **Scanner gritou “crítico!” e era bobagem** | O achado fica na fila para você olhar — não vai direto para o PDF executivo. |
| **IA “achou” vulnerabilidade só no texto** | Sem evidência / PoC, não passa no filtro (gate). |
| **Cliente pergunta “tem prova?”** | Você tem log, comando e classificação — não só opinião. |
| **Retrabalho humilhante** | Menos “desculpa, era falso positivo” depois de enviar o relatório. |

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

- chat natural em português
- painel de ferramentas
- logs por conversa
- triagem e biblioteca de PDFs
- mapa de ameaças
- tour guiado (**F1**) se você for novo
- atalhos de teclado para fluir rápido

Abre, pede, executa, revisa, entrega.

#### Exemplos fáceis de entender

| Momento do dia | O que você usa |
|----------------|----------------|
| **Chegou agora e não conhece a tela** | Aperta **F1** — tour guiado. |
| **Quer repetir o mesmo tipo de scan** | Fixa a tool no painel ou roda o Piloto. |
| **Precisa provar o que rolou ontem** | Abre logs / PDF salvos — não caça print no Discord. |
| **Entrega amanhã** | Tria achados hoje à noite, baixa o PDF de manhã. |
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
Evidência + triagem
        ↓
PDF / relatório
```

**DarkStar** = a cabine  
**Argus** = a copiloto  
**Kali** = a caixa de ferramentas  

Você manda. O sistema trabalha.

---

## O que você consegue fazer (de verdade)

- Pedir scans e enumerações em linguagem natural  
- Rodar missão automática com o Piloto  
- Ver logs ao vivo e histórico completo  
- Triar achados e baixar PDF  
- Trocar de modelo de IA (ChatGPT, Claude, Gemini, Grok, DeepSeek…)  
- Ligar modo offline com Ollama  
- Desbloquear perfil avançado com master key  
- Integrar com Cursor/Claude via MCP (para quem quer ir além)

Se você é consultor solo, lab de estudo ou time pequeno: isso aqui foi feito para o seu fluxo.

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

Na primeira vez, o script prepara quase tudo sozinho.  
Coloque sua chave no arquivo `.env` (`OPENROUTER_API_KEY`) se for usar modo online.

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
3. Ligue o switch **08 offline** na barra lateral  

A partir daí: Argus + Kali **só no seu PC**.  
Útil em lab sem internet, cliente restrito — ou qualquer lugar onde a nuvem não pode entrar.

---

## Primeiro teste (lab autorizado)

1. Abra http://127.0.0.1:8000  
2. Aperte **F1** para o tour (opcional)  
3. Digite algo como:  
   *“faz um scan leve de portas em scanme.nmap.org”*  
4. Ou clique **PILOTO** e deixe a missão rodar  
5. Revise em **relatório** e baixe o PDF  

Se a mágica acontecer na sua tela… bem-vindo ao DarkStar.

---

## Configuração rápida (`.env`)

| O que | Para quê |
|-------|----------|
| `OPENROUTER_API_KEY` | IA na nuvem (modo online) |
| `ALLOWED_TARGETS` | Só esses alvos podem ser testados |
| `CHAT_API_TOKEN` | Protege a API local |
| `MASTER_KEY` | Libera perfil completo / offensive |
| `AI_PROVIDER=ollama` | Começa já em modo local |

---

## Se travar em algo

| Problema | Solução rápida |
|----------|----------------|
| Não abre | Confira se o `start.bat` / `start.sh` está rodando |
| Kali off | Docker Desktop aberto + `start.bat repair` |
| IA muda | Chave OpenRouter / saldo, ou Ollama no offline |
| Comando bloqueado | Fora do escopo ou perfil restrito |
| Tela antiga | `Ctrl+F5` |

---

## Licença

MIT — com uso ético e autorizado.

Quer ir mais fundo?  
[`docs/MCP.md`](docs/MCP.md) · [`docs/INTELLIGENCE.md`](docs/INTELLIGENCE.md) · [`docs/POSITIONING.md`](docs/POSITIONING.md)

---

### DarkStar não é “mais um chat de hacking”.

É o ponto em que a conversa vira execução…  
a execução vira evidência…  
e a evidência vira entrega.

**Você pede. A Argus age. O relatório fecha.**
