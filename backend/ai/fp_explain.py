"""Heurística de falso positivo + fila de triagem em linguagem simples."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

_INFO_SEV = {"info", "informational", "none", "unknown", ""}
_HIGH_SEV = {"critical", "high", "alto"}
_HTTP_HINTS = ("http", "https", "header", "hsts", "csp", "cookie", "xss", "csrf")
_WAF_HINTS = ("waf", "cloudflare", "akamai", "blocked", "rate limit", "429", "403 forbidden")
_TIMEOUT_HINTS = ("timeout", "timed out", "connection refused", "no route")
_INCOMPLETE_HINTS = (
    "timeout",
    "timed out",
    "unresponsive",
    "sem resposta",
    "wordlist ausente",
    "missing wordlist",
    "no input",
    "não respondeu",
    "connection refused",
    "no route",
)
_PAYLOAD_HINTS = (
    "<script",
    "alert(",
    "onerror=",
    "onmouseover=",
    "union select",
    "sleep(",
    "../etc/passwd",
    "{{7*7}}",
    "`id`",
    "whoami",
    "' or '1'='1",
    '" or "1"="1',
)
_WEB_VULN_KINDS = frozenset({"xss", "sqli", "rce", "lfi", "ssti", "idor"})
_SCAN_TITLE_PREFIXES = (
    "ok —",
    "ok -",
    "falha —",
    "falha -",
    "resultado —",
    "resultado -",
)
_RECEIPT_SOURCES = frozenset({"execution_log", "client_history"})
_SERIOUS_SEV = frozenset({"medium", "high", "critical", "medio", "média", "alto"})
_IDOR_HINTS = (
    "idor",
    "bola",
    "broken access",
    "broken object",
    "insecure direct object",
    "falha de autoriza",
    "sem valida",
    "não está validando",
    "nao esta validando",
    "dados de outros usu",
    "outro usuário",
    "outro usuario",
    "outros usuários",
    "outros usuarios",
    "iterar sobre os id",
    "iterar sobre id",
    "horizontal privilege",
    "escalonamento de privil",
    "acesso a dados de",
    "authorization bypass",
    "access control",
)
_VULN_NARRATIVE_HINTS = _IDOR_HINTS + (
    "xss",
    "cross-site",
    "sql injection",
    "sqli",
    "remote code",
    "command injection",
    "path traversal",
    "local file inclusion",
    "ssti",
    "template inject",
    "cve-",
    "vulnerabilidade",
    "exploit",
    "payload",
)


def _blob(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(k) or "")
        for k in ("title", "evidence", "template_id", "cve", "tool", "command", "severity")
    ).lower()


_SEV_PLAIN = {
    "critical": "Muito grave",
    "high": "Grave",
    "alto": "Grave",
    "medium": "Atenção",
    "medio": "Atenção",
    "média": "Atenção",
    "low": "Leve",
    "baixo": "Leve",
    "info": "Só informação",
    "informational": "Só informação",
}

# Explicações para quem não é de segurança: o que é, analogia, impacto, como decidir.
_LAY: dict[str, dict[str, Any]] = {
    "xss": {
        "plain_title": "Alguém pode colocar um programa escondido na página",
        "what_it_is": (
            "O site parece aceitar texto que o navegador trata como programa, não como frase. "
            "Na prática, um visitante mal-intencionado poderia misturar código no meio de um campo "
            "(busca, comentário, nome) e esse código rodaria no computador de outras pessoas."
        ),
        "everyday": (
            "Imagine um mural de recados da loja. Em vez de escrever “aberto até as 18h”, "
            "alguém cola um aviso falso que pede o cartão do cliente. Quem lê acha que o recado "
            "é da loja."
        ),
        "why_it_matters": (
            "Se for verdade, a pessoa atacante pode roubar a sessão de um usuário (entrar na conta "
            "sem senha), ver o que ele vê, ou enganar clientes em nome da empresa."
        ),
        "could_happen": [
            "Um cliente entra no site e o navegador dele executa um programa que não é de vocês.",
            "A conta de um usuário (ou a de um administrador) pode ser usada por outra pessoa.",
            "Pode aparecer um formulário falso pedindo senha ou dados de pagamento.",
        ],
        "how_to_decide": [
            "Olhe a evidência: o texto estranho (o “payload”) aparece de volta na página?",
            "Se a página devolve o código ou um alerta do navegador, trate como problema real.",
            "Se só há timeout, bloqueio ou uma mensagem genérica, pode ser alarme falso.",
        ],
    },
    "sqli": {
        "plain_title": "O formulário pode estar falando direto com o banco de dados",
        "what_it_is": (
            "Campos como login, busca ou filtro podem estar mandando o que a pessoa digitou "
            "direto para o banco, sem separar “dado” de “comando”. Isso se chama injeção de SQL."
        ),
        "everyday": (
            "É como um atendente que anota o pedido na cozinha sem conferir. Se alguém escrever "
            "no pedido “cancele todos os outros e me dê o caixa”, a cozinha obedece."
        ),
        "why_it_matters": (
            "O banco costuma guardar clientes, senhas, pedidos e dados internos. "
            "Se a injeção for real, quem explora pode ler, alterar ou apagar essas informações."
        ),
        "could_happen": [
            "Ler lista de clientes, senhas ou pedidos sem autorização.",
            "Entrar em uma conta sem saber a senha.",
            "Alterar ou apagar registros (preços, usuários, histórico).",
        ],
        "how_to_decide": [
            "A evidência mostra erro de banco, nomes de tabela, ou um resultado que não deveria aparecer?",
            "Se sim, é problema real — mesmo que o teste não tenha “invadido” de fato.",
            "Se a ferramenta só tentou e o site bloqueou ou não respondeu, marque incerto ou alarme falso.",
        ],
    },
    "rce": {
        "plain_title": "Alguém pode mandar o servidor executar um comando",
        "what_it_is": (
            "A ferramenta indica que o sistema pode aceitar uma instrução e rodá-la na máquina, "
            "como se fosse um operador interno. Isso é execução remota de código."
        ),
        "everyday": (
            "É entregar a chave da sala dos servidores para quem está na rua. "
            "Quem entra não só vê a vitrine: mexe nos equipamentos."
        ),
        "why_it_matters": (
            "É um dos problemas mais sérios: dá controle da máquina, dos arquivos e, em muitos casos, "
            "do restante da rede interna."
        ),
        "could_happen": [
            "Instalar programa malicioso no servidor.",
            "Ler arquivos internos (configuração, backups, chaves).",
            "Usar esse servidor como ponte para atacar outros sistemas da empresa.",
        ],
        "how_to_decide": [
            "A evidência mostra a saída de um comando (por exemplo, o nome do sistema) que só o servidor saberia?",
            "Se mostrou, é problema real e urgente.",
            "Se a ferramenta só “achou um padrão” sem prova, marque incerto até repetir o teste com autorização.",
        ],
    },
    "lfi": {
        "plain_title": "A página pode estar abrindo arquivos internos do servidor",
        "what_it_is": (
            "Um parâmetro da URL (como ?file=) pode estar sendo usado para ler arquivos do disco "
            "em vez de só a página pedida. Isso se chama inclusão ou leitura de arquivo local."
        ),
        "everyday": (
            "É pedir “o cardápio” e o garçom trazer também o caderno de senhas do escritório, "
            "porque ninguém conferiu o que estava no pedido."
        ),
        "why_it_matters": (
            "Arquivos internos podem ter senhas, chaves e dados de clientes. "
            "Quem lê isso de fora já tem um pé dentro da empresa."
        ),
        "could_happen": [
            "Ler arquivos de configuração com senhas.",
            "Ver código-fonte e descobrir outras falhas.",
            "Em alguns sistemas, chegar a executar programas no servidor.",
        ],
        "how_to_decide": [
            "A evidência mostra conteúdo de arquivo (passwd, wp-config, .env) que não deveria ser público?",
            "Se sim, é problema real.",
            "Se só há um 404 ou bloqueio, pode ser alarme falso.",
        ],
    },
    "ssti": {
        "plain_title": "O site pode estar executando o que você escreve no meio do texto",
        "what_it_is": (
            "Algumas páginas montam HTML com um “modelo”. Se o que a pessoa digita entra nesse modelo "
            "sem filtro, o servidor pode calcular ou executar isso. Chama-se injeção em template."
        ),
        "everyday": (
            "É um contrato com espaços em branco. Em vez de só preencher o nome, alguém escreve "
            "uma cláusula nova e o cartório registra do jeito que está."
        ),
        "why_it_matters": "Pode vazar dados internos ou, no pior caso, mandar o servidor rodar comandos.",
        "could_happen": [
            "Vazar variáveis internas da aplicação.",
            "Chegar a executar comandos no servidor.",
        ],
        "how_to_decide": [
            "A evidência mostra um cálculo (por exemplo 7*7 virando 49) no lugar do texto?",
            "Se sim, é problema real.",
            "Se não houve reprodução, marque incerto.",
        ],
    },
    "cve": {
        "plain_title": "Um programa deste alvo tem uma falha já conhecida",
        "what_it_is": (
            "CVE é um número de catálogo mundial de falhas. Significa: “este software, nesta versão, "
            "já foi descoberto com um buraco”. Não é um ataque acontecendo agora — é um aviso de que "
            "o buraco pode estar aberto se a versão for a mesma."
        ),
        "everyday": (
            "É um recall de carro: o modelo X, ano Y, tem um defeito conhecido. "
            "Só vale se o carro da empresa for exatamente esse modelo."
        ),
        "why_it_matters": (
            "Se a versão vulnerável estiver mesmo no ar, criminosos já sabem como explorar — "
            "existe receita pronta na internet."
        ),
        "could_happen": [
            "Uso de um ataque já documentado contra esse software.",
            "Invasão, vazamento ou queda do serviço, conforme o CVE.",
        ],
        "how_to_decide": [
            "Confira se a versão do programa no alvo é a citada (banner, pacote, painel).",
            "Se a versão for vulnerável e o serviço estiver exposto, é problema real.",
            "Se já estiver atualizado ou for outro produto, é alarme falso.",
        ],
    },
    "hsts": {
        "plain_title": "O site não obriga o navegador a usar a versão trancada (HTTPS)",
        "what_it_is": (
            "HTTPS é o cadeado da conexão. HSTS é um recado do site: “da próxima vez, "
            "nem tente a versão sem cadeado”. Sem isso, em uma rede Wi‑Fi pública alguém "
            "pode tentar desviar o primeiro acesso para uma página falsa."
        ),
        "everyday": (
            "É uma loja com porta de vidro e fechadura, mas o segurança não avisa o cliente "
            "para sempre usar a porta trancada. Na primeira visita, a pessoa pode entrar pela porta errada."
        ),
        "why_it_matters": (
            "Não é invasão do servidor. É uma proteção a menos no caminho entre o cliente e o site. "
            "Vale corrigir, mas o impacto costuma ser menor do que SQL injection ou XSS."
        ),
        "could_happen": [
            "Em rede pública, um atacante pode tentar interceptar o primeiro acesso.",
            "O cadeado pode não ser exigido de forma consistente.",
        ],
        "how_to_decide": [
            "Abra o site em HTTPS e veja se a resposta traz o cabeçalho Strict-Transport-Security.",
            "Se o cabeçalho já existir, a ferramenta errou (alarme falso).",
            "Se faltar de verdade, marque como problema real de endurecimento — não como “site invadido”.",
        ],
    },
    "clickjack": {
        "plain_title": "A página pode ser colocada por cima de outro site, como uma armadilha",
        "what_it_is": (
            "Sem a proteção X-Frame-Options (ou CSP frame-ancestors), outro site pode embutir "
            "a página de vocês num quadro invisível. A pessoa clica achando que é um botão inocente, "
            "mas está clicando no site de vocês. Isso se chama clickjacking."
        ),
        "everyday": (
            "É colocar um vidro com um botão desenhado em cima do caixa eletrônico. "
            "A pessoa aperta “imprimir comprovante” e, por baixo, confirma uma transferência."
        ),
        "why_it_matters": (
            "Usuários logados podem ser enganados a mudar senha, transferir, apagar ou autorizar algo "
            "sem perceber. Não é o servidor sendo invadido; é o clique da pessoa sendo desviado."
        ),
        "could_happen": [
            "Um usuário autenticado clica sem saber e altera algo na conta.",
            "A marca da empresa aparece num golpe hospedado em outro domínio.",
        ],
        "how_to_decide": [
            "Veja se a resposta HTTP traz X-Frame-Options ou frame-ancestors.",
            "Se já existir, é alarme falso.",
            "Se faltar, é problema real de proteção no navegador — impacto médio na maioria dos casos.",
        ],
    },
    "csp": {
        "plain_title": "O site não limita de onde os programas da página podem vir",
        "what_it_is": (
            "Content-Security-Policy (CSP) é uma lista: “só rode scripts deste endereço”. "
            "Sem ela, qualquer script que entrar na página (por um XSS, um anúncio, um plugin) tem mais liberdade."
        ),
        "everyday": (
            "É uma festa sem lista de convidados: qualquer um que chegar pode subir no palco e falar ao microfone."
        ),
        "why_it_matters": (
            "CSP não substitui corrigir XSS, mas reduz o estrago. Falta de CSP sozinha raramente é “invasão”; "
            "é uma trava a menos."
        ),
        "could_happen": [
            "Um script de terceiro (ou um XSS) consegue rodar com menos obstáculo.",
        ],
        "how_to_decide": [
            "Confira o cabeçalho Content-Security-Policy na resposta.",
            "Se já existir uma política razoável, pode ser alarme falso ou detalhe menor.",
            "Se não existir, marque como problema real de endurecimento.",
        ],
    },
    "nosniff": {
        "plain_title": "O servidor não impede o navegador de “adivinhar” o tipo do arquivo",
        "what_it_is": (
            "X-Content-Type-Options: nosniff manda o navegador respeitar o tipo declarado "
            "(isto é texto, isto é imagem). Sem isso, um arquivo mal nomeado pode ser tratado como programa."
        ),
        "everyday": "É um pacote rotulado “biscoito” que o porteiro não confere: pode ser outra coisa dentro.",
        "why_it_matters": "É um reforço pequeno. Sozinho quase nunca derruba um sistema.",
        "could_happen": [
            "Em combinação com outro erro, um arquivo pode ser executado como script no navegador.",
        ],
        "how_to_decide": [
            "Se o cabeçalho nosniff já estiver presente, é alarme falso.",
            "Se faltar, pode marcar como problema leve de endurecimento.",
        ],
    },
    "ssl": {
        "plain_title": "A trava da conexão (HTTPS) parece fraca ou mal configurada",
        "what_it_is": (
            "HTTPS cifra o que trafega entre o cliente e o servidor. Certificado vencido, protocolo velho "
            "ou cifra fraca equivalem a um cadeado enferrujado: ainda parece trancado, mas abre com menos esforço."
        ),
        "everyday": (
            "É enviar uma carta “lacrada” com fita crepe em vez de lacre oficial. "
            "No correio, alguém pode abrir e fechar de novo."
        ),
        "why_it_matters": (
            "Em uma rede controlada pelo atacante (Wi‑Fi de hotel, provedor), dados de login e formulários "
            "podem ser lidos ou alterados no caminho."
        ),
        "could_happen": [
            "Senha ou cartão interceptados no trânsito.",
            "O navegador mostra aviso de site inseguro e o cliente desconfia da marca.",
        ],
        "how_to_decide": [
            "Abra o site no navegador: há aviso de certificado? A data está válida?",
            "Se o cadeado estiver ok e o alerta for de uma cifra antiga, avalie com o time se ainda é usada.",
            "Timeout ou ferramenta que não completou o handshake → incerto, não “site invadido”.",
        ],
    },
    "port": {
        "plain_title": "Há uma “porta” deste computador visível na internet",
        "what_it_is": (
            "Computadores na internet têm “portas”, como números de apartamento. "
            "Uma porta aberta só significa: “alguém atende neste número”. "
            "Isso não é, sozinho, uma invasão nem um vírus."
        ),
        "everyday": (
            "É ver que a loja tem uma porta dos fundos. Ter a porta não é assalto. "
            "Vira problema se essa porta não deveria existir, ou se a fechadura é conhecida por ser fraca."
        ),
        "why_it_matters": (
            "Cada serviço visível aumenta a superfície: painel de banco, remoto, e-mail. "
            "Muitos são necessários (80 e 443 para site). Outros (remoto administrativo) não deveriam estar públicos."
        ),
        "could_happen": [
            "Alguém tenta senhas nesse serviço o dia inteiro.",
            "Se o programa atrás da porta tiver CVE, a porta vira a entrada.",
        ],
        "how_to_decide": [
            "Esse serviço precisa mesmo estar na internet, ou só na rede interna?",
            "Se for o site (80/443) esperado, em geral NÃO é vulnerabilidade — é informação.",
            "Só marque como problema real se o serviço for desnecessário, antigo, ou com falha conhecida.",
        ],
    },
    "exposure": {
        "plain_title": "Um painel interno parece acessível pela internet",
        "what_it_is": (
            "A ferramenta encontrou uma tela de administração, backup, phpinfo, diretório de arquivos "
            "ou algo que costuma ser só para a equipe. Estar visível na internet já é um risco, "
            "mesmo com senha."
        ),
        "everyday": (
            "É deixar a porta da sala de gerência dando para a calçada. "
            "Pode ter fechadura, mas todo mundo vê que existe e pode ficar tentando a chave."
        ),
        "why_it_matters": "Painéis internos não foram feitos para o público. Ataques de senha e falhas nesses sistemas são comuns.",
        "could_happen": [
            "Tentativas infinitas de senha no painel.",
            "Se a senha for fraca ou padrão, alguém entra de verdade.",
        ],
        "how_to_decide": [
            "Dá para abrir essa URL sem VPN, do celular na rua?",
            "Se sim e não deveria, é problema real (exposição).",
            "Se só abre na rede interna e a ferramenta viu um eco antigo, pode ser alarme falso.",
        ],
    },
    "wordpress": {
        "plain_title": "O WordPress (ou um plugin) parece desatualizado ou exposto",
        "what_it_is": (
            "WordPress é o sistema por trás de muitos sites. Plugins e temas antigos são o caminho "
            "mais comum de invasão em sites institucionais."
        ),
        "everyday": "É uma fechadura da marca certa, mas com um modelo que ladrões já copiaram há anos.",
        "why_it_matters": "Sites WordPress desatualizados são alvo fácil de defacement (página trocada) e de malware que espalha spam.",
        "could_happen": [
            "Página da empresa trocada por recado de atacante.",
            "Instalação de plugin malicioso que rouba formulários.",
        ],
        "how_to_decide": [
            "A versão apontada está mesmo no ar? Confira no painel ou no HTML.",
            "Se a versão for antiga, é problema real: atualize núcleo, temas e plugins.",
            "Se já estiver atualizado, a ferramenta pode ter lido um arquivo velho (alarme falso).",
        ],
    },
    "idor": {
        "plain_title": "Dá para ver dados de outra pessoa só mudando o ID",
        "what_it_is": (
            "A API ou a página entrega informação de um usuário quando se troca o número/ID na URL "
            "ou no pedido, sem checar se quem pediu tem permissão. Isso é IDOR / falha de controle de acesso."
        ),
        "everyday": (
            "É como pedir a chave do armário 12 e o atendente entregar a do armário 13 sem perguntar "
            "se o armário é seu."
        ),
        "why_it_matters": (
            "Um atacante pode varrer IDs e coletar e-mails, telefones, nomes ou dados internos "
            "de todos os usuários — base para fraude e engenharia social."
        ),
        "could_happen": [
            "Vazamento em massa de dados pessoais (e-mail, telefone, nome).",
            "Acesso a contas ou funções de outros perfis.",
            "Escalonamento se o ID exposto for de admin ou de recurso privilegiado.",
        ],
        "how_to_decide": [
            "Com a mesma sessão, trocar o ID devolveu dados de outro usuário?",
            "Se sim → vulnerabilidade real. Se a API negou (403/404) → pode ser alarme falso.",
            "Confirme se o ambiente é o autorizado e se o dado realmente é de outra conta.",
        ],
    },
    "scan_summary": {
        "plain_title": "Isto é o resultado de um teste — não é, por si, uma falha",
        "what_it_is": (
            "A conversa registrou que uma ferramenta rodou (por exemplo um varredura de portas). "
            "“OK” só quer dizer que o comando terminou. Não prova que exista um buraco."
        ),
        "everyday": (
            "É o recibo de que o encanador passou na casa. O recibo não é um vazamento. "
            "O vazamento estaria descrito à parte, com foto e local."
        ),
        "why_it_matters": (
            "Misturar “o teste rodou” com “achamos uma falha” deixa o PDF mentiroso. "
            "Só confirme como vulnerabilidade se a evidência descrever um problema concreto."
        ),
        "could_happen": [
            "Nada, se for só o log da execução.",
            "O PDF pode assustar o cliente à toa se isto for marcado como falha.",
        ],
        "how_to_decide": [
            "A evidência descreve uma falha específica (XSS, SQL, CVE, header faltando)?",
            "Se não, marque alarme falso ou “não tenho certeza” — não coloque no corpo do PDF como vulnerabilidade.",
            "Se sim, volte e classifique aquele achado específico, não este resumo.",
        ],
    },
    "generic": {
        "plain_title": "A ferramenta apontou um possível problema",
        "what_it_is": (
            "Um scanner automático encontrou um sinal. Scanners erram: às vezes gritam “fogo” "
            "quando é só fumaça da cozinha. Por isso pedimos a sua leitura antes do PDF."
        ),
        "everyday": (
            "É o alarme da casa disparando. Pode ser um arrombamento — ou o gato. "
            "Alguém precisa olhar pela janela antes de ligar para a polícia."
        ),
        "why_it_matters": (
            "O relatório em PDF vai para pessoas que não viram o teste. "
            "Só deve constar como vulnerabilidade o que vocês confirmarem."
        ),
        "could_happen": [
            "Se for real, o impacto depende do tipo (os detalhes técnicos estão na evidência).",
            "Se for falso, o cliente perde tempo e confiança no relatório.",
        ],
        "how_to_decide": [
            "A evidência reproduz o problema no alvo autorizado, com um resultado claro?",
            "Se sim → problema real. Se a ferramenta não completou ou foi bloqueada → incerto ou alarme falso.",
            "Na dúvida, escolha “Não sei ainda”: o item vai para o anexo, não some.",
        ],
    },
}


def is_incomplete_evidence(blob: str) -> bool:
    text = (blob or "").lower()
    return any(h in text for h in _INCOMPLETE_HINTS)


def has_exploit_payload(blob: str) -> bool:
    text = (blob or "").lower()
    return any(h in text for h in _PAYLOAD_HINTS)


def has_vuln_narrative_signals(blob: str) -> bool:
    text = (blob or "").lower()
    return any(h in text for h in _VULN_NARRATIVE_HINTS)


def looks_like_idor(blob: str) -> bool:
    text = (blob or "").lower()
    return any(h in text for h in _IDOR_HINTS)


def is_scan_receipt_title(title: str) -> bool:
    t = (title or "").strip().lower()
    return any(t.startswith(p) for p in _SCAN_TITLE_PREFIXES)


def is_execution_receipt(finding: dict[str, Any]) -> bool:
    """Recibo de ferramenta (nmap/httpx/…), não uma falha descrita."""
    source = str(finding.get("source") or "")
    if source in _RECEIPT_SOURCES:
        return True
    return is_scan_receipt_title(str(finding.get("title") or ""))


def is_pure_scan_receipt(finding: dict[str, Any]) -> bool:
    """Recibo sem narrativa de vulnerabilidade no blob — deve ser descartado, não FP."""
    if not is_execution_receipt(finding):
        return False
    return not has_vuln_narrative_signals(_blob(finding))


def apply_fp_hard_rules(
    *,
    kind: str,
    blob: str,
    likely_fp: int,
    verdict: str,
    severity: str = "",
) -> tuple[int, str, bool, str]:
    """Mesma escala: likely_fp = chance de alarme falso (0–100)."""
    likely = max(0, min(100, int(likely_fp)))
    v = verdict if verdict in {"confirmed", "false_positive", "unsure"} else "unsure"
    adjusted = False
    reason = ""
    incomplete = is_incomplete_evidence(blob)
    sev = str(severity or "").lower()

    if kind == "scan_summary" and not has_vuln_narrative_signals(blob):
        if v != "false_positive" or likely < 88:
            adjusted = True
            reason = "Isto é log de teste, não uma falha. Ajustado para alarme falso."
        v = "false_positive"
        likely = max(likely, 88)
    elif incomplete:
        if v == "confirmed":
            adjusted = True
            reason = (
                "O teste não completou (timeout, wordlist ou sem resposta); não dá para confirmar."
            )
            v = "unsure"
        if likely <= 25:
            likely = 40
    elif kind in _WEB_VULN_KINDS and (
        has_exploit_payload(blob) or (kind == "idor" and looks_like_idor(blob))
    ):
        if v == "false_positive" or likely >= 55:
            adjusted = True
            reason = "Há evidência de falha clássica; chance de alarme falso reduzida."
            if v == "false_positive":
                v = "unsure"
        likely = min(likely, 22)
        if v != "unsure":
            v = "confirmed"

    # Nunca auto-FP em medium/high/critical
    if sev in _SERIOUS_SEV and v == "false_positive":
        adjusted = True
        reason = "Severidade média/alta: não auto-classificar como alarme falso."
        v = "unsure"
        likely = min(likely, 54)

    return likely, v, adjusted, reason


def _detect_kind(finding: dict[str, Any], blob: str) -> str:
    title = str(finding.get("title") or "").strip().lower()
    # IDOR/authz antes de scan_summary — mesmo em títulos "OK — …"
    if looks_like_idor(blob):
        return "idor"
    if "xss" in blob or "cross-site" in blob:
        return "xss"
    if "sql" in blob or "sqli" in blob:
        return "sqli"
    if any(k in blob for k in ("rce", "remote code", "command injection", "os command")):
        return "rce"
    if re.search(r"\b(lfi|rfi)\b", blob) or "path traversal" in blob or "local file" in blob:
        return "lfi"
    if "ssti" in blob or "template inject" in blob:
        return "ssti"
    if is_scan_receipt_title(title) and not has_vuln_narrative_signals(blob):
        return "scan_summary"
    if "hsts" in blob or "strict-transport" in blob:
        return "hsts"
    if "x-frame" in blob or "clickjack" in blob:
        return "clickjack"
    if "content-security" in blob or re.search(r"\bcsp\b", blob):
        return "csp"
    if "x-content-type" in blob or "nosniff" in blob:
        return "nosniff"
    if any(k in blob for k in ("tls", "ssl", "certificate", "cipher")):
        return "ssl"
    if "wordpress" in blob or "wp-" in blob:
        return "wordpress"
    if finding.get("cve") or "cve-" in blob:
        return "cve"
    if re.search(r"\d+/tcp", blob) or "open port" in blob or "porta aberta" in blob:
        return "port"
    if any(k in blob for k in ("admin", "phpinfo", "exposed", "dashboard", "painel")):
        return "exposure"
    if is_scan_receipt_title(title):
        return "scan_summary"
    return "generic"


def detect_finding_kind(finding: dict[str, Any]) -> str:
    """Tipo do achado (xss, sqli, porta, etc.) a partir do título/evidência."""
    return _detect_kind(finding, _blob(finding))


def _plain_title(finding: dict[str, Any], kind: str | None = None) -> str:
    kind = kind or _detect_kind(finding, _blob(finding))
    guide = _LAY.get(kind) or _LAY["generic"]
    title = str(finding.get("title") or "").strip()
    if kind == "cve" and (finding.get("cve") or "cve-" in title.lower()):
        cve = str(finding.get("cve") or title)[:40]
        return f"Um programa deste alvo tem uma falha já conhecida ({cve})."
    if kind != "generic":
        return str(guide["plain_title"])
    return title[:160] or str(guide["plain_title"])


def _severity_plain(sev: str) -> str:
    return _SEV_PLAIN.get(str(sev or "info").lower(), "Atenção")


def explain_false_positive(
    finding: dict[str, Any], *, siblings: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Score 0–100 e textos em PT para o analista decidir."""
    siblings = siblings or []
    blob = _blob(finding)
    kind = _detect_kind(finding, blob)
    guide = _LAY.get(kind) or _LAY["generic"]
    sev = str(finding.get("severity") or "").lower()
    title_raw = str(finding.get("title") or "")
    if re.search(r"\[(critical|high)\]", title_raw, re.I) and sev in _INFO_SEV:
        sev = "high"
    status = str(finding.get("status") or "candidate")
    reasons: list[str] = []
    why_vuln: list[str] = []
    why_fp: list[str] = []
    score = 15
    inflate_info = kind not in _WEB_VULN_KINDS

    suppressed = False
    try:
        from backend.ai.fp_learn import is_suppressed

        suppressed = is_suppressed(finding)
    except Exception:  # noqa: BLE001
        suppressed = False
    if suppressed:
        score += 40
        reasons.append(
            "Você (ou alguém neste lab) já marcou um achado parecido como falso positivo."
        )
        why_fp.append("Esse padrão já foi classificado como alarme falso antes.")

    if sev in _INFO_SEV and inflate_info:
        score += 25
        reasons.append("O scanner classificou isso só como informação, não como ataque comprovado.")
        why_fp.append(
            "Itens ‘info’ costumam ser enumeração (banner, porta, tecnologia), não uma falha explorável."
        )
    elif sev in {"low", "baixo"} and inflate_info:
        score += 8
        reasons.append("Severidade baixa: impacto limitado se for real.")
    elif sev in _HIGH_SEV:
        score -= 15
        why_vuln.append("A ferramenta marcou impacto alto — vale confirmar com calma.")

    if finding.get("cve") or "cve-" in blob:
        score -= 10
        why_vuln.append(
            "Há um CVE citado: se o software for mesmo essa versão, o risco é concreto."
        )
    if any(k in blob for k in ("sql", "xss", "rce", "ssti", "lfi", "rfi", "idor", "bola")):
        score -= 12
        why_vuln.append(
            "O nome sugere uma falha clássica de aplicação — se a evidência mostrar payload, trate como vulnerabilidade."
        )

    if kind == "idor":
        score -= 18
        why_vuln.append(
            "Falha de autorização (IDOR): se trocar o ID devolve dados de outra conta, é vulnerabilidade real."
        )

    if any(k in blob for k in ("missing header", "hsts", "x-frame", "csp", "x-content-type")):
        why_vuln.append(
            "Headers de segurança ausentes facilitam ataques no navegador (clickjacking, XSS, downgrade HTTP)."
        )
        host = str(finding.get("host") or finding.get("surface_target") or "")
        if host and not any(h in blob for h in _HTTP_HINTS) and "http" not in host:
            score += 18
            why_fp.append("Pode não ser um site HTTP — header só faz sentido em páginas web.")

    if any(k in blob for k in _WAF_HINTS):
        score += 20
        reasons.append("A resposta parece bloqueio de WAF/CDN, não uma confirmação da falha.")
        why_fp.append("Firewall pode ter barrado o teste: o achado fica inconclusivo.")

    if any(k in blob for k in _TIMEOUT_HINTS):
        score += 18
        why_fp.append(
            "Timeout ou conexão recusada não prova a vulnerabilidade — só que o teste não completou."
        )

    title_key = str(finding.get("title") or "").strip().lower()[:80]
    cve_key = str(finding.get("cve") or "").upper()
    dup = 0
    for other in siblings:
        if other is finding or other.get("id") == finding.get("id"):
            continue
        ot = str(other.get("title") or "").strip().lower()[:80]
        oc = str(other.get("cve") or "").upper()
        if title_key and ot == title_key:
            dup += 1
        elif cve_key and oc == cve_key:
            dup += 1
    if dup:
        score += 12
        reasons.append(
            "Há outro achado com o mesmo título/CVE nesta conversa (possível duplicata)."
        )
        why_fp.append("Scanners repetem o mesmo alerta em URLs diferentes.")

    tool = str(finding.get("tool") or "").lower()
    if tool in {"nmap", "naabu", "masscan"} and "tcp" in blob:
        why_fp.append(
            "Porta aberta não é, por si só, uma vulnerabilidade — só superfície de ataque."
        )
        if sev in _INFO_SEV or not finding.get("cve"):
            score += 10

    if kind == "scan_summary":
        score += 22
        why_fp.append("Este item é o log de que um teste rodou, não a descrição de um buraco.")

    if kind in _WEB_VULN_KINDS and has_exploit_payload(blob):
        score -= 20
        why_vuln.append(
            "A evidência traz payload típico — isso costuma ser problema real, não ruído."
        )

    if not why_vuln:
        why_vuln.append(
            str(guide.get("why_it_matters") or "")[:240]
            or (
                "Se a evidência mostrar o problema de forma reproduzível no alvo autorizado, trate como vulnerabilidade."
            )
        )
    if not why_fp:
        why_fp.append(
            "Pode ser ruído de scanner, ambiente de lab, ou um controle que já existe atrás de WAF."
        )
    if not reasons:
        reasons.append("Ainda não há confirmação humana — precisa da sua leitura.")

    if status == "confirmed" and sev in _INFO_SEV:
        score += 12
        why_fp.append(
            "A automação marcou como vulnerabilidade, mas o scanner só classificou como informação."
        )

    score = max(0, min(100, score))
    fp_threshold = 70 if kind in _WEB_VULN_KINDS else 55
    if score >= fp_threshold:
        suggestion = "false_positive"
    elif score <= 25:
        suggestion = "confirmed"
    else:
        suggestion = "unsure"
    score, suggestion, _adj, _why = apply_fp_hard_rules(
        kind=kind,
        blob=blob,
        likely_fp=score,
        verdict=suggestion,
        severity=sev,
    )
    if suggestion == "false_positive":
        suggestion_label = "A ferramenta pode ter se enganado"
        suggestion_hint = (
            "Pelo que vimos, isto parece mais alarme falso do que um ataque de verdade."
        )
    elif suggestion == "confirmed":
        suggestion_label = "Isto parece um problema real"
        suggestion_hint = (
            "Vale olhar com calma: o tipo de falha e a evidência combinam com um risco concreto."
        )
    else:
        suggestion_label = "Precisa da sua leitura"
        suggestion_hint = (
            "A automação não tem certeza. Use os passos abaixo e escolha uma das três opções."
        )

    how = list(guide.get("how_to_decide") or [])
    verify = " ".join(how) if how else _what_to_check(finding, blob)
    return {
        "likely_fp": score,
        "suggestion": suggestion,
        "suggestion_label": suggestion_label,
        "suggestion_hint": suggestion_hint,
        "kind": kind,
        "plain_title": _plain_title(finding, kind),
        "what_it_is": str(guide.get("what_it_is") or ""),
        "everyday": str(guide.get("everyday") or ""),
        "why_it_matters": str(guide.get("why_it_matters") or ""),
        "could_happen": list(guide.get("could_happen") or [])[:4],
        "how_to_decide": how[:4],
        "severity_plain": _severity_plain(sev),
        "why_vulnerability": why_vuln[:4],
        "why_false_positive": why_fp[:4],
        "reasons": reasons[:5],
        "what_to_check": verify,
        "status": status,
        "suppressed_pattern": suppressed,
    }


def _what_to_check(finding: dict[str, Any], blob: str) -> str:
    if any(k in blob for k in ("hsts", "x-frame", "csp", "x-content-type", "missing header")):
        return (
            "Abra o site no navegador (HTTPS), veja os headers da resposta. "
            "Se o header já existir, é falso positivo. Se faltar de verdade, é vulnerabilidade de endurecimento."
        )
    if "cve-" in blob or finding.get("cve"):
        return (
            "Confira a versão do software no banner/pacote. "
            "CVE só vale se a versão vulnerável estiver mesmo no alvo."
        )
    if any(k in blob for k in ("sql", "xss", "rce", "ssti")):
        return (
            "Veja se a evidência mostra o payload refletido ou erro de SQL. "
            "Sem reprodução no alvo autorizado, trate como incerto."
        )
    if any(k in blob for k in _WAF_HINTS):
        return (
            "O teste pode ter sido bloqueado. Tente de outra origem ou marque incerto até retestar."
        )
    if re.search(r"\d+/tcp", blob) or "open port" in blob:
        return (
            "Porta aberta não é, sozinha, uma falha. "
            "Só marque vulnerabilidade se o serviço estiver desnecessário ou com CVE."
        )
    return (
        "Confira se o alvo é o ambiente autorizado e se a evidência reproduz o problema "
        "(não só um banner ou timeout)."
    )


def build_triage_buckets(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Separa achados em:
    - queue: só incerteza (suggestion=unsure) — o humano decide no modal
    - auto_confirmed / auto_false_positive: heurística segura — classificar sem modal
    - auto_discarded: recibos de ferramenta (não são falhas; fora do PDF de vulns)
    """
    items = [f for f in findings if isinstance(f, dict)]
    queue: list[dict[str, Any]] = []
    auto_confirmed: list[dict[str, Any]] = []
    auto_false_positive: list[dict[str, Any]] = []
    auto_discarded: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in items:
        st = str(f.get("status") or "candidate")
        if st in {"discarded"}:
            continue
        fid = str(f.get("id") or "")
        key = fid or f"{f.get('title')}|{f.get('surface_target')}"
        if key in seen:
            continue
        seen.add(key)

        # Recibos puros → discarded (não inflam contagem de FP no PDF)
        if is_pure_scan_receipt(f) and st in {
            "candidate",
            "inconclusive",
            "",
            "false_positive",
            "confirmed",
        }:
            expl = explain_false_positive(f, siblings=items)
            auto_discarded.append({**f, "triage": expl, "second_look": False})
            continue

        if st in {"false_positive"}:
            continue

        expl = explain_false_positive(f, siblings=items)
        suggestion = str(expl.get("suggestion") or "unsure")
        likely = int(expl.get("likely_fp") or 0)
        pending = st in {"candidate", "inconclusive", ""}
        # Confirmado humano mas agora parece FP claro → reabre como incerteza
        second_look = st == "confirmed" and likely >= 55
        if not pending and not second_look:
            continue
        row = {**f, "triage": expl, "second_look": second_look}
        if second_look or suggestion == "unsure":
            queue.append(row)
        elif suggestion == "confirmed" and pending:
            auto_confirmed.append(row)
        elif suggestion == "false_positive" and pending:
            auto_false_positive.append(row)
        else:
            queue.append(row)
    queue.sort(key=lambda x: int((x.get("triage") or {}).get("likely_fp") or 0), reverse=True)
    return {
        "queue": queue,
        "auto_confirmed": auto_confirmed,
        "auto_false_positive": auto_false_positive,
        "auto_discarded": auto_discarded,
    }


def build_triage_queue(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fila do modal: apenas itens duvidosos (compatível com callers antigos)."""
    return build_triage_buckets(findings)["queue"]


def residual_risk_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Nível de perigo 0–100 só com confirmados (pós-triagem).

    Faixas: Baixo · Médio · Médio alto · Alto.
    A nota vem do pior achado confirmado (piso por gravidade) e sobe com outros.
    """
    # Piso: um único achado já comunica o perigo daquela gravidade
    floor = {
        "critical": 82,
        "high": 62,
        "alto": 62,
        "medium": 38,
        "medio": 38,
        "média": 38,
        "low": 18,
        "baixo": 18,
        "info": 8,
        "informational": 8,
    }
    # Cada confirmado extra empurra em direção a 100 (retornos decrescentes)
    extra = {
        "critical": 10,
        "high": 8,
        "alto": 8,
        "medium": 5,
        "medio": 5,
        "média": 5,
        "low": 3,
        "baixo": 3,
        "info": 1,
        "informational": 1,
    }
    order = {
        "critical": 0,
        "high": 1,
        "alto": 1,
        "medium": 2,
        "medio": 2,
        "média": 2,
        "low": 3,
        "baixo": 3,
        "info": 4,
        "informational": 4,
    }

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    if not confirmed:
        return {
            "score": 0,
            "label": "Baixo",
            "confirmed": 0,
            "scale": "danger_0_100",
        }

    sevs: list[str] = []
    for f in confirmed:
        s = str(f.get("severity") or "info").lower()
        sevs.append(s if s in floor else "info")
    sevs.sort(key=lambda s: order.get(s, 9))

    worst = sevs[0]
    score = int(floor.get(worst, 8))
    for s in sevs[1:]:
        score += int(extra.get(s, 2))
    score = min(100, score)

    if score >= 75:
        label = "Alto"
    elif score >= 50:
        label = "Médio alto"
    elif score >= 30:
        label = "Médio"
    elif score > 0:
        label = "Baixo"
    else:
        label = "Baixo"

    return {
        "score": score,
        "label": label,
        "confirmed": len(confirmed),
        "scale": "danger_0_100",
    }


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()
    for f in findings:
        if f.get("status") in {"false_positive", "discarded"}:
            continue
        s = str(f.get("severity") or "info").lower()
        if s in {"critical"}:
            counts["critical"] += 1
        elif s in {"high", "alto"}:
            counts["high"] += 1
        elif s in {"medium", "medio", "média"}:
            counts["medium"] += 1
        elif s in {"low", "baixo"}:
            counts["low"] += 1
        else:
            counts["info"] += 1
    return {
        "critical": int(counts["critical"]),
        "high": int(counts["high"]),
        "medium": int(counts["medium"]),
        "low": int(counts["low"]),
        "info": int(counts["info"]),
    }
