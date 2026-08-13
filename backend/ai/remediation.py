"""Remediação acionável por tipo de finding (mapa estático + fallback)."""

from __future__ import annotations

import re
from typing import Any


_KIND_TO_KEY = {
    "xss": "xss",
    "sqli": "sqli",
    "rce": "rce",
    "lfi": "lfi",
    "ssti": "ssti",
    "cve": "cve",
    "hsts": "header_hsts",
    "clickjack": "header_xfo",
    "csp": "header_csp",
    "nosniff": "header_xcto",
    "ssl": "ssl",
    "port": "port_exposure",
    "wordpress": "wordpress",
    "exposure": "exposure",
}


def classify_remediation_key(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or "").lower()
    evidence = str(finding.get("evidence") or "").lower()
    blob = f"{title} {evidence}"
    ftype = str(finding.get("finding_type") or "").lower()
    kind = str(finding.get("kind") or "")
    if not kind:
        try:
            from backend.ai.fp_explain import detect_finding_kind

            kind = detect_finding_kind(finding)
        except Exception:  # noqa: BLE001
            kind = ""
    if kind in _KIND_TO_KEY:
        return _KIND_TO_KEY[kind]
    if finding.get("cve") or "cve-" in blob:
        return "cve"
    if ftype == "header" or any(
        k in blob
        for k in (
            "hsts",
            "x-frame",
            "csp",
            "strict-transport",
            "x-content-type",
            "missing header",
            "security header",
        )
    ):
        if "hsts" in blob or "strict-transport" in blob:
            return "header_hsts"
        if "x-frame" in blob:
            return "header_xfo"
        if "csp" in blob or "content-security" in blob:
            return "header_csp"
        if "x-content-type" in blob:
            return "header_xcto"
        return "header_generic"
    if ftype == "ssl" or any(k in blob for k in ("ssl", "tls", "certificate", "cipher")):
        return "ssl"
    if ftype == "xss" or "xss" in blob or "cross-site" in blob:
        return "xss"
    if ftype == "sqli" or "sql" in blob:
        return "sqli"
    if ftype == "port_info" or re.search(r"\d+/tcp", blob):
        return "port_exposure"
    if "wordpress" in blob or "wp-" in blob:
        return "wordpress"
    if "admin" in blob or "exposed" in blob or "panel" in blob:
        return "exposure"
    return "generic"


_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "cve": {
        "title": "Atualizar o programa com a falha conhecida",
        "who": "Infraestrutura / responsável pelo software",
        "why": "Existe um buraco já catalogado (CVE). Enquanto a versão antiga estiver no ar, o ataque tem receita pronta.",
        "steps": [
            "Anote o CVE e a versão atual do programa (banner, pacote, painel).",
            "Consulte o vendor e suba para a versão que corrige esse CVE.",
            "Se não houver patch, isole o serviço (VPN, firewall) ou desligue-o até atualizar.",
            "Depois do deploy, rode de novo o mesmo teste/template para confirmar que o alerta sumiu.",
        ],
        "verify": "O mesmo scanner/template do CVE não deve mais disparar no alvo.",
        "action": (
            "Aplicar patch/upgrade para a versão corrigida do CVE. "
            "Validar com reteste do mesmo template/CVE após o deploy."
        ),
    },
    "header_hsts": {
        "title": "Obrigar o navegador a usar só a conexão trancada (HTTPS)",
        "who": "Quem cuida do site / reverse-proxy (nginx, Cloudflare, load balancer)",
        "why": "Sem HSTS, na primeira visita alguém em uma rede Wi‑Fi pública pode tentar desviar o cliente para uma página sem cadeado.",
        "steps": [
            "Confirme que o site já abre só em HTTPS (redirecione HTTP → HTTPS).",
            "No proxy ou na aplicação, envie o cabeçalho Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            "Teste em um navegador: DevTools → Network → a resposta 200 deve trazer esse cabeçalho.",
            "Quando estiver estável, avalie o preload (hstspreload.org) — é opcional e difícil de desfazer.",
        ],
        "verify": "A resposta HTTPS traz Strict-Transport-Security com max-age alto (pelo menos 6 meses).",
        "action": (
            "Configurar Strict-Transport-Security (ex.: max-age=31536000; includeSubDomains) "
            "no edge/reverse-proxy e forçar HTTPS."
        ),
    },
    "header_xfo": {
        "title": "Impedir que a página seja embutida em outro site",
        "who": "Time do site / proxy",
        "why": "Sem essa trava, outro site pode colocar a página de vocês num quadro invisível e roubar cliques (clickjacking).",
        "steps": [
            "Defina X-Frame-Options: DENY (ou SAMEORIGIN se vocês mesmos embutem a página).",
            "Melhor ainda: Content-Security-Policy com frame-ancestors 'none' ou 'self'.",
            "Publique e recarregue a home e as telas de login/pagamento.",
        ],
        "verify": "Nas respostas, aparece X-Frame-Options ou CSP frame-ancestors. O site não abre dentro de um iframe de outro domínio.",
        "action": "Definir X-Frame-Options: DENY (ou SAMEORIGIN) e/ou CSP frame-ancestors.",
    },
    "header_csp": {
        "title": "Limitar de onde os programas da página podem vir",
        "who": "Frontend + quem opera o CDN/proxy",
        "why": "CSP reduz o estrago se um script estranho entrar na página (XSS, anúncio, plugin).",
        "steps": [
            "Comece em modo relatório: Content-Security-Policy-Report-Only e veja o que quebraria.",
            "Depois force uma política: default-src 'self'; script-src só dos endereços que vocês controlam.",
            "Evite 'unsafe-inline' e 'unsafe-eval' em script-src; use nonce ou hash se precisar de script inline.",
            "Acompanhe os reports por alguns dias e ajuste antes de apertar mais.",
        ],
        "verify": "O cabeçalho Content-Security-Policy aparece nas páginas HTML e o console do navegador não enche de violações esperadas.",
        "action": (
            "Implantar CSP restritiva (default-src 'self'; script-src …) "
            "e evoluir com report-only antes do enforce."
        ),
    },
    "header_xcto": {
        "title": "Impedir o navegador de “adivinhar” o tipo do arquivo",
        "who": "Proxy / aplicação",
        "why": "Sem nosniff, um arquivo mal rotulado pode ser tratado como programa no navegador.",
        "steps": [
            "Envie X-Content-Type-Options: nosniff em todas as respostas (HTML, API, arquivos).",
            "Confira se o Content-Type de cada resposta está correto (text/html, application/json, etc.).",
        ],
        "verify": "O cabeçalho nosniff aparece de forma consistente (não só na home).",
        "action": "Adicionar X-Content-Type-Options: nosniff em todas as respostas.",
    },
    "header_generic": {
        "title": "Padronizar os avisos de segurança do site (headers)",
        "who": "Time de plataforma",
        "why": "Cabeçalhos de segurança são travas baratas no navegador. Faltando um conjunto mínimo, ataques comuns ficam mais fáceis.",
        "steps": [
            "Revise HSTS, X-Frame-Options ou frame-ancestors, CSP, nosniff e Referrer-Policy.",
            "Aplique no reverse-proxy para valer em todo o domínio, não página a página.",
            "Use um checklist (OWASP Secure Headers) e reteste com o mesmo scanner.",
        ],
        "verify": "Um scan de headers (ou o próprio relatório) deixa de marcar os avisos que vocês corrigiram.",
        "action": "Revisar e padronizar headers de segurança no proxy/aplicação (OWASP Secure Headers).",
    },
    "ssl": {
        "title": "Fortalecer o cadeado da conexão (HTTPS/TLS)",
        "who": "Infraestrutura / certificado",
        "why": "Cadeado fraco ou vencido deixa senha e dados visíveis no caminho e assusta o cliente no navegador.",
        "steps": [
            "Renove o certificado se estiver vencido ou com nome errado.",
            "Desligue SSL 3, TLS 1.0 e 1.1; deixe só TLS 1.2 e 1.3.",
            "Use cifras modernas com Perfect Forward Secrecy; desligue RC4, 3DES, export.",
            "Redirecione HTTP para HTTPS e teste em ssllabs.com/ssltest (ou equivalente interno).",
        ],
        "verify": "O navegador mostra cadeado válido; o teste TLS não aponta protocolo antigo nem certificado inválido.",
        "action": (
            "Desabilitar protocolos/cifras obsoletas, renovar certificado válido, "
            "habilitar TLS 1.2+ e Perfect Forward Secrecy."
        ),
    },
    "xss": {
        "title": "Impedir que texto virar programa na página (XSS)",
        "who": "Desenvolvimento da aplicação",
        "why": "Se o que a pessoa digita volta para a página sem escape, outro visitante pode roubar a sessão ou ver um formulário falso.",
        "steps": [
            "Localize o campo/URL da evidência (busca, comentário, parâmetro refletido).",
            "No servidor e no template, escape/sanitize a saída conforme o contexto (HTML, atributo, JS).",
            "Não monte HTML com concatenação da entrada do usuário; use o encoder do framework.",
            "Ligue um cookie de sessão HttpOnly e, se possível, Secure + SameSite.",
            "Some uma CSP que bloqueie script inline de terceiros.",
            "Reteste o mesmo payload da evidência: ele não deve executar nem aparecer cru na página.",
        ],
        "verify": "O payload da evidência aparece como texto (não como alerta/script) e a sessão não vaza.",
        "action": (
            "Sanitizar/escapar saída, CSP restritiva, validar entrada e "
            "usar encoding contextual no framework."
        ),
    },
    "sqli": {
        "title": "Separar o que a pessoa digita do comando do banco (SQL injection)",
        "who": "Backend / DBA",
        "why": "Se o formulário manda o texto direto na query, alguém pode ler, alterar ou apagar o banco.",
        "steps": [
            "Ache a query ligada ao parâmetro da evidência (login, busca, id).",
            "Troque concatenação de SQL por query parametrizada ou ORM (nunca monte SQL com + ou f-string da entrada).",
            "Valide tipo e tamanho da entrada (número é número).",
            "A conta do banco da aplicação deve ter o mínimo de permissão (sem DROP/GRANT).",
            "Reteste o payload: não deve vazar erro de SQL nem dados de outra conta.",
        ],
        "verify": "O mesmo teste não devolve erro de banco nem registros que o usuário não deveria ver.",
        "action": (
            "Usar queries parametrizadas/ORM, validar entrada e "
            "reduzir privilégios da conta do banco da aplicação."
        ),
    },
    "rce": {
        "title": "Impedir que o servidor execute comando de fora",
        "who": "Desenvolvimento + infra (urgente)",
        "why": "Execução remota de código dá o controle da máquina. Trate como incidente até isolar e corrigir.",
        "steps": [
            "Isole o serviço (firewall, desligar exposição) se a evidência mostrar comando executado.",
            "Encontre onde a entrada vira shell, eval, desserialização ou template inseguro.",
            "Não passe dado do usuário para system/exec/eval; use APIs internas com lista fechada de ações.",
            "Atualize bibliotecas com CVE de RCE e rode o mesmo PoC depois do patch.",
            "Revise logs e senhas: se o comando rodou de verdade, assuma comprometimento.",
        ],
        "verify": "O PoC da evidência não devolve mais saída de comando do sistema.",
        "action": "Eliminar execução de entrada do usuário (shell/eval), aplicar patch e retestar o PoC.",
    },
    "lfi": {
        "title": "Impedir leitura de arquivos internos pela URL",
        "who": "Desenvolvimento",
        "why": "Um parâmetro como ?file= não deve abrir arquivos do disco (senhas, .env, código).",
        "steps": [
            "Pare de usar o parâmetro como caminho de arquivo; mapeie IDs para arquivos permitidos.",
            "Se precisar de arquivo, use lista branca e ignore ../ e caminhos absolutos.",
            "Rode a aplicação com usuário sem leitura de /etc, backups e secrets.",
            "Reteste o path da evidência: não deve devolver conteúdo de arquivo do sistema.",
        ],
        "verify": "Pedidos com ../ ou /etc/passwd não devolvem arquivo interno.",
        "action": "Não interpolar path do usuário; allowlist e reteste de path traversal.",
    },
    "ssti": {
        "title": "Não deixar o texto do usuário virar código do template",
        "who": "Desenvolvimento",
        "why": "Template injection pode vazar dados internos ou chegar a executar comando no servidor.",
        "steps": [
            "Não renderize a entrada do usuário como template; trate como dado.",
            "Atualize o motor de template e desligue funções perigosas (os, config).",
            "Reteste expressões do tipo {{7*7}} — devem aparecer literais, não 49.",
        ],
        "verify": "A expressão da evidência não é avaliada pelo servidor.",
        "action": "Tratar entrada como dado, não como template; retestar a expressão da evidência.",
    },
    "port_exposure": {
        "title": "Esconder serviços que não precisam estar na internet",
        "who": "Rede / cloud (firewall, security group)",
        "why": "Porta aberta não é invasão, mas cada serviço público é uma porta tentada o dia inteiro.",
        "steps": [
            "Liste o que realmente precisa ser público (em geral 80/443 do site).",
            "Feche no firewall/security group o que for painel, banco, RDP, SSH, Redis, etc.",
            "O que a equipe precisa acessar, coloque atrás de VPN ou IP allowlist.",
            "Se o serviço for obrigatório, atualize-o e troque senha padrão.",
        ],
        "verify": "Um scan externo não vê mais a porta desnecessária; o site continua no ar.",
        "action": (
            "Fechar porta/serviço desnecessário no firewall/SG; "
            "expor apenas via VPN ou allowlist de IPs autorizados."
        ),
    },
    "wordpress": {
        "title": "Atualizar e endurecer o WordPress",
        "who": "Quem administra o site",
        "why": "Plugin e tema velhos são o caminho mais comum de invasão em site institucional.",
        "steps": [
            "Atualize núcleo, temas e plugins; apague o que não usa.",
            "Troque senhas de admin, ative 2FA e limite tentativas de login.",
            "Desligue enumeração de usuários (/?author=1) e XML-RPC se não precisar.",
            "Faça backup, depois reteste o mesmo alerta.",
        ],
        "verify": "Versões atuais no painel; o scanner não aponta mais o plugin/tema antigo.",
        "action": (
            "Atualizar core/plugins/temas, remover componentes órfãos, "
            "reforçar autenticação e limitar enumeração de usuários."
        ),
    },
    "exposure": {
        "title": "Tirar painel interno da internet pública",
        "who": "Infra + aplicação",
        "why": "Tela de admin, phpinfo, backup ou diretório listado na rua vira alvo de senha e exploit.",
        "steps": [
            "Confirme a URL da evidência fora da VPN: se abre, não deveria.",
            "Peça autenticação forte e coloque o path só em VPN ou IP da equipe.",
            "Remova phpinfo, .git, backups e listagem de diretório do servidor web.",
            "Reteste a URL anônima: deve dar 401/403 ou não resolver.",
        ],
        "verify": "Do celular na rua a URL não abre o painel nem lista arquivos.",
        "action": (
            "Autenticar o recurso, restringir por IP/VPN, "
            "remover paths de administração da internet pública."
        ),
    },
    "generic": {
        "title": "Corrigir conforme a evidência deste achado",
        "who": "Dono do sistema apontado na evidência",
        "why": "O scanner apontou um sinal. A correção segue o que a evidência mostrou neste item, não um recorte genérico.",
        "steps": [
            "Leia o título, o comando e a evidência deste achado no relatório.",
            "Reproduza no ambiente autorizado o mesmo passo (sem inventar ataque novo).",
            "Aplique a correção no código, config ou rede que a evidência indica.",
            "Documente a mudança e rode de novo o mesmo teste.",
        ],
        "verify": "O mesmo comando/template não reproduz o problema no alvo.",
        "action": (
            "Aplicar correção alinhada à evidência/PoC do achado, "
            "documentar mudança e retestar o mesmo vetor."
        ),
    },
}


def remediation_for(finding: dict[str, Any]) -> dict[str, Any]:
    key = classify_remediation_key(finding)
    base = dict(_REMEDIATIONS.get(key) or _REMEDIATIONS["generic"])
    steps = list(base.get("steps") or [])
    cve = str(finding.get("cve") or "")
    if not cve:
        m = re.search(r"CVE-\d{4}-\d+", str(finding.get("title") or finding.get("evidence") or ""), re.I)
        if m:
            cve = m.group(0).upper()
    action = str(base.get("action") or "")
    if cve and key == "cve":
        action = f"{cve}: {action}"
        if steps:
            steps = [f"CVE {cve}: identifique a versão instalada."] + steps
    summary = str(base.get("why") or action)
    numbered = " ".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
    if numbered:
        action = f"{action} Passos: {numbered}"
    return {
        "key": key,
        "title": str(base.get("title") or "Correção"),
        "action": action,
        "why": summary,
        "who": str(base.get("who") or ""),
        "steps": steps,
        "verify": str(base.get("verify") or ""),
        "plain_title": str(finding.get("plain_title") or finding.get("title") or ""),
        "severity": str(finding.get("severity") or ""),
        "severity_label": str(finding.get("severity_label") or finding.get("severity") or ""),
    }


def remediations_for_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        rem = remediation_for(f)
        title = str(f.get("plain_title") or f.get("title") or "")[:160]
        row_key = f"{rem['key']}|{title}"
        if row_key in seen:
            continue
        seen.add(row_key)
        rows.append(
            {
                "finding_id": f.get("id"),
                "finding_title": title,
                "severity": rem.get("severity") or f.get("severity"),
                "severity_label": rem.get("severity_label") or f.get("severity"),
                "remediation_title": rem["title"],
                "action": rem["action"],
                "why": rem.get("why") or "",
                "who": rem.get("who") or "",
                "steps": rem.get("steps") or [],
                "verify": rem.get("verify") or "",
                "key": rem["key"],
            }
        )
    return rows


# Re-exports da camada IA (wizard / API)
from backend.ai.remediation_ai import (  # noqa: E402
    RemediationAdvisor,
    RemediationPlan,
    RemediationStep,
    RemediationTracker,
    RemediationVerifier,
    remediation_advisor,
    remediation_tracker,
    remediation_verifier,
)

__all__ = [
    "classify_remediation_key",
    "remediation_for",
    "remediations_for_findings",
    "RemediationAdvisor",
    "RemediationPlan",
    "RemediationStep",
    "RemediationTracker",
    "RemediationVerifier",
    "remediation_advisor",
    "remediation_tracker",
    "remediation_verifier",
]
