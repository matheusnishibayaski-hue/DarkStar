"""DarkStar CLI — pentest automatizado para pipelines e uso local.

Uso:
  python -m backend.cli autonomous --target scanme.nmap.org
  python -m backend health --check all
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

import click

from backend.cli_report import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_SCOPE,
    build_cli_report,
    determine_exit_code,
    save_cli_output,
)
from backend.config import (
    AI_PROVIDER,
    ALLOWED_TARGETS,
    ALLOWED_TOOLS,
    KALI_CONTAINER,
    MAX_AUTONOMOUS_ROUNDS,
    OPENROUTER_API_KEY,
    TOOL_CATEGORIES,
)
from backend.deps import APP_VERSION
from backend.security.scope import scope_lock_enabled, validate_autonomous_target


class CLIConfig:
    def __init__(self) -> None:
        self.verbose = False


pass_config = click.make_pass_decorator(CLIConfig, ensure=True)


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Modo verboso")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """DarkStar CLI — pentesting assistido por IA (local / CI)."""
    cfg = CLIConfig()
    cfg.verbose = verbose
    ctx.obj = cfg
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("autonomous")
@click.option("--target", required=True, help="URL, host ou IP do alvo autorizado")
@click.option(
    "--risk-profile",
    type=click.Choice(["passive", "safe-active", "full"], case_sensitive=False),
    default="safe-active",
    show_default=True,
)
@click.option(
    "--scan-profile",
    type=click.Choice(["basic", "intermediate", "full", "custom"], case_sensitive=False),
    default="intermediate",
    show_default=True,
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["json", "sarif"], case_sensitive=False),
    default="json",
    show_default=True,
)
@click.option("--output-file", "-o", type=click.Path(), default=None, help="Arquivo de saída")
@click.option("--quiet", is_flag=True, help="Suprime logs (stdout só com --output-file omitido)")
@click.option("--dry-run", is_flag=True, help="Valida escopo sem executar")
@click.option(
    "--max-rounds",
    type=int,
    default=None,
    help=f"Máximo de rodadas (default env MAX_AUTONOMOUS_ROUNDS={MAX_AUTONOMOUS_ROUNDS})",
)
@click.option("--objective", default=None, help="Objetivo customizado da missão")
@click.option("--github-repo", default=None, help="owner/repo para comentar no PR (requer GITHUB_TOKEN)")
@click.option("--pr", "pr_number", type=int, default=None, help="Número do PR para comentar")
@click.option(
    "--github-pr",
    default=None,
    help="Atalho owner/repo#123 (alternativa a --github-repo + --pr)",
)
@pass_config
def autonomous_cmd(
    config: CLIConfig,
    target: str,
    risk_profile: str,
    scan_profile: str,
    output_format: str,
    output_file: str | None,
    quiet: bool,
    dry_run: bool,
    max_rounds: int | None,
    objective: str | None,
    github_repo: str | None,
    pr_number: int | None,
    github_pr: str | None,
) -> None:
    """Executa pentest autônomo (Piloto) e emite relatório JSON/SARIF."""
    try:
        ok, err = validate_autonomous_target(target)
        if not ok:
            if not quiet:
                click.secho(f"Scope: {err}", fg="red", err=True)
            sys.exit(EXIT_SCOPE)

        if dry_run:
            report = {
                "status": "dry-run",
                "target": target,
                "risk_profile": risk_profile,
                "scan_profile": scan_profile,
                "vulnerability_count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "findings": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": APP_VERSION,
                "exit_code": EXIT_OK,
            }
            _emit_report(report, output_format, output_file, quiet)
            if not quiet:
                click.secho("Validation passed (dry-run)", fg="green")
            sys.exit(EXIT_OK)

        if not quiet:
            click.secho("DarkStar Autonomous Pentest", fg="cyan", bold=True)
            click.echo(f"Target: {target}")
            click.echo(f"Risk Profile: {risk_profile}")
            click.echo(f"Scan Profile: {scan_profile}")

        import backend.ai.autopilot as autopilot_mod
        from backend.ai.autopilot import run_autonomous

        obj = objective or f"Pentest {risk_profile} em {target}"
        rounds_override = max_rounds if max_rounds is not None else None
        if rounds_override is not None and rounds_override > 0:
            # autopilot lê MAX_AUTONOMOUS_ROUNDS do módulo; aplica override local
            original_max = autopilot_mod.MAX_AUTONOMOUS_ROUNDS
            autopilot_mod.MAX_AUTONOMOUS_ROUNDS = int(rounds_override)
        else:
            original_max = None

        try:
            result = run_autonomous(
                target=target,
                objective=obj,
                risk_profile=risk_profile,
                scan_profile=scan_profile,
            )
        finally:
            if original_max is not None:
                autopilot_mod.MAX_AUTONOMOUS_ROUNDS = original_max

        report = build_cli_report(
            target,
            risk_profile=risk_profile,
            scan_profile=scan_profile,
            rounds=result.rounds,
            tools_executed=result.tools_executed,
            stopped_reason=result.stopped_reason,
            objective_met=result.objective_met,
            markdown_report=result.report or "",
            message=result.message or "",
        )
        _emit_report(report, output_format, output_file, quiet)

        if int(report.get("critical") or 0) > 0:
            try:
                from backend.integrations.notifications import notification_manager

                notification_manager.notify(
                    title=f"CRITICAL findings — {target}",
                    message=(
                        f"critical={report.get('critical')} high={report.get('high')} "
                        f"total={report.get('vulnerability_count')}"
                    ),
                    severity="critical",
                )
            except Exception:  # noqa: BLE001
                pass

        if github_pr:
            from backend.integrations.github import parse_pr_ref

            ref_repo, ref_pr = parse_pr_ref(github_pr)
            if ref_repo:
                github_repo = github_repo or ref_repo
            if ref_pr:
                pr_number = pr_number or ref_pr

        if github_repo and pr_number:
            _maybe_comment_pr(github_repo, pr_number, report, quiet)

        if not quiet:
            click.secho(
                f"Done — critical={report['critical']} high={report['high']} "
                f"exit={report['exit_code']}",
                fg="green",
            )
        sys.exit(int(report.get("exit_code") or EXIT_OK))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(EXIT_ERROR)


@cli.command("chat")
@click.option("--message", "-m", required=True, help="Mensagem para a Argus")
@click.option("--model", default=None, help="Modelo de IA")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
)
@click.option("--tool", default=None, help="Ferramenta preferida (opcional)")
@pass_config
def chat_cmd(
    config: CLIConfig,
    message: str,
    model: str | None,
    output_format: str,
    tool: str | None,
) -> None:
    """Chat único com a Argus (pode executar tools no Kali)."""
    try:
        from backend.ai.agent import chat as chat_fn

        result = chat_fn(
            history=[],
            user_message=message,
            preferred_tool=tool,
            model=model,
        )
        if output_format == "json":
            payload = {
                "message": result.message,
                "tool_executions": len(result.tool_executions or []),
                "stopped_reason": result.stopped_reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            click.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            click.echo(result.message or "")
        sys.exit(EXIT_OK)
    except Exception as exc:  # noqa: BLE001
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(EXIT_ERROR)


@cli.command("health")
@click.option(
    "--check",
    type=click.Choice(["all", "docker", "kali", "ai", "config"], case_sensitive=False),
    default="all",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
)
@pass_config
def health_cmd(config: CLIConfig, check: str, output_format: str) -> None:
    """Verifica Docker, Kali, IA e configuração (sem SDK docker)."""
    checks = {
        "docker": _check_docker,
        "kali": _check_kali,
        "ai": _check_ai,
        "config": _check_config,
    }
    results: dict[str, dict[str, Any]] = {}
    if check == "all":
        for name, fn in checks.items():
            results[name] = fn()
    else:
        results[check] = checks[check]()

    if output_format == "json":
        click.echo(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for name, status in results.items():
            ok = status.get("status") == "ok"
            mark = "OK" if ok else "FAIL"
            click.echo(f"[{mark}] {name}: {status.get('message', '')}")

    all_ok = all(r.get("status") == "ok" for r in results.values())
    sys.exit(EXIT_OK if all_ok else 1)


@cli.command("list-tools")
@click.option("--pattern", default=None, help="Filtro por nome")
@click.option("--category", default=None, help="id da categoria (ex.: rede, web)")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
)
@pass_config
def list_tools_cmd(
    config: CLIConfig,
    pattern: str | None,
    category: str | None,
    output_format: str,
) -> None:
    """Lista ferramentas whitelist (ALLOWED_TOOLS)."""
    from backend.tool_catalog import get_tool_info

    names = sorted(ALLOWED_TOOLS)
    if category:
        cat = next((c for c in TOOL_CATEGORIES if c.get("id") == category), None)
        if not cat:
            click.secho(f"Categoria desconhecida: {category}", fg="red", err=True)
            sys.exit(1)
        allowed_cat = set(cat.get("tools") or [])
        names = [n for n in names if n in allowed_cat]
    if pattern:
        p = pattern.lower()
        names = [n for n in names if p in n.lower()]

    tools = []
    for name in names:
        info = get_tool_info(name) or {}
        tools.append(
            {
                "name": name,
                "summary": info.get("summary") or "",
                "example": info.get("example") or "",
            }
        )

    if output_format == "json":
        click.echo(json.dumps(tools, indent=2, ensure_ascii=False))
    else:
        click.echo(f"Ferramentas ({len(tools)}):")
        for t in tools:
            summary = t["summary"] or "—"
            click.echo(f"  - {t['name']}: {summary}")
    sys.exit(EXIT_OK)


def _emit_report(
    report: dict[str, Any],
    output_format: str,
    output_file: str | None,
    quiet: bool,
) -> None:
    if output_file:
        save_cli_output(report, output_file, output_format)
        if not quiet:
            click.secho(f"Report saved: {output_file}", fg="green")
    else:
        if output_format == "sarif":
            from backend.cli_report import convert_to_sarif

            click.echo(json.dumps(convert_to_sarif(report), indent=2, ensure_ascii=False))
        else:
            click.echo(json.dumps(report, indent=2, ensure_ascii=False))


def _maybe_comment_pr(
    repo: str,
    pr_number: int,
    report: dict[str, Any],
    quiet: bool,
) -> None:
    try:
        from backend.integrations.github import GitHubClient

        client = GitHubClient()
        if not client.is_available():
            if not quiet:
                click.secho("GITHUB_TOKEN not set — skipping PR comment", fg="yellow", err=True)
            return
        findings = list(report.get("findings") or [])
        ok = client.comment_on_pr(
            repo_url=repo,
            pr_number=pr_number,
            findings=findings,
            title="DarkStar Security Scan",
            target=str(report.get("target") or ""),
            risk_profile=str(report.get("risk_profile") or ""),
        )
        if not quiet:
            if ok:
                click.secho(f"Commented on PR #{pr_number}", fg="green")
            else:
                click.secho(f"Failed to comment on PR #{pr_number}", fg="yellow", err=True)
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            click.secho(f"GitHub comment skipped: {exc}", fg="yellow", err=True)


def _check_docker() -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0:
            return {"status": "ok", "message": "Docker available"}
        return {"status": "error", "message": (proc.stderr or "docker info failed").strip()[:200]}
    except FileNotFoundError:
        return {"status": "error", "message": "Docker not installed or not in PATH"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "message": str(exc)[:200]}


def _check_kali() -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["docker", "ps", "--filter", f"name={KALI_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return {"status": "error", "message": (proc.stderr or "docker ps failed").strip()[:200]}
        if KALI_CONTAINER in (proc.stdout or ""):
            return {"status": "ok", "message": f"Container {KALI_CONTAINER} running"}
        return {"status": "error", "message": f"Container {KALI_CONTAINER} not running"}
    except FileNotFoundError:
        return {"status": "error", "message": "Docker not installed or not in PATH"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "message": str(exc)[:200]}


def _check_ai() -> dict[str, Any]:
    try:
        from backend.ai.providers.runtime import get_active_provider_name

        active = get_active_provider_name()
        if active == "openrouter" and not OPENROUTER_API_KEY:
            return {"status": "error", "message": "No OPENROUTER_API_KEY"}
        if active == "ollama":
            from backend.ai.providers import get_llm_provider

            h = get_llm_provider().health()
            if not h.get("ok"):
                return {
                    "status": "error",
                    "message": h.get("detail") or "Ollama unhealthy",
                }
        return {"status": "ok", "message": f"AI provider: {active}"}
    except Exception as exc:  # noqa: BLE001
        # Fallback sem runtime
        if AI_PROVIDER == "openrouter" and not OPENROUTER_API_KEY:
            return {"status": "error", "message": "No OPENROUTER_API_KEY"}
        return {"status": "error", "message": str(exc)[:200]}


def _check_config() -> dict[str, Any]:
    if scope_lock_enabled():
        msg = f"Scope lock ON ({len(ALLOWED_TARGETS)} target(s))"
    else:
        msg = "Scope: unrestricted (ALLOWED_TARGETS empty)"
    return {"status": "ok", "message": msg}


# Re-export for tests
__all__ = [
    "cli",
    "autonomous_cmd",
    "chat_cmd",
    "health_cmd",
    "list_tools_cmd",
    "determine_exit_code",
]


if __name__ == "__main__":
    cli()
