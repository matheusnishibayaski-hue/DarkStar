"""Camada IA de remediação — planos step-by-step via LLM (sync)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.ai.providers import get_llm_provider
from backend.ai.providers.base import LLMMessage
from backend.config import BASE_DIR, PRIMARY_MODEL


def _remediation_seed(finding: dict[str, Any]) -> dict[str, Any]:
    """Lazy import evita ciclo com remediation.py (re-exports)."""
    from backend.ai.remediation import remediation_for

    return remediation_for(finding)

logger = logging.getLogger(__name__)

_TRACK_PATH = BASE_DIR / "backend" / "data" / "remediation_track.json"


@dataclass
class RemediationStep:
    step_number: int
    title: str
    description: str
    command: str | None = None
    code_snippet: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationPlan:
    finding_id: str
    vulnerability_title: str
    severity: str
    root_cause: str
    steps: list[RemediationStep] = field(default_factory=list)
    code_before: str = ""
    code_after: str = ""
    test_command: str = ""
    deployment_notes: str = ""
    estimated_time_minutes: int = 30
    difficulty: str = "medium"
    references: list[str] = field(default_factory=list)
    related_cves: list[str] = field(default_factory=list)
    confidence_score: float = 0.5
    source: str = "ai"  # ai | fallback

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vulnerability_title": self.vulnerability_title,
            "severity": self.severity,
            "root_cause": self.root_cause,
            "steps": [s.to_dict() for s in self.steps],
            "code_before": self.code_before,
            "code_after": self.code_after,
            "test_command": self.test_command,
            "deployment_notes": self.deployment_notes,
            "estimated_time_minutes": self.estimated_time_minutes,
            "difficulty": self.difficulty,
            "references": self.references,
            "related_cves": self.related_cves,
            "confidence_score": self.confidence_score,
            "confidence": f"{self.confidence_score * 100:.0f}%",
            "source": self.source,
        }


def _extract_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    chunk = text[start : end + 1]
    try:
        data = json.loads(chunk)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        # try fenced ```json
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I)
        if not m:
            return None
        try:
            data = json.loads(m.group(1))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None


class RemediationAdvisor:
    """Gera plano de remediação contextualizado (pentest) via LLM."""

    def generate_remediation(
        self,
        finding: dict[str, Any],
        code_context: str = "",
        project_info: dict[str, Any] | None = None,
    ) -> RemediationPlan:
        project_info = project_info or {}
        seed = _remediation_seed(finding)
        try:
            provider = get_llm_provider()
            if not provider.is_configured():
                return self.create_fallback_remediation(finding)
            model, _ = provider.resolve_models(PRIMARY_MODEL, None)
            prompt = self._build_prompt(finding, code_context, project_info, seed)
            completion = provider.complete(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert security engineer for authorized pentests. "
                            "Return ONLY valid JSON for a remediation plan. "
                            "Focus on host/service/config fixes; do not invent source file:line."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                tools=None,
                tool_choice=None,
            )
            content = ""
            msg = completion.message
            if isinstance(msg, LLMMessage):
                content = msg.content or ""
            elif isinstance(msg, dict):
                content = str(msg.get("content") or "")
            else:
                content = str(getattr(msg, "content", "") or "")
            plan = self.parse_remediation_response(content, finding)
            return self._enrich(plan, finding)
        except Exception as exc:  # noqa: BLE001
            logger.warning("remediation_ai_failed: %s", exc)
            return self.create_fallback_remediation(finding)

    def _build_prompt(
        self,
        finding: dict[str, Any],
        code_context: str,
        project_info: dict[str, Any],
        seed: dict[str, str],
    ) -> str:
        return f"""
Generate a remediation plan as JSON for this pentest finding.

Finding:
- title: {finding.get('title')}
- severity: {finding.get('severity')}
- status: {finding.get('status')}
- host/url: {finding.get('host') or finding.get('url') or finding.get('matched_at') or ''}
- cve: {finding.get('cve') or ''}
- tool: {finding.get('tool') or ''}
- evidence: {str(finding.get('evidence') or '')[:1200]}
- static_remediation_title: {seed.get('title')}
- static_remediation_action: {seed.get('action')}

Optional code_context:
{code_context or '(none)'}

Optional project_info:
{json.dumps(project_info, ensure_ascii=False)[:800]}

Return JSON with keys:
root_cause, steps (array of {{step, title, description, command, notes}}),
code_before, code_after, test_command, deployment_notes,
estimated_time (minutes int), difficulty (easy|medium|hard),
references (array of urls), confidence (0-1 float).

Use Portuguese for titles/descriptions. Steps: 3-6 practical ops/security actions.
"""

    def parse_remediation_response(
        self, response_text: str, finding: dict[str, Any]
    ) -> RemediationPlan:
        data = _extract_json_object(response_text or "")
        if not data:
            return self.create_fallback_remediation(finding)
        steps: list[RemediationStep] = []
        for i, step_data in enumerate(data.get("steps") or []):
            if not isinstance(step_data, dict):
                continue
            steps.append(
                RemediationStep(
                    step_number=int(step_data.get("step") or i + 1),
                    title=str(step_data.get("title") or f"Passo {i + 1}")[:200],
                    description=str(step_data.get("description") or step_data.get("action") or "")[
                        :2000
                    ],
                    command=(str(step_data["command"])[:1000] if step_data.get("command") else None),
                    code_snippet=(
                        str(step_data["code_snippet"])[:4000]
                        if step_data.get("code_snippet")
                        else None
                    ),
                    notes=(str(step_data["notes"])[:1000] if step_data.get("notes") else None),
                )
            )
        if not steps:
            return self.create_fallback_remediation(finding)
        conf = data.get("confidence", 0.7)
        try:
            conf_f = float(conf)
        except (TypeError, ValueError):
            conf_f = 0.7
        conf_f = max(0.0, min(1.0, conf_f))
        try:
            eta = int(data.get("estimated_time") or data.get("estimated_time_minutes") or 30)
        except (TypeError, ValueError):
            eta = 30
        difficulty = str(data.get("difficulty") or "medium").lower()
        if difficulty not in {"easy", "medium", "hard"}:
            difficulty = "medium"
        refs = data.get("references") or []
        if not isinstance(refs, list):
            refs = []
        return RemediationPlan(
            finding_id=str(finding.get("id") or "unknown"),
            vulnerability_title=str(finding.get("title") or "Security issue"),
            severity=str(finding.get("severity") or "unknown"),
            root_cause=str(data.get("root_cause") or "")[:3000],
            steps=steps,
            code_before=str(data.get("code_before") or "")[:4000],
            code_after=str(data.get("code_after") or "")[:4000],
            test_command=str(data.get("test_command") or "")[:1000],
            deployment_notes=str(data.get("deployment_notes") or "")[:2000],
            estimated_time_minutes=max(5, min(eta, 480)),
            difficulty=difficulty,
            references=[str(r)[:500] for r in refs[:12]],
            related_cves=[],
            confidence_score=conf_f,
            source="ai",
        )

    def _enrich(self, plan: RemediationPlan, finding: dict[str, Any]) -> RemediationPlan:
        cve = str(finding.get("cve") or "").strip()
        if not cve:
            m = re.search(r"CVE-\d{4}-\d+", str(finding.get("title") or ""), re.I)
            if m:
                cve = m.group(0).upper()
        if cve and cve not in plan.related_cves:
            plan.related_cves.append(cve)
        defaults = [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/",
        ]
        for ref in defaults:
            if ref not in plan.references:
                plan.references.append(ref)
        return plan

    def create_fallback_remediation(self, finding: dict[str, Any]) -> RemediationPlan:
        seed = _remediation_seed(finding)
        title = str(finding.get("title") or "Security issue")
        return RemediationPlan(
            finding_id=str(finding.get("id") or "unknown"),
            vulnerability_title=title,
            severity=str(finding.get("severity") or "unknown"),
            root_cause=str(finding.get("evidence") or seed.get("action") or title)[:2000],
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Revisar o achado",
                    description=(
                        f"Confirme evidência/PoC para «{title}» no alvo "
                        f"{finding.get('host') or finding.get('url') or 'N/A'}."
                    ),
                    notes="Use a triagem DarkStar e o pipeline de verify.",
                ),
                RemediationStep(
                    step_number=2,
                    title=seed.get("title") or "Aplicar correção",
                    description=seed.get("action") or "Aplicar correção recomendada.",
                ),
                RemediationStep(
                    step_number=3,
                    title="Retestar",
                    description="Reexecute o mesmo check/tool e confirme que o finding não reaparece.",
                    command=str(finding.get("command") or "")[:500] or None,
                ),
            ],
            code_before="",
            code_after="",
            test_command="",
            deployment_notes="Teste em staging antes de produção. Documente a mudança.",
            estimated_time_minutes=45,
            difficulty="medium",
            references=[
                "https://owasp.org/www-project-top-ten/",
                "https://cwe.mitre.org/",
            ],
            related_cves=[],
            confidence_score=0.35,
            source="fallback",
        )


class RemediationVerifier:
    """Verificação leve — não executa test_command no host."""

    def verify_fix(
        self,
        original_code: str,
        fixed_code: str,
        test_command: str,
        language: str,
    ) -> dict[str, Any]:
        lang = (language or "").lower()
        issues: list[str] = []
        syntax_valid = True
        if lang in {"python", "py"} and fixed_code.strip():
            try:
                compile(fixed_code, "<string>", "exec")
            except SyntaxError as exc:
                syntax_valid = False
                issues.append(f"syntax: {exc}")
        elif fixed_code.strip() and lang not in {"", "python", "py", "javascript", "js", "typescript", "ts", "bash", "shell", "config", "nginx", "yaml"}:
            issues.append("syntax check skipped for this language")
        if test_command:
            issues.append("test_command not executed (safety: no host command run)")
        return {
            "syntax_valid": syntax_valid,
            "test_passes": False,
            "test_skipped": True,
            "security_improved": None,
            "issues": issues,
        }


class RemediationTracker:
    """Persistência JSON de progresso de remediação."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _TRACK_PATH

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def track(
        self,
        finding_id: str,
        remediation_plan: dict[str, Any] | RemediationPlan,
        status: str = "in_progress",
    ) -> dict[str, Any]:
        data = self._load()
        plan = (
            remediation_plan.to_dict()
            if isinstance(remediation_plan, RemediationPlan)
            else dict(remediation_plan or {})
        )
        entry = {
            "finding_id": finding_id,
            "plan": plan,
            "status": status,
            "steps_completed": 0,
            "notes": [],
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        prev = data.get(finding_id)
        if isinstance(prev, dict) and prev.get("created_at"):
            entry["created_at"] = prev["created_at"]
        data[finding_id] = entry
        self._save(data)
        return entry

    def update(
        self,
        finding_id: str,
        *,
        status: str | None = None,
        steps_completed: int | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        data = self._load()
        entry = data.get(finding_id)
        if not isinstance(entry, dict):
            return None
        if status:
            entry["status"] = status
        if steps_completed is not None:
            entry["steps_completed"] = int(steps_completed)
        if notes:
            entry.setdefault("notes", []).append(
                {"ts": datetime.now(timezone.utc).isoformat(), "note": notes[:1000]}
            )
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        data[finding_id] = entry
        self._save(data)
        return entry

    def stats(self) -> dict[str, Any]:
        data = self._load()
        total = len(data)
        completed = sum(1 for v in data.values() if isinstance(v, dict) and v.get("status") == "completed")
        in_progress = sum(
            1 for v in data.values() if isinstance(v, dict) and v.get("status") == "in_progress"
        )
        failed = sum(1 for v in data.values() if isinstance(v, dict) and v.get("status") == "failed")
        return {
            "total_tracked": total,
            "completed": completed,
            "in_progress": in_progress,
            "failed": failed,
            "completion_rate": f"{100 * completed / max(total, 1):.1f}%",
        }


# Singletons usados pelas rotas
remediation_advisor = RemediationAdvisor()
remediation_verifier = RemediationVerifier()
remediation_tracker = RemediationTracker()
