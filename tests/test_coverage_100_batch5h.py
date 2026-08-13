"""Lote 5h: github, notifications ABC, intelligence postgres/json, MCP, playbooks, schedule, security."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.executor.result import ExecutionResult
from backend.intelligence.suggest import build_suggestions


class _FakeQuery:
    def __init__(self, session: _FakeSession, model: object) -> None:
        self.session = session
        self.model = model
        self._filters: dict = {}

    def filter_by(self, **kw):
        self._filters.update(kw)
        return self

    def filter(self, *_a):
        return self

    def order_by(self, *_a):
        return self

    def limit(self, _n):
        return self

    def distinct(self):
        return self

    def _name(self) -> str:
        return getattr(self.model, "__name__", "") or ""

    def one_or_none(self):
        name = self._name()
        if name == "IndustryPattern":
            key = (self._filters.get("industry"), self._filters.get("pattern_key"))
            return self.session.patterns.get(key)
        if name == "TargetIntelligence":
            return self.session.ti_row
        return None

    def all(self):
        name = self._name()
        if name == "IndustryPattern":
            return list(self.session.patterns.values()) or self.session.pattern_rows
        if name == "FindingHistory":
            return self.session.finding_rows
        if name == "TargetIntelligence":
            return self.session.ti_rows
        return self.session.pentest_targets

    def first(self):
        target = self._filters.get("target")
        if target in self.session.missing_pentests:
            return None
        if target:
            rec = MagicMock()
            rec.id = 77
            rec.target = target
            return rec
        return None

    def count(self):
        return 0


class _FakeSession:
    def __init__(self) -> None:
        self.patterns: dict = {}
        self.pattern_rows: list = []
        self.ti_row = None
        self.ti_rows: list = []
        self.finding_rows: list = []
        self.pentest_targets: list = []
        self.missing_pentests: set[str] = set()
        self.added: list = []

    def add(self, obj) -> None:
        self.added.append(obj)
        name = type(obj).__name__
        if name == "PentestRecord":
            obj.id = 101
        elif name == "IndustryPattern":
            self.patterns[(obj.industry, obj.pattern_key)] = obj
        elif name == "TargetIntelligence":
            self.ti_row = obj

    def flush(self) -> None:
        return None

    def query(self, model):
        return _FakeQuery(self, model)


def _scope_for(session: _FakeSession):
    @contextmanager
    def _cm():
        yield session

    return _cm


class TestGitHubAndNotifications(unittest.TestCase):
    def test_github_nwo_and_exception_paths(self):
        from backend.integrations.github import GitHubClient

        c = GitHubClient(token="")
        c._client = MagicMock()
        self.assertIsNone(c.get_repo(""))
        self.assertIsNone(c.get_repo("onlyone"))
        self.assertIsNone(c.get_repo("not-a-repo"))

        repo = MagicMock()
        pr = MagicMock()
        repo.get_pull.return_value = pr
        issue = MagicMock(html_url="https://github.com/o/b5hrepo/issues/1")
        repo.create_issue.return_value = issue
        c._client.get_repo.return_value = repo

        with patch("backend.integrations.github.record_event"):
            c._add_severity_labels(pr, [{"severity": "low"}, {"severity": "medium"}])
            self.assertTrue(
                c.comment_on_pr("owner/b5hrepo", 4, [{"severity": "info"}], add_labels=True)
            )
            repo.get_pull.side_effect = RuntimeError("no-pr-b5h")
            self.assertFalse(c.comment_on_pr("owner/b5hrepo", 9, [{"severity": "high"}]))
            repo.get_pull.side_effect = None
            repo.get_pull.return_value = pr
            repo.create_issue.side_effect = RuntimeError("no-issue-b5h")
            self.assertIsNone(c.create_issue("owner/b5hrepo", {"title": "t", "severity": "low"}))

    def test_notification_abc_not_implemented(self):
        from backend.integrations import notifications as n

        class _Probe(n.NotificationChannel):
            def send(self, title, message, severity="info"):
                return super().send(title, message, severity)

            def is_configured(self):
                return super().is_configured()

        probe = _Probe()
        with self.assertRaises(NotImplementedError):
            probe.send("t", "m")
        with self.assertRaises(NotImplementedError):
            probe.is_configured()


class TestIntelligenceHubBranches(unittest.TestCase):
    def test_disabled_and_try_record_exception(self):
        from backend.intelligence import hub

        with patch.object(hub, "INTELLIGENCE_ENABLED", False):
            self.assertEqual(
                hub.record_from_surface("b5h-off.test"),
                {"enabled": False, "recorded": False},
            )
            hub.try_record_from_surface("b5h-off.test")
        with (
            patch.object(hub, "INTELLIGENCE_ENABLED", True),
            patch.object(hub, "record_from_surface", side_effect=RuntimeError("skip-b5h")),
        ):
            hub.try_record_from_surface("b5h-try-err.test")

    def test_postgres_record_patterns_and_similar(self):
        from backend.intelligence import hub
        from backend.intelligence import store as istore

        session = _FakeSession()
        session.pentest_targets = [
            MagicMock(target="b5h-sim-empty.test"),
            MagicMock(target="b5h-sim-hit.test"),
        ]
        session.missing_pentests.add("b5h-sim-empty.test")
        session.finding_rows = [MagicMock(finding_key="cve:CVE-2024-5555")]
        pat = MagicMock()
        pat.industry = "tech"
        pat.pattern_key = "cve:CVE-2099-1"
        pat.finding_type = "cve"
        pat.frequency = 4
        session.pattern_rows = [pat]
        surface = {
            "findings": [
                {
                    "cve": "CVE-2024-5555",
                    "title": "Same",
                    "severity": "high",
                    "sources": ["nuclei"],
                },
                {
                    "cve": "CVE-2024-5555",
                    "title": "Same",
                    "severity": "high",
                    "sources": "not-a-list",
                },
            ],
            "tools_run": ["nuclei"],
            "phase": "vuln_scan",
            "label": "tech",
        }
        with (
            patch.object(hub, "INTELLIGENCE_ENABLED", True),
            patch.object(istore, "use_postgres", return_value=True),
            patch.object(hub, "load_surface", return_value=surface),
            patch.object(hub, "surface_summary", return_value={"findings": 2}),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            out = hub.record_from_surface("b5h-pg.test", industry="tech")
            self.assertEqual(out.get("storage"), "postgres")
            hub.suggest("b5h-pg.test", industry="tech", limit=4)
            sim = hub.similar_targets("b5h-pg-self.test")
            self.assertEqual(sim.get("storage"), "postgres")

    def test_similar_json_empty_hist_and_no_overlap(self):
        from backend.intelligence import hub
        from backend.intelligence import store as istore

        norm = "b5h-sim-self.test"

        def _hist(target: str, limit: int = 50):
            if target == "b5h-empty-hist.test":
                return []
            if target == "b5h-no-overlap.test":
                return [{"findings": [{"finding_key": "title:other-only"}]}]
            return []

        with (
            patch.object(istore, "use_postgres", return_value=False),
            patch.object(
                hub,
                "load_surface",
                return_value={"findings": [{"cve": "CVE-2024-1", "title": "x"}]},
            ),
            patch.object(
                istore,
                "list_history_targets_json",
                return_value=[norm, "b5h-empty-hist.test", "b5h-no-overlap.test"],
            ),
            patch.object(istore, "read_history_json", side_effect=_hist),
        ):
            out = hub.similar_targets(norm)
            self.assertEqual(out.get("storage"), "json")
            self.assertEqual(out.get("targets"), [])


class TestSuggestPatternsStoreThreat(unittest.TestCase):
    def test_build_suggestions_branches(self):
        emptyish = build_suggestions(
            {
                "ports": [{"port": "22"}],
                "urls": [],
                "findings": [],
                "tools_run": ["httpx"],
            },
            {"patterns": {}},
        )
        self.assertTrue(emptyish)
        self.assertEqual(
            emptyish[0]["suggestion"],
            "Executar recon básico (subfinder/httpx) ou nmap -sV e gravar surface",
        )

        kev = build_suggestions(
            {
                "ports": [{"port": "443"}],
                "urls": ["https://b5h.kev.test"],
                "findings": [
                    {
                        "cve": "CVE-2024-1",
                        "cisa_kev_flag": True,
                        "status": "candidate",
                        "title": "kev",
                    }
                ],
                "tools_run": ["nmap", "nuclei"],
            },
            {"patterns": {}},
        )
        self.assertTrue(any("CVE" in s["suggestion"] or "KEV" in s["suggestion"] for s in kev))

        patterns = {
            "patterns": {
                "tech|cve:CVE-2099-1": {
                    "industry": "tech",
                    "pattern_key": "cve:CVE-2099-1",
                    "finding_type": "cve",
                    "frequency": 6,
                    "title_sample": "Old CVE",
                },
                "tech|title:dup-a": {
                    "industry": "tech",
                    "pattern_key": "title:dup-a",
                    "frequency": 3,
                    "title_sample": "Same Title",
                },
                "tech|title:dup-b": {
                    "industry": "tech",
                    "pattern_key": "title:dup-b",
                    "frequency": 3,
                    "title_sample": "Same Title",
                },
                "tech|empty": {
                    "industry": "tech",
                    "pattern_key": "",
                    "frequency": 9,
                },
                "tech|rare": {
                    "industry": "tech",
                    "pattern_key": "title:rare",
                    "frequency": 1,
                },
                "tech|present": {
                    "industry": "tech",
                    "pattern_key": "cve:CVE-2024-1",
                    "frequency": 9,
                },
            }
        }
        ranked = build_suggestions(
            {
                "ports": [{"port": "80"}],
                "urls": ["https://b5h.pat.test"],
                "findings": [{"cve": "CVE-2024-1", "status": "confirmed", "title": "p"}],
                "tools_run": ["nmap", "nuclei"],
            },
            patterns,
            industry="tech",
            limit=2,
        )
        self.assertLessEqual(len(ranked), 2)

        capped = build_suggestions(
            {"ports": [], "urls": ["https://x"], "findings": [], "tools_run": []},
            {"patterns": {}},
            limit=1,
        )
        self.assertEqual(len(capped), 1)

    def test_compact_sources_and_missing_history(self):
        from backend.intelligence import store as istore
        from backend.intelligence.patterns import compact_finding

        packed = compact_finding({"title": "x", "sources": "nuclei"})
        self.assertEqual(packed["sources"], [])
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(istore, "INTELLIGENCE_DIR", tmp):
                self.assertEqual(istore.read_history_json("b5h-missing-hist"), [])

    def test_threat_model_context_dedup_and_postgres(self):
        from backend.intelligence import store as istore
        from backend.intelligence import threat_modeling as tm
        from backend.intelligence.business_context import BusinessContext

        plan = tm.build_scan_plan(
            {"ports": [{"port": "22"}], "urls": [], "findings": [], "tools_run": ["nmap"]},
            [
                {"name": "API", "focus": "auth", "criticality": 9},
                {"name": "API", "focus": "auth", "criticality": 8},
            ],
            [],
        )
        focuses = [s["focus"] for s in plan]
        self.assertEqual(len(focuses), len(set(focuses)))

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(istore, "INTELLIGENCE_DIR", tmp),
                patch.object(istore, "use_postgres", return_value=False),
                patch.object(
                    tm,
                    "load_surface",
                    return_value={"findings": [], "ports": [], "urls": [], "tools_run": []},
                ),
            ):
                ctx = BusinessContext(industry="tech", company_size="smb")
                payload = tm.generate_threat_model("b5h-tm-ctx.test", context=ctx)
                self.assertEqual(payload["target"], "b5h-tm-ctx.test")

        session = _FakeSession()
        session.ti_row = None
        with (
            patch.object(istore, "use_postgres", return_value=True),
            patch.object(istore, "save_threat_model_json"),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            tm._persist_threat_model(
                "b5h-tm-pg.test",
                {"target": "b5h-tm-pg.test"},
                industry="tech",
                ctx=BusinessContext(),
            )
            self.assertTrue(any(type(x).__name__ == "TargetIntelligence" for x in session.added))

        bad = MagicMock()
        bad.threat_model_json = "{"
        session.ti_row = bad
        with (
            patch.object(istore, "use_postgres", return_value=True),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            self.assertIsNone(tm.get_threat_model("b5h-tm-badjson.test"))
        session.ti_row = MagicMock(threat_model_json="[1]")
        with (
            patch.object(istore, "use_postgres", return_value=True),
            patch("backend.database.db.init_db"),
            patch("backend.database.db.session_scope", _scope_for(session)),
        ):
            self.assertIsNone(tm.get_threat_model("b5h-tm-notdict.test"))


class TestMcpPlaybooksSchedule(unittest.TestCase):
    def test_mcp_empty_args_and_suggest(self):
        from backend import mcp_service

        with self.assertRaises(ValueError):
            mcp_service._tool_get_risk_score({})
        with self.assertRaises(ValueError):
            mcp_service._tool_enrich_target_threat_intel({})
        with self.assertRaises(ValueError):
            mcp_service._tool_suggest_next_checks({})
        with patch(
            "backend.intelligence.hub.suggest",
            return_value={"target": "b5h-mcp.test", "suggestions": []},
        ):
            out = mcp_service._tool_suggest_next_checks(
                {"target": "b5h-mcp.test", "industry": "tech", "limit": 5}
            )
            self.assertEqual(out["target"], "b5h-mcp.test")
        fake = ExecutionResult(
            command="nmap -sV scanme.nmap.org",
            reason="",
            stdout="ok",
            stderr="",
            exit_code=0,
            success=True,
        )
        with (
            patch("backend.security.scope.validate_command_scope", return_value=(True, "")),
            patch("backend.executor.kali.execute_kali_command", return_value=fake),
        ):
            ran = mcp_service._tool_run_kali_tool(
                {"command": "nmap -sV scanme.nmap.org", "reason": "b5h"}
            )
            self.assertTrue(ran.get("success"))

    def test_playbook_isolated_exceptions(self):
        from backend.playbooks import loader as ld

        ok = ExecutionResult("nmap t", "r", "v", "", 0, True)
        with (
            patch.object(
                ld,
                "load_playbook",
                return_value={
                    "id": "b5h-pb",
                    "steps": [{"tool": "nmap", "args": ["{target}"]}],
                },
            ),
            patch.object(ld, "execute_kali_command", return_value=ok),
            patch("backend.playbooks.loader.validate_autonomous_target", return_value=(True, "")),
            patch("backend.playbooks.loader.validate_command_scope", return_value=(True, "")),
            patch("backend.executor.surface.get_or_create_surface", side_effect=OSError("surf")),
            patch("backend.ai.verify.run_verification_pipeline", side_effect=RuntimeError("ver")),
            patch(
                "backend.intelligence.hub.try_record_from_surface",
                side_effect=RuntimeError("intel"),
            ),
        ):
            out = ld.run_playbook("b5h-pb", "b5h-pb.lab.test")
            self.assertEqual(out["playbook_id"], "b5h-pb")
            self.assertEqual(out["steps_run"], 1)

    def test_schedule_record_save_and_tick(self):
        from backend.schedule import runner as rn

        job = {
            "id": "b5h-full-rec-1",
            "target": "b5h-full.test",
            "job_type": "full",
            "scan_profile": "basic",
            "risk_profile": "passive",
            "client_id": "b5h-cli",
        }
        with (
            patch("backend.alerts.webhook.send_webhook", return_value=True),
            patch("backend.alerts.webhook.maybe_alert_delta", return_value=[]),
            patch("backend.ai.risk_score.risk_score_for_target", return_value={"score": 1}),
            patch("backend.ai.risk_history.previous_score", return_value=0),
            patch("backend.ai.risk_history.record_risk_snapshot"),
            patch("backend.ai.delta.compute_delta", return_value={"new": []}),
            patch("backend.database.db.record_scan_from_target", side_effect=RuntimeError("db")),
            patch.object(rn, "advance_job"),
        ):
            out = rn.execute_job(job)
            self.assertTrue(out.get("ok"))

        with (
            patch.object(rn, "save_job", side_effect=OSError("no-save")),
            patch("threading.Thread") as th,
        ):
            th.return_value.start = MagicMock()
            rn._start_repeat_mission(
                {
                    "id": "b5h-rep-sv",
                    "target": "b5h.rep.test",
                    "scan_profile": "basic",
                    "custom_tools": [],
                    "chat_session_id": "b5hsid1",
                    "risk_profile": "passive",
                }
            )
            th.assert_called()

        tick_job = {"id": "b5h-tick-1", "target": "b5h.tick.test", "job_type": "remind"}
        with patch.object(rn, "_stop") as stop:
            stop.wait.side_effect = [False, True]
            with (
                patch.object(rn, "SCHEDULE_ENABLED", True),
                patch.object(rn, "due_jobs", return_value=[tick_job]),
                patch.object(rn, "execute_job", return_value={"ok": True}) as ex,
            ):
                rn._tick()
                ex.assert_called_once_with(tick_job)


class TestSecurityAuditRolesFrameworks(unittest.TestCase):
    def test_audit_remove_invalid_and_json(self):
        from backend.security import audit as audit_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(audit_mod, "AUDIT_DIR", root):
                self.assertEqual(audit_mod.remove_entries_by_log_id(""), 0)
                self.assertEqual(audit_mod.remove_entries_by_log_id("not-alnum!"), 0)
                (root / "events-2099-01-01.jsonl").mkdir()
                p = root / "events-2099-01-02.jsonl"
                p.write_text(
                    "\n{not-json}\n" + json.dumps({"log_file_id": "b5hlogid1"}) + "\n",
                    encoding="utf-8",
                )
                removed = audit_mod.remove_entries_by_log_id("b5hlogid1")
                self.assertGreaterEqual(removed, 1)

    def test_privileges_empty_key_and_expired_token(self):
        from backend.security import privileges as priv

        with patch.object(priv, "MASTER_KEY", ""):
            self.assertFalse(priv.verify_master_key("x"))
        with patch.object(priv, "MASTER_KEY", "abc"):
            self.assertFalse(priv.verify_master_key(""))
            self.assertFalse(priv.verify_master_key(None))
        dead = "b5hTokExpired001"
        with priv._lock:
            priv._tokens[dead] = time.time() - 10
        with patch.object(priv, "_purge_locked"):
            self.assertFalse(priv.validate_privilege_token(dead))
        with priv._lock:
            priv._tokens.pop(dead, None)

    def test_can_write_and_mixed_framework(self):
        from backend.compliance import frameworks as fw
        from backend.security import roles as roles_mod

        self.assertTrue(roles_mod.can_write())
        with patch.object(roles_mod, "OPERATOR_ROLE", "viewer"):
            self.assertFalse(roles_mod.can_write())
        with patch.dict(
            fw.FRAMEWORKS,
            {"MixedFw": {"name": "M", "region": "x", "controls": []}},
            clear=False,
        ):
            self.assertIsNotNone(fw.get_framework("mixedfw"))


if __name__ == "__main__":
    unittest.main()
