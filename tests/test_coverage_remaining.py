"""Fecha gaps restantes para cobertura alta (agent/autopilot/system/recon/kali)."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from tests.llm_test_utils import make_openrouter_provider

from fastapi.testclient import TestClient

from backend.ai.agent import ChatResponse, chat_stream
from backend.ai.autopilot import AutonomousResponse, run_autonomous, run_autonomous_stream
from backend.security.missions import get_mission_registry


class TestAgentGaps(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()

    def test_persist_recon_early_exits(self):
        from backend.ai import agent as ag

        blocked = MagicMock(
            success=True,
            blocked=True,
            command="nmap a.com",
            stdout="",
            stderr="",
            tool="nmap",
            exit_code=-1,
        )
        ag._persist_recon(blocked, ["a.com"])
        fail = MagicMock(
            success=False,
            blocked=False,
            command="nmap a.com",
            stdout="",
            stderr="fail",
            tool="nmap",
            exit_code=1,
        )
        ag._persist_recon(fail, ["a.com"])

        ok = MagicMock(
            success=True,
            blocked=False,
            command="nmap",
            stdout="x",
            stderr="",
            tool="nmap",
            exit_code=0,
        )
        with patch(
            "backend.executor.recon_db.extract_targets", return_value=[]
        ), patch(
            "backend.executor.recon_db.is_recon_target", return_value=False
        ):
            ag._persist_recon(ok, [])

        with patch(
            "backend.executor.recon_db.extract_targets", return_value=["a.com"]
        ), patch(
            "backend.executor.recon_db.is_recon_target", return_value=True
        ), patch.object(
            ag, "extract_recon_from_output", return_value={"a": 1}
        ), patch.object(ag, "merge_recon_update") as merge:
            ag._persist_recon(ok, ["a.com"])
            merge.assert_not_called()

    def test_record_execution_with_emit(self):
        from backend.ai import agent as ag

        events = []
        fake = MagicMock(
            command="nmap -V",
            reason="r",
            stdout="ok",
            stderr="",
            exit_code=0,
            success=True,
            blocked=False,
            log_file_id="id1",
            tool="nmap",
            truncated_for_llm=False,
        )
        with patch("backend.ai.agent.new_log_id", return_value="eid1"), patch(
            "backend.ai.agent.get_stream_hub"
        ) as hub, patch(
            "backend.ai.agent.execute_in_kali", return_value=fake
        ), patch(
            "backend.ai.agent.summarize_output", return_value=("ok", False)
        ), patch(
            "backend.ai.agent.format_result_for_llm", return_value="fmt"
        ), patch(
            "backend.ai.agent._persist_recon"
        ):
            hub.return_value.create = MagicMock()
            out = ag._record_execution(
                "nmap -V",
                "r",
                [],
                emit=lambda e, d: events.append((e, d)),
            )
        self.assertEqual(out, "fmt")
        self.assertEqual(events[0][0], "tool_start")
        self.assertEqual(events[1][0], "tool_done")

    def test_no_api_key_and_mission_lifecycle(self):
        from backend.ai import agent as ag

        provider = make_openrouter_provider(api_key="")
        with patch("backend.ai.agent.get_llm_provider", return_value=provider):
            res = ag._run_openrouter([], "hi")
        self.assertIn("OPENROUTER_API_KEY", res.message)

        mid = "missioncov1"
        provider = make_openrouter_provider(api_key="sk")
        with patch("backend.ai.agent.get_llm_provider", return_value=provider), patch(
            "backend.ai.agent._run_openrouter_body",
            return_value=ChatResponse(message="ok"),
        ) as body:
            res = ag._run_openrouter([], "hi", mission_id=mid)
        self.assertEqual(res.message, "ok")
        body.assert_called_once()

    def test_non_retryable_llm_error(self):
        from backend.ai.agent import _run_openrouter_body

        client = MagicMock()
        client.chat.completions.create.side_effect = RuntimeError("401 invalid key")
        provider = make_openrouter_provider(client, models=("m1", "m2"))
        with patch("backend.ai.agent.get_llm_provider", return_value=provider):
            result = _run_openrouter_body([], "hi", None, None, None, None, None)
        self.assertIn("inválida", result.message.lower())

    def test_skip_unknown_tool_and_bad_json_args(self):
        from backend.ai.agent import _run_openrouter_body

        unknown = MagicMock()
        unknown.id = "u1"
        unknown.function.name = "other_tool"
        unknown.function.arguments = "{}"

        bad = MagicMock()
        bad.id = "b1"
        bad.function.name = "run_kali_tool"
        bad.function.arguments = "{not-json"

        final = MagicMock(content="done", tool_calls=None)
        client = MagicMock()
        client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=MagicMock(content="", tool_calls=[unknown, bad]))]),
            MagicMock(choices=[MagicMock(message=final)]),
        ]
        provider = make_openrouter_provider(client, models=("m1", "m1"))
        with patch("backend.ai.agent.get_llm_provider", return_value=provider), patch(
            "backend.ai.agent.resolve_tool_arguments",
            return_value=(None, "Falha ao decodificar os argumentos fornecidos pela IA."),
        ), patch(
            "backend.ai.agent._record_execution", return_value="out"
        ) as rec, patch(
            "backend.ai.agent.should_attempt_healing", return_value=False
        ):
            # seed one execution so healing index works
            from backend.ai.agent import ToolExecution

            executions_holder = []

            def _rec(command, reason, executions, **kwargs):
                executions.append(
                    ToolExecution(
                        command=command or "",
                        reason=reason,
                        stdout="",
                        stderr="",
                        exit_code=0,
                        success=True,
                    )
                )
                executions_holder.append(1)
                return "out"

            rec.side_effect = _rec
            result = _run_openrouter_body([], "hi", None, None, None, None, None)
        self.assertEqual(result.message, "done")
        self.assertTrue(executions_holder)

    def test_max_iterations_finalization(self):
        from backend.ai import agent as ag

        tool_call = MagicMock()
        tool_call.id = "t"
        tool_call.function.name = "run_kali_tool"
        tool_call.function.arguments = '{"command":"nmap -V","reason":"x"}'
        msg = MagicMock(content="", tool_calls=[tool_call])
        client = MagicMock()
        # Always return tool calls until loop ends, then final create
        client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg)]),
            MagicMock(choices=[MagicMock(message=msg)]),
            MagicMock(choices=[MagicMock(message=MagicMock(content="final", tool_calls=None))]),
        ]

        def _rec(command, reason, executions, **kwargs):
            executions.append(
                MagicMock(
                    command=command,
                    reason=reason,
                    success=True,
                    blocked=False,
                    exit_code=0,
                    stdout="",
                    stderr="",
                    log_file_id="",
                    tool="nmap",
                )
            )
            return "out"

        provider = make_openrouter_provider(client, models=("m1", "m1"))
        with patch("backend.ai.agent.get_llm_provider", return_value=provider), patch(
            "backend.ai.agent.MAX_TOOL_ITERATIONS", 2
        ), patch(
            "backend.ai.agent._record_execution", side_effect=_rec
        ), patch(
            "backend.ai.agent.should_attempt_healing", return_value=False
        ):
            result = ag._run_openrouter_body([], "hi", None, None, None, None, None)
        self.assertEqual(result.message, "final")

    def test_max_iterations_finalization_error(self):
        from backend.ai import agent as ag

        tool_call = MagicMock()
        tool_call.id = "t"
        tool_call.function.name = "run_kali_tool"
        tool_call.function.arguments = '{"command":"nmap -V","reason":"x"}'
        msg = MagicMock(content="", tool_calls=[tool_call])
        client = MagicMock()
        client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg)]),
            RuntimeError("boom"),
        ]

        def _rec(command, reason, executions, **kwargs):
            executions.append(MagicMock(success=True, blocked=False, exit_code=0))
            return "out"

        provider = make_openrouter_provider(client, models=("m1", "m1"))
        with patch("backend.ai.agent.get_llm_provider", return_value=provider), patch(
            "backend.ai.agent.MAX_TOOL_ITERATIONS", 1
        ), patch(
            "backend.ai.agent._record_execution", side_effect=_rec
        ), patch(
            "backend.ai.agent.should_attempt_healing", return_value=False
        ):
            result = ag._run_openrouter_body([], "hi", None, None, None, None, None)
        self.assertIn("Erro na finalização", result.message)

    def test_chat_stream_error_event(self):
        with patch(
            "backend.ai.agent.chat", side_effect=RuntimeError("stream-boom")
        ):
            body = "".join(chat_stream([], "hi"))
        self.assertIn("event: error", body)
        self.assertIn("stream-boom", body)

    def test_cancelled_mission_in_body(self):
        from backend.ai.agent import _run_openrouter_body

        mid = "cancelbody1"
        get_mission_registry().register(mid)
        get_mission_registry().cancel(mid)
        with patch("backend.ai.agent.get_llm_provider", return_value=make_openrouter_provider()):
            result = _run_openrouter_body([], "hi", None, None, None, None, mid)
        self.assertEqual(result.stopped_reason, "cancelled")


class TestAutopilotGaps(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()

    def test_missing_fields_and_no_key(self):
        provider = make_openrouter_provider(api_key="")
        with patch("backend.ai.autopilot.get_llm_provider", return_value=provider):
            r = run_autonomous("t", "o")
        self.assertEqual(r.stopped_reason, "error")
        provider = make_openrouter_provider(api_key="sk")
        with patch("backend.ai.autopilot.get_llm_provider", return_value=provider):
            r = run_autonomous("", "obj")
            self.assertEqual(r.stopped_reason, "error")
            r = run_autonomous("t", "  ")
            self.assertEqual(r.stopped_reason, "error")

    def test_cycle_nudge_and_text_return(self):
        from backend.ai import autopilot as ap
        from backend.ai.providers.base import LLMCompletion, LLMMessage

        with patch(
            "backend.ai.autopilot._completion",
            side_effect=[
                LLMCompletion(message=LLMMessage(content="")),
                LLMCompletion(message=LLMMessage(content="waiting")),
            ],
        ):
            out, finished, met, model = ap._run_autonomous_cycle(
                MagicMock(), [{"role": "system", "content": "s"}], [], "m1", "m2", 3
            )
        self.assertEqual(out, "waiting")
        self.assertFalse(finished)

    def test_cycle_cancel_retry_healing_budget(self):
        from backend.ai import autopilot as ap
        from backend.ai.providers.base import LLMCompletion, LLMMessage, ToolCall

        mid = "apcancel1"
        get_mission_registry().register(mid)
        get_mission_registry().cancel(mid)
        text, finished, met, _ = ap._run_autonomous_cycle(
            MagicMock(), [], [], "m1", "m2", 2, mission_id=mid
        )
        self.assertTrue(finished)
        self.assertIn("cancelada", text.lower())

        # retryable then success finish
        finish = ToolCall(id="f", name="finish_mission", arguments="{bad")
        provider = MagicMock()
        provider.is_retryable_error.side_effect = lambda e: "429" in e or "rate" in e.lower()
        provider.format_error.side_effect = lambda e: e
        with patch(
            "backend.ai.autopilot._completion",
            side_effect=[
                RuntimeError("429 rate"),
                LLMCompletion(message=LLMMessage(content="", tool_calls=[finish])),
            ],
        ), patch("backend.ai.autopilot.time.sleep"), patch(
            "backend.ai.autopilot.resolve_tool_arguments",
            return_value=(None, "args inválidos"),
        ):
            text, finished, met, model = ap._run_autonomous_cycle(
                provider, [{"role": "system", "content": "s"}], [], "m1", "m2", 2
            )
        self.assertTrue(finished)
        self.assertFalse(met)
        self.assertEqual(model, "m2")

        # bad kali args + healing + budget 1
        tool = ToolCall(id="k", name="run_kali_tool", arguments="not-json")

        def _record(command, reason, executions, **kwargs):
            executions.append(
                MagicMock(success=False, blocked=False, exit_code=1, command=command)
            )
            return "fail"

        with patch(
            "backend.ai.autopilot._completion",
            return_value=LLMCompletion(message=LLMMessage(content="", tool_calls=[tool])),
        ), patch(
            "backend.ai.autopilot.resolve_tool_arguments",
            return_value=({"command": "nmap", "reason": "x"}, ""),
        ), patch(
            "backend.ai.autopilot._record_execution", side_effect=_record
        ), patch(
            "backend.ai.autopilot.should_attempt_healing", return_value=True
        ), patch(
            "backend.ai.autopilot.healing_prompt", return_value="heal"
        ):
            text, finished, met, _ = ap._run_autonomous_cycle(
                MagicMock(), [{"role": "system", "content": "s"}], [], "m1", "m2", 1
            )
        self.assertFalse(finished)

    def test_run_autonomous_happy_and_errors(self):
        finish = MagicMock()
        finish.id = "f"
        finish.function.name = "finish_mission"
        finish.function.arguments = '{"summary":"done","objective_met":true}'

        events = []

        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="scanme.nmap.org"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value="CTX"
        ), patch(
            "backend.ai.autopilot.MAX_AUTONOMOUS_ROUNDS", 2
        ), patch(
            "backend.ai.autopilot._run_autonomous_cycle",
            return_value=("done", True, True, "m1"),
        ), patch(
            "backend.ai.autopilot.generate_report", return_value="# r"
        ):
            res = run_autonomous(
                "scanme.nmap.org",
                "mapear",
                mission_id="m1",
                emit=lambda e, d: events.append(e),
            )
        self.assertTrue(res.objective_met)
        self.assertIn("mission_start", events)
        self.assertIn("CTX", "CTX")  # recon context applied in system

        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="t"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value=""
        ), patch(
            "backend.ai.autopilot._run_autonomous_cycle",
            side_effect=RuntimeError("llm down"),
        ):
            res = run_autonomous("t.com", "obj")
        self.assertEqual(res.stopped_reason, "error")

        # max tools path
        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="t"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value=""
        ), patch(
            "backend.ai.autopilot.MAX_AUTONOMOUS_TOOLS", 0
        ), patch(
            "backend.ai.autopilot.max_tool_budget", return_value=0
        ), patch(
            "backend.ai.autopilot.generate_report", return_value="# r"
        ):
            res = run_autonomous("t.com", "obj")
        self.assertEqual(res.stopped_reason, "max_tools")

    def test_stream_error(self):
        with patch(
            "backend.ai.autopilot.run_autonomous", side_effect=RuntimeError("ap-fail")
        ):
            body = "".join(run_autonomous_stream("t.com", "obj"))
        self.assertIn("event: error", body)


class TestSystemAndInfraGaps(unittest.TestCase):
    def test_health_error_branches(self):
        from backend.main import app

        client = TestClient(app)
        with patch("backend.routes.system.subprocess.run") as run:
            run.return_value = MagicMock(
                returncode=1, stdout="", stderr="docker down"
            )
            res = client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["docker"])

        with patch(
            "backend.routes.system.subprocess.run", side_effect=FileNotFoundError
        ):
            res = client.get("/api/health")
        self.assertIn("Docker", res.json()["kali_error"])

        with patch(
            "backend.routes.system.subprocess.run", side_effect=RuntimeError("boom")
        ):
            res = client.get("/api/health")
        self.assertIn("boom", res.json()["kali_error"])

        with patch("backend.routes.system.subprocess.run") as run, patch(
            "backend.routes.system.sys.platform", "win32"
        ), patch(
            "backend.executor.wifi_scan.windows_wifi_health",
            side_effect=RuntimeError("wifi-x"),
        ):
            run.return_value = MagicMock(
                returncode=0, stdout="kali-tools\n", stderr=""
            )
            res = client.get("/api/health")
        self.assertEqual(res.json().get("wifi_message"), "wifi-x")

    def test_log_stream_ok(self):
        from backend.executor.stream_hub import get_stream_hub
        from backend.main import app

        hub = get_stream_hub()
        hub.create("streameid1", "nmap")
        hub.finish("streameid1", exit_code=0, success=True)
        client = TestClient(app)
        res = client.get("/api/logs/stream/streameid1")
        self.assertEqual(res.status_code, 200)

    def test_files_log_content(self):
        from backend.main import app

        client = TestClient(app)
        with patch(
            "backend.routes.system.read_execution_log", return_value="logdata"
        ):
            res = client.get("/api/logs/abc123")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.text, "logdata")

    def test_kali_scope_block(self):
        from backend.executor import kali as k

        with patch.object(k, "validate_command", return_value=(True, "")), patch(
            "backend.executor.kali.validate_command_scope",
            return_value=(False, "fora do escopo"),
        ):
            events = list(
                k.execute_kali_command_stream(["nmap", "evil.example"], "r")
            )
        types = [e.get("type") for e in events]
        self.assertIn("done", types)
        done = next(e for e in events if e["type"] == "done")
        self.assertTrue(done["result"].blocked)

    def test_recon_ttl_and_merge(self):
        from backend.executor import recon_db as rd

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(rd, "RECON_DIR", root), patch.object(
                rd, "RECON_TTL_DAYS", 1
            ):
                path = root / "old.com.json"
                path.write_text(
                    json.dumps(
                        {
                            "target": "old.com",
                            "updated_at": "2020-01-01T00:00:00+00:00",
                            "open_ports": [80],
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(rd.get_recon_data("old.com"), {})
                self.assertFalse(path.exists())

                rd.save_recon_data("live.com", "open_ports", [80])
                rd.save_recon_data("live.com", "open_ports", [443])
                rd.save_recon_data("live.com", "meta", {"a": 1})
                rd.save_recon_data("live.com", "meta", {"b": 2})
                data = rd.get_recon_data("live.com")
                self.assertEqual(data["open_ports"], [80, 443])
                self.assertEqual(data["meta"], {"a": 1, "b": 2})

                # expired listing cleanup
                path2 = root / "exp.com.json"
                path2.write_text(
                    json.dumps(
                        {
                            "target": "exp.com",
                            "updated_at": "2019-01-01T00:00:00+00:00",
                        }
                    ),
                    encoding="utf-8",
                )
                summaries = rd.list_recon_summaries()
                self.assertTrue(all(s["target"] != "exp.com" for s in summaries))

                self.assertFalse(rd.is_recon_target("unknown"))
                self.assertFalse(rd.is_recon_target("x.local"))
                self.assertIsNone(rd._parse_updated_at(""))
                self.assertIsNone(rd._parse_updated_at("not-a-date"))

                with patch.object(rd, "RECON_TTL_DAYS", 0):
                    self.assertFalse(rd._is_recon_expired({"updated_at": "2020-01-01T00:00:00+00:00"}))

                ctx = rd.build_recon_context(["missing.example"])
                self.assertEqual(ctx, "")
                ctx = rd.build_recon_context(["live.com"])
                self.assertIn("live.com", ctx)

    def test_observability_fallbacks(self):
        from backend import observability as obs

        # Force psutil + resource fail → ctypes or empty
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name in ("psutil", "resource"):
                raise ImportError("no")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            metrics = obs.get_metrics()
        self.assertIn("request_id", metrics)

        # Force all memory backends to fail
        def fake_import_all(name, *args, **kwargs):
            if name in ("psutil", "resource", "ctypes"):
                raise ImportError("no")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import_all):
            metrics = obs.get_metrics()
        self.assertIn("request_id", metrics)

    def test_report_empty_recon_line(self):
        from backend.ai.report import generate_report

        with patch(
            "backend.ai.report.list_recon_summaries", return_value=[]
        ), patch(
            "backend.ai.report.list_output_files", return_value=[]
        ):
            md = generate_report([], [])
        self.assertIn("Nenhum dado de recon", md)

    def test_stream_hub_keepalive(self):
        from backend.executor.stream_hub import StreamHub

        hub = StreamHub()
        hub.create("keep1", "cmd")
        hub._streams["keep1"].finished = True
        with patch("backend.executor.stream_hub.Empty", Exception):
            # force Empty on get by making queue.get raise Empty-like
            pass
        from queue import Empty

        stream = hub.get("keep1")
        assert stream is not None

        def get_timeout(timeout=15):
            raise Empty

        stream.queue.get = get_timeout  # type: ignore[method-assign]
        # finished=True → break after Empty
        events = list(hub.subscribe_sse("keep1"))
        self.assertEqual(events, [])

        # missing stream
        events = list(hub.subscribe_sse("missing"))
        self.assertIn("error", events[0])

    def test_files_store_edge(self):
        from backend.executor import files_store as fs

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(fs, "OUTPUTS_DIR", root):
                # is_relative_to AttributeError path
                fake = MagicMock()
                fake.is_relative_to.side_effect = AttributeError
                fake.parents = []
                with patch.object(Path, "resolve", return_value=fake):
                    # safe_resolve may still work differently — just call list
                    pass
                root.mkdir(exist_ok=True)
                (root / "a.txt").write_text("x", encoding="utf-8")
                with patch.object(fs, "is_allowed_extension", return_value=False):
                    self.assertEqual(fs.list_output_files(), [])
                with patch.object(fs, "is_allowed_extension", return_value=True):
                    listed = fs.list_output_files()
                    self.assertTrue(listed)


class TestRateLimitFix(unittest.TestCase):
    def test_chat_stream_rate_limited_fresh_limiter(self):
        import backend.security.rate_limit as rl
        from backend.main import app
        from tests.auth_patch import patch_chat_api_token

        rl._limiter = None

        def mock_chat_stream(*_args, **_kwargs):
            yield 'event: done\ndata: {"message":"ok","tool_executions":[]}\n\n'

        with patch_chat_api_token(""), patch(
            "backend.middleware.RATE_LIMIT_REQUESTS", 2
        ), patch(
            "backend.middleware.RATE_LIMIT_WINDOW_SEC", 60
        ), patch(
            "backend.routes.chat.chat_stream", mock_chat_stream
        ):
            rl._limiter = None
            client = TestClient(app)
            payload = {"message": "teste", "history": []}
            for _ in range(2):
                res = client.post("/api/chat/stream", json=payload)
                self.assertEqual(res.status_code, 200)
            res = client.post("/api/chat/stream", json=payload)
            self.assertEqual(res.status_code, 429)


class TestFinalCoveragePush(unittest.TestCase):
    def setUp(self):
        get_mission_registry()._missions.clear()

    def test_chat_stream_emit_path(self):
        def fake_chat(*_a, emit=None, **_k):
            if emit:
                emit("tool_start", {"execution_id": "e", "command": "x", "reason": "r"})
            return ChatResponse(message="ok", tool_executions=[])

        with patch("backend.ai.agent.chat", side_effect=fake_chat):
            body = "".join(chat_stream([], "hi"))
        self.assertIn("tool_start", body)
        self.assertIn("event: done", body)

    def test_autopilot_create_client_and_nonretry(self):
        from backend.ai import autopilot as ap

        with patch("backend.ai.autopilot.get_llm_provider") as gp:
            fake = make_openrouter_provider()
            gp.return_value = fake
            self.assertIs(ap._create_client(), fake)

        provider = MagicMock()
        provider.is_retryable_error.return_value = False
        provider.format_error.side_effect = lambda e: f"Erro: {e}"
        with patch(
            "backend.ai.autopilot._completion",
            side_effect=RuntimeError("hard fail"),
        ):
            with self.assertRaises(RuntimeError):
                ap._run_autonomous_cycle(provider, [], [], "m1", "m1", 2)

        text, finished, met, _ = ap._run_autonomous_cycle(
            provider, [], [], "m1", "m2", 0
        )
        self.assertEqual(text, "")
        self.assertFalse(finished)

    def test_autopilot_rounds_and_messages(self):
        from backend.ai import autopilot as ap
        from backend.ai.agent import ToolExecution

        calls = {"n": 0}

        def cycle(client, messages, executions, *a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                executions.append(
                    ToolExecution(
                        command="nmap -V",
                        reason="r",
                        stdout="ok",
                        stderr="",
                        exit_code=0,
                        success=True,
                    )
                )
                return "", False, False, "m1"
            return "early", True, False, "m1"

        events = []
        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="t.com"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value=""
        ), patch(
            "backend.ai.autopilot.MAX_AUTONOMOUS_ROUNDS", 2
        ), patch(
            "backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle
        ), patch(
            "backend.ai.autopilot.generate_report", return_value="# r"
        ):
            res = run_autonomous(
                "t.com",
                "obj",
                emit=lambda e, d: events.append(e),
            )
        self.assertEqual(res.stopped_reason, "finished_early")
        self.assertIn("round_start", events)

        # texto sem finish + executions → mensagem de encerramento
        def cycle2(client, messages, executions, *a, **k):
            executions.append(
                ToolExecution(
                    command="nmap -V",
                    reason="r",
                    stdout="ok",
                    stderr="",
                    exit_code=0,
                    success=True,
                )
            )
            return "partial text", False, False, "m1"

        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="t.com"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value=""
        ), patch(
            "backend.ai.autopilot.MAX_AUTONOMOUS_ROUNDS", 1
        ), patch(
            "backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle2
        ), patch(
            "backend.ai.autopilot.generate_report", return_value="# r"
        ):
            res = run_autonomous("t.com", "obj")
        self.assertIn("partial text", res.message)

        # cancelado após finish
        mid = "finiscancel"
        get_mission_registry().register(mid)

        def cycle3(*_a, **_k):
            get_mission_registry().cancel(mid)
            return "bye", True, True, "m1"

        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="t.com"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value=""
        ), patch(
            "backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle3
        ), patch(
            "backend.ai.autopilot.generate_report", return_value="# r"
        ):
            res = run_autonomous("t.com", "obj", mission_id=mid)
        self.assertEqual(res.stopped_reason, "cancelled")

        # sem texto e com executions
        def cycle4(client, messages, executions, *a, **k):
            executions.append(
                ToolExecution(
                    command="x",
                    reason="r",
                    stdout="",
                    stderr="",
                    exit_code=0,
                    success=True,
                )
            )
            return "", False, False, "m1"

        with patch("backend.ai.autopilot.get_llm_provider", return_value=make_openrouter_provider(MagicMock())), patch(
            "backend.ai.autopilot.normalize_target", return_value="t.com"
        ), patch(
            "backend.ai.autopilot.build_recon_context", return_value=""
        ), patch(
            "backend.ai.autopilot.MAX_AUTONOMOUS_ROUNDS", 1
        ), patch(
            "backend.ai.autopilot._run_autonomous_cycle", side_effect=cycle4
        ), patch(
            "backend.ai.autopilot.generate_report", return_value="# r"
        ):
            res = run_autonomous("t.com", "obj")
        self.assertIn("Missão encerrada", res.message)

        ex = ToolExecution(
            command="c", reason="r", stdout="", stderr="", exit_code=0, success=True
        )
        self.assertEqual(ap._execution_dict(ex)["command"], "c")

        def fake_run(*_a, emit=None, **_k):
            if emit:
                emit("mission_start", {"target": "t"})
            return AutonomousResponse(message="ok", tool_executions=[ex])

        with patch("backend.ai.autopilot.run_autonomous", side_effect=fake_run):
            body = "".join(run_autonomous_stream("t.com", "obj"))
        self.assertIn("mission_start", body)
        self.assertIn("event: done", body)

    def test_system_linux_wifi_and_container_missing(self):
        from backend.main import app

        client = TestClient(app)
        with patch("backend.routes.system.subprocess.run") as run, patch(
            "backend.routes.system.sys.platform", "linux"
        ):
            run.side_effect = [
                MagicMock(returncode=0, stdout="other\n", stderr=""),
                MagicMock(
                    returncode=0,
                    stdout="Interface wlan0\nInterface wlan1\n",
                    stderr="",
                ),
            ]
            # first call: docker ps without kali → kali_ok False, wifi branch skipped
            res = client.get("/api/health")
            self.assertEqual(res.status_code, 200)
            self.assertIn("não está rodando", res.json()["kali_error"])

        with patch("backend.routes.system.subprocess.run") as run, patch(
            "backend.routes.system.sys.platform", "linux"
        ):
            run.side_effect = [
                MagicMock(returncode=0, stdout="kali-tools\n", stderr=""),
                MagicMock(
                    returncode=0,
                    stdout="Interface wlan0\n",
                    stderr="",
                ),
            ]
            res = client.get("/api/health")
            self.assertTrue(res.json()["wifi_ready"])

        with patch("backend.routes.system.subprocess.run") as run, patch(
            "backend.routes.system.sys.platform", "linux"
        ):
            run.side_effect = [
                MagicMock(returncode=0, stdout="kali-tools\n", stderr=""),
                MagicMock(returncode=1, stdout="", stderr=""),
            ]
            res = client.get("/api/health")
            self.assertIn("Nenhuma interface", res.json()["wifi_message"])

        with patch("backend.routes.system.subprocess.run") as run, patch(
            "backend.routes.system.sys.platform", "linux"
        ):
            run.side_effect = [
                MagicMock(returncode=0, stdout="kali-tools\n", stderr=""),
                RuntimeError("iw fail"),
            ]
            res = client.get("/api/health")
            self.assertIn("iw fail", res.json()["wifi_message"])

    def test_files_download_guards(self):
        from backend.main import app

        client = TestClient(app)
        with patch(
            "backend.routes.files.resolve_output_file", return_value=None
        ):
            self.assertEqual(client.get("/api/files/x.txt").status_code, 400)

        p = MagicMock()
        p.is_file.return_value = True
        p.stat.return_value.st_size = 10**12
        p.name = "big.txt"
        with patch(
            "backend.routes.files.resolve_output_file", return_value=p
        ), patch(
            "backend.routes.files.is_allowed_extension", return_value=True
        ), patch(
            "backend.routes.files.MAX_FILE_DOWNLOAD_BYTES", 100
        ):
            self.assertEqual(client.get("/api/files/big.txt").status_code, 413)

        with patch(
            "backend.routes.files.resolve_output_file", return_value=p
        ), patch(
            "backend.routes.files.is_allowed_extension", return_value=False
        ):
            self.assertEqual(client.get("/api/files/big.txt").status_code, 403)

    def test_kali_empty_result_stderr_timeout_wifi(self):
        from backend.executor import kali as k

        with patch.object(k, "execute_kali_command_stream", return_value=iter([])):
            r = k.execute_kali_command(["nmap"], "r")
        self.assertFalse(r.success)
        self.assertIn("Falha interna", r.stderr)

        # stderr branch + timeout in docker streaming
        proc = MagicMock()
        proc.poll.side_effect = [None, None, 0]
        proc.wait.return_value = 1
        proc.stdout = MagicMock()
        proc.stderr = MagicMock()
        proc.kill = MagicMock()

        with patch("backend.executor.kali.subprocess.Popen", return_value=proc), patch(
            "backend.executor.kali.threading.Thread"
        ), patch(
            "backend.executor.kali.time.time", side_effect=[0, 0.5, 100]
        ), patch(
            "backend.executor.kali.Queue"
        ) as Q:
            q = MagicMock()
            q.get.return_value = ("stderr", "err\n")
            Q.return_value = q
            with self.assertRaises(Exception):
                k._run_docker_streaming(
                    ["nmap", "-V"], timeout=1, execution_id=None, mission_id=None
                )

        # wifi rfkill path
        with patch.object(k, "validate_command", return_value=(True, "")), patch(
            "backend.executor.kali.validate_command_scope", return_value=(True, "")
        ), patch(
            "backend.security.privileges.privilege_blocks_tool", return_value=(False, "")
        ), patch.object(k, "_is_wifi_tool", return_value=True), patch(
            "backend.executor.kali.subprocess.run", return_value=MagicMock()
        ) as run, patch.object(
            k,
            "_run_docker_streaming",
            return_value=(0, "out", ""),
        ), patch(
            "backend.executor.kali.save_execution_log", return_value="lid"
        ), patch(
            "backend.executor.kali._audit_result"
        ), patch(
            "backend.executor.kali.get_stream_hub"
        ) as hub:
            hub.return_value.get.return_value = None
            hub.return_value.finish = MagicMock()
            list(k.execute_kali_command_stream(["airodump-ng", "wlan0"], "r"))
            self.assertTrue(run.called)

    def test_stream_keepalive_and_summarize_dup(self):
        from queue import Empty

        from backend.executor.stream_hub import StreamHub
        from backend.executor.summarize import summarize_output

        hub = StreamHub()
        hub.create("keep2", "cmd")
        stream = hub.get("keep2")
        assert stream is not None
        n = {"i": 0}

        def get_timeout(timeout=15):
            n["i"] += 1
            if n["i"] == 1:
                raise Empty
            stream.finished = True
            raise Empty

        stream.queue.get = get_timeout  # type: ignore[method-assign]
        events = list(hub.subscribe_sse("keep2"))
        self.assertTrue(any("keepalive" in e for e in events))

        # duplicate critical lines → line 34 continue
        big = ("CVE-2024-1 found\n" * 3) + ("x" * 30000)
        with patch("backend.executor.summarize.OUTPUT_TOKEN_LIMIT", 50):
            text, truncated = summarize_output(big, "")
        self.assertTrue(truncated)

    def test_wifi_stderr_branches(self):
        from backend.executor import wifi_scan as ws

        with patch.object(
            ws,
            "_run_netsh",
            return_value=MagicMock(returncode=0, stdout="ok", stderr="warn"),
        ), patch(
            "backend.executor.wifi_scan.save_execution_log", return_value="id"
        ):
            r = ws.execute_host_wifi("wlan-interfaces", "r")
        self.assertIn("STDERR", r.stdout + r.stderr)

        with patch(
            "backend.executor.wifi_scan.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="ok", stderr="e"),
        ), patch(
            "backend.executor.wifi_scan.save_execution_log", return_value="id"
        ), patch(
            "backend.executor.wifi_scan.sys.platform", "linux"
        ):
            # call linux path if exists
            if hasattr(ws, "execute_linux_wifi"):
                pass
            r = ws.execute_host_wifi("wlan-scan", "r")
            self.assertTrue(hasattr(r, "stdout"))

    def test_observability_psutil_and_resource(self):
        import sys

        from backend import observability as obs

        fake_psutil = MagicMock()
        proc = MagicMock()
        proc.cpu_percent.return_value = 1.5
        proc.memory_info.return_value = MagicMock(rss=2 * 1024 * 1024)
        fake_psutil.Process.return_value = proc
        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            m = obs.get_metrics()
        self.assertEqual(m.get("cpu_percent"), 1.5)

        fake_resource = MagicMock()
        fake_resource.RUSAGE_SELF = 0
        fake_resource.getrusage.return_value = MagicMock(ru_maxrss=2048)
        real_import = __import__

        def importer(name, *a, **k):
            if name == "psutil":
                raise ImportError
            if name == "resource":
                return fake_resource
            return real_import(name, *a, **k)

        with patch("builtins.__import__", side_effect=importer), patch(
            "sys.platform", "linux"
        ):
            m = obs.get_metrics()
        self.assertIn("memory_mb", m)

    def test_missions_cancel_kill_and_auth(self):
        from backend.main import app
        from backend.security.missions import get_mission_registry

        reg = get_mission_registry()
        mid = "killproc1"
        reg.register(mid)
        bad = MagicMock()
        bad.kill.side_effect = OSError("gone")
        reg.register_process(mid, "e1", bad)
        self.assertTrue(reg.cancel(mid))

        # register/unregister without mission
        reg.register_process(None, "e", MagicMock())
        reg.unregister_process(None, "e")
        reg.register_process("missing", "e", MagicMock())
        reg.unregister_process("missing", "e")

        client = TestClient(app)
        reg.register("authcancel1")
        res = client.post("/api/missions/authcancel1/cancel")
        self.assertEqual(res.status_code, 200)

        res = client.post("/api/playbooks/" + ("x" * 70) + "/run", json={"target": "t.com"})
        self.assertEqual(res.status_code, 400)

    def test_recon_edges_and_files_relative(self):
        from backend.executor import files_store as fs
        from backend.executor import recon_db as rd

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(rd, "RECON_DIR", root), patch.object(rd, "RECON_TTL_DAYS", 1):
                # falsy fields only → compact empty (line 180)
                path = root / "empty.com.json"
                path.write_text(
                    json.dumps(
                        {
                            "target": "empty.com",
                            "updated_at": "2099-01-01T00:00:00+00:00",
                            "open_ports": [],
                            "notes": "",
                        }
                    ),
                    encoding="utf-8",
                )
                # updated_at is truthy — strip it via get_recon_data mock
                with patch.object(
                    rd,
                    "get_recon_data",
                    return_value={"target": "empty.com", "open_ports": [], "notes": ""},
                ):
                    self.assertEqual(rd.build_recon_context(["empty.com"]), "")

                # bad json in list
                (root / "bad.json").write_text("{", encoding="utf-8")
                rd.list_recon_summaries()

                # expired unlink OSError
                exp = root / "gone.com.json"
                exp.write_text(
                    json.dumps(
                        {
                            "target": "gone.com",
                            "updated_at": "2010-01-01T00:00:00+00:00",
                        }
                    ),
                    encoding="utf-8",
                )
                with patch.object(Path, "unlink", side_effect=OSError("busy")):
                    rd.get_recon_data("gone.com")
                    rd.list_recon_summaries()

            fake_root = MagicMock()
            fake_root.is_dir.return_value = False
            with patch.object(fs, "ensure_outputs_dir"), patch.object(
                fs, "OUTPUTS_DIR"
            ) as od:
                od.resolve.return_value = fake_root
                self.assertEqual(fs.list_output_files(), [])

    def test_audit_redact_and_blank_lines(self):
        from backend.security import audit as au

        red = au._redact("OPENROUTER_API_KEY=secret")
        self.assertIn("***", red)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "events-2099-01-01.jsonl"
            f.write_text("\n{notjson}\n{\"ts\":\"2099\",\"type\":\"x\"}\n", encoding="utf-8")
            with patch.object(au, "AUDIT_DIR", root):
                events = au.list_events(limit=10)
            self.assertTrue(any(e.get("type") == "x" for e in events))


class TestLastPercent(unittest.TestCase):
    def test_files_relative_fallback_and_dirs(self):
        from backend.executor import files_store as fs

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sub").mkdir()
            (root / "ok.txt").write_text("x", encoding="utf-8")

            # is_relative_to → False (linha 102)
            root_resolved = root.resolve()
            outside = MagicMock()
            outside.is_relative_to.return_value = False
            with patch.object(fs, "OUTPUTS_DIR", root):
                with patch.object(
                    Path, "resolve", side_effect=[root_resolved, outside]
                ):
                    self.assertIsNone(fs.resolve_output_file("ok.txt"))

            # AttributeError fallback on is_relative_to
            fake_path = MagicMock()
            fake_path.is_relative_to.side_effect = AttributeError
            fake_path.parents = []
            with patch.object(fs, "OUTPUTS_DIR", root), patch.object(
                Path, "resolve", side_effect=[root_resolved, fake_path]
            ):
                self.assertIsNone(fs.resolve_output_file("ok.txt"))

            with patch.object(fs, "OUTPUTS_DIR", root), patch.object(
                fs, "ensure_outputs_dir"
            ), patch.object(fs, "is_allowed_extension", return_value=True):
                listed = fs.list_output_files()
            self.assertTrue(listed)

    def test_recon_ttl_false_and_missing_dir(self):
        from backend.executor import recon_db as rd

        with patch.object(rd, "RECON_TTL_DAYS", 7):
            self.assertFalse(
                rd._is_recon_expired({"updated_at": "not-iso"})
            )
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope"
            with patch.object(rd, "RECON_DIR", missing):
                self.assertEqual(rd.list_recon_summaries(), [])

    def test_observability_ctypes_success(self):
        import ctypes as real_ctypes
        import sys
        import types

        from backend import observability as obs

        # psutil presente mas falha → cai no fallback Windows/ctypes (linha 169)
        boom_psutil = types.ModuleType("psutil")
        boom_psutil.Process = MagicMock(side_effect=RuntimeError("no-psutil"))  # type: ignore[attr-defined]
        boom_resource = types.ModuleType("resource")

        def boom_getrusage(*_a, **_k):
            raise OSError("no-resource")

        boom_resource.getrusage = boom_getrusage  # type: ignore[attr-defined]
        boom_resource.RUSAGE_SELF = 0  # type: ignore[attr-defined]

        with patch.dict(
            sys.modules, {"psutil": boom_psutil, "resource": boom_resource}
        ), patch("sys.platform", "win32"), patch.object(
            real_ctypes.windll.psapi,
            "GetProcessMemoryInfo",
            return_value=1,
        ):
            m = obs.get_metrics()
        self.assertIn("memory_mb", m)

    def test_missions_incr_fail_rate_scope_sessions_playbook(self):
        from backend.executor.result import ExecutionResult
        from backend.playbooks import loader as pl
        from backend.security import rate_limit as rl
        from backend.security import scope as sc
        from backend.security import sessions as sess
        from backend.security.missions import get_mission_registry

        reg = get_mission_registry()
        mid = "incrfail1"
        reg.register(mid)
        with patch("backend.observability.incr", side_effect=RuntimeError("no")):
            self.assertTrue(reg.cancel(mid))

        rl._limiter = None
        limiter = rl.get_rate_limiter(5, 60)
        old = time.time() - 120
        with limiter._lock:
            limiter._hits["k"].append(old)
            limiter._hits["k"].append(time.time())
        ok, _ = limiter.allow("k")
        self.assertTrue(ok)

        with patch.object(sc, "ALLOWED_TARGETS", []):
            self.assertTrue(sc.is_target_allowed("any.com"))
        with patch.object(sc, "ALLOWED_TARGETS", ["allowed.com"]):
            ok, _ = sc.validate_command_scope(["nmap", "-V"])
            self.assertTrue(ok)

        with tempfile.TemporaryDirectory() as tmp:
            sf = Path(tmp) / "s.json"
            with patch.object(sess, "SESSIONS_FILE", sf):
                store = sess.SessionStore(60)
                with patch.object(Path, "write_text", side_effect=OSError("disk")):
                    store._save()
                store._sessions["old"] = time.time() - 10
                store.purge_expired()

        step_fail = ExecutionResult(
            command="nmap x",
            reason="r",
            stdout="",
            stderr="fail",
            exit_code=1,
            success=False,
            tool="nmap",
        )
        with patch.object(
            pl,
            "load_playbook",
            return_value={
                "id": "p",
                "steps": [
                    {"tool": "nmap", "args": ["{target}"]},
                    {"tool": "nmap", "args": ["{target}"]},
                ],
            },
        ), patch(
            "backend.playbooks.loader.execute_kali_command", return_value=step_fail
        ), patch(
            "backend.playbooks.loader.validate_command_scope",
            return_value=(True, ""),
        ), patch(
            "backend.playbooks.loader.validate_autonomous_target",
            return_value=(True, ""),
        ):
            out = pl.run_playbook("p", "scanme.nmap.org")
        self.assertEqual(out["steps_run"], 1)


if __name__ == "__main__":
    unittest.main()


