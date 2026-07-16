"""Testes de integração (FastAPI TestClient)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.auth_patch import patch_chat_api_token


class TestApiIntegration(unittest.TestCase):
    def setUp(self):
        from backend.main import app

        self.client = TestClient(app)

    def test_health(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("version", data)
        self.assertEqual(data["status"], "ok")

    def test_client_config(self):
        res = self.client.get("/api/client-config")
        self.assertEqual(res.status_code, 200)
        self.assertIn("authRequired", res.json())

    def test_models_catalog(self):
        res = self.client.get("/api/models")
        self.assertEqual(res.status_code, 200)
        self.assertIn("tiers", res.json())

    def test_api_token_required(self):
        from backend.main import app

        with patch_chat_api_token("secret-test-token"):
            client = TestClient(app)

            res = client.get("/api/tools")
            self.assertEqual(res.status_code, 401)

            res = client.get("/api/tools", headers={"X-Chat-Token": "secret-test-token"})
            self.assertEqual(res.status_code, 200)

            res = client.get("/api/health")
            self.assertEqual(res.status_code, 200)


class TestReconTtl(unittest.TestCase):
    def test_expired_recon_removed(self):
        import backend.config as cfg
        import backend.executor.recon_db as recon_db

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(cfg, "RECON_DIR", Path(tmp)),
                patch.object(recon_db, "RECON_DIR", Path(tmp)),
                patch.object(recon_db, "RECON_TTL_DAYS", 1),
            ):
                recon_db.save_recon_data("scanme.nmap.org", "open_ports", ["80/tcp open http"])
                path = Path(tmp) / "scanme.nmap.org.json"
                self.assertTrue(path.is_file())

                old = (Path(tmp) / "scanme.nmap.org.json").read_text(encoding="utf-8")
                data = json.loads(old)
                data["updated_at"] = "2020-01-01T00:00:00+00:00"
                path.write_text(json.dumps(data), encoding="utf-8")

                loaded = recon_db.get_recon_data("scanme.nmap.org")
                self.assertEqual(loaded, {})
                self.assertFalse(path.is_file())

    def test_recon_api_list_and_detail(self):
        import backend.config as cfg
        import backend.executor.recon_db as recon_db

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(cfg, "RECON_DIR", Path(tmp)),
                patch.object(recon_db, "RECON_DIR", Path(tmp)),
            ):
                recon_db.save_recon_data(
                    "lab.test",
                    "open_ports",
                    ["443/tcp open https"],
                )
                from backend.main import app

                client = TestClient(app)
                res = client.get("/api/recon")
                self.assertEqual(res.status_code, 200)
                targets = res.json()["targets"]
                self.assertEqual(len(targets), 1)
                self.assertEqual(targets[0]["target"], "lab.test")

                res = client.get("/api/recon/lab.test")
                self.assertEqual(res.status_code, 200)
                self.assertIn("open_ports", res.json())

                res = client.get("/api/recon/unknown.target")
                self.assertEqual(res.status_code, 404)


class TestFilesApi(unittest.TestCase):
    def test_files_api_list_and_download(self):
        import backend.config as cfg
        import backend.executor.files_store as files_store

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scan.xml").write_text("<nmaprun></nmaprun>", encoding="utf-8")
            (root / "capture.pcap").write_bytes(b"pcap")
            with (
                patch.object(cfg, "OUTPUTS_DIR", root),
                patch.object(files_store, "OUTPUTS_DIR", root),
            ):
                from backend.main import app

                client = TestClient(app)
                res = client.get("/api/files")
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertEqual(data["root"], "/tools/output")
                names = {f["name"] for f in data["files"]}
                self.assertIn("scan.xml", names)
                self.assertIn("capture.pcap", names)

                res = client.get("/api/files/scan.xml")
                self.assertEqual(res.status_code, 200)
                self.assertIn(b"nmaprun", res.content)

                res = client.get("/api/files/../scan.xml")
                self.assertIn(res.status_code, (400, 404))

                res = client.get("/api/files/missing.txt")
                self.assertEqual(res.status_code, 404)


class TestStreamHub(unittest.TestCase):
    def test_push_and_subscribe(self):
        from backend.executor.stream_hub import get_stream_hub

        hub = get_stream_hub()
        hub.create("testexec99", "nmap -V")
        hub.push_line("testexec99", "stdout", "line1")
        hub.finish("testexec99", exit_code=0, success=True)

        events = list(hub.subscribe_sse("testexec99"))
        joined = "".join(events)
        self.assertIn("line1", joined)
        self.assertIn("done", joined)


if __name__ == "__main__":
    unittest.main()
