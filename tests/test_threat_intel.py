"""Testes de backend/ai/threat_intel.py — CISA KEV + FIRST EPSS."""

from __future__ import annotations

import unittest
from unittest import mock

import backend.ai.threat_intel as ti
from backend.ai.risk_score import compute_risk_score


def _reset_caches() -> None:
    ti._kev_cache["data"] = None
    ti._kev_cache["fetched_at"] = 0.0
    ti._epss_cache.clear()


class TestNormalizeCve(unittest.TestCase):
    def test_valid_cve(self):
        self.assertEqual(ti.normalize_cve("cve-2021-44228"), "CVE-2021-44228")

    def test_invalid_cve(self):
        self.assertEqual(ti.normalize_cve("not-a-cve"), "")
        self.assertEqual(ti.normalize_cve(""), "")


class TestCisaKevCatalog(unittest.TestCase):
    def setUp(self):
        _reset_caches()

    def _sample_payload(self):
        return {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j2",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "not-a-cve"},
            ]
        }

    def test_fetch_and_cache(self):
        with mock.patch.object(ti, "_http_get_json", return_value=self._sample_payload()) as m:
            catalog = ti.fetch_cisa_kev_catalog()
            self.assertIn("CVE-2021-44228", catalog)
            self.assertEqual(catalog["CVE-2021-44228"]["vendor_project"], "Apache")
            self.assertTrue(catalog["CVE-2021-44228"]["ransomware_use"])
            # segunda chamada usa o cache — não bate na rede de novo
            ti.fetch_cisa_kev_catalog()
            self.assertEqual(m.call_count, 1)

    def test_network_failure_returns_previous_cache(self):
        with mock.patch.object(ti, "_http_get_json", return_value=self._sample_payload()):
            ti.fetch_cisa_kev_catalog()
        with mock.patch.object(ti, "_http_get_json", side_effect=OSError("boom")):
            catalog = ti.fetch_cisa_kev_catalog(force_refresh=True)
            self.assertIn("CVE-2021-44228", catalog)

    def test_network_failure_first_call_returns_empty(self):
        with mock.patch.object(ti, "_http_get_json", side_effect=OSError("boom")):
            catalog = ti.fetch_cisa_kev_catalog()
            self.assertEqual(catalog, {})

    def test_is_in_kev(self):
        with mock.patch.object(ti, "_http_get_json", return_value=self._sample_payload()):
            self.assertIsNotNone(ti.is_in_kev("CVE-2021-44228"))
            self.assertIsNone(ti.is_in_kev("CVE-9999-99999"))
            self.assertIsNone(ti.is_in_kev("garbage"))


class TestEpssScore(unittest.TestCase):
    def setUp(self):
        _reset_caches()

    def test_fetch_epss_score(self):
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.973", "percentile": "0.998"}]}
        with mock.patch.object(ti, "_http_get_json", return_value=payload) as m:
            score = ti.fetch_epss_score("CVE-2021-44228")
            self.assertAlmostEqual(score["score"], 0.973)
            self.assertAlmostEqual(score["percentile"], 0.998)
            ti.fetch_epss_score("CVE-2021-44228")
            self.assertEqual(m.call_count, 1)

    def test_fetch_epss_no_data(self):
        with mock.patch.object(ti, "_http_get_json", return_value={"data": []}):
            score = ti.fetch_epss_score("CVE-2021-44228")
            self.assertEqual(score, {"score": 0.0, "percentile": 0.0})

    def test_fetch_epss_invalid_cve(self):
        self.assertIsNone(ti.fetch_epss_score("not-a-cve"))

    def test_fetch_epss_network_failure(self):
        with mock.patch.object(ti, "_http_get_json", side_effect=OSError("boom")):
            self.assertIsNone(ti.fetch_epss_score("CVE-2021-44228"))


class TestLookupCveIntel(unittest.TestCase):
    def setUp(self):
        _reset_caches()

    def test_lookup_combines_kev_and_epss(self):
        kev_payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "dateAdded": "2021-12-10",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }
        epss_payload = {"data": [{"epss": "0.9", "percentile": "0.99"}]}

        def _fake_get(url: str):
            return kev_payload if "cisa.gov" in url else epss_payload

        with mock.patch.object(ti, "_http_get_json", side_effect=_fake_get):
            intel = ti.lookup_cve_intel("cve-2021-44228")
        self.assertEqual(intel["cve"], "CVE-2021-44228")
        self.assertTrue(intel["cisa_kev_flag"])
        self.assertTrue(intel["kev_ransomware_use"])
        self.assertAlmostEqual(intel["epss_score"], 0.9)

    def test_lookup_invalid_cve_returns_empty(self):
        self.assertEqual(ti.lookup_cve_intel(""), {})


class TestEnrichFinding(unittest.TestCase):
    def setUp(self):
        _reset_caches()

    def test_enrich_elevates_severity_when_kev(self):
        kev_payload = {
            "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]
        }
        epss_payload = {"data": [{"epss": "0.9", "percentile": "0.99"}]}

        def _fake_get(url: str):
            return kev_payload if "cisa.gov" in url else epss_payload

        finding = {"cve": "CVE-2021-44228", "severity": "low"}
        with mock.patch.object(ti, "_http_get_json", side_effect=_fake_get):
            ti.enrich_finding_with_threat_intel(finding)
        self.assertEqual(finding["severity"], "high")
        self.assertTrue(finding["cisa_kev_flag"])
        self.assertIn("threat_intel_note", finding)

    def test_enrich_noop_without_cve(self):
        finding = {"severity": "low"}
        ti.enrich_finding_with_threat_intel(finding)
        self.assertNotIn("cisa_kev_flag", finding)

    def test_enrich_disabled_via_config(self):
        finding = {"cve": "CVE-2021-44228", "severity": "low"}
        with mock.patch.object(ti, "THREAT_INTEL_ENABLED", False):
            ti.enrich_finding_with_threat_intel(finding)
        self.assertNotIn("cisa_kev_flag", finding)

    def test_enrich_does_not_downgrade_critical(self):
        kev_payload = {
            "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]
        }
        with mock.patch.object(
            ti, "_http_get_json", side_effect=lambda u: kev_payload if "cisa.gov" in u else {"data": []}
        ):
            finding = {"cve": "CVE-2021-44228", "severity": "critical"}
            ti.enrich_finding_with_threat_intel(finding)
        self.assertEqual(finding["severity"], "critical")


class TestEnrichSurface(unittest.TestCase):
    def setUp(self):
        _reset_caches()

    def test_enrich_surface_with_threat_intel(self):
        surface_data = {
            "target": "example.com",
            "findings": [
                {"id": "1", "cve": "CVE-2021-44228", "severity": "low"},
                {"id": "2", "cve": "", "severity": "info"},
            ],
        }
        kev_payload = {
            "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]
        }
        with mock.patch(
            "backend.executor.surface.load_surface", return_value=surface_data
        ), mock.patch("backend.executor.surface.save_surface") as save_mock, mock.patch.object(
            ti, "_http_get_json", side_effect=lambda u: kev_payload if "cisa.gov" in u else {"data": []}
        ):
            processed = ti.enrich_surface_with_threat_intel("example.com")
        self.assertEqual(processed, 1)
        save_mock.assert_called_once()
        self.assertEqual(surface_data["findings"][0]["severity"], "high")

    def test_enrich_surface_missing_target_returns_zero(self):
        with mock.patch("backend.executor.surface.load_surface", return_value={}):
            self.assertEqual(ti.enrich_surface_with_threat_intel("nope.example"), 0)


class TestRiskScoreKevBoost(unittest.TestCase):
    def test_kev_flag_boosts_score_over_base(self):
        base = compute_risk_score([{"severity": "medium", "cvss_score": 5.0}])
        boosted = compute_risk_score(
            [{"severity": "medium", "cvss_score": 5.0, "cisa_kev_flag": True}]
        )
        self.assertGreater(boosted["score"], base["score"])

    def test_high_epss_boosts_score_over_base(self):
        base = compute_risk_score([{"severity": "medium", "cvss_score": 5.0}])
        boosted = compute_risk_score(
            [{"severity": "medium", "cvss_score": 5.0, "epss_score": 0.9}]
        )
        self.assertGreater(boosted["score"], base["score"])


if __name__ == "__main__":
    unittest.main()
