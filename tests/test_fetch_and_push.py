import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github" / "scripts"))

from fetch_and_push import build_metrics_rows, upload_to_sharepoint, write_csv_output


class FetchAndPushTests(unittest.TestCase):
    def test_build_metrics_rows_includes_expected_keys(self):
        metrics = {
            "repository": "octo/sample",
            "fetched_at": "2026-07-26T00:00:00Z",
            "code_scanning_open": 4,
            "code_scanning_critical": 1,
            "code_scanning_high": 2,
            "dependabot_open": 3,
            "secret_scanning_open": 1,
            "status": "ok",
        }

        rows = build_metrics_rows(metrics)

        self.assertEqual(rows[0]["repository"], "octo/sample")
        self.assertEqual(rows[0]["code_scanning_open"], 4)
        self.assertEqual(rows[0]["dependabot_open"], 3)
        self.assertEqual(rows[0]["secret_scanning_open"], 1)

    def test_write_csv_output_creates_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "metrics.csv"
            metrics = {
                "repository": "octo/sample",
                "fetched_at": "2026-07-26T00:00:00Z",
                "code_scanning_open": 1,
                "code_scanning_critical": 0,
                "code_scanning_high": 1,
                "dependabot_open": 0,
                "secret_scanning_open": 0,
                "status": "ok",
            }

            write_csv_output(metrics, output_path)

            self.assertTrue(output_path.exists())
            with output_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(rows[0]["repository"], "octo/sample")

    def test_upload_to_sharepoint_mock_mode_writes_local_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = Path(temp_dir) / "sample.csv"
            source_path.write_text("repository,code_scanning_open\nocto/sample,1\n", encoding="utf-8")
            mock_dir = Path(temp_dir) / "mock-sharepoint"

            upload_to_sharepoint("fake-token", str(source_path), mock_mode=True, output_dir=mock_dir)

            self.assertTrue((mock_dir / source_path.name).exists())
            self.assertEqual((mock_dir / source_path.name).read_text(encoding="utf-8"), "repository,code_scanning_open\nocto/sample,1\n")


if __name__ == "__main__":
    unittest.main()
