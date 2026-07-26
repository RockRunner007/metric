import csv
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github" / "scripts"))

from fetch_and_push import build_metrics_rows, get_ghas_metrics, get_repositories, upload_to_sharepoint, write_csv_output, write_pages_artifacts


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

    def test_write_pages_artifacts_creates_data_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "site"
            metrics = {
                "repository": "octo/sample",
                "rows": [{
                    "repository": "octo/sample",
                    "fetched_at": "2026-07-26T00:00:00Z",
                    "code_scanning_open": 1,
                    "code_scanning_critical": 0,
                    "code_scanning_high": 1,
                    "dependabot_open": 0,
                    "secret_scanning_open": 0,
                    "status": "ok",
                }],
            }

            target_dir = write_pages_artifacts(metrics, output_dir)

            self.assertTrue((target_dir / "ghas_metrics.json").exists())
            self.assertTrue((target_dir / "ghas_metrics.csv").exists())

    def test_get_repositories_prefers_authenticated_user_endpoint(self):
        with patch("fetch_and_push.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = [{"full_name": "octo/one"}, {"full_name": "octo/two"}]
            mock_get.return_value = mock_response

            repos = get_repositories("token", "octo")

            self.assertEqual(repos[0]["full_name"], "octo/one")
            self.assertEqual(repos[1]["full_name"], "octo/two")
            self.assertIn("/user/repos", mock_get.call_args_list[0][0][0])

    def test_get_ghas_metrics_uses_github_token_when_pat_missing(self):
        with patch("fetch_and_push.GH_TOKEN", ""), patch("fetch_and_push.ORG_NAME", ""), patch.dict("os.environ", {"GITHUB_TOKEN": "token-from-workflow", "GITHUB_REPOSITORY": "octo/demo"}, clear=False), patch("fetch_and_push.get_repositories", return_value=[{"full_name": "octo/demo", "archived": False}]) as mock_repos, patch("fetch_and_push.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = []
            mock_get.return_value = mock_response

            metrics = get_ghas_metrics()

            self.assertEqual(metrics["rows"][0]["repository"], "octo/demo")
            mock_repos.assert_called_once()


if __name__ == "__main__":
    unittest.main()
