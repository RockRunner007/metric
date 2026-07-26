import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests

GH_TOKEN = os.getenv("GH_PAT")
ORG_NAME = os.getenv("GH_ORG_NAME") or os.getenv("GITHUB_REPOSITORY_OWNER") or ""
TENANT_ID = os.getenv("SP_TENANT_ID", "")
CLIENT_ID = os.getenv("SP_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("SP_CLIENT_SECRET", "")
SP_SITE_URL = os.getenv("SP_SITE_URL", "")
TARGET_FOLDER = os.getenv("SP_TARGET_FOLDER", "/Shared Documents/SecurityReports")
OUTPUT_JSON = os.getenv("OUTPUT_JSON", "ghas_metrics.json")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "ghas_metrics.csv")


def get_repositories(token: str, owner: str) -> list[dict[str, Any]]:
    """Return all repositories visible to the authenticated user, including personal and org-owned repos."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    repos_urls = [
        "https://api.github.com/user/repos?per_page=100",
        f"https://api.github.com/orgs/{owner}/repos?per_page=100",
        f"https://api.github.com/users/{owner}/repos?per_page=100",
    ]

    repos: list[dict[str, Any]] = []
    for repos_url in repos_urls:
        repos_response = requests.get(repos_url, headers=headers, timeout=30)
        if repos_response.status_code == 200:
            repos = repos_response.json()
            if repos:
                break
        elif repos_response.status_code == 404:
            continue
        else:
            repos_response.raise_for_status()

    if not repos:
        raise ValueError(f"Unable to list repositories for {owner}")

    return repos


def get_ghas_metrics() -> dict[str, Any]:
    """Fetches GHAS metrics for all repositories visible to the authenticated account."""
    if not GH_TOKEN or not ORG_NAME:
        raise ValueError("GH_PAT and GH_ORG_NAME must be configured")

    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    repos = get_repositories(GH_TOKEN, ORG_NAME)

    rows: list[dict[str, Any]] = []
    for repo in repos:
        if not repo.get("archived"):
            repo_name = repo.get("full_name", "")
            repo_metrics = {
                "repository": repo_name,
                "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "code_scanning_open": 0,
                "code_scanning_critical": 0,
                "code_scanning_high": 0,
                "dependabot_open": 0,
                "secret_scanning_open": 0,
                "status": "ok",
                "scan_status": "unknown",
                "scan_state": None,
                "default_setup_state": None,
            }

            try:
                default_setup_url = f"https://api.github.com/repos/{repo_name}/code-scanning/default-setup"
                default_setup_response = requests.get(default_setup_url, headers=headers, timeout=30)
                default_setup_response.raise_for_status()
                default_setup = default_setup_response.json()
                repo_metrics["default_setup_state"] = default_setup.get("state")
                repo_metrics["scan_state"] = default_setup.get("state")
                if default_setup.get("state") == "configured":
                    repo_metrics["scan_status"] = "configured"
                else:
                    repo_metrics["scan_status"] = "pending"
            except requests.HTTPError as exc:
                repo_metrics["scan_status"] = "error"
                repo_metrics["status"] = f"code_scanning_error:{exc.response.status_code}"

            try:
                code_scanning_url = f"https://api.github.com/repos/{repo_name}/code-scanning/alerts?state=open&per_page=100"
                cs_response = requests.get(code_scanning_url, headers=headers, timeout=30)
                cs_response.raise_for_status()
                alerts = cs_response.json()
                repo_metrics["code_scanning_open"] = len(alerts)
                repo_metrics["code_scanning_critical"] = sum(
                    1 for item in alerts if item.get("rule", {}).get("security_severity_level") == "critical"
                )
                repo_metrics["code_scanning_high"] = sum(
                    1 for item in alerts if item.get("rule", {}).get("security_severity_level") == "high"
                )
                if repo_metrics["code_scanning_open"]:
                    repo_metrics["scan_status"] = "findings"
            except requests.HTTPError as exc:
                repo_metrics["status"] = f"code_scanning_error:{exc.response.status_code}"

            try:
                dependabot_url = f"https://api.github.com/repos/{repo_name}/dependabot/alerts?state=open&per_page=100"
                dep_response = requests.get(dependabot_url, headers=headers, timeout=30)
                dep_response.raise_for_status()
                dependabot_alerts = dep_response.json()
                repo_metrics["dependabot_open"] = len(dependabot_alerts)
            except requests.HTTPError as exc:
                repo_metrics["status"] = f"dependabot_error:{exc.response.status_code}"

            try:
                secret_scanning_url = f"https://api.github.com/repos/{repo_name}/secret-scanning/alerts?state=open&per_page=100"
                ss_response = requests.get(secret_scanning_url, headers=headers, timeout=30)
                ss_response.raise_for_status()
                secret_alerts = ss_response.json()
                repo_metrics["secret_scanning_open"] = len(secret_alerts)
            except requests.HTTPError as exc:
                repo_metrics["status"] = f"secret_scanning_error:{exc.response.status_code}"

            rows.append(repo_metrics)

    severity_rows = sorted(
        rows,
        key=lambda item: (
            item["code_scanning_open"] + item["dependabot_open"] + item["secret_scanning_open"]
        ),
        reverse=True,
    )

    summary = {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organization": ORG_NAME,
        "repositories_scanned": len(rows),
        "repositories_with_findings": sum(1 for item in rows if any([item["code_scanning_open"], item["dependabot_open"], item["secret_scanning_open"]])),
        "repositories_configured": sum(1 for item in rows if item.get("scan_status") == "configured"),
        "repositories_pending": sum(1 for item in rows if item.get("scan_status") == "pending"),
        "repositories_with_alerts": sum(1 for item in rows if item.get("scan_status") == "findings"),
        "total_code_scanning_open": sum(item["code_scanning_open"] for item in rows),
        "total_code_scanning_critical": sum(item["code_scanning_critical"] for item in rows),
        "total_code_scanning_high": sum(item["code_scanning_high"] for item in rows),
        "total_dependabot_open": sum(item["dependabot_open"] for item in rows),
        "total_secret_scanning_open": sum(item["secret_scanning_open"] for item in rows),
        "total_findings": sum(
            item["code_scanning_open"] + item["dependabot_open"] + item["secret_scanning_open"] for item in rows
        ),
        "top_repositories": severity_rows[:10],
        "rows": rows,
    }
    return summary


def build_metrics_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    rows = metrics.get("rows")
    if rows:
        return rows

    if "repository" in metrics:
        return [metrics]

    return []


def write_csv_output(metrics: dict[str, Any], output_path: Optional[Path] = None) -> Path:
    rows = build_metrics_rows(metrics)
    target_path = output_path or Path(OUTPUT_CSV)
    with target_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "repository",
                "fetched_at",
                "code_scanning_open",
                "code_scanning_critical",
                "code_scanning_high",
                "dependabot_open",
                "secret_scanning_open",
                "status",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    return target_path


def write_json_output(metrics: dict[str, Any], output_path: Optional[Path] = None) -> Path:
    target_path = output_path or Path(OUTPUT_JSON)
    with target_path.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    return target_path


def write_pages_artifacts(metrics: dict[str, Any], output_dir: Optional[Path] = None) -> Path:
    target_dir = output_dir or Path("docs") / "data"
    target_dir.mkdir(parents=True, exist_ok=True)

    write_json_output(metrics, target_dir / "ghas_metrics.json")
    write_csv_output(metrics, target_dir / "ghas_metrics.csv")
    return target_dir


def get_sharepoint_token() -> Optional[str]:
    """Authenticates against Microsoft Graph to get an access token."""
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        return None

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
    }
    response = requests.post(url, data=data, timeout=30)
    response.raise_for_status()
    return response.json().get("access_token")


def upload_to_sharepoint(token: str, file_path: str, mock_mode: bool = False, output_dir: Optional[Path] = None) -> None:
    """Uploads the compiled metrics file to the target SharePoint directory via Graph API.

    When mock_mode is enabled, the file is written to a local directory instead of trying
    to contact SharePoint. This makes the workflow testable without a paid SharePoint site.
    """
    file_name = os.path.basename(file_path)

    if mock_mode:
        target_dir = output_dir or Path("mock-sharepoint")
        target_dir.mkdir(parents=True, exist_ok=True)
        destination = target_dir / file_name
        with open(file_path, "rb") as src, destination.open("wb") as dst:
            dst.write(src.read())
        print(f"Mock upload complete: wrote {file_name} to {destination}")
        return

    if not SP_SITE_URL:
        raise ValueError("SP_SITE_URL is not configured")

    site_path = SP_SITE_URL.rstrip("/")
    url = f"{site_path}/drive/root:{TARGET_FOLDER}/{file_name}:/content"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }

    with open(file_path, "rb") as handle:
        response = requests.put(url, headers=headers, data=handle, timeout=60)

    response.raise_for_status()
    print(f"Successfully uploaded {file_name} to SharePoint.")


if __name__ == "__main__":
    try:
        metrics = get_ghas_metrics()
    except Exception as exc:  # noqa: BLE001
        metrics = {
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "organization": ORG_NAME,
            "error": str(exc),
            "rows": [
                {
                    "repository": ORG_NAME or "unknown",
                    "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "code_scanning_open": 0,
                    "code_scanning_critical": 0,
                    "code_scanning_high": 0,
                    "dependabot_open": 0,
                    "secret_scanning_open": 0,
                    "status": f"error:{exc}",
                }
            ],
        }
        print(f"GitHub metrics collection failed: {exc}")

    write_json_output(metrics)
    csv_path = write_csv_output(metrics)
    pages_dir = write_pages_artifacts(metrics)
    print(f"Wrote JSON metrics to {OUTPUT_JSON}, CSV metrics to {csv_path}, and Pages data to {pages_dir}")

    if not os.getenv("SP_SKIP_UPLOAD"):
        try:
            token = get_sharepoint_token()
            if token:
                upload_to_sharepoint(token, str(csv_path))
            else:
                if os.getenv("SP_MOCK_MODE", "true").lower() == "true":
                    upload_to_sharepoint("mock-token", str(csv_path), mock_mode=True)
                else:
                    print("SharePoint credentials not configured; leaving CSV artifact for download.")
        except Exception as exc:  # noqa: BLE001
            print(f"SharePoint upload failed: {exc}. CSV artifact preserved.")
