import csv
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import requests

GH_TOKEN = os.getenv("GH_PAT") or os.getenv("GITHUB_TOKEN") or ""
ORG_NAME = os.getenv("GH_ORG_NAME") or os.getenv("GITHUB_REPOSITORY_OWNER") or ""
TENANT_ID = os.getenv("SP_TENANT_ID", "")
CLIENT_ID = os.getenv("SP_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("SP_CLIENT_SECRET", "")
SP_SITE_URL = os.getenv("SP_SITE_URL", "")
TARGET_FOLDER = os.getenv("SP_TARGET_FOLDER", "/Shared Documents/SecurityReports")
OUTPUT_JSON = os.getenv("OUTPUT_JSON", "ghas_metrics.json")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "ghas_metrics.csv")
REPO_ALLOWLIST_FILE = os.getenv("REPO_ALLOWLIST_FILE", ".github/config/repo_allowlist.json")
COLUMN_MANIFEST_FILE = os.getenv("COLUMN_MANIFEST_FILE", ".github/config/column_manifest.json")
TICKET_CSV = os.getenv("TICKET_CSV", "tickets.csv")
DEFAULT_CSV_COLUMNS = [
    "repository",
    "fetched_at",
    "code_scanning_open",
    "code_scanning_critical",
    "code_scanning_high",
    "code_scanning_medium",
    "dependabot_open",
    "secret_scanning_open",
    "status",
    "scan_status",
    "scan_state",
    "default_setup_state",
]


def get_runtime_config() -> tuple[str, str]:
    token = os.getenv("GH_PAT") or os.getenv("GITHUB_TOKEN") or GH_TOKEN or ""
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                check=True,
                capture_output=True,
                text=True,
            )
            token = result.stdout.strip()
        except Exception:
            token = ""

    owner = (
        os.getenv("GH_ORG_NAME")
        or os.getenv("GITHUB_REPOSITORY_OWNER")
        or ORG_NAME
        or ""
    )
    if not owner:
        repository = os.getenv("GITHUB_REPOSITORY", "")
        if "/" in repository:
            owner = repository.split("/", 1)[0]
        else:
            try:
                result = subprocess.run(
                    ["gh", "api", "user"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                user_payload = json.loads(result.stdout or "{}")
                owner = user_payload.get("login") or ""
            except Exception:
                owner = ""
    return token, owner


def load_repo_allowlist(path: Optional[Union[Path, str]] = None) -> list[str]:
    """Load a repository allowlist from a JSON file if one is present."""
    allowlist_path = Path(path or REPO_ALLOWLIST_FILE)
    if not allowlist_path.exists():
        return []

    with allowlist_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, list):
        return [str(item) for item in payload if str(item)]
    if isinstance(payload, dict):
        for key in ("repositories", "repos", "scan_repositories"):
            value = payload.get(key)
            if isinstance(value, list):
                return [str(item) for item in value if str(item)]
    return []


def filter_repositories_by_allowlist(repositories: list[dict[str, Any]], allowlist: list[str]) -> list[dict[str, Any]]:
    """Restrict the repo set to the configured allowlist when one is provided."""
    if not allowlist:
        return repositories

    allowlist_set = {item.lower() for item in allowlist if item}
    return [repo for repo in repositories if str(repo.get("full_name", "")).lower() in allowlist_set]


def _retryable_request(func):
    """Decorator to add retry logic to requests."""
    def wrapper(*args, **kwargs):
        for i in range(3):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.RequestException as e:
                if i < 2:
                    print(f"Request failed: {e}. Retrying in 5s...")
                    time.sleep(5)
                else:
                    raise
    return wrapper

@_retryable_request
def _fetch_paginated_data(url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    """Fetch all pages of data from a paginated GitHub API endpoint."""
    results = []
    next_url: Optional[str] = url
    while next_url:
        response = requests.get(next_url, headers=headers, timeout=30)
        response.raise_for_status()
        results.extend(response.json())

        # Get next page URL from 'Link' header
        next_url = None
        if 'link' in response.headers:
            links = requests.utils.parse_header_links(response.headers['link'])
            next_url = next((link['url'] for link in links if link.get('rel') == 'next'), None)
    return results

def get_repositories(token: str, owner: str) -> list[dict[str, Any]]:
    """Return repositories visible to the authenticated user without relying on the /user/repos endpoint."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    repos_urls = [
        f"https://api.github.com/users/{owner}/repos?per_page=100",
        f"https://api.github.com/orgs/{owner}/repos?per_page=100",
    ]

    all_repos: list[dict[str, Any]] = []
    seen_repos = set()

    for url in repos_urls:
        try:
            fetched_repos = _fetch_paginated_data(url, headers)
            for repo in fetched_repos:
                if repo.get("full_name") not in seen_repos:
                    all_repos.append(repo)
                    seen_repos.add(repo.get("full_name"))
        except requests.HTTPError as exc:
            # A 404 is expected if the owner is a user and we query the org endpoint, or vice-versa.
            if exc.response.status_code != 404:
                raise

    if not all_repos:
        print(f"Warning: Unable to list any repositories for {owner}. The account may have no repositories or the token may lack permissions.")

    return all_repos


def _get_metrics_for_repo(repo: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    """Gathers all GHAS metrics for a single repository."""
    repo_name = repo.get("full_name", "")
    if not repo_name:
        return None

    print(f"Processing repository: {repo_name}")
    repo_metrics = {
        "repository": repo_name,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "code_scanning_open": 0,
        "code_scanning_critical": 0,
        "code_scanning_high": 0,
        "code_scanning_medium": 0,
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
        if default_setup_response.status_code == 404:
            repo_metrics["scan_state"] = "not_supported"
            repo_metrics["default_setup_state"] = "not_supported"
            repo_metrics["scan_status"] = "not_supported"
        else:
            default_setup_response.raise_for_status()
            default_setup = default_setup_response.json()
            default_setup_state = default_setup.get("state")
            repo_metrics["default_setup_state"] = default_setup_state
            repo_metrics["scan_state"] = default_setup_state
            if default_setup_state == "configured":
                repo_metrics["scan_status"] = "configured"
            else:
                repo_metrics["scan_status"] = "pending"
    except requests.HTTPError as exc:
        # This is a critical failure for this repo, so we set the status and return.
        if exc.response.status_code != 404:
            repo_metrics["scan_status"] = "error"
            repo_metrics["status"] = f"code_scanning_error:{exc.response.status_code}"
 
    try:
        code_scanning_url = f"https://api.github.com/repos/{repo_name}/code-scanning/alerts?state=open&per_page=100"
        alerts = _fetch_paginated_data(code_scanning_url, headers)
        repo_metrics["code_scanning_open"] = len(alerts)
        repo_metrics["code_scanning_critical"] = sum(
            1 for item in alerts if item.get("rule", {}).get("security_severity_level") == "critical"
        )
        repo_metrics["code_scanning_high"] = sum(
            1 for item in alerts if item.get("rule", {}).get("security_severity_level") == "high"
        )
        repo_metrics["code_scanning_medium"] = sum(
            1 for item in alerts if item.get("rule", {}).get("security_severity_level") == "medium"
        )
        if repo_metrics["code_scanning_open"]:
            repo_metrics["scan_status"] = "findings"
    except requests.HTTPError as exc:
        if exc.response.status_code not in {403, 404}:
            repo_metrics["status"] = f"code_scanning_error:{exc.response.status_code}"
        else:
            repo_metrics["code_scanning_open"] = 0
            repo_metrics["code_scanning_critical"] = 0
            repo_metrics["code_scanning_high"] = 0
            repo_metrics["code_scanning_medium"] = 0

    try:
        dependabot_url = f"https://api.github.com/repos/{repo_name}/dependabot/alerts?state=open&per_page=100"
        dependabot_alerts = _fetch_paginated_data(dependabot_url, headers)
        repo_metrics["dependabot_open"] = len(dependabot_alerts)
    except requests.HTTPError as exc:
        if exc.response.status_code not in {403, 404}:
            repo_metrics["status"] = f"dependabot_error:{exc.response.status_code}"
        else:
            repo_metrics["dependabot_open"] = 0

    try:
        secret_scanning_url = f"https://api.github.com/repos/{repo_name}/secret-scanning/alerts?state=open&per_page=100"
        secret_alerts = _fetch_paginated_data(secret_scanning_url, headers)
        repo_metrics["secret_scanning_open"] = len(secret_alerts)
    except requests.HTTPError as exc:
        if exc.response.status_code not in {403, 404}:
            repo_metrics["status"] = f"secret_scanning_error:{exc.response.status_code}"
        else:
            repo_metrics["secret_scanning_open"] = 0

    return repo_metrics


def get_ghas_metrics() -> dict[str, Any]:
    """Fetches GHAS metrics for all repositories visible to the authenticated account."""
    token, owner = get_runtime_config()
    if not token or not owner:
        raise ValueError("GH_PAT or GITHUB_TOKEN and a repository owner must be configured")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    repos = get_repositories(token, owner)
    allowlist = load_repo_allowlist()
    # If the allowlist is not empty, filter. Otherwise, use all discovered repos.
    if allowlist:
        repos = filter_repositories_by_allowlist(repos, allowlist)

    # Process repositories in parallel for performance
    rows: list[dict[str, Any]] = []
    valid_rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create a future for each repository to be processed
        futures = {executor.submit(_get_metrics_for_repo, repo, headers) for repo in repos if not repo.get("archived")}
        for future in as_completed(futures):
            try:
                result = future.result()
                # The result can be None if the repo data was invalid
                rows.append(result)
            except Exception as exc:
                print(f"Error processing a repository: {exc}")

    # Filter out any None results from failed repo processing before doing any calculations.
    valid_rows = [row for row in rows if row is not None]
    
    # Calculate summary metrics after all rows are collected
    repositories_scanned = len(valid_rows)
    repositories_with_findings = sum(1 for item in valid_rows if any([item.get("code_scanning_open", 0), item.get("dependabot_open", 0), item.get("secret_scanning_open", 0)]))
    total_code_scanning_open = sum(item.get("code_scanning_open", 0) for item in valid_rows)
    total_dependabot_open = sum(item.get("dependabot_open", 0) for item in valid_rows)
    total_secret_scanning_open = sum(item.get("secret_scanning_open", 0) for item in valid_rows)
    total_findings = total_code_scanning_open + total_dependabot_open + total_secret_scanning_open

    severity_rows = sorted(
        valid_rows,
        key=lambda item: (
            item.get("code_scanning_open", 0) + item.get("dependabot_open", 0) + item.get("secret_scanning_open", 0)
        ),
        reverse=True,
    )

    summary = {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organization": owner,
        "repositories_scanned": repositories_scanned,
        "repositories_with_findings": repositories_with_findings,
        "repositories_configured": sum(1 for item in valid_rows if item.get("scan_status") == "configured"),
        "repositories_pending": sum(1 for item in valid_rows if item.get("scan_status") == "pending"),
        "repositories_with_alerts": sum(1 for item in valid_rows if item.get("scan_status") == "findings"),
        "total_code_scanning_open": total_code_scanning_open,
        "total_code_scanning_critical": sum(item.get("code_scanning_critical", 0) for item in valid_rows),
        "total_code_scanning_high": sum(item.get("code_scanning_high", 0) for item in valid_rows),
        "total_code_scanning_medium": sum(item.get("code_scanning_medium", 0) for item in valid_rows),
        "total_dependabot_open": total_dependabot_open,
        "total_secret_scanning_open": total_secret_scanning_open,
        "total_findings": total_findings,
        "top_repositories": severity_rows[:10],
        "rows": valid_rows,
    }
    return summary


def build_metrics_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    rows = metrics.get("rows")
    if rows:
        return rows

    if "repository" in metrics:
        return [metrics]

    return []


def load_column_manifest(path: Optional[Union[Path, str]] = None) -> dict[str, Any]:
    """Load the column manifest from disk when present, otherwise return the default schema."""
    manifest_path = Path(path or COLUMN_MANIFEST_FILE)
    if not manifest_path.exists():
        return {"columns": DEFAULT_CSV_COLUMNS}

    with manifest_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict):
        columns = data.get("columns")
        if isinstance(columns, list) and columns:
            return {"columns": [str(column) for column in columns]}
    return {"columns": DEFAULT_CSV_COLUMNS}


def write_column_manifest(metrics: dict[str, Any], output_path: Optional[Path] = None) -> Path:
    """Write a JSON manifest describing the CSV schema for this metrics export."""
    rows = build_metrics_rows(metrics)
    known_columns = set(DEFAULT_CSV_COLUMNS)
    for row in rows:
        known_columns.update(row.keys())

    columns = list(DEFAULT_CSV_COLUMNS)
    for column in sorted(known_columns):
        if column not in columns:
            columns.append(column)

    manifest = {"columns": columns, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    target_path = output_path or Path("columns.json")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    return target_path


def write_csv_output(metrics: dict[str, Any], output_path: Optional[Path] = None) -> Path:
    rows = build_metrics_rows(metrics)
    target_path = output_path or Path(OUTPUT_CSV)
    fieldnames = DEFAULT_CSV_COLUMNS
    with target_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, restval="", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return target_path


def write_ticket_csv_output(metrics: dict[str, Any], output_path: Optional[Path] = None) -> Path:
    """Write a separate CSV intended for future ticket creation workflows."""
    rows = build_metrics_rows(metrics)
    target_path = output_path or Path(TICKET_CSV)

    ticket_rows: list[dict[str, Any]] = []
    for row in rows:
        total_findings = (
            int(row.get("code_scanning_open", 0))
            + int(row.get("dependabot_open", 0))
            + int(row.get("secret_scanning_open", 0))
        )
        if total_findings > 0 or row.get("scan_status") in {"error", "pending"}:
            ticket_rows.append(
                {
                    "repository": row.get("repository", ""),
                    "scan_status": row.get("scan_status", "unknown"),
                    "total_findings": total_findings,
                    "code_scanning_open": row.get("code_scanning_open", 0),
                    "code_scanning_critical": row.get("code_scanning_critical", 0),
                    "code_scanning_high": row.get("code_scanning_high", 0),
                    "code_scanning_medium": row.get("code_scanning_medium", 0),
                    "dependabot_open": row.get("dependabot_open", 0),
                    "secret_scanning_open": row.get("secret_scanning_open", 0),
                    "status": row.get("status", "ok"),
                }
            )

    with target_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "repository",
                "scan_status",
                "total_findings",
                "code_scanning_open",
                "code_scanning_critical",
                "code_scanning_high",
                "code_scanning_medium",
                "dependabot_open",
                "secret_scanning_open",
                "status",
            ],
        )
        writer.writeheader()
        writer.writerows(ticket_rows)
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
    write_column_manifest(metrics, target_dir / "columns.json")
    write_ticket_csv_output(metrics, target_dir / "tickets.csv")
    write_column_manifest(metrics, Path(COLUMN_MANIFEST_FILE))
    write_ticket_csv_output(metrics, Path(TICKET_CSV))
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
    runtime_token, runtime_owner = get_runtime_config()
    try:
        metrics = get_ghas_metrics()
    except Exception as exc:  # noqa: BLE001
        error_message = f"error:{exc}"
        metrics = {
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "organization": runtime_owner or ORG_NAME or "unknown",
            "error": str(exc),
            "repositories_scanned": 0,
            "repositories_with_findings": 0,
            "repositories_configured": 0,
            "repositories_pending": 0,
            "repositories_with_alerts": 0,
            "total_code_scanning_open": 0,
            "total_code_scanning_critical": 0,
            "total_code_scanning_high": 0,
            "total_code_scanning_medium": 0,
            "total_dependabot_open": 0,
            "total_secret_scanning_open": 0,
            "total_findings": 0,
            "top_repositories": [],
            "rows": [],
        }
        print(f"GitHub metrics collection failed: {exc}")

    # Always write the manifest first to ensure the schema is up-to-date
    write_column_manifest(metrics, Path(COLUMN_MANIFEST_FILE))

    write_json_output(metrics)
    csv_path = write_csv_output(metrics)
    pages_dir = write_pages_artifacts(metrics)
    print(f"Wrote JSON metrics to {OUTPUT_JSON}, CSV metrics to {csv_path}, Pages data to {pages_dir}, and ticket export to {TICKET_CSV}")

    if not os.getenv("SP_SKIP_UPLOAD"):
        try:
            sp_token = get_sharepoint_token()
            is_mock_mode = os.getenv("SP_MOCK_MODE", "true").lower() == "true"

            if sp_token and not is_mock_mode:
                upload_to_sharepoint(sp_token, str(csv_path), mock_mode=False)
            elif is_mock_mode:
                upload_to_sharepoint("mock-token", str(csv_path), mock_mode=True)
            else:
                print("SharePoint credentials not configured and not in mock mode; skipping upload.")
        except Exception as exc:  # noqa: BLE001
            print(f"SharePoint upload failed: {exc}. CSV artifact preserved.")
