# GHAS Metrics Exporter

This project provides a Python script and GitHub Actions workflow to automatically collect GitHub Advanced Security (GHAS) metrics from repositories within an organization or user account. It generates comprehensive reports in JSON and CSV formats, creates data artifacts for a GitHub Pages dashboard, and can optionally upload results to a SharePoint site.

## Features

- **Comprehensive Metrics**: Gathers data for Code Scanning, Dependabot, and Secret Scanning alerts.
- **Per-Repository Details**: Reports on open alert counts, including critical/high severity for code scanning.
- **Configuration Status**: Tracks the default setup state for code scanning across repositories (`configured`, `pending`, `not_supported`).
- **Flexible Reporting**: Generates `ghas_metrics.json` (full data dump) and `ghas_metrics.csv` (tabular data).
- **GitHub Pages Integration**: Creates data artifacts in the `docs/` directory and provides an `index.html` for visualization.
- **SharePoint Upload**: Can automatically upload the CSV report to a specified SharePoint document library.
- **Automated Execution**: A GitHub Actions workflow runs the script on a schedule (`cron`) or on manual trigger (`workflow_dispatch`).

## How It Works

The core logic is in the `.github/scripts/fetch_and_push.py` script. It performs the following steps:

1.  **Configuration**: Reads environment variables to get the GitHub token, organization/user name, and SharePoint credentials.
2.  **Repository Discovery**: Fetches a unique list of all repositories accessible to the configured token for the target owner. It intelligently checks both user and organization endpoints to build a complete list.
3.  **Allowlist Filtering**: By default, the script scans all discovered repositories. If the `.github/config/repo_allowlist.json` file contains a list of repository names, the script will filter its run to **only** those repositories.
4.  **Metric Collection**: For each repository, it makes paginated API calls to fetch:
    - Code Scanning default setup status.
    - All open alerts for Code Scanning, Dependabot, and Secret Scanning.
5.  **Aggregation**: Compiles the per-repository data into a summary report, including top repositories by finding count.
6.  **Artifact Generation**: Writes the collected data to multiple files:
    - `ghas_metrics.json` / `ghas_metrics.csv`: For local use or as workflow artifacts.
    - `docs/data/*`: For the GitHub Pages site.
    - `tickets.csv`: A specialized CSV for potential ticketing integrations.
7.  **SharePoint Upload**: If configured, authenticates with Microsoft Graph and uploads the primary CSV report.

## Setup and Configuration

### Prerequisites

- Python 3.9+
- Dependencies listed in `requirements.txt`.

To set up locally, clone the repository and run:

```bash
pip install -r requirements.txt
```

### Environment Variables & Secrets

The script and workflow rely on environment variables and GitHub secrets for configuration.

#### GitHub Configuration

| Variable / Secret       | Description                                                                                             | Required | Default in Workflow         |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | -------- | --------------------------- |
| `GITHUB_TOKEN`          | A token with `security-events:read` permissions to fetch GHAS data.                                     | **Yes**  | `${{ github.token }}`       |
| `GH_ORG_NAME`           | The name of the GitHub organization or user to scan.                                                    | **Yes**  | `${{ github.repository_owner }}` |
| `REPO_ALLOWLIST_FILE`   | Path to a JSON file to filter repositories. If the `repositories` array is empty, all repos are scanned.  | No       | `.github/config/repo_allowlist.json` |

#### SharePoint Configuration (Optional)

To enable SharePoint uploads, you must configure an Azure AD App Registration with `Sites.ReadWrite.All` permissions and provide the following secrets.

| Secret                    | Description                                                                                             | Required for Upload |
| ------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------- |
| `SHAREPOINT_TENANT_ID`    | The Azure AD Tenant ID.                                                                                 | **Yes**             |
| `SHAREPOINT_CLIENT_ID`    | The Client ID of the App Registration.                                                                  | **Yes**             |
| `SHAREPOINT_CLIENT_SECRET`| The client secret for the App Registration.                                                             | **Yes**             |
| `SHAREPOINT_SITE_URL`     | The URL to the SharePoint site (e.g., `https://your-tenant.sharepoint.com/sites/YourSite`).             | **Yes**             |
| `SP_MOCK_MODE`            | Set to `false` in the workflow to attempt a real upload. Defaults to `true` for safe local testing.     | No                  |

## Usage

### Automated Workflow

The primary way to run this tool is through the **Sync GHAS Metrics to SharePoint** workflow defined in `.github/workflows/ghas_to_sharepoint.yml`.

- **Scheduled Runs**: The workflow is configured to run automatically every day at midnight UTC.
- **Manual Runs**: You can trigger the workflow manually from the "Actions" tab in the GitHub repository.

After a successful run, the workflow will:
1.  Update the data in the `docs/` directory.
2.  Deploy the `docs/` directory as a GitHub Pages site.
3.  Upload a `ghas-metrics` artifact containing all generated reports.

### Local Execution

You can also run the script locally. First, ensure you have a GitHub token with the required permissions.

```bash
# Set environment variables
export GITHUB_TOKEN="ghp_..."
export GH_ORG_NAME="your-github-org"

# Run the script
python .github/scripts/fetch_and_push.py
```

This will generate the report files in the root of the repository and in the `docs/data` directory.