import os
import json
import requests

# 1. Environment Configurations
GH_TOKEN = os.getenv("GH_PAT")
ORG_NAME = os.getenv("GH_ORG_NAME")
TENANT_ID = os.getenv("SP_TENANT_ID")
CLIENT_ID = os.getenv("SP_CLIENT_ID")
CLIENT_SECRET = os.getenv("SP_CLIENT_SECRET")
SP_SITE_URL = os.getenv("SP_SITE_URL")  # e.g., "://sharepoint.com:/sites/YourSite"
TARGET_FOLDER = "/Shared Documents/SecurityReports"

def get_ghas_metrics():
    """Fetches summary code scanning alert metrics for the organization."""
    url = f"https://github.com{ORG_NAME}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    # Fetching page 1 of open alerts as an example metric aggregation
    params = {"state": "open", "per_page": 100}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    alerts = response.json()
    
    # Aggregate data into metrics
    metrics = {
        "total_open_alerts": len(alerts),
        "critical_severity_count": sum(1 for a in alerts if a.get('rule', {}).get('security_severity_level') == 'critical'),
        "high_severity_count": sum(1 for a in alerts if a.get('rule', {}).get('security_severity_level') == 'high'),
    }
    return metrics

def get_sharepoint_token():
    """Authenticates against Microsoft Graph to get an access token."""
    url = f"https://microsoftonline.com{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "scope": "https://microsoft.com",
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

def upload_to_sharepoint(token, file_path):
    """Uploads the compiled metrics file to the target SharePoint directory via Graph API."""
    file_name = os.path.basename(file_path)
    # Target Microsoft Graph API endpoint for SharePoint Site drives
    url = f"https://microsoft.com{SP_SITE_URL}/drive/root:{TARGET_FOLDER}/{file_name}:/content"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    with open(file_path, "rb") as f:
        response = requests.put(url, headers=headers, data=f)
    
    response.raise_for_status()
    print(f"Successfully uploaded {file_name} to SharePoint.")

if __name__ == "__main__":
    # Extract
    gh_metrics = get_ghas_metrics()
    
    # Save local file
    output_file = "ghas_metrics.json"
    with open(output_file, "w") as out:
        json.dump(gh_metrics, out, indent=4)
        
    # Authenticate and Push
    sp_token = get_sharepoint_token()
    upload_to_sharepoint(sp_token, output_file)
