import os
import json
import requests
import urllib3
from mcp.server.fastmcp import FastMCP

# Disable SSL warnings for self-signed certificates or test environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize FastMCP Server
mcp = FastMCP("Claroty CTD Bridge")

# Hardcoded environment parameters as provided
CTD_HOST = "site-tender-python-1.knwlkgvw.demotapp.com"
USERNAME = "admin"
PASSWORD = "NQi49w8dTU4mFLCc"

class CTDClient:
    def __init__(self):
        self.base_url = f"https://{CTD_HOST}"
        self.token = None

    def authenticate(self):
        """Authenticates with CTD and grabs a fresh token."""
        url = f"{self.base_url}/auth/authenticate"
        payload = {"username": USERNAME, "password": PASSWORD}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        
        data = response.json()
        if "error" in data:
            raise Exception(f"Authentication Failed: {data['error']}")
            
        self.token = data['token']
        return {'Authorization': self.token}

    def get_headers(self):
        """Returns valid headers, authenticating if token is missing."""
        if not self.token:
            return self.authenticate()
        return {'Authorization': self.token}


# Instantiating a persistent client state
client = CTDClient()

@mcp.tool()
def get_confirmed_cves(page: int = 1) -> str:
    """
    Fetches a list of confirmed CVE IDs and their asset counts from the Claroty CTD platform.
    Use this to identify which CVEs are present in the environment before looking up assets.
    """
    try:
        headers = client.get_headers()
        params = {
            'page': str(page),
            'per_page': '100',
            'site_id__exact': '1',
            'ghost__exact': 'false'
        }
        
        response = requests.get(
            f"{client.base_url}/ranger/vulnerabilities",
            headers=headers,
            params=params,
            verify=False
        )
        
        # Handle expired token gracefully by retrying once
        if response.status_code == 401:
            headers = client.authenticate()
            response = requests.get(
                f"{client.base_url}/ranger/vulnerabilities",
                headers=headers,
                params=params,
                verify=False
            )

        data = response.json()
        objects = data.get('objects', [])
        
        if not objects:
            return "No vulnerabilities found or end of pages reached."

        result = []
        for item in objects:
            cve_id = item.get('cve_id')
            confirmed_count = item.get('assets_count', {}).get('confirmed_assets_count', 0)
            if cve_id and confirmed_count > 0:
                result.append({
                    "cve_id": cve_id,
                    "confirmed_assets_count": confirmed_count
                })

        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error fetching CVEs: {str(e)}"


@mcp.tool()
def get_assets_by_cve(cve_id: str) -> str:
    """
    Retrieves all network assets affected by a specific CVE ID (e.g., 'CVE-2021-34527').
    Returns asset configurations including hostname, IP address, MAC address, vendor, and firmware details.
    """
    try:
        headers = client.get_headers()
        params = {
            'per_page': '500',
            'cve_id__exact': cve_id,
            'affected_assets__exact': 'true',
            'ghost__exact': 'false',
            'special_hint__exact': '0'
        }
        
        response = requests.get(
            f"{client.base_url}/ranger/assets",
            headers=headers,
            params=params,
            verify=False
        )
        
        # Handle expired token gracefully by retrying once
        if response.status_code == 401:
            headers = client.authenticate()
            response = requests.get(
                f"{client.base_url}/ranger/assets",
                headers=headers,
                params=params,
                verify=False
            )

        data = response.json()
        objects = data.get('objects', [])
        
        if not objects:
            return f"No assets found affected by CVE: {cve_id}"

        clean_assets = []
        for asset in objects:
            # Clean and flatten list items for clear LLM parsing
            clean_asset = {
                "id": asset.get("id"),
                "name": asset.get("name"),
                "ipv4": asset.get("ipv4"),
                "mac": asset.get("mac"),
                "vendor": asset.get("vendor"),
                "os": asset.get("os"),
                "model": asset.get("model"),
                "firmware": asset.get("firmware"),
                "serial_number": asset.get("serial_number"),
                "num_alerts": asset.get("num_alerts")
            }
            clean_assets.append(clean_asset)

        return json.dumps(clean_assets, indent=2)
    except Exception as e:
        return f"Error fetching assets for {cve_id}: {str(e)}"

if __name__ == "__main__":
    # Running the MCP server over standard input/output (stdio)
    mcp.run(transport='stdio')