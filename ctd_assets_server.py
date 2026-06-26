import os
import json
import requests
import urllib3
from mcp.server.fastmcp import FastMCP

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mcp = FastMCP("Claroty CTD Assets Core")

CTD_HOST = ""
USERNAME = ""
PASSWORD = ""

class CTDClient:
    def __init__(self):
        self.base_url = f"https://{CTD_HOST}"
        self.token = None

    def authenticate(self):
        """Authenticates with CTD based on the /auth/authenticate spec."""
        url = f"{self.base_url}/auth/authenticate"
        payload = {"username": USERNAME, "password": PASSWORD}
        headers = {'Content-type': 'application/json'}
        
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        
        data = response.json()
        if "error" in data and data.get("success") is False:
            raise Exception(f"Authentication Failed: {data['error']}")
            
        self.token = data['token']
        return {'Authorization': self.token}

    def get_headers(self):
        if not self.token:
            return self.authenticate()
        return {'Authorization': self.token}

    def request(self, method, endpoint, params=None):
        """Helper to handle self-healing token retries automatically."""
        headers = self.get_headers()
        url = f"{self.base_url}{endpoint}"
        
        response = requests.request(method, url, headers=headers, params=params, verify=False)
        
        if response.status_code == 401:
            headers = self.authenticate()
            response = requests.request(method, url, headers=headers, params=params, verify=False)
            
        response.raise_for_status()
        return response.json()

client = CTDClient()

@mcp.tool()
def search_assets(ip_address: str = None, mac_address: str = None, vendor: str = None, asset_type: str = None) -> str:
    """
    Searches for network assets in the CTD environment. 
    You can filter by IP address, MAC address, vendor name, or asset type.
    If no filters are provided, it returns the first 500 assets.
    """
    try:
        # Reverted to the standard v1 endpoint as requested
        params = {'per_page': 500}
        
        # Map human-readable args to exact OpenAPI query parameters
        if ip_address:
            params['ipv4__exact'] = ip_address
        if mac_address:
            params['mac__icontains'] = mac_address
        if vendor:
            params['vendor__icontains'] = vendor
        if asset_type:
            params['asset_type__exact'] = asset_type

        # Using /ranger/assets instead of /ranger/v2/assets
        data = client.request("GET", "/ranger/assets", params=params)
        objects = data.get('objects', [])
        
        if not objects:
            return "No assets found matching those criteria."

        # Flatten and filter out heavy metadata to save LLM context
        clean_assets = []
        for asset in objects:
            clean_assets.append({
                "resource_id": asset.get("resource_id"),
                "name": asset.get("name"),
                "ip": asset.get("ipv4", [None])[0] if asset.get("ipv4") else None,
                "mac": asset.get("mac", [None])[0] if asset.get("mac") else None,
                "vendor": asset.get("vendor"),
                "os": asset.get("os"),
                "risk_level": asset.get("risk_level"),
                "purdue_level": asset.get("purdue_level")
            })

        return json.dumps(clean_assets, indent=2)
    except Exception as e:
        return f"Error searching assets: {str(e)}"
    
@mcp.tool()
def get_asset_details(resource_id: str) -> str:
    """
    Retrieves the complete, deep-dive diagnostic profile of a single asset.
    You MUST provide the exact 'resource_id' (e.g., '179-1') obtained from other tools.
    """
    try:
        data = client.request("GET", f"/ranger/assets/{resource_id}")
        
        # We return the raw string dump here because a deep dive usually requires 
        # the LLM to read the exact protocol arrays, active queries, and firmware specs.
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error fetching details for asset {resource_id}: {str(e)}"

@mcp.tool()
def get_vulnerable_assets() -> str:
    """
    Retrieves a list of assets that have active Insights/Vulnerabilities.
    This specifically returns assets mapped to the top 10 highest-scoring CVEs.
    """
    try:
        params = {'per_page': 100}
        data = client.request("GET", "/ranger/assets_with_insights", params=params)
        objects = data.get('objects', [])
        
        if not objects:
            return "No highly vulnerable assets found."

        vulnerable_assets = []
        for asset in objects:
            vulnerable_assets.append({
                "resource_id": asset.get("resource_id"),
                "name": asset.get("name"),
                "ip": asset.get("IPv4", [None])[0] if asset.get("IPv4") else None,
                "risk_level": asset.get("risk_level"),
                "total_cves_count": asset.get("total_cves_count"),
                # Extract just the CVE IDs and scores to keep the context clean
                "top_vulnerabilities": [
                    {"cve": i.get("cve_id"), "cvss": i.get("cvss")} 
                    for i in asset.get("insights", [])
                ]
            })

        return json.dumps(vulnerable_assets, indent=2)
    except Exception as e:
        return f"Error fetching vulnerable assets: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport='stdio')
