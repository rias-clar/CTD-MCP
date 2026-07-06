import json
from pydantic import Field
from typing import Optional
from mcp.server.fastmcp import FastMCP
from src.modules.base import BaseModule

class AssetsModule(BaseModule):
    """Handles asset discovery, deep-dives, and posture assessment using CTD V1 APIs."""

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(server, self.search_assets, "search_assets")
        self._add_tool(server, self.search_assets_optim, "search_assets_optim")
        self._add_tool(server, self.get_asset_details, "get_asset_details")
        self._add_tool(server, self.get_vulnerable_assets, "get_vulnerable_assets")

    def search_assets(
        self,
        ip_address: Optional[str] = Field(default=None, description="Exact IPv4 address filter."),
        mac_address: Optional[str] = Field(default=None, description="MAC address filter (contains)."),
        vendor: Optional[str] = Field(default=None, description="Vendor name filter (contains)."),
        risk_level: Optional[int] = Field(default=None, description="Exact risk level integer filter."),
        fields: Optional[str] = Field(
            default="resource_id,;$name,;$ipv4,;$mac,;$vendor,;$risk_level,;$purdue_level,;$asset_type__", 
            description="Claroty formatted string of fields to return. Separator is ',;$'"
        )
    ) -> str:
        """
        Searches for network assets in the CTD environment using the /ranger/assets (v1) endpoint.
        If no filters are provided, it returns the first 100 results.
        """
        try:
            params = {
                'per_page': 100,  # Keeping it reasonable for LLM context limits
                'fields': fields
            }
            
            # Map intuitive arguments to exact OpenAPI query parameters
            if ip_address: params['ipv4__exact'] = ip_address
            if mac_address: params['mac__icontains'] = mac_address
            if vendor: params['vendor__icontains'] = vendor
            if risk_level is not None: params['risk_level__exact'] = risk_level

            data = self.client.request("GET", "/ranger/assets", params=params)
            objects = data.get('objects', [])
            
            if not objects:
                return "No assets found matching those criteria."

            return json.dumps(objects, indent=2)
            
        except Exception as e:
            return f"Error searching assets: {str(e)}"
        

    def search_assets_optim(
        self,
        filters: dict[str, str | int | bool] | None = Field(
            default=None,
            description="Dictionary of filters (e.g., {'vendor__icontains': 'Rockwell'}). MUST strictly use keys defined in resource://ctd/assets-schema."
        ),
        fields: list[str] = Field(
            default=["id", "name", "ipv4", "ipv6", "mac", "vendor", "model", "firmware", "asset_type", "risk_level"],
            description="List of exact field names to return. ONLY return the fields EXPLICITLY REQUESTED by the user. Do NOT hallucinate your own fields. MUST strictly match the keys in resource://ctd/assets-schema."
        ),
        page: int = Field(default=1, description="The starting page number."),
        per_page: int = Field(default=500, description="Number of assets to pull per page (Recommended maximum 500)."),
        auto_paginate: bool = Field(
            default=True, 
            description="If True, automatically fetches all pages until all assets are retrieved."
        )
    ) -> str:
        """
        Searches for network assets in the CTD environment using V1 endpoint parameters.
        Consult resource://ctd/assets-schema to see all available filters and fields.
        """
        try:
            # Base parameters including your required defaults
            params = {
                'per_page': per_page,
                'page': page,
                'special_hint__exact': 0,
                'valid__exact': True,
                'ghost__exact': False,
                # Since 'fields' now always defaults to a list, we can just join it immediately!
                'fields': ",;$".join(fields)
            }

            # Dynamically apply LLM filters
            if filters:
                for key, value in filters.items():
                    # Prevents the LLM from accidentally overriding the enforced special_hint default
                    # It CAN override valid__exact or ghost__exact if the user explicitly asks for invalid/ghost assets
                    if key != 'special_hint__exact':
                        params[key] = value

            all_objects = []
            current_page = page

            # Pagination Loop
            while True:
                params['page'] = current_page
                
                # Using the V1 endpoint as strictly requested
                data = self.client.request("GET", "/ranger/assets", params=params)
                objects = data.get('objects', [])
                
                if not objects:
                    break

                all_objects.extend(objects)

                # Stop if auto_paginate is False, or if the returned objects are less than per_page
                if not auto_paginate or len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                return "No assets found matching those criteria."

            return json.dumps(all_objects, indent=2)
            
        except Exception as e:
            return f"Error searching assets: {str(e)}"

    def get_asset_details(
        self, 
        resource_id: str = Field(description="The exact 'resource_id' of the asset (e.g., '179-1').")
    ) -> str:
        """
        Retrieves the complete, unfiltered diagnostic profile of a single asset.
        Use this when a deep-dive into a specific asset's full metadata is needed.
        """
        try:
            data = self.client.request("GET", f"/ranger/assets/{resource_id}")
            return json.dumps(data, indent=2)
        except Exception as e:
            return f"Error fetching details for asset {resource_id}: {str(e)}"

    def get_vulnerable_assets(
        self,
        cve_id: Optional[str] = Field(default=None, description="Filter by a specific CVE ID (e.g., 'CVE-2019-12260')."),
        fields: Optional[str] = Field(
            default="resource_id,;$name,;$ipv4,;$risk_level,;$total_cves_count,;$insights", 
            description="Claroty formatted string of fields to return. Separator is ',;$'"
        )
    ) -> str:
        """
        Retrieves a list of assets that have active Insights/Vulnerabilities.
        This queries the /ranger/assets_with_insights endpoint.
        """
        try:
            params = {
                'per_page': 50,
                'fields': fields
            }
            
            if cve_id:
                params['insight_cve_id__exact'] = cve_id

            data = self.client.request("GET", "/ranger/assets_with_insights", params=params)
            objects = data.get('objects', [])
            
            if not objects:
                return "No highly vulnerable assets found matching criteria."

            return json.dumps(objects, indent=2)
            
        except Exception as e:
            return f"Error fetching vulnerable assets: {str(e)}"