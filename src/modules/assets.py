import json
from typing import Any, Optional
from pydantic import Field, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.assets import ASSETS_SCHEMA_URI, ASSETS_SCHEMA_DOCS

class AssetsModule(BaseModule):
    """Handles asset discovery, deep-dives, and posture assessment using CTD V1 APIs."""

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
                server=server, 
                method=self.search_assets, 
                name="search_assets",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )        
        self._add_tool(server, self.get_asset_details, "get_asset_details")
        self._add_tool(server, self.get_vulnerable_assets, "get_vulnerable_assets")

    def register_resources(self, server: FastMCP) -> None:
        """Register the static schema resources with the MCP Server."""
        
        resource = TextResource(
            uri=AnyUrl(ASSETS_SCHEMA_URI),
            name="ctd_assets_schema",
            description="Contains the master guide, allowed filters, and enums for the `search_assets` and `search_assets_optim` tools.",
            text=ASSETS_SCHEMA_DOCS, 
            mimeType="text/markdown"
        )
        
        self._add_resource(server, resource)
        
    def search_assets(
            self,
            filters: dict[str, str | int | bool] | None = Field(
                default=None,
                description="Dictionary of search filters. Consult resource://ctd/assets-schema for allowed filter keys, data types, and enum mappings.",
                examples=[{"vendor__icontains": "Rockwell", "risk_level__exact": 3}],
            ),
            fields: list[str] = Field(
                default=["id", "name", "ipv4", "ipv6", "mac", "vendor", "model", "firmware", "asset_type", "risk_level"],
                description="List of requested asset fields. Consult resource://ctd/assets-schema for available fields. Defaults to a standard set of identity and network fields if omitted.",
                examples=[["id", "hostname", "ipv4", "vulnerabilities"]],
            ),
            limit: int | None = Field(
                default=None,
                ge=1,
                le=500,
                description="Maximum number of assets to return. If omitted, all matching assets are retrieved via auto-pagination.",
            ),
        ) -> str:
            """Find network assets by specified criteria and return their details.

            Use this tool to discover assets based on identity, location, risk score, 
            or hardware classification. Consult resource://ctd/assets-schema before 
            constructing filter expressions to ensure correct data types and integer 
            enum values.
            """
            try:
                # Input Validation 
                clean_fields = [str(f).strip() for f in fields if str(f).strip()]
                if not clean_fields:
                    clean_fields = ["id", "name", "ipv4", "mac", "asset_type"] # Default fallback

                # Base default parameters
                params: dict[str, Any] = {
                    'special_hint__exact': 0,  # Default to unicast
                    'valid__exact': True,      # Default to valid assets
                    'ghost__exact': False,     # Default to non-ghost assets
                    'approved__exact': True,   # Default to approved assets
                    'fields': ",;$".join(clean_fields)
                }

                # Apply LLM filters
                if filters:
                    for key, value in filters.items(): 
                        params[key] = value

                # Pagination
                all_objects = []
                current_page = 1
                
                # Chunking
                per_page = min(limit, 500) if limit is not None else 500
                params['per_page'] = per_page

                while True:
                    params['page'] = current_page
                    
                    # Fetch from V1 endpoint
                    response_data = self.client.request("GET", "/ranger/assets", params=params)
                    objects = response_data.get('objects', [])
                    
                    if not objects:
                        break
                        
                    all_objects.extend(objects)

                    # Stop Conditions:
                    # Hit or exceeded the requested limit:
                    if limit is not None and len(all_objects) >= limit:
                        all_objects = all_objects[:limit] # Truncate to exact requested limit
                        break
                    
                    # Reached the end of the database:
                    if len(objects) < per_page:
                        break
                        
                    current_page += 1

                if not all_objects:
                    return "No assets found matching the specified criteria."

                # Output Token Optimization
                # Strip key-value pairs where the value is None, "", or []
                optimized_objects = []
                for obj in all_objects:
                    cleaned_obj = {k: v for k, v in obj.items() if v not in (None, "", [], {})}
                    optimized_objects.append(cleaned_obj)

                # Clean JSON serialization, remove all unnecessary spaces and newlines
                return json.dumps(optimized_objects, separators=(',', ':'))

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