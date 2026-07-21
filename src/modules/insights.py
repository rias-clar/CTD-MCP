import json
from typing import Any, Optional
from pydantic import Field, AnyUrl
import urllib.parse

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.insights import INSIGHTS_SCHEMA_URI, INSIGHTS_SCHEMA_DOCS


class InsightsModule(BaseModule):
    """
    Interface for retrieving automated operational and security insights from Claroty CTD.
    
    Provides access to holistic network risk assessments, pinpointing vulnerable assets, 
    risky network configurations, and critical communication patterns (e.g., external 
    connections, unsecured protocols, and PLC manipulations) across the industrial network.
    """

    def register_tools(self, server: FastMCP) -> None:
        """Registers the Insights tools with the MCP Server."""
        
        self._add_tool(
                server=server, 
                method=self.get_insights_schema, 
                name="get_insights_schema",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )
        
        self._add_tool(
            server=server,
            method=self.search_insights,
             name= "search_insights",
             annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

        self._add_tool(
            server=server,
            method=self.get_insight_details,
             name= "get_insight_details",
             annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

        self._add_tool(
            server=server,
            method=self.filter_assets_by_insight,
            name= "filter_assets_by_insight",
            annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

    #register resources
    def register_resources(self, server: FastMCP) -> None:
        """Register the static Insights schema resources with the MCP Server."""
        
        resource = TextResource(
            uri=AnyUrl(INSIGHTS_SCHEMA_URI),
            name="ctd_insights_schema",
            description="Contains the master guide, allowed filters, and enums for the `search_insights` tools",
            text=INSIGHTS_SCHEMA_DOCS, 
            mimeType="text/markdown"
        )
        
        self._add_resource(server, resource)

    #def for calling resource for insight schema
    def get_insights_schema(self) -> str:
        """Retrieves the complete Claroty CTD Insights Search Schema, Filter Keys, and Guide.
        
        Call this tool BEFORE executing search_insights if to look up 
        allowed filter keys, insight names, required data types, or integer enum mappings.
        """
        return INSIGHTS_SCHEMA_DOCS

    def search_insights(
        self,
        exact_insight: str | list[str] | None = Field(
            default=None,
            description="Specific insight name to filter by. Accepts a single string. Call `get_insights_schema` tool for allowed insight names. Defaults to all insights if omitted.",
            examples=["Unsecured Protocols", "Windows CVEs"]
        ),
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
            default=None,
            description="Dictionary of additional search filters. Call `get_insights_schema` tool for allowed filter keys",
            examples=[{"insight_status__exact": 0, "criticality__exact": [1, 2]}]
        ),
        start_time: str | None = Field(
            default=None,
            description="Optional start time for the search window, formatted as a UTC ISO 8601 string.",
            examples=["2026-07-09T00:00:00.000Z"]
        ),
        end_time: str | None = Field(
            default=None,
            description="Optional end time for the search window, formatted as a UTC ISO 8601 string.",
            examples=["2026-07-16T23:59:59.000Z"]
        )
    ) -> str:
        """Retrieve aggregated network insights, risky assets, and vulnerability summaries.

        Use this tool to discover high-level security warnings and operational 
        insights detected by CTD. Call the `get_insights_schema` tool before 
        constructing filter expressions to ensure correct integer mappings.
        """
        try:
            # 1. Base Default Parameters
            params: dict[str, Any] = {
                'page': 1,
                'per_page': 50,
                'format': 'insight_page',
                'sort': '-risk_level',
                'site_id__exact': 1,
                'ghost__exact': False,
                'special_hint__exact': 0,
                'insight_status__exact': 0,
            }

            if exact_insight is not None:
                if isinstance(exact_insight, list):
                    params['insights_insight_name__exact'] = ",;$".join(str(v).strip() for v in exact_insight)
                else:
                    params['insights_insight_name__exact'] = exact_insight

            # 2. Apply Time Window
            if start_time:
                params['insight_timestamp__gte'] = str(start_time).strip()
            if end_time:
                params['insight_timestamp__lte'] = str(end_time).strip()

            # 3. Apply LLM Filters & Handle Arrays
            if filters:
                for key, value in filters.items():
                    if isinstance(value, list):
                        params[key] = ",;$".join(str(v).strip() for v in value)
                    else:
                        params[key] = value

            # 4. Fetch from Endpoint
            response_data = self.client.request("GET", "/ranger/insights_summary", params=params)
            
            # Handle potential wrapper (e.g., if inside an 'objects' key like Assets)
            if isinstance(response_data, dict) and "objects" in response_data:
                objects = response_data.get("objects", [])
            elif isinstance(response_data, list):
                objects = response_data
            else:
                return "Error: Unexpected response format from the insights API."

            if not objects:
                return "No insights found matching the specified criteria."

            # 5. Output Token Optimization
            keys_to_drop = {"headers", "default_sort", "other_side_headers", "other_side_default_sort"}
            optimized_objects = []

            for obj in objects:
                # Strip out UI-specific keys and empty values
                cleaned_obj = {
                    k: v for k, v in obj.items() 
                    if k not in keys_to_drop and v not in (None, "", [], {})
                }
                optimized_objects.append(cleaned_obj)

            # Clean JSON serialization
            return json.dumps(optimized_objects, separators=(',', ':'))

        except Exception as e:
            return f"Error searching insights: {str(e)}"
    
    #add tools for specific insights
    def get_insight_details(
            self,
            insight_name: str = Field(
                description="Specific insight name to filter by. Accepts a single string. Call `get_insights_schema` tool for allowed insight names.",
                examples=["Unsecured Protocols", "Windows CVEs"]
            )
        ) -> str:
            """Retrieve all assets and details for a specific insight.

            Returns a Markdown table of affected assets and insight context. Each row 
            includes a `Filter Key` to be used with the `filter_assets_by_insight` 
            tool for deeper investigation. Call `get_insights_schema` first for valid 
            insight names.
            """
                
            try:
                insight_path = urllib.parse.quote(insight_name.strip())
                
                all_rows = []
                current_page = 1
                per_page = 50
                
                metadata = {"description": "", "total_records": 0}
                valid_headers = []
                valid_indices = []

                while True:
                    params = {
                        'format': 'insight_page',
                        'page': current_page,
                        'per_page': per_page,
                        'ghost__exact': False,
                        'special_hint__exact': 0,
                        'site_id__exact': 1,
                        'insight_status__exact': 0,
                    }

                    response_data = self.client.request("GET", f"/ranger/insight_details/{insight_path}", params=params)

                    if not response_data or not isinstance(response_data, dict):
                        break

                    page_rows = response_data.get("rows", [])
                    
                    # Extract headers and metadata on the first page
                    if current_page == 1:
                        raw_desc = response_data.get("description", "")
                        metadata["description"] = raw_desc.replace("<br>", " ").replace("<strong>", "").replace("</strong>", "")
                        metadata["total_records"] = response_data.get("count_total", 0)
                        
                        for h in response_data.get("headers", []):
                            # Drop the "Actions" column
                            if h.get("type") != "bulk_actions" and h.get("name", "").lower() != "actions":
                                valid_headers.append(h.get("name"))
                                valid_indices.append(h.get("header_num"))

                    if not page_rows:
                        break

                    all_rows.extend(page_rows)

                    # Stop Condition: Reached the end of available server data
                    if len(page_rows) < per_page:
                        break
                        
                    current_page += 1

                if not all_rows:
                    return f"No detail records found for insight '{insight_name}'."

                # Construct Markdown Output
                md_lines = [
                    f"### Insight: {insight_name}",
                    f"**Description:** {metadata['description']}",
                    f"**Total Records:** {metadata['total_records']}",
                    ""
                ]

                # Append the Filter Key column for LLM context
                table_headers = valid_headers + ["filter_key (Asset Lookup)"]
                
                # Build Table Header Row
                md_lines.append("| " + " | ".join(table_headers) + " |")
                md_lines.append("|" + "|".join(["---"] * len(table_headers)) + "|")

                # Build Table Rows
                for row in all_rows:
                    cells = row.get("cells", [])
                    row_data = []
                    
                    # Match cells to the valid indices
                    for idx in valid_indices:
                        if idx < len(cells):
                            # Clean cell text to prevent Markdown table breaks
                            cell_text = str(cells[idx]).replace("|", "\\|").replace("\n", " ")
                            row_data.append(cell_text)
                        else:
                            row_data.append("")
                    
                    # Extract and append the filter key
                    filter_key = row.get("row_filter", {}).get("filter_key", "")
                    row_data.append(str(filter_key).replace("|", "\\|"))
                    
                    md_lines.append("| " + " | ".join(row_data) + " |")

                return "\n".join(md_lines)

            except Exception as e:
                return f"Error fetching details for insight '{insight_name}': {str(e)}"

    def filter_assets_by_insight(
        self,
        filter_key: str | None = Field(
            default=None,
            description="The EXACT string from the 'filter_key (Asset Lookup)' column of the `get_insight_details` table. This string MUST be passed VERBATIM, including all commas, dollar signs, and semicolons (e.g., `,;$`). Do not alter, parse, or clean this string; it is a proprietary system token used to drill down into a specific sub-category. IMPORTANT: Only query ONE filter_key per message. Do not make parallel tool calls.",
            examples=["Unsecured Protocols,;$1,;$,;$SMB,;$SMB+version+1..."]
        ),
        insight_name: str | None = Field(
            default=None,
            description="The exact insight name to get ALL assets associated with the insight. Call `get_insights_schema` for allowed names.",
            examples=["Unsecured Protocols", "Windows CVEs"]
        ),
        limit: int = Field(
            default=50,
            ge=1,
            le=500,
            description="Maximum number of assets to return. Defaults to 50."
        )
    ) -> str:
        """Retrieve assets information associated with a specific insight or insight sub-category.

        Extracts foundational device information (IPs, MACs, OS, etc.) for affected assets. 
        At least one parameter is strictly required: a `filter_key` (to drill down into a 
        specific sub-category or single row returned by `get_insight_details`) or an 
        `insight_name` (to broadly retrieve all assets tied to the entire insight category). 
        Do not attempt to query multiple filter_keys at once; process them sequentially 
        or request user preference.
        """

        if not filter_key and not insight_name:
            return "Error: You must provide at least one parameter (either 'filter_key' or 'insight_name')."

        try:
            # Base default parameters for the assets endpoint
            params: dict[str, Any] = {
                'special_hint__exact': 0,  
                'valid__exact': True,      
                'ghost__exact': False,     
                'approved__exact': True,
                # Request a condensed set of highly relevant fields to save tokens
                'fields': "id,;$name,;$ipv4,;$vendor,;$model,;$asset_type,;$risk_level"
            }

            # Apply the appropriate filter
            if filter_key:
                params['insight_row_key__exact'] = filter_key.strip()
            elif insight_name:
                params['insight_name__exact'] = insight_name.strip()

            all_objects = []
            current_page = 1
            per_page = min(limit, 100)

            while True:
                params['page'] = current_page
                params['per_page'] = per_page

                # Fetch from V1 Assets endpoint
                response_data = self.client.request("GET", "/ranger/assets", params=params)
                
                if not isinstance(response_data, dict):
                    break

                objects = response_data.get('objects', [])
                if not objects:
                    break

                all_objects.extend(objects)

                # Stop Conditions
                if len(all_objects) >= limit:
                    all_objects = all_objects[:limit]
                    break
                if len(objects) < per_page:
                    break
                    
                current_page += 1

            if not all_objects:
                identifier = filter_key if filter_key else insight_name
                return f"No assets found matching the insight criteria for: '{identifier}'."

            # Output Token Optimization
            optimized_objects = []
            for obj in all_objects:
                # Strip out null, empty string, or empty list values
                cleaned_obj = {k: v for k, v in obj.items() if v not in (None, "", [], {})}
                optimized_objects.append(cleaned_obj)

            return json.dumps(optimized_objects, separators=(',', ':'))

        except Exception as e:
            return f"Error filtering assets by insight: {str(e)}"