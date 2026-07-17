import json
from typing import Any, Optional
from pydantic import Field, AnyUrl
from src.modules.base import BaseModule

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource


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
            method=self.search_insights,
             name= "search_insights",
             annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

    #register resources

    #def for calling resource for insight schema

    def search_insights(
        self,
        filters: dict[str, Any] | None = Field(
            default=None,
            description="Dictionary of search filters (e.g., insight_status__exact, insights_insight_name__exact). Enums can accept arrays of values for 'OR' searches. Consult the insights schema resource for allowed keys.",
            examples=[{"insight_status__exact": 0, "criticality__exact": [1, 2]}]
        ),
        start_time: str | None = Field(
            default=None,
            description="Optional start time for the search window (insight_timestamp__gte) formatted as a UTC ISO 8601 string.",
            examples=["2026-07-09T00:00:00.000Z"]
        ),
        end_time: str | None = Field(
            default=None,
            description="Optional end time for the search window (insight_timestamp__lte) formatted as a UTC ISO 8601 string.",
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
    