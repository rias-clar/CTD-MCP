from typing import Callable, Any
from mcp.server.fastmcp import FastMCP
from mcp.types import Resource, ToolAnnotations
from src.client import CTDClient

# Default Annotations for Read-Only Tools
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False, #CTD is closed
)

class BaseModule:
    def __init__(self, client: CTDClient) -> None:
        """
        Initializes the base module with a shared Claroty CTD API client.
        """
        self.client = client
        self.tools: list[str] = []       # Tracks registered tool names
        self.resources: list[str] = []   # Tracks registered resource URIs

    def register_tools(self, server: FastMCP) -> None:
        """Must be overridden by child modules to register their specific tools."""
        raise NotImplementedError("Subclasses must implement register_tools")

    def register_resources(self, server: FastMCP) -> None:
        """Optional: Can be overridden by child modules to register their specific resources."""
        pass

    def _add_tool(
        self, 
        server: FastMCP, 
        method: Callable[..., Any], 
        name: str,
        annotations: ToolAnnotations | None = None
    ) -> None:
        """Programmatically registers a class method as an MCP tool using native add_tool."""
        prefixed_name = f"ctd_{name}"
        server.add_tool(
            method,
            name=prefixed_name,
            annotations=annotations or READ_ONLY_ANNOTATIONS,
            structured_output=False,
        )
        self.tools.append(prefixed_name)

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
        """
        Programmatically registers an MCP Resource object with the server.
        """
        server.add_resource(resource=resource)
        
        resource_uri = resource.uri
        self.resources.append(str(resource_uri))