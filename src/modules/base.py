from mcp.server.fastmcp import FastMCP
from typing import Callable
from src.client import CTDClient

class BaseModule:
    """Base class for all CTD MCP modules."""
    
    def __init__(self, client: CTDClient):
        self.client = client

    def register_tools(self, server: FastMCP) -> None:
        """Must be implemented by subclasses to register their tools."""
        raise NotImplementedError("Subclasses must implement register_tools")

    def _add_tool(self, server: FastMCP, method: Callable, name: str) -> None:
        """Programmatically registers a class method as an MCP tool."""
        decorator = server.tool(name=name)
        decorator(method)