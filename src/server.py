import sys
from mcp.server.fastmcp import FastMCP
from src.client import CTDClient
from src.modules.assets import AssetsModule
from src.modules.vulnerabilities import VulnerabilitiesModule

# 1. Initialize the FastMCP Server
# This name will appear in MCP clients (ie, Ollama)
mcp = FastMCP("Claroty CTD MCP Server")

def main():
    try:
        # 2. Initialize the API Client
        # This will automatically pull credentials from .env file
        client = CTDClient()

        # 3. Instantiate Modules
        # APPEND TO LIST WITH NEW MODULES AS THEY ARE CREATED!!!
        modules = [
            AssetsModule(client=client),
            #VulnerabilitiesModule(client=client), 
        ]

        # 4. Explicitly Register Tools
        # This loops through all active modules and connects their tools into FastMCP
        for module in modules:
            module.register_tools(mcp)
            module.register_resources(mcp)

        # 5. Start the server
        # FastMCP defaults to standard input/output (stdio) transport, (required for CLI tools)
        mcp.run()

        # 6. Start server via HTTP for Web UIs
        # for later integration with OpenWeb UI
        # mcp.run(transport='sse', host ='0.0.0.0', port=8000)
        
    except ValueError as e:
        sys.stderr.write(f"Configuration Error: {e}\n")
    except Exception as e:
        sys.stderr.write(f"Failed to start MCP server: {e}\n")

if __name__ == "__main__":
    main()