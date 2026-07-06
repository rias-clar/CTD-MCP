import json
from mcp.server.fastmcp import FastMCP

def register_assets_resource(mcp: FastMCP) -> None:
    @mcp.resource("resource://ctd/assets-schema")
    def get_assets_schema() -> str:
        """
        Master schema for the CTD search_assets tool.
        Contains all allowed 'filters' keys and return 'fields'.
        """
        schema = {
            "search_assets_allowed_fields": [
                "id", "site_id", "resource_id", "timestamp", "last_updated", "name", 
                "approved", "valid", "ghost", "risk_level", "site_name", "network_id", 
                "subnet_id", "virtual_zone_id", "virtual_zone_name", "purdue_level", 
                "first_seen", "ipv4", "ipv6", "mac", "vlan", "gateway", "asset_type", 
                "class_type", "hostname", "os", "model", "vendor", "plc_slots", 
                "firmware", "serial_number", "criticality", "domain_workgroup", 
                "default_gateway", "edge_id", "installed_antivirus", "state", 
                "patch_count", "installed_programs_count", "os_build", "os_architecture", 
                "os_service_pack", "display_name", "protocol", "last_seen", "num_alerts", 
                "insight_names", "risk_score"
            ],
            
            "search_assets_allowed_filters": {
                "q__icontains": {"type": "string", "desc": "Global free-text search across Name, IP, Version, Model, and MAC."},
                "ipv4__exact": {"type": "string", "desc": "Exact IPv4 address"},
                "ipv6__exact": {"type": "string", "desc": "Exact IPv6 address"},
                "mac__icontains": {"type": "string", "desc": "MAC address (contains text)"},
                "vlan__exact": {"type": "string", "desc": "Exact VLAN identifier"},
                "gateway__exact": {"type": "string", "desc": "Exact Gateway IP address"},
                "asset_type__exact": {"type": "string", "desc": "Specific classification (e.g., ePLC=0, eHMI=1, eSwitch=12)"},
                "class_type__exact": {"type": "string", "desc": "Asset class (IT, OT, IoT)"},
                "host_name__exact": {"type": "string", "desc": "Exact host name"},
                "display_name__icontains": {"type": "string", "desc": "Display name (contains text)"},
                "domain_name__exact": {"type": "string", "desc": "Exact domain name"},
                "os__exact": {"type": "string", "desc": "Exact operating system name"},
                "model__icontains": {"type": "string", "desc": "Hardware model (contains text)"},
                "vendor__icontains": {"type": "string", "desc": "Hardware vendor (contains text)"},
                "firmware__exact": {"type": "string", "desc": "Exact firmware version"},
                "serial__exact": {"type": "string", "desc": "Exact serial number"},
                "protocol__exact": {"type": "string", "desc": "Protocol used (e.g., Modbus, DNP3)"},
                "risk_level__exact": {"type": "integer", "desc": "Exact risk score integer"},
                "criticality__exact": {"type": "string", "desc": "Exact criticality level (eLow=0, eMedium=1, eHigh=2)"},
                "purdue_level__exact": {"type": "string", "desc": "Exact Purdue model level (e.g. 1.5, 3)"},
                "ghost__exact": {"type": "boolean", "desc": "True if this is a ghost asset (receive only). Defaults to False."},
                "last_seen__exact": {"type": "string", "desc": "Timestamp of last instance seen"},
                "last_updated__gt": {"type": "string", "desc": "Timestamp (YYYY-MM-DDTHH:MM:SS) for finding assets modified after this date"},
                "approved__exact": {"type": "boolean", "desc": "True if the asset is approved"},
                "valid__exact": {"type": "boolean", "desc": "True if the asset is valid. Defaults to True."},
                "id__exact": {"type": "integer", "desc": "Internal unique identifier"},
                "site_id__exact": {"type": "integer", "desc": "Identifier of the site"},
                "network_id__exact": {"type": "integer", "desc": "Identifier of the network"},
                "subnet_id__exact": {"type": "integer", "desc": "Identifier of the subnet"},
                "virtual_zone_id__exact": {"type": "integer", "desc": "Identifier of the virtual zone"}
            }
        }
        return json.dumps(schema, indent=2)