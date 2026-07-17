# src/resources/insights.py

INSIGHTS_SCHEMA_URI = "resource://ctd/insights-schema"
    
INSIGHTS_SCHEMA_DOCS = """# CTD Insights Search Schema and Guide

This document provides the allowed fields, filters, and enums for the `search_insights` tool.

## 1. Default Parameters Do not pass these unless overriding default behavior:
* `site_id__exact`: `1`
* `ghost__exact`: `false` (Excludes ghost/receive-only assets)
* `special_hint__exact`: `0` (Defaults to unicast. Enums: 0=unicast, 1=broadcast, 2=multicast, 3=out of scope, 4=external)
* `insight_status__exact`: `0` (Defaults to Open insights. Enums: 0=Open, 1=Hidden, 2=Completed)

---

## 2. Allowed Search Filters
Use these keys in the `filters` dictionary. Match the data types exactly.
For any filter marked with **Enums**, pass a single value or an array of multiple values to perform an "OR" search (e.g., `"criticality__exact": [1, 2]`).

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `insight_status__exact` | Integer | Status of the insight. **Enums:** `0` (Open), `1` (Hidden), `2` (Completed). | `0` |
| `asset_type__exact` | Integer | Asset classification ID. *(See Asset Type **Enums** below)* | `12` |
| `vendor__icontains` | String | Partial or full hardware vendor name match. | `"Rockwell"` |
| `protocol__exact` | String | Exact network protocol match. | `"Modbus"` |
| `criticality__exact` | Integer | Asset operational criticality. **Enums:** `0` (eLow), `1` (eMedium), `2` (eHigh). | `[1, 2]` |
| `class_type__exact` | Integer | Asset class ID. **Enums:** `0` (OT), `1` (IT), `2` (IoT). | `0` |
| `insight_excluded_types__in` | Integer | Exclude specific insight types by ID. Accepts multiple IDs. *(See Insight Types below)* | `[1, 2]` |

---

## 3. Master List of Insight Types
Use the **Insight Name** (exact string match) for the `exact_insight` tool parameter to filter by a specific insight. Use the **ID** integer for the `insight_excluded_types__in` filter to exclude specific insight types. 

| ID | Insight Name | ID | Insight Name |
| :--- | :--- | :--- | :--- |
| `1` | Windows CVEs | `18` | Assets Accessed SMB shares |
| `2` | Full Match CVEs | `19` | SNMP Querying Assets |
| `3` | Model Match CVEs | `20` | Unsecured Protocols |
| `4` | Vendor Match CVEs | `21` | Web Servers |
| `5` | Top Risky Assets | `22` | Data Acquisition Write (Operated PLCs) |
| `6` | DHCP Clients | `23` | Windows CVEs Full Match |
| `8` | Talking with External IPs | `24` | Program Match CVEs |
| `9` | Files Downloaded (clients) | `25` | SMBv1 Negotiate |
| `10` | Talking with Ghost Assets | `27` | PLCs talking IT protocol |
| `11` | Multiple Interfaces | `28` | Remote desktop application |
| `12` | Highly Connected Assets | `29` | USB devices connected to assets |
| `13` | Open Ports | `30` | Assets with partial connection to the internet |
| `14` | Privileged Operations (Operated PLCs) | `31` | Using unencrypted and weak passwords |
| `15` | Clients remotely managed | `32` | PLCs exposed to program changes |
| `16` | Managed PLCs (by Rockwell users) | `33` | PLCs exposed to Triton |
| `17` | Assets accessing SMB Pipes | `34` | End Of Life Assets |
| | | `35` | Unsupported OS |

---

## 4. Asset Type Enums (`asset_type__exact`)
When filtering by asset type, use the corresponding Integer value from this table:

| ID | Asset Type | ID | Asset Type | ID | Asset Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0` | ePLC | `1` | eHMI | `2` | eEndpoint |
| `3` | eNetworking | `4` | eBroadcast | `5` | eDomainController |
| `6` | ePrinter | `7` | eSCADAClient | `8` | eSCADAServer |
| `9` | eHistorian | `10` | eFileServer | `11` | eRouter |
| `12` | eSwitch | `13` | eRemoteIO | `14` | eEngineeringStation |
| `15` | eGateway | `16` | eOPCServer | `17` | eOT |
| `18` | eRTU | `19` | eIED | `20` | eController |
| `21` | eNTPServer | `22` | eUserConsole | `23` | eUserWorkstation |
| `24` | eTerminalServer | `25` | eSyslogServer | `26` | eFrontEndProcessor |
| `27` | eModem | `28` | eProxyServer | `29` | eReverseProxyServer |
| `30` | eNetworkAccessStorage | `31` | eFirewall | `32` | eAVServer |
| `33` | eADServer | `34` | eWebServer | `35` | eDBServer |
| `36` | eStorageArray | `37` | eGPSClock | `38` | eSCADAMaster |
| `39` | eVoipPhone | `40` | eTVScreen | `41` | eBluetoothDevice |
| `42` | eCamera | `43` | eVendingMachine | `44` | eSmartPhone |
| `45` | eSmartWatch | `46` | eInfusionPump | `47` | eMedicalDevice |
| `48` | eBarcodeScanner | `49` | eMicroscope | `50` | eAccessControl |
| `51` | eSmartLight | `52` | eStreamer | `53` | eHomeAssistant |
| `54` | eMediaServer | `55` | eCleaningDevice | `56` | eVoipServer |
| `57` | eRobot | `58` | eAutonomousVehicle | `59` | eWirelessLanController |
| `60` | eAccessPoint | `61` | eAAAServer | `62` | eGPSDevice |
| `63` | eUPS | `64` | eVideoRecorder | `65` | eVirtualizationServer |
| `66` | eDataLogger | `67` | eSensor | `68` | eElectricalDrive |
| `69` | eMotorStarter | `70` | eVulnerabilityScanner | `71` | eVOIPAccessPoint |
| `72` | eSNMPServer | `73` | eSNMPScanner | `74` | eBiometricScanner |
| `75` | eDNSServer | `76` | eVisionCamera | `77` | eBarcodeReader |
| `78` | eVisionController | `79` | eVisionSensor | `80` | eRTLS |
| `81` | eCNC | `82` | eCNCMill | `83` | eCNCLathe |
| `84` | eAnalysisStation | `85` | eWeightSensor | `86` | eXRayCargoScanner |
"""