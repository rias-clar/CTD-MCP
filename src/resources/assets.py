
#src/resources/assets.py

ASSETS_SCHEMA_URI = "resource://ctd/assets-schema"
    
ASSETS_SCHEMA_DOCS = """# CTD Assets Search Schema and Guide

This document provides the allowed fields, filters, and enums for the `search_assets` tool.

## 1. Default Parameters
Unless otherwise specified by the user, the tool automatically applies these default search filters. You do not need to pass these unless you want to override the default behavior:
* `ghost__exact`: `false` (Excludes ghost/receive-only assets)
* `valid__exact`: `true` (Only returns valid assets)
* `approved__exact`: `true` (Only returns approved assets)
* `special_hint__exact`: `0` (Defaults to unicast. Enums: 0=unicast, 1=broadcast, 2=multicast, 3=out of scope, 4=external)

---

## 2. Allowed Search Filters
Use these keys in the `filters` dictionary. Match the data types exactly.

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `ipv4__exact` | String | Exact IPv4 address. | `"192.168.1.50"` |
| `ipv6__exact` | String | Exact IPv6 address. | `"2001:0db8:85a3::8a2e:0370:7334"` |
| `mac__icontains` | String | Partial or full MAC address. | `"00:1A:2B"` or `"00:1A:2B:3C:4D:5E"` |
| `vlan__exact` | String | Exact VLAN identifier. | `"100"` |
| `asset_type__exact` | Integer | Specific asset classification ID. *(See Asset Type Enums below)* | `12` (for eSwitch) |
| `class_type__exact` | Integer | Asset class ID. **Enums:** `0` (OT), `1` (IT), `2` (IoT). | `0` |
| `display_name__icontains` | String | Matches asset name, hostname, or display name. | `"Engineering Workstation"` |
| `os__exact` | String | Exact operating system name. | `"Windows 10"` |
| `model__icontains` | String | Hardware model name. | `"ControlLogix"` |
| `vendor__icontains` | String | Hardware vendor name. | `"Rockwell"` or `"Siemens"` |
| `firmware__exact` | String | Exact firmware version. | `"v20.011"` |
| `serial__exact` | String | Exact hardware serial number. | `"SN-12345678"` |
| `protocol__exact` | String | Network protocol used. | `"Modbus"` or `"DNP3"` |
| `risk_level__exact` | Integer | CTD calculated risk for asset, based on vulnerabilities, insights, alerts, etc. **Enums:** `0` (Low), `1` (Medium), `2` (High), `3` (Critical). | `3` |
| `criticality__exact` | Integer | Value representing how critical the asset is to the operation/environment. **Enums:** `0` (eLow), `1` (eMedium), `2` (eHigh). | `2` |
| `purdue_level__exact`| String | Purdue model level. **Enums:** `"0"`, `"1"`, `"1.5"`, `"2"`, `"2.5"`, `"3"`, `"3.5"`, `"4"`, `"5"`, `"6"`. | `"3"` |
| `last_seen__exact` | String | ISO 8601 Timestamp of last observation. | `"2023-10-27T10:00:00Z"` |
| `site_id__exact` | Integer | Unique identifier for the physical/logical site. | `1` |
| `special_hint__exact` | Integer | Address type of the asset. **Enums:** `0` (unicast), `1` (broadcast), `2` (multicast), `3` (out of scope), `4` (external). | `0` |


---

## 3. Allowed Return Fields
Only request the fields necessary to answer the user's prompt. Do not request fields that are not in this list. 
**Note:** If you do not provide a `fields` list, the system will default to returning: `id`, `name`, `ipv4`, `ipv6`, `mac`, `vendor`, `model`, `firmware`, `asset_type`, and `risk_level`.

* **Identity:** `id`, `name`, `display_name`, `hostname`, `mac`, `serial_number`
* **Network:** `ipv4`, `ipv6`, `vlan`, `gateway`, `default_gateway`, `network_id`, `subnet_id`, `protocol`
* **Classification:** `vendor`, `model`, `firmware`, `asset_type`, `class_type`, `os`, `os_build`, `os_architecture`, `os_service_pack`
* **Location/Topology:** `site_id`, `site_name`, `virtual_zone_id`, `virtual_zone_name`, `purdue_level`, `edge_id`
* **Risk & Posture:** `risk_level`, `risk_score`, `criticality`, `num_alerts`, `insight_names`
* **Software/State:** `installed_antivirus`, `patch_count`, `installed_programs_count`, `plc_slots`, `state`, `domain_workgroup`
* **Status:** `approved`, `valid`, `ghost`, `timestamp`, `first_seen`, `last_seen`
* **Details/Custom Information:** `custom_informations`, `custom_attributes`

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
