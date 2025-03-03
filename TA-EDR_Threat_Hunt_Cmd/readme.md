# EDR Threat Hunting Command for Splunk

This Splunk app provides a custom search command `edrhunt` for retrieving and analyzing endpoint telemetry data from CrowdStrike Falcon and SentinelOne for threat hunting and investigation based on agent discovery.

## Author
Anthony Giallombardo & Assistant Claude

## System Overview

The system consists of two main components:

1. **Agent Discovery System**: Automatically discovers and tracks EDR agents from CrowdStrike and SentinelOne
   - Uses KV Store for persistent agent information tracking
   - Provides scheduled searches for regular updates
   - Enables easy filtering and selection of endpoints

2. **EDR Hunting Command**: A custom search command for retrieving and analyzing endpoint telemetry
   - Queries processes, files, network connections, and events from endpoints
   - Supports both CrowdStrike Falcon and SentinelOne platforms
   - Provides rich filtering and data extraction capabilities

## Key Features

### Automated Agent Discovery

- **Discover agents automatically** from CrowdStrike and SentinelOne
- **Store agent information** in a KV Store-backed lookup table
- **Schedule regular updates** to maintain an accurate inventory
- **Track agent status and metadata** (hostname, IP, OS, version, etc.)
- **Automatic cleanup** of stale agents based on configurable TTL

### EDR Telemetry Hunting

- **Query comprehensive endpoint data** including:
  - Process executions with command lines
  - File information and metadata
  - Network connections and destinations
  - Registry modifications (CrowdStrike only)
  - Script executions
  - Event timeline data
- **Support for both major EDR platforms**
- **Multi-threading** for parallel processing of multiple endpoints
- **Configurable time ranges** for historical data analysis
- **Advanced query filtering** for precise data retrieval

## Installation

1. Install the app from Splunkbase or manually upload the app package to your Splunk instance
2. Restart Splunk
3. Go to the app's setup page to configure API credentials and settings
4. Verify connections with the test buttons
5. The scheduled searches will automatically start populating the agent lookup table

## Configuration

### API Credentials

- **CrowdStrike**: Enter your Client ID and Client Secret
- **SentinelOne**: Enter your Username and Password

### API Settings

- **API URL**: The base URL for the API service (default values should work for most deployments)
- **Rate Limit**: Maximum number of requests per minute
- **Request Timeout**: Timeout in seconds for API requests

### Command Defaults

- **Default Thread Count**: Number of threads for parallel processing
- **Default Batch Size**: Number of records to process in each batch
- **Default Max Rate**: Default maximum request rate
- **Default Result Limit**: Maximum number of results to return per agent

## Agent Discovery Usage

The `agentdiscovery` command manages the agent inventory:

### Manual Agent Discovery

```
| makeresults count=1
| fields - _time _raw
| agentdiscovery provider="crowdstrike" operation="discover" limit=100
| table agent_id hostname os status last_seen ip_address
```

### Update Agent Inventory

```
| makeresults count=1
| fields - _time _raw
| agentdiscovery provider="crowdstrike" operation="update" limit=1000
```

### List Agents from Inventory

```
| makeresults count=1
| fields - _time _raw
| agentdiscovery provider="crowdstrike" operation="list"
| table agent_id hostname os status last_seen
```

### Purge Agent Inventory

```
| makeresults count=1
| fields - _time _raw
| agentdiscovery provider="crowdstrike" operation="purge"
```

## EDR Hunting Usage

The `edrhunt` command retrieves endpoint telemetry and works seamlessly with the agent lookup:

### Basic Usage with Agent Lookup

```
| inputlookup edr_agents_lookup
| search hostname="*FINANCE*" AND provider="crowdstrike"
| edrhunt provider="crowdstrike" data_type="processes" time_range="24h"
| table hostname edr_process_names edr_command_lines
```

### Process Investigation

```
| inputlookup edr_agents_lookup
| search os="*Windows*" AND status="active"
| edrhunt provider="crowdstrike" data_type="processes" time_range="12h" 
| search edr_process_names="*powershell.exe*" OR edr_process_names="*cmd.exe*"
| table hostname edr_command_lines
```

### Network Connections Analysis

```
| inputlookup edr_agents_lookup
| search provider="sentinelone" 
| head 10
| edrhunt provider="sentinelone" data_type="network" time_range="7d"
| search edr_remote_ports="445" OR edr_remote_ports="3389"
| stats count by hostname edr_remote_ips edr_remote_ports
```

### Multi-data Investigation

```
| inputlookup edr_agents_lookup
| search hostname="DC-MAIN-01" 
| edrhunt provider="crowdstrike" data_type="all" time_range="24h"
| table hostname edr_process_count edr_network_event_count
```

## Agent Discovery Parameters

- **provider** (required): Which EDR to query (`crowdstrike` or `sentinelone`)
- **operation** (optional): Operation to perform (`discover`, `update`, `list`, `purge`) (default: `update`)
- **limit** (optional): Maximum number of agents to discover (default: 1000)
- **collection** (optional): Name of the KV Store collection to use (default: `edr_agents`)
- **ttl** (optional): Time-to-live in days for agent records (default: 7)

## EDR Hunting Parameters

- **provider** (required): Which EDR to query (`crowdstrike` or `sentinelone`)
- **agent_id_field** (optional): Field containing the agent/device ID (default: "agent_id")
- **hostname_field** (optional): Field containing the hostname (default: "hostname")
- **data_type** (optional): Type of data to retrieve (default: "summary")
  - **"summary"**: Basic host information
  - **"processes"**: Process execution data
  - **"files"**: File inventory data
  - **"network"**: Network connection data
  - **"events"**: Event stream data
  - **"registry"**: Registry modifications (CrowdStrike only)
  - **"scripts"**: Script execution data
  - **"vulnerabilities"**: Vulnerability assessment data
  - **"all"**: Retrieve all available data types
- **time_range** (optional): Time range for historical data (e.g., "1h", "24h", "7d", "30d") (default: "24h")
- **query** (optional): Query string to filter results using provider-specific syntax
- **threads** (optional): Number of threads to use (1-16, default from settings)
- **batch_size** (optional): Number of records to process in each batch
- **max_rate** (optional): Maximum requests per minute
- **limit** (optional): Maximum number of items to return per agent
- **debug** (optional): Enable debug logging

## Scheduled Searches

The app includes three scheduled searches:

1. **Daily CrowdStrike Agent Discovery**: Runs at 1 AM to update the agent inventory with CrowdStrike agents
2. **Daily SentinelOne Agent Discovery**: Runs at 2 AM to update the agent inventory with SentinelOne agents
3. **Weekly Agent Cleanup**: Runs every Sunday at 3 AM to remove stale agents from the inventory

## Advanced Use Cases

### 1. Process Chain Analysis

Detect suspicious process chains:

```
| inputlookup edr_agents_lookup
| search os="*Windows*"
| edrhunt provider="crowdstrike" data_type="processes" time_range="24h"
| spath input=edr_processes path=process_name output=process_name
| spath input=edr_processes path=parent_process_name output=parent_process_name
| search parent_process_name IN ("winword.exe", "excel.exe", "outlook.exe", "POWERPNT.EXE") 
        AND process_name IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| stats count by hostname parent_process_name process_name
| sort -count
```

### 2. Unusual Network Connections

Identify rare or suspicious outbound connections:

```
| inputlookup edr_agents_lookup
| search provider="crowdstrike"
| edrhunt provider="crowdstrike" data_type="network" time_range="7d"
| mvexpand edr_remote_ips
| search NOT edr_remote_ips IN (10.*, 172.16.*, 192.168.*)
| stats count by hostname edr_remote_ips edr_remote_ports
| rare edr_remote_ips limit=20
```

### 3. Living Off the Land Detection

Find use of legitimate tools for potentially malicious purposes:

```
| inputlookup edr_agents_lookup
| search os="*Windows*"
| edrhunt provider="crowdstrike" data_type="processes" time_range="24h"
| spath input=edr_command_lines
| search 
    (edr_command_lines="*certutil*" AND (edr_command_lines="*encode*" OR edr_command_lines="*decode*" OR edr_command_lines="*urlcache*")) OR
    (edr_command_lines="*wmic*" AND edr_command_lines="*process call create*") OR
    (edr_command_lines="*regsvr32*" AND edr_command_lines="*/s*" AND edr_command_lines="*/u*") OR
    (edr_command_lines="*msiexec*" AND edr_command_lines="*/q*")
| table hostname edr_command_lines
```

## Integration with Asset Information

You can join the agent lookup with asset information for context:

```
| inputlookup edr_agents_lookup 
| lookup asset_inventory hostname OUTPUT department criticality owner
| search criticality="high"
| edrhunt provider="crowdstrike" data_type="summary"
| table hostname department criticality owner edr_status edr_last_seen
```

## Troubleshooting

- **Enable debug logging** in the setup page
- **Run the agent discovery in 'discover' mode** to test without updating the lookup
- **Check Splunk logs** at `$SPLUNK_HOME/var/log/splunk/edrhunt.log`
- **Verify KV Store health** with `| rest /services/kvstore/status`
- **Test API connections** using the test buttons in the setup page

## Required API Permissions

### CrowdStrike
- **OAuth Scopes**:
  - `device:read`
  - `event-service:read`
  - `indicator:read`

### SentinelOne
- **API Permissions**:
  - `Activities: View Data`
  - `Agents: View Data`
  - `Deep Visibility: View Data`


## Support

For questions or support, please contact the author https://github.com/agiallombardo.

## License

This app is licensed under the GNU GPL v3.