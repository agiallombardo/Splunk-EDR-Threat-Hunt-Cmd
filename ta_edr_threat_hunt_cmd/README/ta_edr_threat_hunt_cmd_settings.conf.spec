# ta_edr_threat_hunt_cmd_settings.conf.spec
#
# This file contains the configuration spec for EDR Threat Hunt Command settings

[logging]
enable_logging = [0|1]
* Enable or disable logging for the app
* Default: 0

log_level = [DEBUG|INFO|WARNING|ERROR|CRITICAL]
* Logging level for the app
* Default: INFO

[performance]
default_threads = <integer>
* Number of threads to use for processing
* Default: 4
* Range: 1-32

default_batch_size = <integer>
* Number of records to process in each batch
* Default: 100
* Range: 10-10000

default_limit = <integer>
* Maximum number of results to return by default
* Default: 1000
* Range: 1-100000

process_limit = <integer>
* Maximum number of process results to return
* Default: 5000
* Range: 1-100000

event_limit = <integer>
* Maximum number of event results to return
* Default: 5000
* Range: 1-100000

network_limit = <integer>
* Maximum number of network results to return
* Default: 5000
* Range: 1-100000

file_limit = <integer>
* Maximum number of file results to return
* Default: 5000
* Range: 1-100000

enable_response_compression = [0|1]
* Enable or disable compression for API responses
* Default: 1

enable_connection_pooling = [0|1]
* Enable or disable connection pooling
* Default: 1

api_timeout = <integer>
* Timeout for API calls in seconds
* Default: 300
* Range: 30-1800

include_raw_default = [0|1]
* Include raw results in command output by default
* Default: 0

[rate_limiting]
crowdstrike_max_rate = <integer>
* Maximum number of CrowdStrike API requests per minute
* Default: 100
* Range: 1-1000

sentinelone_max_rate = <integer>
* Maximum number of SentinelOne API requests per minute
* Default: 100
* Range: 1-1000

defender_max_rate = <integer>
* Maximum number of Microsoft Defender API requests per minute
* Default: 100
* Range: 1-1000

[sampling]
enable_sampling = [0|1]
* Enable or disable data sampling for large result sets
* Default: 0

sample_threshold = <integer>
* Number of results before sampling is applied
* Default: 10000
* Range: 1000-100000

sample_size = <integer>
* Number of results to include in sample
* Default: 1000
* Range: 100-10000

[cache]
enable_cache = [0|1]
* Enable or disable caching of query results
* Default: 1

cache_expiry = <integer>
* Time in seconds before cache entries expire
* Default: 3600
* Range: 60-86400

cache_size_limit = <integer>
* Maximum number of entries in the cache
* Default: 1000
* Range: 100-10000

cache_ttl = <integer>
* Default time-to-live for cache entries in seconds
* Default: 3600
* Range: 60-86400

[kvstore]
kvstore_collection = <string>
* Name of the KV Store collection to use for storing agent information
* Default: edr_agents

agent_ttl = <integer>
* Time-to-live for agent entries in seconds
* Default: 604800
* Range: 3600-31536000

backup_to_csv = [0|1]
* Enable or disable backup of KV Store to CSV
* Default: 0

backup_frequency = <integer>
* Frequency of KV Store backups in seconds
* Default: 86400
* Range: 3600-604800

backup_path = <string>
* Path to store KV Store backups
* Leave empty for default location

encrypted_fields = <string>
* Comma-separated list of fields to encrypt in KV Store
* Leave empty for no encryption

[agent_discovery]
default_scan_interval = <integer>
* Default interval for agent discovery scans in seconds
* Default: 86400
* Range: 3600-604800

schedule_scan = [0|1]
* Enable or disable scheduled agent discovery scans
* Default: 1

auto_purge_stale = [0|1]
* Automatically purge stale agent records
* Default: 1

stale_threshold = <integer>
* Time in seconds before an agent is considered stale
* Default: 2592000
* Range: 86400-31536000
