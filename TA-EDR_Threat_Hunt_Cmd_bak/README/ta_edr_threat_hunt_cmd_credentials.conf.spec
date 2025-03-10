[settings]
# Global settings
enable_logging = [0|1]
log_level = [DEBUG|INFO|WARNING|ERROR|CRITICAL]
default_threads = <integer>
default_batch_size = <integer>
default_limit = <integer>
process_limit = <integer>
event_limit = <integer>
network_limit = <integer>
file_limit = <integer>

# Provider rate limits (requests per minute)
crowdstrike_max_rate = <integer>
sentinelone_max_rate = <integer>
defender_max_rate = <integer>

# Performance optimizations
enable_response_compression = [0|1]
enable_connection_pooling = [0|1]
api_timeout = <integer>
include_raw_default = [0|1]

# Data sampling for large result sets
enable_sampling = [0|1]
sample_threshold = <integer>
sample_size = <integer>

# Cache settings
enable_cache = [0|1]
cache_expiry = <integer>
cache_size_limit = <integer>
cache_ttl = <integer>

# Provider settings - CrowdStrike
crowdstrike_enabled = [0|1]
crowdstrike_api_url = <url>
crowdstrike_api_timeout = <integer>
crowdstrike_api_connect_timeout = <integer>
crowdstrike_api_read_timeout = <integer>
crowdstrike_default_batch_size = <integer>
crowdstrike_default_filter = <string>

# Provider settings - SentinelOne
sentinelone_enabled = [0|1]
sentinelone_api_url = <url>
sentinelone_api_timeout = <integer>
sentinelone_api_connect_timeout = <integer>
sentinelone_api_read_timeout = <integer>
sentinelone_default_batch_size = <integer>
sentinelone_default_filter = <string>

# Provider settings - Defender
defender_enabled = [0|1]
defender_api_url = <url>
defender_api_timeout = <integer>
defender_api_connect_timeout = <integer>
defender_api_read_timeout = <integer>
defender_default_batch_size = <integer>
defender_default_filter = <string>
defender_use_advanced_hunting = [0|1]

# KV Store settings
kvstore_collection = <string>
agent_ttl = <integer>
backup_to_csv = [0|1]
backup_frequency = <integer>
backup_path = <string>
encrypted_fields = <comma-separated-list>

# Agent discovery settings
default_scan_interval = <integer>
schedule_scan = [0|1]
auto_purge_stale = [0|1]
stale_threshold = <integer>