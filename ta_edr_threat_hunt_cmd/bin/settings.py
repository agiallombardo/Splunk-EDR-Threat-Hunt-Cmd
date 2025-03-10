#
# Copyright 2023 Your Company
#
import bootstrap
import logging

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    MultipleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

util.remove_http_proxy_env_vars()


ta_name = "ta_edr_threat_hunt_cmd"
app_internal_name = "ta_edr_threat_hunt_cmd"

# Define the logging settings fields
fields_logging = [
    field.RestField(
        "enable_logging", required=False, encrypted=False, default="0", 
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "log_level", required=True, encrypted=False, default="INFO", 
        validator=validator.String(
            min_len=4,
            max_len=8,
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        )
    )
]
model_logging = RestModel(fields_logging, name="logging")

# Define the performance settings fields
fields_performance = [
    field.RestField(
        "default_threads", required=True, encrypted=False, default="4",
        validator=validator.Number(
            min_val=1,
            max_val=32
        )
    ),
    field.RestField(
        "default_batch_size", required=True, encrypted=False, default="100",
        validator=validator.Number(
            min_val=10,
            max_val=10000
        )
    ),
    field.RestField(
        "default_limit", required=True, encrypted=False, default="1000",
        validator=validator.Number(
            min_val=1,
            max_val=100000
        )
    ),
    field.RestField(
        "process_limit", required=True, encrypted=False, default="5000",
        validator=validator.Number(
            min_val=1,
            max_val=100000
        )
    ),
    field.RestField(
        "event_limit", required=True, encrypted=False, default="5000",
        validator=validator.Number(
            min_val=1,
            max_val=100000
        )
    ),
    field.RestField(
        "network_limit", required=True, encrypted=False, default="5000",
        validator=validator.Number(
            min_val=1,
            max_val=100000
        )
    ),
    field.RestField(
        "file_limit", required=True, encrypted=False, default="5000",
        validator=validator.Number(
            min_val=1,
            max_val=100000
        )
    ),
    field.RestField(
        "enable_response_compression", required=False, encrypted=False, default="1",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "enable_connection_pooling", required=False, encrypted=False, default="1",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "api_timeout", required=True, encrypted=False, default="300",
        validator=validator.Number(
            min_val=30,
            max_val=1800
        )
    ),
    field.RestField(
        "include_raw_default", required=False, encrypted=False, default="0",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    )
]
model_performance = RestModel(fields_performance, name="performance")

# Define the rate limiting settings fields
fields_rate_limiting = [
    field.RestField(
        "crowdstrike_max_rate", required=True, encrypted=False, default="100",
        validator=validator.Number(
            min_val=1,
            max_val=1000
        )
    ),
    field.RestField(
        "sentinelone_max_rate", required=True, encrypted=False, default="100",
        validator=validator.Number(
            min_val=1,
            max_val=1000
        )
    ),
    field.RestField(
        "defender_max_rate", required=True, encrypted=False, default="100",
        validator=validator.Number(
            min_val=1,
            max_val=1000
        )
    )
]
model_rate_limiting = RestModel(fields_rate_limiting, name="rate_limiting")

# Define the sampling settings fields
fields_sampling = [
    field.RestField(
        "enable_sampling", required=False, encrypted=False, default="0",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "sample_threshold", required=True, encrypted=False, default="10000",
        validator=validator.Number(
            min_val=1000,
            max_val=100000
        )
    ),
    field.RestField(
        "sample_size", required=True, encrypted=False, default="1000",
        validator=validator.Number(
            min_val=100,
            max_val=10000
        )
    )
]
model_sampling = RestModel(fields_sampling, name="sampling")

# Define the cache settings fields
fields_cache = [
    field.RestField(
        "enable_cache", required=False, encrypted=False, default="1",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "cache_expiry", required=True, encrypted=False, default="3600",
        validator=validator.Number(
            min_val=60,
            max_val=86400
        )
    ),
    field.RestField(
        "cache_size_limit", required=True, encrypted=False, default="1000",
        validator=validator.Number(
            min_val=100,
            max_val=10000
        )
    ),
    field.RestField(
        "cache_ttl", required=True, encrypted=False, default="3600",
        validator=validator.Number(
            min_val=60,
            max_val=86400
        )
    )
]
model_cache = RestModel(fields_cache, name="cache")

# Define the KV Store settings fields
fields_kvstore = [
    field.RestField(
        "kvstore_collection", required=True, encrypted=False, default="edr_agents",
        validator=validator.String(
            min_len=1,
            max_len=50
        )
    ),
    field.RestField(
        "agent_ttl", required=True, encrypted=False, default="604800",
        validator=validator.Number(
            min_val=3600,
            max_val=31536000
        )
    ),
    field.RestField(
        "backup_to_csv", required=False, encrypted=False, default="0",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "backup_frequency", required=True, encrypted=False, default="86400",
        validator=validator.Number(
            min_val=3600,
            max_val=604800
        )
    ),
    field.RestField(
        "backup_path", required=False, encrypted=False, default="",
        validator=validator.String(
            min_len=0,
            max_len=200
        )
    ),
    field.RestField(
        "encrypted_fields", required=False, encrypted=False, default="",
        validator=validator.String(
            min_len=0,
            max_len=200
        )
    )
]
model_kvstore = RestModel(fields_kvstore, name="kvstore")

# Define the agent discovery settings fields
fields_agent_discovery = [
    field.RestField(
        "default_scan_interval", required=True, encrypted=False, default="86400",
        validator=validator.Number(
            min_val=3600,
            max_val=604800
        )
    ),
    field.RestField(
        "schedule_scan", required=False, encrypted=False, default="1",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "auto_purge_stale", required=False, encrypted=False, default="1",
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    ),
    field.RestField(
        "stale_threshold", required=True, encrypted=False, default="2592000",
        validator=validator.Number(
            min_val=86400,
            max_val=31536000
        )
    )
]
model_agent_discovery = RestModel(fields_agent_discovery, name="agent_discovery")

# Define all the models in a MultipleModel
endpoint = MultipleModel(
    "ta_edr_threat_hunt_cmd_settings",
    models=[
        model_logging,
        model_performance,
        model_rate_limiting,
        model_sampling,
        model_cache,
        model_kvstore,
        model_agent_discovery
    ],
)


# Import the custom logging utility
try:
    from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
    logger = get_logger(app_internal_name)
except ImportError:
    # Fallback to basic logging if custom logging utility is not available
    logger = logging.getLogger(app_internal_name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.error("Failed to import custom logging utility, using basic logging instead")

class SettingsRestHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=SettingsRestHandler,
    )
