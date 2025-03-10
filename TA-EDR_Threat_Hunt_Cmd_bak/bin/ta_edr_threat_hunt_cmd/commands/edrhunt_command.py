#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import time
import threading
import queue
import uuid
import datetime
from concurrent.futures import ThreadPoolExecutor

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

# Import our modules
from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
from ta_edr_threat_hunt_cmd.lib.utils.credentials import CredentialManager
from ta_edr_threat_hunt_cmd.lib.utils.config_utils import ConfigManager
from ta_edr_threat_hunt_cmd.lib.utils.rate_limiting import RateLimiter
from ta_edr_threat_hunt_cmd.lib.storage.kvstore import KVStoreManager

# Import provider modules dynamically based on user selection
from ta_edr_threat_hunt_cmd.lib.providers.base import BaseProvider
from ta_edr_threat_hunt_cmd.lib.providers.crowdstrike import CrowdstrikeProvider
from ta_edr_threat_hunt_cmd.lib.providers.sentinelone import SentinelOneProvider
from ta_edr_threat_hunt_cmd.lib.providers.defender import DefenderProvider

@Configuration()
class EDRHuntCommand(StreamingCommand):
    """
    Enhanced EDR Threat Hunting command for retrieving and analyzing endpoint data.
    
    This command retrieves process execution, file, network, and other telemetry data 
    from multiple EDR platforms including CrowdStrike Falcon, SentinelOne, and Microsoft
    Defender for Endpoint. Supports multi-tenancy and multiple consoles per tenant.
    
    Example:
    | makeresults 
    | eval agent_id="12345abcdef" 
    | edrhunt provider="crowdstrike" data_type="processes" time_range="1d" tenant="corporate" console="us"
    
    | inputlookup edr_agents.csv 
    | edrhunt provider="sentinelone" data_type="network" time_range="7d" tenant="emea"
    """
    
    # Available providers
    SUPPORTED_PROVIDERS = ["crowdstrike", "sentinelone", "defender"]
    
    # Supported data types
    SUPPORTED_DATA_TYPES = [
        "summary",         # Basic host information
        "processes",       # Process execution data
        "files",           # File inventory data
        "network",         # Network connection data
        "events",          # Event stream data
        "registry",        # Registry modifications (CrowdStrike only)
        "scripts",         # Script execution data
        "threats",         # Threat/alert data
        "vulnerabilities", # Vulnerability assessment data
        "all"              # Attempt to retrieve all available data
    ]
    
    provider = Option(
        doc='''
        Name of the EDR provider to use. 
        Supported values: "crowdstrike", "sentinelone", "defender"
        ''',
        require=True,
        validate=validators.Set("crowdstrike", "sentinelone", "defender")
    )
    
    tenant = Option(
        doc='''
        Tenant ID for multi-tenant deployments.
        Default is "default".
        ''',
        require=False,
        default="default"
    )
    
    console = Option(
        doc='''
        Console/instance ID when using multiple consoles for the same provider.
        Default is "primary".
        ''',
        require=False,
        default="primary"
    )
    
    agent_id_field = Option(
        doc='''
        Field name containing the agent/device ID.
        Default is "agent_id"
        ''',
        require=False,
        default="agent_id"
    )
    
    hostname_field = Option(
        doc='''
        Field name containing the hostname (used if agent_id not available).
        Default is "hostname"
        ''',
        require=False,
        default="hostname"
    )
    
    data_type = Option(
        doc='''
        Type of data to retrieve.
        Supported values: "summary", "processes", "files", "network", "events", 
                         "registry", "scripts", "threats", "vulnerabilities", "all"
        Default is "summary"
        ''',
        require=False,
        default="summary",
        validate=validators.Set("summary", "processes", "files", "network", "events", 
                              "registry", "scripts", "threats", "vulnerabilities", "all")
    )
    
    time_range = Option(
        doc='''
        Time range for historical data (e.g., "1h", "24h", "7d", "30d").
        Default is "24h"
        ''',
        require=False,
        default="24h"
    )
    
    query = Option(
        doc='''
        Optional query string to filter results. 
        Use provider-specific query syntax.
        ''',
        require=False
    )
    
    threads = Option(
        doc='''
        Number of threads to use for parallel processing (1-16).
        Default is 4.
        ''',
        require=False,
        default=None,
        validate=validators.Integer(1, 16)
    )
    
    max_rate = Option(
        doc='''
        Maximum requests per minute to send to the API.
        Default depends on the provider.
        ''',
        require=False,
        default=None,
        validate=validators.Integer(1)
    )
    
    batch_size = Option(
        doc='''
        Number of records to process in each batch.
        Default is 20.
        ''',
        require=False,
        default=None,
        validate=validators.Integer(1)
    )
    
    limit = Option(
        doc='''
        Maximum number of items to return per agent.
        Default varies by data type.
        ''',
        require=False,
        default=None,
        validate=validators.Integer(1)
    )
    
    lookup_agent = Option(
        doc='''
        Whether to look up agent details from KV Store if not found in the provider.
        Default is false.
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    
    kvstore_collection = Option(
        doc='''
        Name of the KV Store collection to use for agent lookup.
        Default is "edr_agents".
        ''',
        require=False,
        default="edr_agents"
    )
    
    include_raw = Option(
        doc='''
        Whether to include raw response data in the output.
        Default is false (more efficient).
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    
    debug = Option(
        doc='''
        Enable debug logging (true/false).
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    
    def __init__(self):
        super(EDRHuntCommand, self).__init__()
        self.trace_id = str(uuid.uuid4())[:8]
        self.result_queue = queue.Queue()
        self.config = {}
        self.provider_instance = None
        self.metrics = {
            'start_time': time.time(),
            'record_count': 0,
            'success_count': 0,
            'error_count': 0,
            'lookup_count': 0,
            'api_calls': 0,
            'api_errors': 0,
            'rate_limit_waits': 0,
            'total_wait_time': 0
        }
    
    def initialize(self):
        """Initialize the command, setting up components and configuration."""
        # Set up the logger
        self.logger = get_logger('edrhunt')
        
        # Set log level
        if self.debug:
            self.logger.set_level('DEBUG')
        
        # Set context for all logs in this command execution
        self.logger.set_context(
            trace_id=self.trace_id,
            provider=self.provider,
            tenant=self.tenant,
            console=self.console,
            data_type=self.data_type
        )
        
        # Log initialization
        self.logger.info(f"Initializing EDR hunt command for {self.provider}/{self.tenant}/{self.console}")
        
        # Get session key
        self.session_key = self._metadata.searchinfo.session_key
        
        # Create component managers
        self.credential_manager = CredentialManager(self.session_key, self.logger)
        self.config_manager = ConfigManager(self.session_key, self.logger)
        
        # If agent lookup enabled, initialize KV Store manager
        if self.lookup_agent:
            self.kvstore = KVStoreManager(
                self.session_key,
                self.kvstore_collection,
                self.logger
            )
        else:
            self.kvstore = None
        
        # Load command configuration
        self.load_configuration()
        
        # Initialize the appropriate provider
        self.initialize_provider()
        
        # Initialize rate limiter
        self.initialize_rate_limiter()
        
        # Log initialization complete
        self.logger.info(f"Initialization complete. Parameters: data_type={self.data_type}, time_range={self.time_range}, threads={self.threads}, limit={self.limit}")
    
    def load_configuration(self):
        """Load and apply configuration settings."""
        # Get command configuration
        command_config = self.config_manager.get_command_config('edrhunt')
        self.config = command_config
        
        # Apply configuration defaults if not specified in command
        if self.threads is None:
            self.threads = int(command_config.get('default_threads', 4))
            
        if self.batch_size is None:
            self.batch_size = int(command_config.get('default_batch_size', 20))
            
        if self.max_rate is None:
            provider_default = {
                'crowdstrike': 120,
                'sentinelone': 60,
                'defender': 100
            }.get(self.provider.lower(), 100)
            self.max_rate = int(command_config.get(f'{self.provider}_max_rate', provider_default))
            
        if self.limit is None:
            # Default varies by data type
            if self.data_type == "processes":
                self.limit = int(command_config.get('process_limit', 1000))
            elif self.data_type == "events":
                self.limit = int(command_config.get('event_limit', 5000))
            elif self.data_type == "network":
                self.limit = int(command_config.get('network_limit', 1000))
            elif self.data_type == "files":
                self.limit = int(command_config.get('file_limit', 500))
            else:
                self.limit = int(command_config.get('default_limit', 500))
    
    def initialize_provider(self):
        """Initialize the appropriate provider instance."""
        if self.provider.lower() == "crowdstrike":
            self.provider_instance = CrowdstrikeProvider(
                self.tenant, 
                self.console, 
                self.credential_manager, 
                self.config_manager, 
                self.logger
            )
        elif self.provider.lower() == "sentinelone":
            self.provider_instance = SentinelOneProvider(
                self.tenant, 
                self.console, 
                self.credential_manager, 
                self.config_manager, 
                self.logger
            )
        elif self.provider.lower() == "defender":
            self.provider_instance = DefenderProvider(
                self.tenant, 
                self.console, 
                self.credential_manager, 
                self.config_manager, 
                self.logger
            )
        else:
            self.logger.error(f"Unsupported provider: {self.provider}")
            self.provider_instance = None
    
    def initialize_rate_limiter(self):
        """Initialize the rate limiter for API calls."""
        self.rate_limiter = RateLimiter(
            requests_per_minute=self.max_rate,
            burst=int(self.max_rate / 4),  # Allow bursts up to 25% of max rate
            logger=self.logger
        )
    
    def process_record(self, record):
        """
        Process a single record to retrieve EDR data.
        
        Args:
            record (dict): Input record
            
        Returns:
            dict: Processed record with EDR data
        """
        try:
            self.metrics['record_count'] += 1
            
            # Add trace ID for traceability
            record['edr_trace_id'] = self.trace_id
            
            # Get the agent ID from the record
            agent_id = record.get(self.agent_id_field)
            if not agent_id:
                # Try hostname if agent ID not available
                hostname = record.get(self.hostname_field)
                if hostname:
                    # Attempt to resolve hostname to agent ID
                    agent_id = self.resolve_hostname_to_agent_id(hostname)
                    if agent_id:
                        record['resolved_agent_id'] = agent_id
                    else:
                        record['edr_error'] = f"Could not resolve hostname '{hostname}' to agent ID"
                        self.metrics['error_count'] += 1
                        return record
                else:
                    record['edr_error'] = f"No {self.agent_id_field} or {self.hostname_field} found in record"
                    self.metrics['error_count'] += 1
                    return record
            
            # Ensure provider is authenticated
            if not self.provider_instance.ensure_auth():
                record['edr_error'] = f"Authentication failed for {self.provider}/{self.tenant}/{self.console}"
                self.metrics['error_count'] += 1
                return record
            
            # Wait for rate limiting if needed
            wait_time = self.rate_limiter.wait_if_needed(self.provider.lower())
            if wait_time > 0:
                self.metrics['rate_limit_waits'] += 1
                self.metrics['total_wait_time'] += wait_time
                time.sleep(wait_time)
            
            # Process based on data type
            if self.data_type == "summary":
                self.get_agent_summary(agent_id, record)
            elif self.data_type == "processes":
                self.get_processes(agent_id, record)
            elif self.data_type == "files":
                self.get_files(agent_id, record)
            elif self.data_type == "network":
                self.get_network_connections(agent_id, record)
            elif self.data_type == "events":
                # Not fully implemented for all providers yet
                record['edr_data_type'] = "events"
                record['edr_message'] = "Event data retrieval not fully implemented yet"
            elif self.data_type == "registry":
                # CrowdStrike specific
                if self.provider.lower() == "crowdstrike":
                    # Not fully implemented yet
                    record['edr_data_type'] = "registry"
                    record['edr_message'] = "Registry data retrieval not fully implemented yet"
                else:
                    record['edr_error'] = f"Registry data retrieval not supported for {self.provider}"
            elif self.data_type == "scripts":
                # Not fully implemented for all providers yet
                record['edr_data_type'] = "scripts"
                record['edr_message'] = "Script data retrieval not fully implemented yet"
            elif self.data_type == "threats":
                self.get_threats(agent_id, record)
            elif self.data_type == "vulnerabilities":
                # Not fully implemented for all providers yet
                record['edr_data_type'] = "vulnerabilities"
                record['edr_message'] = "Vulnerability data retrieval not fully implemented yet"
            elif self.data_type == "all":
                # Get multiple data types
                self.get_agent_summary(agent_id, record)
                self.get_processes(agent_id, record)
                self.get_network_connections(agent_id, record)
                self.get_files(agent_id, record)
            else:
                record['edr_error'] = f"Unsupported data type: {self.data_type}"
                self.metrics['error_count'] += 1
            
            # Add common fields
            record['edr_provider'] = self.provider
            record['edr_tenant'] = self.tenant
            record['edr_console'] = self.console
            record['edr_data_type'] = self.data_type
            record['edr_time_range'] = self.time_range
            record['edr_agent_id'] = agent_id
            record['edr_query_time'] = datetime.datetime.utcnow().isoformat() + 'Z'
            
            # Check if we were successful
            if 'edr_error' not in record:
                self.metrics['success_count'] += 1
                
            return record
            
        except Exception as e:
            self.logger.error(f"Error processing record: {str(e)}")
            record['edr_error'] = str(e)
            self.metrics['error_count'] += 1
            return record
    
    def resolve_hostname_to_agent_id(self, hostname):
        """
        Resolve a hostname to an agent ID using the provider's API or KV Store.
        
        Args:
            hostname (str): Hostname to resolve
            
        Returns:
            str: Agent ID or None if not found
        """
        self.logger.debug(f"Resolving hostname {hostname} to agent ID")
        
        # First, try to resolve using the provider's API
        try:
            # Wait for rate limiting if needed
            wait_time = self.rate_limiter.wait_if_needed(self.provider.lower())
            if wait_time > 0:
                self.metrics['rate_limit_waits'] += 1
                self.metrics['total_wait_time'] += wait_time
                time.sleep(wait_time)
                
            self.metrics['api_calls'] += 1
            
            # Different providers have different ways to resolve hostname
            # This is a simplified approach assuming the provider's discover_agents method can filter by hostname
            agents = self.provider_instance.discover_agents(limit=10)
            
            for agent in agents:
                if agent.get('hostname', '').lower() == hostname.lower():
                    self.logger.info(f"Resolved hostname {hostname} to agent ID {agent.get('agent_id')}")
                    return agent.get('agent_id')
                    
            # If not found in API, try KV Store if enabled
            if self.lookup_agent and self.kvstore:
                self.metrics['lookup_count'] += 1
                
                # Query KV Store for the hostname
                query = {
                    'hostname': hostname,
                    'provider': self.provider.lower(),
                    'tenant': self.tenant
                }
                
                agents = self.kvstore.query(query)
                
                if agents:
                    self.logger.info(f"Found agent ID {agents[0].get('agent_id')} for hostname {hostname} in KV Store")
                    return agents[0].get('agent_id')
            
            self.logger.warning(f"Could not resolve hostname {hostname} to agent ID")
            return None
            
        except Exception as e:
            self.logger.error(f"Error resolving hostname: {str(e)}")
            self.metrics['api_errors'] += 1
            return None
    
    def get_agent_summary(self, agent_id, record):
        """
        Get agent summary information.
        
        Args:
            agent_id (str): Agent ID
            record (dict): Record to update with summary data
        """
        try:
            # Get agent summary from provider
            self.metrics['api_calls'] += 1
            summary = self.provider_instance.get_agent_summary(agent_id)
            
            if summary:
                # Extract key fields from summary for direct record access
                # Common fields across providers
                record['edr_hostname'] = summary.get('hostname', '')
                record['edr_ip_address'] = summary.get('ip_address', '')
                record['edr_external_ip'] = summary.get('external_ip', '')
                record['edr_os'] = summary.get('os', '')
                record['edr_os_platform'] = summary.get('os_platform', '')
                record['edr_os_version'] = summary.get('os_version', '')
                record['edr_agent_version'] = summary.get('version', '')
                record['edr_status'] = summary.get('status', '')
                record['edr_first_seen'] = summary.get('first_seen', '')
                record['edr_last_seen'] = summary.get('last_seen', '')
                record['edr_mac_address'] = summary.get('mac_address', '')
                
                # Store full summary if include_raw enabled
                if self.include_raw:
                    record['edr_agent_summary'] = json.dumps(summary)
                    
                record['edr_data_retrieved'] = True
            elif self.lookup_agent and self.kvstore:
                # If not found directly, try KV Store
                self.metrics['lookup_count'] += 1
                self.logger.info(f"Agent summary not found directly, trying KV Store lookup for {agent_id}")
                
                # Query KV Store for the agent ID
                kv_agent = self.kvstore.get_item(agent_id)
                
                if kv_agent:
                    # Extract key fields from KV Store data
                    record['edr_hostname'] = kv_agent.get('hostname', '')
                    record['edr_ip_address'] = kv_agent.get('ip_address', '')
                    record['edr_external_ip'] = kv_agent.get('external_ip', '')
                    record['edr_os'] = kv_agent.get('os', '')
                    record['edr_os_platform'] = kv_agent.get('os_platform', '')
                    record['edr_os_version'] = kv_agent.get('os_version', '')
                    record['edr_agent_version'] = kv_agent.get('version', '')
                    record['edr_status'] = kv_agent.get('status', '')
                    record['edr_first_seen'] = kv_agent.get('first_seen', '')
                    record['edr_last_seen'] = kv_agent.get('last_seen', '')
                    record['edr_mac_address'] = kv_agent.get('mac_address', '')
                    
                    record['edr_data_source'] = 'kvstore'
                    record['edr_data_retrieved'] = True
                else:
                    record['edr_error'] = f"No summary found for agent {agent_id}"
                    record['edr_data_retrieved'] = False
            else:
                record['edr_error'] = f"No summary found for agent {agent_id}"
                record['edr_data_retrieved'] = False
                
        except Exception as e:
            self.logger.error(f"Error getting agent summary: {str(e)}")
            record['edr_error'] = f"Error getting agent summary: {str(e)}"
            record['edr_data_retrieved'] = False
            self.metrics['api_errors'] += 1
    
    def get_processes(self, agent_id, record):
        """
        Get process execution data for an agent.
        
        Args:
            agent_id (str): Agent ID
            record (dict): Record to update with process data
        """
        try:
            # Get process data from provider
            self.metrics['api_calls'] += 1
            result = self.provider_instance.get_processes(
                agent_id, 
                self.time_range, 
                self.query, 
                self.limit
            )
            
            if result:
                # Add key fields to record for direct access
                record['edr_process_match'] = result.get('match', False)
                record['edr_process_count'] = result.get('resource_count', 0)
                
                # Add summarized process data
                record['edr_process_names'] = result.get('process_names', [])
                
                # Limit command lines to prevent explosion
                command_lines = result.get('command_lines', [])
                if len(command_lines) > 20:
                    command_lines = command_lines[:20]
                record['edr_command_lines'] = command_lines
                
                # Add hash data depending on what's available
                record['edr_process_hashes'] = result.get('sha256_hashes', result.get('sha1_hashes', []))
                
                # Store full process data if include_raw enabled
                if self.include_raw and 'details' in result:
                    record['edr_processes'] = json.dumps(result['details'])
                    
                record['edr_data_retrieved'] = True
            else:
                record['edr_process_match'] = False
                record['edr_process_count'] = 0
                record['edr_data_retrieved'] = False
                
        except Exception as e:
            self.logger.error(f"Error getting process data: {str(e)}")
            record['edr_error'] = f"Error getting process data: {str(e)}"
            record['edr_data_retrieved'] = False
            self.metrics['api_errors'] += 1
    
    def get_network_connections(self, agent_id, record):
        """
        Get network connection data for an agent.
        
        Args:
            agent_id (str): Agent ID
            record (dict): Record to update with network data
        """
        try:
            # Get network data from provider
            self.metrics['api_calls'] += 1
            result = self.provider_instance.get_network_connections(
                agent_id, 
                self.time_range, 
                self.query, 
                self.limit
            )
            
            if result:
                # Add key fields to record for direct access
                record['edr_network_match'] = result.get('match', False)
                record['edr_network_connection_count'] = result.get('resource_count', 0)
                
                # Add summarized network data
                record['edr_domains'] = result.get('domains', [])
                record['edr_remote_ips'] = result.get('remote_ips', [])
                record['edr_remote_ports'] = result.get('remote_ports', [])
                record['edr_protocols'] = result.get('protocols', [])
                
                # Store full network data if include_raw enabled
                if self.include_raw and 'details' in result:
                    record['edr_network_connections'] = json.dumps(result['details'])
                    
                record['edr_data_retrieved'] = True
            else:
                record['edr_network_match'] = False
                record['edr_network_connection_count'] = 0
                record['edr_data_retrieved'] = False
                
        except Exception as e:
            self.logger.error(f"Error getting network data: {str(e)}")
            record['edr_error'] = f"Error getting network data: {str(e)}"
            record['edr_data_retrieved'] = False
            self.metrics['api_errors'] += 1
    
    def get_files(self, agent_id, record):
        """
        Get file data for an agent.
        
        Args:
            agent_id (str): Agent ID
            record (dict): Record to update with file data
        """
        try:
            # Get file data from provider
            self.metrics['api_calls'] += 1
            result = self.provider_instance.get_files(
                agent_id, 
                self.query, 
                self.limit
            )
            
            if result:
                # Add key fields to record for direct access
                record['edr_file_match'] = result.get('match', False)
                record['edr_file_count'] = result.get('resource_count', 0)
                
                # Add summarized file data
                record['edr_file_paths'] = result.get('file_paths', [])
                record['edr_file_names'] = result.get('file_names', [])
                record['edr_file_hashes'] = result.get('file_sha256', result.get('file_sha1', []))
                
                # Store full file data if include_raw enabled
                if self.include_raw and 'details' in result:
                    record['edr_files'] = json.dumps(result['details'])
                    
                record['edr_data_retrieved'] = True
            else:
                record['edr_file_match'] = False
                record['edr_file_count'] = 0
                record['edr_data_retrieved'] = False
                
        except Exception as e:
            self.logger.error(f"Error getting file data: {str(e)}")
            record['edr_error'] = f"Error getting file data: {str(e)}"
            record['edr_data_retrieved'] = False
            self.metrics['api_errors'] += 1
    
    def get_threats(self, agent_id, record):
        """
        Get threat data for an agent.
        
        Args:
            agent_id (str): Agent ID
            record (dict): Record to update with threat data
        """
        try:
            # Check if provider supports threats method
            if not hasattr(self.provider_instance, 'get_threats'):
                record['edr_error'] = f"Threat data retrieval not supported for {self.provider}"
                record['edr_data_retrieved'] = False
                return
                
            # Get threat data from provider
            self.metrics['api_calls'] += 1
            result = self.provider_instance.get_threats(
                agent_id, 
                self.time_range, 
                self.query, 
                self.limit
            )
            
            if result:
                # Add key fields to record for direct access
                record['edr_threat_match'] = result.get('match', False)
                record['edr_threat_count'] = result.get('resource_count', 0)
                
                # Add summarized threat data
                record['edr_threat_names'] = result.get('threat_names', [])
                record['edr_threat_classifications'] = result.get('classifications', [])
                record['edr_threat_severity'] = result.get('highest_severity', 0)
                
                # Store full threat data if include_raw enabled
                if self.include_raw and 'details' in result:
                    record['edr_threats'] = json.dumps(result['details'])
                    
                record['edr_data_retrieved'] = True
            else:
                record['edr_threat_match'] = False
                record['edr_threat_count'] = 0
                record['edr_data_retrieved'] = False
                
        except Exception as e:
            self.logger.error(f"Error getting threat data: {str(e)}")
            record['edr_error'] = f"Error getting threat data: {str(e)}"
            record['edr_data_retrieved'] = False
            self.metrics['api_errors'] += 1
    
    def process_batch(self, batch, executor):
        """
        Process a batch of records using thread pool.
        
        Args:
            batch (list): List of records to process
            executor (ThreadPoolExecutor): Thread pool executor
            
        Returns:
            list: List of processed records
        """
        # Submit all records to thread pool
        futures = [executor.submit(self.process_record, record) for record in batch]
        
        # Wait for all to complete and get results
        processed_records = []
        for future in futures:
            try:
                processed_records.append(future.result())
            except Exception as e:
                self.logger.error(f"Error processing record in thread pool: {str(e)}")
        
        return processed_records
    
    def stream(self, records):
        """
        Process each record in the pipeline and retrieve EDR data.
        
        Args:
            records (iterable): Input records
            
        Yields:
            dict: Processed records with EDR data
        """
        # Initialize components
        self.initialize()
        
        # Verify provider was initialized successfully
        if not self.provider_instance:
            for record in records:
                record['edr_error'] = f"Failed to initialize provider {self.provider}"
                yield record
            return
        
        # Process records in batches
        batch = []
        batch_count = 0
        
        for record in records:
            # Add record to current batch
            batch.append(record)
            
            # When batch is full, process it
            if len(batch) >= int(self.batch_size):
                batch_count += 1
                self.logger.info(f"Processing batch {batch_count} ({len(batch)} records)")
                
                # Process the batch
                with ThreadPoolExecutor(max_workers=int(self.threads)) as executor:
                    processed_records = self.process_batch(batch, executor)
                
                # Yield processed records
                for processed_record in processed_records:
                    yield processed_record
                
                # Clear batch
                batch = []
        
        # Process any remaining records
        if batch:
            batch_count += 1
            self.logger.info(f"Processing final batch {batch_count} ({len(batch)} records)")
            
            with ThreadPoolExecutor(max_workers=int(self.threads)) as executor:
                processed_records = self.process_batch(batch, executor)
            
            # Yield remaining processed records
            for processed_record in processed_records:
                yield processed_record
        
        # Log summary statistics
        self.log_metrics()
    
    def log_metrics(self):
        """Log performance metrics and summary information."""
        # Calculate elapsed time
        elapsed = time.time() - self.metrics['start_time']
        
        # Calculate records per second
        records_per_second = self.metrics['record_count'] / elapsed if elapsed > 0 else 0
        
        # Metrics summary
        summary = {
            'elapsed_seconds': round(elapsed, 2),
            'record_count': self.metrics['record_count'],
            'success_count': self.metrics['success_count'],
            'error_count': self.metrics['error_count'],
            'lookup_count': self.metrics['lookup_count'],
            'api_calls': self.metrics['api_calls'],
            'api_errors': self.metrics['api_errors'],
            'rate_limit_waits': self.metrics['rate_limit_waits'],
            'total_wait_time': round(self.metrics['total_wait_time'], 2),
            'records_per_second': round(records_per_second, 2)
        }
        
        self.logger.info(f"Command completed: processed {summary['record_count']} records in {summary['elapsed_seconds']}s")
        self.logger.info(f"Results: {summary['success_count']} successes, {summary['error_count']} errors, {summary['lookup_count']} lookups")
        self.logger.info(f"API usage: {summary['api_calls']} calls, {summary['api_errors']} errors, waited {summary['total_wait_time']}s for rate limits")
        self.logger.info(f"Performance: {summary['records_per_second']} records/second")