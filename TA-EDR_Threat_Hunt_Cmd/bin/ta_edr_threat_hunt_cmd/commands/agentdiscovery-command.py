#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import time
import datetime
import uuid
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

# Import our modules
from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
from ta_edr_threat_hunt_cmd.lib.utils.credentials import CredentialManager
from ta_edr_threat_hunt_cmd.lib.utils.config_utils import ConfigManager
from ta_edr_threat_hunt_cmd.lib.storage.kvstore import KVStoreManager

# Import provider modules dynamically based on user selection
from ta_edr_threat_hunt_cmd.lib.providers.base import BaseProvider
from ta_edr_threat_hunt_cmd.lib.providers.crowdstrike import CrowdstrikeProvider
from ta_edr_threat_hunt_cmd.lib.providers.sentinelone import SentinelOneProvider
from ta_edr_threat_hunt_cmd.lib.providers.defender import DefenderProvider

@Configuration()
class AgentDiscoveryCommand(StreamingCommand):
    """
    Enhanced agent discovery command with multi-tenancy support.
    
    This command discovers and manages EDR agents from CrowdStrike, SentinelOne, 
    and Microsoft Defender for Endpoint, with support for multiple tenants and consoles.
    
    Examples:
    | agentdiscovery provider="crowdstrike" tenant="corporate" console="us" operation="update"
    | agentdiscovery provider="defender" tenant="emea" operation="discover" limit=100
    | agentdiscovery provider="sentinelone" operation="list" tenant="*"
    """
    
    # Command options
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
        Use "*" to work with all tenants.
        Default is "default".
        ''',
        require=False,
        default="default"
    )
    
    console = Option(
        doc='''
        Console/instance ID when using multiple consoles for the same provider.
        Use "*" to work with all consoles for the specified tenant(s) and provider.
        Default is "primary".
        ''',
        require=False,
        default="primary"
    )
    
    operation = Option(
        doc='''
        Operation to perform on the agent lookup:
        - "discover": Discover agents but don't update the lookup
        - "update": Discover agents and update the lookup (default)
        - "list": List agents from the lookup without discovery
        - "purge": Delete agents from the lookup
        ''',
        require=False,
        default="update",
        validate=validators.Set("discover", "update", "list", "purge")
    )
    
    limit = Option(
        doc='''
        Maximum number of agents to discover per tenant/console.
        Default is 1000.
        ''',
        require=False,
        default=1000,
        validate=validators.Integer(0)
    )
    
    collection = Option(
        doc='''
        Name of the KV Store collection to use.
        Default is "edr_agents".
        ''',
        require=False,
        default="edr_agents"
    )
    
    ttl = Option(
        doc='''
        Time-to-live in days for agent records.
        Agents not updated within this period will be removed.
        Default is 7 days.
        ''',
        require=False,
        default=7,
        validate=validators.Integer(1)
    )
    
    debug = Option(
        doc='''
        Enable debug logging (true/false).
        ''',
        require=False,
        default=False
    )
    
    def __init__(self):
        super(AgentDiscoveryCommand, self).__init__()
        self.trace_id = str(uuid.uuid4())[:8]
        self.result_queue = []
        
    def initialize(self):
        """Initialize the command, setting up components and configuration."""
        # Set up the logger
        self.logger = get_logger('agentdiscovery')
        
        # Set log level
        if self.debug:
            self.logger.set_level('DEBUG')
        
        # Set context for all logs in this command execution
        self.logger.set_context(
            trace_id=self.trace_id,
            provider=self.provider,
            tenant=self.tenant,
            console=self.console,
            operation=self.operation
        )
        
        # Log initialization
        self.logger.info(f"Initializing agent discovery command")
        
        # Get session key
        self.session_key = self._metadata.searchinfo.session_key
        
        # Create component managers
        self.credential_manager = CredentialManager(self.session_key, self.logger)
        self.config_manager = ConfigManager(self.session_key, self.logger)
        self.kvstore_manager = KVStoreManager(
            self.session_key,
            self.collection,
            self.logger
        )
        
        # Log configuration
        self.logger.debug(f"Command parameters: limit={self.limit}, ttl={self.ttl}, collection={self.collection}")
        
        # Get list of tenants to process
        if self.tenant == "*":
            self.tenants = self.config_manager.get_tenants()
            self.logger.info(f"Processing all tenants: {', '.join(self.tenants)}")
        else:
            self.tenants = [self.tenant]
            
        # Get list of consoles to process
        if self.console == "*":
            # Will be determined per tenant later
            self.consoles = {}
        else:
            # Same console for all tenants
            self.consoles = {tenant: [self.console] for tenant in self.tenants}
            
        # Initialize provider cache
        self.provider_instances = {}
    
    def get_provider(self, tenant, console):
        """
        Get the appropriate provider instance with caching.
        
        Args:
            tenant: Tenant ID
            console: Console ID
            
        Returns:
            Provider instance
        """
        cache_key = f"{tenant}:{console}"
        
        if cache_key in self.provider_instances:
            return self.provider_instances[cache_key]
            
        # Create a new provider instance
        if self.provider.lower() == "crowdstrike":
            provider = CrowdstrikeProvider(tenant, console, self.credential_manager, self.config_manager, self.logger)
        elif self.provider.lower() == "sentinelone":
            provider = SentinelOneProvider(tenant, console, self.credential_manager, self.config_manager, self.logger)
        elif self.provider.lower() == "defender":
            provider = DefenderProvider(tenant, console, self.credential_manager, self.config_manager, self.logger)
        else:
            self.logger.error(f"Unsupported provider: {self.provider}")
            return None
            
        # Cache the provider
        self.provider_instances[cache_key] = provider
        return provider
    
    def discover_agents(self, tenant, console):
        """
        Discover agents from a specific tenant and console.
        
        Args:
            tenant: Tenant identifier
            console: Console identifier
            
        Returns:
            list: List of agent dictionaries
        """
        provider = self.get_provider(tenant, console)
        if not provider:
            self.logger.error(f"Failed to create provider for {tenant}/{console}")
            return []
            
        # Set thread context for logging
        self.logger.set_thread_context(tenant=tenant, console=console)
            
        try:
            # Start timing
            start_time = time.time()
            
            # Authenticate
            if not provider.authenticate():
                self.logger.error(f"Authentication failed for {provider}")
                return []
                
            # Discover agents
            agents = provider.discover_agents(limit=int(self.limit))
            
            # Calculate elapsed time
            elapsed = time.time() - start_time
            
            # Annotate agents with tenant and console info if not already present
            for agent in agents:
                if 'tenant' not in agent:
                    agent['tenant'] = tenant
                if 'console' not in agent:
                    agent['console'] = console
                if 'provider' not in agent:
                    agent['provider'] = self.provider.lower()
                
            self.logger.info(f"Discovered {len(agents)} agents from {provider} in {elapsed:.2f}s")
            return agents
            
        except Exception as e:
            self.logger.error(f"Error discovering agents from {provider}: {str(e)}")
            return []
    
    def update_kvstore(self, agents):
        """
        Update the KV Store collection with agent information.
        
        Args:
            agents: List of agent dictionaries
            
        Returns:
            dict: Summary of update operations
        """
        try:
            # Make sure collection exists
            if not self.kvstore_manager.check_collection_exists():
                self.logger.info(f"Creating KV Store collection: {self.collection}")
                self.kvstore_manager.create_collection()
            
            # Get existing agents for comparison
            existing_agents = self.kvstore_manager.get_all_items()
            existing_keys = {a.get('_key') for a in existing_agents if a.get('_key')}
            
            # Prepare for batch operations
            to_update = []
            to_create = []
            
            for agent in agents:
                # Ensure agent has _key field
                if '_key' not in agent and 'agent_id' in agent:
                    agent['_key'] = agent['agent_id']
                
                if agent.get('_key') in existing_keys:
                    to_update.append(agent)
                else:
                    to_create.append(agent)
            
            # Perform batch operations
            created_count = 0
            updated_count = 0
            
            if to_create:
                self.logger.info(f"Creating {len(to_create)} new agent records")
                created_count = self.kvstore_manager.batch_create(to_create)
                
            if to_update:
                self.logger.info(f"Updating {len(to_update)} existing agent records")
                updated_count = self.kvstore_manager.batch_update(to_update)
                
            # Remove stale agents based on TTL
            removed_count = self.kvstore_manager.remove_stale_items('updated_at', int(self.ttl))
            
            return {
                'created': created_count,
                'updated': updated_count,
                'removed': removed_count,
                'total': created_count + updated_count
            }
            
        except Exception as e:
            self.logger.error(f"Error updating KV Store: {str(e)}")
            return {
                'created': 0,
                'updated': 0,
                'removed': 0,
                'total': 0,
                'error': str(e)
            }
    
    def list_agents(self, tenant=None, console=None, provider=None):
        """
        List agents from the KV Store collection with optional filtering.
        
        Args:
            tenant: Optional tenant filter
            console: Optional console filter
            provider: Optional provider filter
            
        Returns:
            list: List of agent dictionaries
        """
        try:
            query = {}
            
            # Apply filters
            if tenant and tenant != "*":
                query['tenant'] = tenant
                
            if console and console != "*":
                query['console'] = console
                
            if provider:
                query['provider'] = provider
                
            self.logger.debug(f"Querying KV Store with filter: {query}")
            
            # Get agents from KV Store
            agents = self.kvstore_manager.query(query)
            
            self.logger.info(f"Retrieved {len(agents)} agents from KV Store")
            return agents
            
        except Exception as e:
            self.logger.error(f"Error listing agents from KV Store: {str(e)}")
            return []
    
    def purge_agents(self, tenant=None, console=None, provider=None):
        """
        Purge agents from the KV Store collection with optional filtering.
        
        Args:
            tenant: Optional tenant filter
            console: Optional console filter
            provider: Optional provider filter
            
        Returns:
            int: Number of agents purged
        """
        try:
            query = {}
            
            # Apply filters
            if tenant and tenant != "*":
                query['tenant'] = tenant
                
            if console and console != "*":
                query['console'] = console
                
            if provider:
                query['provider'] = provider
                
            self.logger.debug(f"Purging agents with filter: {query}")
            
            # Delete agents from KV Store
            count = self.kvstore_manager.delete_by_query(query)
            
            self.logger.info(f"Purged {count} agents from KV Store")
            return count
            
        except Exception as e:
            self.logger.error(f"Error purging agents from KV Store: {str(e)}")
            return 0
    
    def enqueue_result(self, result):
        """Add a result to the queue for later output."""
        self.result_queue.append(result)
    
    def process_tenant_console(self, tenant, console):
        """
        Process a specific tenant and console combination.
        
        Args:
            tenant: Tenant identifier
            console: Console identifier
        """
        self.logger.info(f"Processing tenant {tenant}, console {console}")
        
        # Set thread context for logging
        self.logger.set_thread_context(tenant=tenant, console=console)
        
        if self.operation == "list":
            # List agents from KV Store
            agents = self.list_agents(tenant, console, self.provider.lower())
            
            # Add to results
            for agent in agents:
                self.enqueue_result(agent)
                
            # Add summary record
            self.enqueue_result({
                'command': 'agentdiscovery',
                'operation': 'list',
                'tenant': tenant,
                'console': console,
                'provider': self.provider,
                'agent_count': len(agents),
                'status': 'success'
            })
            
        elif self.operation == "purge":
            # Purge agents from KV Store
            count = self.purge_agents(tenant, console, self.provider.lower())
            
            # Add summary record
            self.enqueue_result({
                'command': 'agentdiscovery',
                'operation': 'purge',
                'tenant': tenant,
                'console': console,
                'provider': self.provider,
                'purged_count': count,
                'status': 'success'
            })
            
        elif self.operation in ["discover", "update"]:
            # Discover agents
            agents = self.discover_agents(tenant, console)
            
            # Update KV Store if requested
            updated = {"total": 0}
            if self.operation == "update" and agents:
                updated = self.update_kvstore(agents)
                
            # In discover mode, add agents to results
            if self.operation == "discover":
                for agent in agents:
                    self.enqueue_result(agent)
            
            # Add summary record
            self.enqueue_result({
                'command': 'agentdiscovery',
                'operation': self.operation,
                'tenant': tenant,
                'console': console,
                'provider': self.provider,
                'agent_count': len(agents),
                'created_count': updated.get('created', 0),
                'updated_count': updated.get('updated', 0),
                'removed_count': updated.get('removed', 0),
                'status': 'success'
            })
    
    def stream(self, records):
        """
        Process the command operation and return results.
        
        This is the main entry point for the command.
        """
        # Initialize command
        self.initialize()
        
        # Process all tenant/console combinations
        for tenant in self.tenants:
            # Set tenant console context
            self.logger.set_thread_context(tenant=tenant)
            
            # Get consoles for this tenant if using wildcard
            if self.console == "*":
                tenant_consoles = self.config_manager.get_consoles(tenant, self.provider.lower())
                self.logger.debug(f"Found consoles for tenant {tenant}: {tenant_consoles}")
            else:
                tenant_consoles = self.consoles.get(tenant, [self.console])
                
            # Process each console
            for console in tenant_consoles:
                self.process_tenant_console(tenant, console)
        
        # Log completion
        self.logger.info(f"Command completed, yielding {len(self.result_queue)} results")
        
        # Yield results, adding at least one record if results are empty
        if not self.result_queue:
            yield {
                'command': 'agentdiscovery',
                'operation': self.operation,
                'provider': self.provider,
                'status': 'success',
                'message': 'No matching tenant/console combinations found'
            }
        else:
            for result in self.result_queue:
                yield result
