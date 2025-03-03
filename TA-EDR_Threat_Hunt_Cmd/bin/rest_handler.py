#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import time
import datetime
import re
import csv
import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest

# Add bin directory to path
bin_dir = os.path.dirname(os.path.abspath(__file__))
if bin_dir not in sys.path:
    sys.path.insert(0, bin_dir)

# Import TA-EDR_Threat_Hunt_Cmd modules
from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
from ta_edr_threat_hunt_cmd.lib.utils.credentials import CredentialManager
from ta_edr_threat_hunt_cmd.lib.utils.config_utils import ConfigManager
from ta_edr_threat_hunt_cmd.lib.storage.kvstore import KVStoreManager

class EDRRestHandler(admin.MRestHandler):
    """
    REST API handler for TA-EDR_Threat_Hunt_Cmd app.
    
    Provides API endpoints for querying agents and running EDR commands.
    Base endpoint: /services/edr
    """
    
    # Available endpoints and required capabilities
    ENDPOINTS = {
        'agents': {
            'capabilities': ['admin_all_objects'],
            'methods': ['GET', 'POST', 'DELETE']
        },
        'tenants': {
            'capabilities': ['admin_all_objects'],
            'methods': ['GET']
        },
        'consoles': {
            'capabilities': ['admin_all_objects'],
            'methods': ['GET']
        },
        'execute': {
            'capabilities': ['admin_all_objects'],
            'methods': ['POST']
        },
        'health': {
            'capabilities': ['admin_all_objects'],
            'methods': ['GET']
        }
    }
    
    def __init__(self, scriptMode, ctxInfo):
        """Initialize the REST handler."""
        admin.MRestHandler.__init__(self, scriptMode, ctxInfo)
        self.logger = get_logger('edr_rest')
        self.app_name = 'TA-EDR_Threat_Hunt_Cmd'
    
    def setup(self):
        """Set up the REST handler."""
        # Set up argument parser for each endpoint
        for endpoint, info in self.ENDPOINTS.items():
            if self.requestedAction in [admin.ACTION_CREATE, admin.ACTION_EDIT] and 'POST' in info['methods']:
                self.supportedArgs.addReqArg(f'{endpoint}_payload')
            elif self.requestedAction == admin.ACTION_REMOVE and 'DELETE' in info['methods']:
                self.supportedArgs.addReqArg(f'{endpoint}_id')
            elif self.requestedAction == admin.ACTION_LIST and 'GET' in info['methods']:
                # Add optional filter args for GET requests
                for filter_arg in ['tenant', 'provider', 'console', 'hostname', 'status', 'limit', 'offset', 'sort']:
                    self.supportedArgs.addOptArg(filter_arg)
    
    def handleList(self, confInfo):
        """
        Handle GET requests for various endpoints.
        
        Supported endpoints:
        - /services/edr/agents
        - /services/edr/tenants
        - /services/edr/consoles
        - /services/edr/health
        """
        # Initialize component managers
        session_key = self.getSessionKey()
        config_manager = ConfigManager(session_key, self.logger)
        credential_manager = CredentialManager(session_key, self.logger)
        
        # Determine endpoint from path
        path_parts = self.callerArgs.id.split('/')
        if len(path_parts) > 0:
            endpoint = path_parts[0]
        else:
            endpoint = 'agents'  # Default endpoint

       # Process endpoint
        if endpoint == 'agents':
            # Return agents from KV Store
            self._handle_agents_get(confInfo)
        elif endpoint == 'tenants':
            # Return configured tenants
            self._handle_tenants_get(confInfo)
        elif endpoint == 'consoles':
            # Return configured consoles
            self._handle_consoles_get(confInfo)
        elif endpoint == 'health':
            # Return health status
            self._handle_health_get(confInfo)
        else:
            self.logger.error(f"Unsupported endpoint: {endpoint}")
            raise admin.ArgValidationException(f"Unsupported endpoint: {endpoint}")
    
    def handleCreate(self, confInfo):
        """
        Handle POST requests for various endpoints.
        
        Supported endpoints:
        - /services/edr/agents
        - /services/edr/execute
        """
        # Initialize component managers
        session_key = self.getSessionKey()
        
        # Determine endpoint from path
        path_parts = self.callerArgs.id.split('/')
        if len(path_parts) > 0:
            endpoint = path_parts[0]
        else:
            endpoint = 'agents'  # Default endpoint
        
        # Process endpoint
        if endpoint == 'agents':
            # Create agent in KV Store
            self._handle_agents_post(confInfo)
        elif endpoint == 'execute':
            # Execute EDR command
            self._handle_execute_post(confInfo)
        else:
            self.logger.error(f"Unsupported endpoint: {endpoint}")
            raise admin.ArgValidationException(f"Unsupported endpoint: {endpoint}")
    
    def handleRemove(self, confInfo):
        """
        Handle DELETE requests for various endpoints.
        
        Supported endpoints:
        - /services/edr/agents
        """
        # Initialize component managers
        session_key = self.getSessionKey()
        
        # Determine endpoint from path
        path_parts = self.callerArgs.id.split('/')
        if len(path_parts) > 0:
            endpoint = path_parts[0]
        else:
            endpoint = 'agents'  # Default endpoint
        
        # Process endpoint
        if endpoint == 'agents':
            # Delete agent from KV Store
            self._handle_agents_delete(confInfo)
        else:
            self.logger.error(f"Unsupported endpoint: {endpoint}")
            raise admin.ArgValidationException(f"Unsupported endpoint: {endpoint}")
    
    def _handle_agents_get(self, confInfo):
        """Handle GET requests for the agents endpoint."""
        session_key = self.getSessionKey()
        kvstore = KVStoreManager(session_key, 'edr_agents', self.logger)
        
        # Parse query parameters
        tenant = self.callerArgs.data.get('tenant', ['*'])[0]
        provider = self.callerArgs.data.get('provider', ['*'])[0]
        console = self.callerArgs.data.get('console', ['*'])[0]
        hostname = self.callerArgs.data.get('hostname', ['*'])[0]
        status = self.callerArgs.data.get('status', ['*'])[0]
        limit = self.callerArgs.data.get('limit', ['1000'])[0]
        offset = self.callerArgs.data.get('offset', ['0'])[0]
        sort = self.callerArgs.data.get('sort', ['hostname'])[0]
        
        # Build query
        query = {}
        
        if tenant != '*':
            query['tenant'] = tenant
        
        if provider != '*':
            query['provider'] = provider
        
        if console != '*':
            query['console'] = console
        
        if hostname != '*':
            query['hostname'] = {"$regex": f"^{re.escape(hostname)}", "$options": "i"}
        
        if status != '*':
            query['status'] = status
        
        # Query KV Store
        agents = kvstore.query(query)
        
        # Sort results
        if sort.startswith('-'):
            # Descending sort
            sort_field = sort[1:]
            agents = sorted(agents, key=lambda x: x.get(sort_field, ''), reverse=True)
        else:
            # Ascending sort
            agents = sorted(agents, key=lambda x: x.get(sort, ''))
        
        # Apply pagination
        try:
            offset = int(offset)
            limit = int(limit)
            agents = agents[offset:offset + limit]
        except (ValueError, IndexError):
            pass
        
        # Return results
        confInfo['agents'] = {
            'count': len(agents),
            'agents': json.dumps(agents)
        }
    
    def _handle_agents_post(self, confInfo):
        """Handle POST requests for the agents endpoint."""
        session_key = self.getSessionKey()
        kvstore = KVStoreManager(session_key, 'edr_agents', self.logger)
        
        # Parse payload
        payload_str = self.callerArgs.data.get('agents_payload', ['{}'])[0]
        
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON payload: {payload_str}")
            raise admin.ArgValidationException("Invalid JSON payload")
        
        # Ensure _key is present in each agent
        for agent in payload:
            if '_key' not in agent and 'agent_id' in agent:
                agent['_key'] = agent['agent_id']
            
            if '_key' not in agent:
                self.logger.error("Missing _key or agent_id in agent data")
                raise admin.ArgValidationException("Missing _key or agent_id in agent data")
            
            # Add updated_at timestamp
            agent['updated_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
        
        # Create or update agents
        result = kvstore.batch_save(payload)
        
        # Return result
        confInfo['agents'] = {
            'status': 'success',
            'count': len(payload),
            'result': json.dumps(result)
        }
    
    def _handle_agents_delete(self, confInfo):
        """Handle DELETE requests for the agents endpoint."""
        session_key = self.getSessionKey()
        kvstore = KVStoreManager(session_key, 'edr_agents', self.logger)
        
        # Parse query parameters
        agent_id = self.callerArgs.data.get('agents_id', [''])[0]
        
        if not agent_id:
            self.logger.error("Missing agent_id parameter")
            raise admin.ArgValidationException("Missing agent_id parameter")
        
        # Delete agent
        result = kvstore.delete_item(agent_id)
        
        # Return result
        confInfo['agents'] = {
            'status': 'success' if result else 'error',
            'message': f"Agent {agent_id} {'deleted' if result else 'not found'}"
        }
    
    def _handle_tenants_get(self, confInfo):
        """Handle GET requests for the tenants endpoint."""
        session_key = self.getSessionKey()
        config_manager = ConfigManager(session_key, self.logger)
        
        # Get tenants
        tenants = config_manager.get_tenants()
        tenant_info = {}
        
        for tenant_id in tenants:
            tenant_info[tenant_id] = config_manager.get_tenant_info(tenant_id) or {'name': tenant_id}
        
        # Return results
        confInfo['tenants'] = {
            'count': len(tenants),
            'tenants': json.dumps(tenant_info)
        }
    
    def _handle_consoles_get(self, confInfo):
        """Handle GET requests for the consoles endpoint."""
        session_key = self.getSessionKey()
        config_manager = ConfigManager(session_key, self.logger)
        
        # Parse query parameters
        tenant = self.callerArgs.data.get('tenant', ['*'])[0]
        provider = self.callerArgs.data.get('provider', ['*'])[0]
        
        # Get tenants
        tenants = [tenant] if tenant != '*' else config_manager.get_tenants()
        
        # Get consoles for each tenant
        consoles = {}
        
        for tenant_id in tenants:
            providers = [provider] if provider != '*' else ['crowdstrike', 'sentinelone', 'defender']
            
            if tenant_id not in consoles:
                consoles[tenant_id] = {}
                
            for provider_name in providers:
                consoles[tenant_id][provider_name] = config_manager.get_consoles(tenant_id, provider_name)
        
        # Return results
        confInfo['consoles'] = {
            'consoles': json.dumps(consoles)
        }
    
    def _handle_execute_post(self, confInfo):
        """Handle POST requests for the execute endpoint."""
        session_key = self.getSessionKey()
        
        # Parse payload
        payload_str = self.callerArgs.data.get('execute_payload', ['{}'])[0]
        
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON payload: {payload_str}")
            raise admin.ArgValidationException("Invalid JSON payload")
        
        # Validate required parameters
        required_params = ['command', 'parameters']
        for param in required_params:
            if param not in payload:
                self.logger.error(f"Missing required parameter: {param}")
                raise admin.ArgValidationException(f"Missing required parameter: {param}")
        
        command = payload['command']
        parameters = payload['parameters']
        
        # Handle different commands
        if command == 'health_check':
            # Run health check
            self._run_health_check(confInfo, parameters)
        elif command == 'edrhunt':
            # Run edrhunt command
            self._run_edrhunt(confInfo, parameters)
        elif command == 'agentdiscovery':
            # Run agentdiscovery command
            self._run_agentdiscovery(confInfo, parameters)
        else:
            self.logger.error(f"Unsupported command: {command}")
            raise admin.ArgValidationException(f"Unsupported command: {command}")
    
    def _handle_health_get(self, confInfo):
        """Handle GET requests for the health endpoint."""
        session_key = self.getSessionKey()
        kvstore = KVStoreManager(session_key, 'edr_health_results', self.logger)
        
        # Parse query parameters
        limit = self.callerArgs.data.get('limit', ['10'])[0]
        offset = self.callerArgs.data.get('offset', ['0'])[0]
        sort = self.callerArgs.data.get('sort', ['-_key'])[0]  # Default to newest first
        
        # Query KV Store for health results
        health_results = kvstore.query({})
        
        # Sort results
        if sort.startswith('-'):
            # Descending sort
            sort_field = sort[1:]
            health_results = sorted(health_results, key=lambda x: x.get(sort_field, ''), reverse=True)
        else:
            # Ascending sort
            health_results = sorted(health_results, key=lambda x: x.get(sort, ''))
        
        # Apply pagination
        try:
            offset = int(offset)
            limit = int(limit)
            health_results = health_results[offset:offset + limit]
        except (ValueError, IndexError):
            pass
        
        # Get the latest health status
        latest_status = 'unknown'
        latest_score = 0
        
        if health_results:
            latest = health_results[0]
            latest_status = latest.get('health_status', 'unknown')
            latest_score = latest.get('overall_score', 0)
        
        # Return results
        confInfo['health'] = {
            'count': len(health_results),
            'latest_status': latest_status,
            'latest_score': latest_score,
            'health_results': json.dumps(health_results)
        }
    
    def _run_health_check(self, confInfo, parameters):
        """Run health check and return results."""
        session_key = self.getSessionKey()
        
        # Import health check module
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from edr_health_check import EDRHealthCheck
        
        # Parse parameters
        collection = parameters.get('collection', 'edr_health_results')
        app_name = parameters.get('app_name', self.app_name)
        
        # Get Splunk server info
        server_url = 'https://localhost:8089'  # Default
        
        try:
            response, content = rest.simpleRequest(
                '/services/server/info',
                sessionKey=session_key,
                getargs={'output_mode': 'json'}
            )
            
            if response.status == 200:
                server_info = json.loads(content)
                server_name = server_info['entry'][0]['content']['serverName']
                server_rest_uri = server_info['entry'][0]['content'].get('server_rest_uri', '')
                
                if server_rest_uri:
                    server_url = server_rest_uri
                else:
                    port = server_info['entry'][0]['content'].get('mgmtHostPort', '8089')
                    server_url = f"https://{server_name}:{port}"
        except Exception as e:
            self.logger.error(f"Error getting server info: {str(e)}")
        
        # Run health check
        try:
            # Create a temporary credential to authenticate the health check
            username = 'health_check_temp'
            password = self._generate_temp_password()
            
            # Create the health check instance
            health_check = EDRHealthCheck(server_url, username, session_key, app_name)
            
            # Run the health check
            report = health_check.run()
            
            # Save results to KV Store
            success = health_check.save_to_kvstore(collection)
            
            # Return results
            confInfo['execute'] = {
                'status': 'success' if success else 'error',
                'command': 'health_check',
                'health_status': report.get('health_status', 'unknown'),
                'overall_score': report.get('overall_score', 0),
                'app_version': report.get('app_status', {}).get('version', 'unknown'),
                'timestamp': report.get('timestamp', '')
            }
            
        except Exception as e:
            self.logger.error(f"Error running health check: {str(e)}")
            confInfo['execute'] = {
                'status': 'error',
                'command': 'health_check',
                'error': str(e)
            }
    
    def _run_edrhunt(self, confInfo, parameters):
        """Run edrhunt command and return results."""
        session_key = self.getSessionKey()
        
        # Validate required parameters
        required_params = ['provider', 'data_type']
        for param in required_params:
            if param not in parameters:
                self.logger.error(f"Missing required parameter: {param}")
                raise admin.ArgValidationException(f"Missing required parameter: {param}")
        
        # Build search query
        agent_id = parameters.get('agent_id', '')
        hostname = parameters.get('hostname', '')
        
        if not agent_id and not hostname:
            self.logger.error("Either agent_id or hostname must be provided")
            raise admin.ArgValidationException("Either agent_id or hostname must be provided")
        
        # Build search
        if agent_id:
            search = f'| makeresults | eval agent_id="{agent_id}"'
        else:
            search = f'| makeresults | eval hostname="{hostname}"'
        
        # Add edrhunt command
        search += f' | edrhunt provider="{parameters["provider"]}" data_type="{parameters["data_type"]}"'
        
        # Add optional parameters
        optional_params = ['tenant', 'console', 'time_range', 'query', 'threads', 'max_rate', 'limit']
        
        for param in optional_params:
            if param in parameters:
                search += f' {param}="{parameters[param]}"'
        
        # Run search
        try:
            # Execute search
            search_results = self._execute_search(search, session_key)
            
            if search_results.get('status') == 'error':
                confInfo['execute'] = search_results
                return
                
            # Get search results
            results = search_results.get('results', [])
            
            # Return results
            confInfo['execute'] = {
                'status': 'success',
                'command': 'edrhunt',
                'count': len(results),
                'results': json.dumps(results)
            }
            
        except Exception as e:
            self.logger.error(f"Error running edrhunt command: {str(e)}")
            confInfo['execute'] = {
                'status': 'error',
                'command': 'edrhunt',
                'error': str(e)
            }
    
    def _run_agentdiscovery(self, confInfo, parameters):
        """Run agentdiscovery command and return results."""
        session_key = self.getSessionKey()
        
        # Validate required parameters
        required_params = ['provider', 'operation']
        for param in required_params:
            if param not in parameters:
                self.logger.error(f"Missing required parameter: {param}")
                raise admin.ArgValidationException(f"Missing required parameter: {param}")
        
        # Build search
        search = f'| agentdiscovery provider="{parameters["provider"]}" operation="{parameters["operation"]}"'
        
        # Add optional parameters
        optional_params = ['tenant', 'console', 'limit', 'ttl', 'collection']
        
        for param in optional_params:
            if param in parameters:
                search += f' {param}="{parameters[param]}"'
        
        # Run search
        try:
            # Execute search
            search_results = self._execute_search(search, session_key)
            
            if search_results.get('status') == 'error':
                confInfo['execute'] = search_results
                return
                
            # Get search results
            results = search_results.get('results', [])
            
            # Return results
            confInfo['execute'] = {
                'status': 'success',
                'command': 'agentdiscovery',
                'count': len(results),
                'results': json.dumps(results)
            }
            
        except Exception as e:
            self.logger.error(f"Error running agentdiscovery command: {str(e)}")
            confInfo['execute'] = {
                'status': 'error',
                'command': 'agentdiscovery',
                'error': str(e)
            }
    
    def _execute_search(self, search, session_key, timeout=60):
        """
        Execute a search and return results.
        
        Args:
            search (str): Search query
            session_key (str): Splunk session key
            timeout (int): Search timeout in seconds
            
        Returns:
            dict: Search results
        """
        try:
            # Create search job
            search_url = f"/services/search/jobs"
            
            response, content = rest.simpleRequest(
                search_url,
                sessionKey=session_key,
                method='POST',
                postargs={
                    'search': search,
                    'earliest_time': '-1m',
                    'latest_time': 'now',
                    'exec_mode': 'normal'
                }
            )
            
            if response.status != 201:
                return {
                    'status': 'error',
                    'error': f"Failed to create search job: {response.status} {content}"
                }
                
            # Extract job ID
            import xml.etree.ElementTree as ET
            sid = ET.fromstring(content).findtext('.//sid')
            
            if not sid:
                return {
                    'status': 'error',
                    'error': "Failed to extract search job ID"
                }
                
            # Wait for search to complete
            job_url = f"/services/search/jobs/{sid}"
            
            for _ in range(timeout):
                # Sleep 1 second between checks
                time.sleep(1)
                
                response, content = rest.simpleRequest(
                    f"{job_url}?output_mode=json",
                    sessionKey=session_key
                )
                
                if response.status != 200:
                    return {
                        'status': 'error',
                        'error': f"Failed to check search job status: {response.status} {content}"
                    }
                    
                # Parse job status
                job_status = json.loads(content)
                job_content = job_status['entry'][0]['content']
                
                if job_content.get('isDone', False):
                    # Job is complete
                    if job_content.get('isFailed', False):
                        # Job failed
                        return {
                            'status': 'error',
                            'error': job_content.get('messages', [{'text': 'Unknown error'}])[0]['text']
                        }
                        
                    # Get results
                    response, content = rest.simpleRequest(
                        f"{job_url}/results?output_mode=json",
                        sessionKey=session_key
                    )
                    
                    if response.status != 200:
                        return {
                            'status': 'error',
                            'error': f"Failed to get search results: {response.status} {content}"
                        }
                        
                    # Parse results
                    results = json.loads(content)
                    
                    return {
                        'status': 'success',
                        'sid': sid,
                        'count': len(results.get('results', [])),
                        'results': results.get('results', [])
                    }
            
            # Timeout waiting for search to complete
            return {
                'status': 'error',
                'error': f"Search timed out after {timeout} seconds"
            }
            
        except Exception as e:
            self.logger.error(f"Error executing search: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _generate_temp_password(self, length=16):
        """Generate a temporary password for health check authentication."""
        import random
        import string
        
        chars = string.ascii_letters + string.digits + '!@#$%^&*()_-+={}[]|:;<>,.?/'
        return ''.join(random.choice(chars) for _ in range(length))

# Entry point for the REST handler
if __name__ == "__main__":
    admin.init(EDRRestHandler, admin.CONTEXT_APP_ONLY)
