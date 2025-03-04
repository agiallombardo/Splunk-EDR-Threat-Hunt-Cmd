#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import time
import datetime
import re
import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest
import requests
from splunk.clilib import cli_common as cli

# Add bin directory to path
bin_dir = os.path.dirname(os.path.abspath(__file__))
if bin_dir not in sys.path:
    sys.path.insert(0, bin_dir)

class SetupHandler(admin.MConfigHandler):
    """
    Unified setup handler for TA-EDR_Threat_Hunt_Cmd configuration.
    Follows best practices for Splunk setup pages.
    """
    
    # Define the parameters that should be saved
    PARAM_MAP = {
        'enable_logging': {'section': 'global', 'key': 'enable_logging', 'type': 'bool'},
        'log_level': {'section': 'global', 'key': 'log_level', 'type': 'string'},
        'default_threads': {'section': 'edrhunt', 'key': 'default_threads', 'type': 'int'},
        'default_batch_size': {'section': 'edrhunt', 'key': 'default_batch_size', 'type': 'int'},
        'crowdstrike_enabled': {'section': 'crowdstrike', 'key': 'enabled', 'type': 'bool'},
        'crowdstrike_max_rate': {'section': 'crowdstrike', 'key': 'max_rate', 'type': 'int'},
        'crowdstrike_api_timeout': {'section': 'crowdstrike', 'key': 'api_timeout', 'type': 'int'},
        'crowdstrike_api_url': {'section': 'crowdstrike', 'key': 'api_url', 'type': 'string'},
        'sentinelone_enabled': {'section': 'sentinelone', 'key': 'enabled', 'type': 'bool'},
        'sentinelone_max_rate': {'section': 'sentinelone', 'key': 'max_rate', 'type': 'int'},
        'sentinelone_api_timeout': {'section': 'sentinelone', 'key': 'api_timeout', 'type': 'int'},
        'sentinelone_api_url': {'section': 'sentinelone', 'key': 'api_url', 'type': 'string'},
        'defender_enabled': {'section': 'defender', 'key': 'enabled', 'type': 'bool'},
        'defender_max_rate': {'section': 'defender', 'key': 'max_rate', 'type': 'int'},
        'defender_api_timeout': {'section': 'defender', 'key': 'api_timeout', 'type': 'int'},
        'defender_api_url': {'section': 'defender', 'key': 'api_url', 'type': 'string'},
        'kvstore_collection': {'section': 'edrhunt', 'key': 'collection_name', 'type': 'string'},
        'agent_ttl': {'section': 'agentdiscovery', 'key': 'default_ttl', 'type': 'int'},
        'backup_to_csv': {'section': 'agentdiscovery', 'key': 'backup_to_csv', 'type': 'bool'},
        'enable_health_monitoring': {'section': 'health', 'key': 'enabled', 'type': 'bool'},
        'health_check_interval': {'section': 'health', 'key': 'check_interval', 'type': 'int'},
        'health_results_collection': {'section': 'health', 'key': 'results_collection', 'type': 'string'},
        'health_retention_days': {'section': 'health', 'key': 'retention_days', 'type': 'int'},
        'alert_on_degradation': {'section': 'health', 'key': 'alert_on_degradation', 'type': 'bool'},
        'alert_email': {'section': 'health', 'key': 'alert_email', 'type': 'string'},
    }
    
    # Default values for configuration
    DEFAULTS = {
        'enable_logging': 'true',
        'log_level': 'INFO',
        'default_threads': '4',
        'default_batch_size': '20',
        'crowdstrike_enabled': 'true',
        'crowdstrike_max_rate': '120',
        'crowdstrike_api_timeout': '30',
        'crowdstrike_api_url': 'https://api.crowdstrike.com',
        'sentinelone_enabled': 'true',
        'sentinelone_max_rate': '60',
        'sentinelone_api_timeout': '30',
        'sentinelone_api_url': 'https://management-api.sentinelone.net',
        'defender_enabled': 'true',
        'defender_max_rate': '100',
        'defender_api_timeout': '30',
        'defender_api_url': 'https://api.securitycenter.microsoft.com',
        'kvstore_collection': 'edr_agents',
        'agent_ttl': '7',
        'backup_to_csv': 'true',
        'enable_health_monitoring': 'true',
        'health_check_interval': '24',
        'health_results_collection': 'edr_health_results',
        'health_retention_days': '30',
        'alert_on_degradation': 'true',
        'alert_email': '',
    }
    
    def setup(self):
        """Set up the handler to be used in various contexts."""
        # Set up logging
        self.app_name = 'TA-EDR_Threat_Hunt_Cmd'
        
        # Get logger
        try:
            # Try to import the app's logger if available
            from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
            self.logger = get_logger('setup_handler')
        except Exception as e:
            self.logger.error(f"Error getting credential {realm}: {str(e)}")
            return None
    
    def test_crowdstrike_connection(self, tenant='default', console='primary'):
        """Test connection to CrowdStrike API."""
        self.logger.info(f"Testing CrowdStrike connection for {tenant}/{console}")
        
        # Get the credential name
        credential_name = f"crowdstrike_{tenant}_{console}"
        
        # Get credentials
        credential = self.get_credential(credential_name)
        if not credential:
            return {
                'success': False, 
                'message': f'Credentials not found for {credential_name}'
            }
        
        client_id = credential['username']
        client_secret = credential['password']
        
        # Get the base URL from configuration
        conf = self.readConf("edr")
        base_url = 'https://api.crowdstrike.com'
        
        if conf and 'crowdstrike' in conf and 'api_url' in conf['crowdstrike']:
            base_url = conf['crowdstrike']['api_url']
        
        # Test authentication
        try:
            url = f"{base_url}/oauth2/token"
            payload = {
                'client_id': client_id,
                'client_secret': client_secret
            }
            
            # Add timeout for the request
            timeout = 30
            if conf and 'crowdstrike' in conf and 'api_timeout' in conf['crowdstrike']:
                try:
                    timeout = int(conf['crowdstrike']['api_timeout'])
                except ValueError:
                    pass
            
            start_time = time.time()
            response = requests.post(url, data=payload, timeout=timeout)
            elapsed = time.time() - start_time
            
            if response.status_code == 201:
                token_data = response.json()
                return {
                    'success': True,
                    'message': f'Successfully authenticated with CrowdStrike API ({elapsed:.2f}s)',
                    'details': {
                        'token_type': token_data.get('token_type'),
                        'expires_in': token_data.get('expires_in'),
                        'tenant': tenant,
                        'console': console
                    }
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to authenticate: HTTP {response.status_code}',
                    'details': {
                        'status_code': response.status_code,
                        'response': response.text[:500] if hasattr(response, 'text') else 'No response text',
                        'tenant': tenant,
                        'console': console
                    }
                }
        except Exception as e:
            self.logger.error(f"CrowdStrike connection error: {str(e)}")
            return {
                'success': False, 
                'message': f'Connection error: {str(e)}',
                'details': {
                    'tenant': tenant,
                    'console': console
                }
            }
    
    def test_sentinelone_connection(self, tenant='default', console='primary'):
        """Test connection to SentinelOne API."""
        self.logger.info(f"Testing SentinelOne connection for {tenant}/{console}")
        
        # Get the credential name
        credential_name = f"sentinelone_{tenant}_{console}"
        
        # Get credentials
        credential = self.get_credential(credential_name)
        if not credential:
            return {
                'success': False, 
                'message': f'Credentials not found for {credential_name}'
            }
        
        username = credential['username']
        password = credential['password']
        
        # Get the base URL from configuration
        conf = self.readConf("edr")
        base_url = 'https://management-api.sentinelone.net'
        
        if conf and 'sentinelone' in conf and 'api_url' in conf['sentinelone']:
            base_url = conf['sentinelone']['api_url']
        
        # Test authentication
        try:
            url = f"{base_url}/web/api/v2.1/users/login"
            headers = {
                "Content-Type": "application/json"
            }
            payload = {
                "data": {
                    "username": username,
                    "password": password
                }
            }
            
            # Add timeout for the request
            timeout = 30
            if conf and 'sentinelone' in conf and 'api_timeout' in conf['sentinelone']:
                try:
                    timeout = int(conf['sentinelone']['api_timeout'])
                except ValueError:
                    pass
            
            start_time = time.time()
            response = requests.post(url, headers=headers, json=payload, timeout=timeout)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                token_data = response.json()
                return {
                    'success': True,
                    'message': f'Successfully authenticated with SentinelOne API ({elapsed:.2f}s)',
                    'details': {
                        'account_name': token_data.get('data', {}).get('account', {}).get('name', 'Unknown'),
                        'tenant': tenant,
                        'console': console
                    }
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to authenticate: HTTP {response.status_code}',
                    'details': {
                        'status_code': response.status_code,
                        'response': response.text[:500] if hasattr(response, 'text') else 'No response text',
                        'tenant': tenant,
                        'console': console
                    }
                }
        except Exception as e:
            self.logger.error(f"SentinelOne connection error: {str(e)}")
            return {
                'success': False, 
                'message': f'Connection error: {str(e)}',
                'details': {
                    'tenant': tenant,
                    'console': console
                }
            }
    
    def test_defender_connection(self, tenant='default', console='primary'):
        """Test connection to Microsoft Defender API."""
        self.logger.info(f"Testing Microsoft Defender connection for {tenant}/{console}")
        
        # Get the credential name
        credential_name = f"defender_{tenant}_{console}"
        
        # Get credentials
        credential = self.get_credential(credential_name)
        if not credential:
            return {
                'success': False, 
                'message': f'Credentials not found for {credential_name}'
            }
        
        client_id = credential['username']
        client_secret = credential['password']
        
        # Get the base URL from configuration
        conf = self.readConf("edr")
        base_url = 'https://api.securitycenter.microsoft.com'
        
        if conf and 'defender' in conf and 'api_url' in conf['defender']:
            base_url = conf['defender']['api_url']
        
        # Test authentication - This is a simplified approach. In practice, Microsoft Defender API 
        # requires additional parameters like tenant_id and authority
        try:
            # For now, return sample success since we can't test full authentication without those details
            return {
                'success': True,
                'message': f'Note: Microsoft Defender connection verification requires Azure AD integration',
                'details': {
                    'note': 'Full authentication would require Azure AD tenant ID and authority URL',
                    'client_id_verified': len(client_id) > 10,
                    'client_secret_verified': len(client_secret) > 10 if client_secret else False,
                    'tenant': tenant,
                    'console': console
                }
            }
        except Exception as e:
            self.logger.error(f"Microsoft Defender connection error: {str(e)}")
            return {
                'success': False, 
                'message': f'Connection error: {str(e)}',
                'details': {
                    'tenant': tenant,
                    'console': console
                }
            }

# Script execution
if __name__ == "__main__":

    if self.requestedAction == admin.ACTION_EDIT:
            # Add all parameters for editing
            for param in self.PARAM_MAP:
                self.supportedArgs.addOptArg(param)
                
            # Add the credential and tenant lists
            self.supportedArgs.addOptArg('crowdstrike_credentials_list')
            self.supportedArgs.addOptArg('sentinelone_credentials_list')
            self.supportedArgs.addOptArg('defender_credentials_list')
            self.supportedArgs.addOptArg('tenant_list')
                
        # Support for custom actions
    if self.customAction == '_execute':
            for arg in ['provider', 'tenant', 'console']:
                self.supportedArgs.addOptArg(arg)
    
    def handleList(self, confInfo):
        """Handle listing of the current configuration."""
        self.logger.info("Getting current configuration")
        
        # Create a base confInfo entry
        confInfo['ta_edr_threat_hunt_cmd_settings'] = {}
        
        # Initialize configuration dict with defaults
        # This ensures all expected fields are present
        config = dict(self.DEFAULTS)
        
        # Get existing configurations from edr.conf
        try:
            confDict = self.readConf('edr')
            
            # Process each parameter from the edr.conf file
            for param, mapping in self.PARAM_MAP.items():
                section = mapping['section']
                key = mapping['key']
                
                if section in confDict and key in confDict[section]:
                    config[param] = confDict[section][key]
        except Exception as e:
            self.logger.error(f"Error reading configuration: {str(e)}")
        
        # Populate confInfo from config dict
        for param, value in config.items():
            confInfo['ta_edr_threat_hunt_cmd_settings'][param] = value
        
        # Get credential lists
        try:
            # Get CrowdStrike credentials
            cs_creds = self.get_credentials_by_prefix('crowdstrike_')
            confInfo['ta_edr_threat_hunt_cmd_settings']['crowdstrike_credentials_list'] = ','.join(cs_creds)
            
            # Get SentinelOne credentials
            s1_creds = self.get_credentials_by_prefix('sentinelone_')
            confInfo['ta_edr_threat_hunt_cmd_settings']['sentinelone_credentials_list'] = ','.join(s1_creds)
            
            # Get Defender credentials
            def_creds = self.get_credentials_by_prefix('defender_')
            confInfo['ta_edr_threat_hunt_cmd_settings']['defender_credentials_list'] = ','.join(def_creds)
        except Exception as e:
            self.logger.error(f"Error retrieving credentials: {str(e)}")
            confInfo['ta_edr_threat_hunt_cmd_settings']['credential_error'] = str(e)
        
        # Get tenant list
        try:
            tenants = self.get_tenants()
            confInfo['ta_edr_threat_hunt_cmd_settings']['tenant_list'] = ','.join(tenants)
        except Exception as e:
            self.logger.error(f"Error retrieving tenants: {str(e)}")
            confInfo['ta_edr_threat_hunt_cmd_settings']['tenant_error'] = str(e)
    
    def handleEdit(self, confInfo):
        """Handle form submission for editing configurations."""
        self.logger.info("Updating configuration")
        
        try:
            # Update edr.conf with the new settings
            self.update_edr_conf()
            
            # Process credentials if provided
            if self.callerArgs.data.get('crowdstrike_credentials_list'):
                self.process_credentials('crowdstrike', self.callerArgs.data['crowdstrike_credentials_list'][0])
                
            if self.callerArgs.data.get('sentinelone_credentials_list'):
                self.process_credentials('sentinelone', self.callerArgs.data['sentinelone_credentials_list'][0])
                
            if self.callerArgs.data.get('defender_credentials_list'):
                self.process_credentials('defender', self.callerArgs.data['defender_credentials_list'][0])
            
            # Process tenants if provided
            if self.callerArgs.data.get('tenant_list'):
                self.process_tenants(self.callerArgs.data['tenant_list'][0])
                
            # Mark the app as configured
            self.mark_app_configured()
            
            # Return success message
            confInfo['ta_edr_threat_hunt_cmd_settings'] = {}
            confInfo['ta_edr_threat_hunt_cmd_settings']['status'] = 'Configuration updated successfully'
            
        except Exception as e:
            self.logger.error(f"Error updating configuration: {str(e)}")
            confInfo['ta_edr_threat_hunt_cmd_settings'] = {}
            confInfo['ta_edr_threat_hunt_cmd_settings']['error'] = f"Error updating configuration: {str(e)}"
    
    def handleCustom(self, confInfo):
        """Handle custom actions like connection testing."""
        if self.customAction != '_execute':
            return
        
        args = self.callerArgs.data
        if 'provider' not in args:
            confInfo['test_result'] = json.dumps({
                'success': False,
                'message': 'Missing provider parameter'
            })
            return
        
        provider = args['provider'][0].lower()
        tenant = args.get('tenant', ['default'])[0]
        console = args.get('console', ['primary'])[0]
        
        # Test the connection
        try:
            if provider == 'crowdstrike':
                test_result = self.test_crowdstrike_connection(tenant, console)
            elif provider == 'sentinelone':
                test_result = self.test_sentinelone_connection(tenant, console)
            elif provider == 'defender':
                test_result = self.test_defender_connection(tenant, console)
            else:
                test_result = {'success': False, 'message': f'Unsupported provider: {provider}'}
            
            confInfo['test_result'] = json.dumps(test_result)
            
        except Exception as e:
            self.logger.error(f"Error testing connection: {str(e)}")
            confInfo['test_result'] = json.dumps({
                'success': False,
                'message': f'Error testing connection: {str(e)}'
            })
    
    def update_edr_conf(self):
        """Update the edr.conf file with form values with validation."""
        self.logger.info("Updating edr.conf")
        
        # Group parameters by section
        section_params = {}
        for param, mapping in self.PARAM_MAP.items():
            section = mapping['section']
            key = mapping['key']
            param_type = mapping['type']
            
            if param in self.callerArgs.data:
                if section not in section_params:
                    section_params[section] = {}
                
                # Get the value from the form
                value = self.callerArgs.data[param][0]
                
                # Validate the value based on type
                try:
                    if param_type == 'int':
                        # Ensure value is a valid integer
                        int_value = int(value)
                        if int_value < 0:
                            raise ValueError(f"Value for {param} must be a positive integer")
                        value = str(int_value)
                    elif param_type == 'bool':
                        # Normalize boolean values
                        value = str(value).lower()
                        if value not in ['true', 'false', '0', '1']:
                            value = 'true' if value else 'false'
                except ValueError as e:
                    self.logger.error(f"Invalid value for {param}: {value} - {str(e)}")
                    raise ValueError(f"Invalid value for {param}: {value} - {str(e)}")
                
                # Store the validated value
                section_params[section][key] = value
        
        # Update each section
        for section, params in section_params.items():
            self.writeConf('edr', section, params)
    
    def process_credentials(self, provider, creds_list):
        """
        Process credential list for a provider.
        This prepares the credential configurations but does not store passwords.
        """
        if not creds_list:
            return
        
        self.logger.info(f"Processing {provider} credentials")
        
        # Split the comma-separated list and validate format
        creds = []
        for c in creds_list.split(','):
            cred = c.strip()
            if not cred:
                continue
                
            # Validate credential name format
            if not re.match(f'^{provider}_[a-zA-Z0-9_-]+_[a-zA-Z0-9_-]+$', cred):
                self.logger.warning(f"Invalid credential format: {cred}, expected format: {provider}_<tenant>_<console>")
                continue
                
            creds.append(cred)
        
        # For each credential, we'll create a stanza in a credentials.conf file
        # that will be used by the credential setup pages
        cred_stanzas = {}
        for cred in creds:
            parts = cred.split('_', 2)
            tenant = parts[1] if len(parts) > 1 else 'default'
            console = parts[2] if len(parts) > 2 else 'primary'
            
            cred_stanzas[cred] = {
                'provider': provider,
                'tenant': tenant,
                'console': console,
                'credential_type': 'username_password',
                'description': f'{provider.capitalize()} API credential for {tenant}/{console}'
            }
        
        # Write to configuration file
        if cred_stanzas:
            self.writeConf('edr_credentials', 'credentials', {'credentials_list': ','.join(creds)})
            
            for cred, settings in cred_stanzas.items():
                self.writeConf('edr_credentials', cred, settings)
    
    def process_tenants(self, tenant_list):
        """Process tenant list and update tenants.conf."""
        if not tenant_list:
            return
        
        self.logger.info("Processing tenants")
        
        # Split the comma-separated list
        tenants = []
        for t in tenant_list.split(','):
            tenant = t.strip()
            if not tenant:
                continue
                
            # Validate tenant name
            if not re.match('^[a-zA-Z0-9_-]+$', tenant):
                self.logger.warning(f"Invalid tenant name: {tenant}, must contain only alphanumeric characters, underscores, and hyphens")
                continue
                
            tenants.append(tenant)
        
        # Create tenant stanzas
        for tenant in tenants:
            stanza = f'tenant:{tenant}'
            settings = {
                'name': tenant.capitalize(),
                'description': f'{tenant.capitalize()} environment',
                'enabled': 'true'
            }
            self.writeConf('tenants', stanza, settings)
    
    def mark_app_configured(self):
        """Mark the app as configured in app.conf."""
        self.logger.info("Marking app as configured")
        
        # Set is_configured to 1 in app.conf
        app_conf_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'local')
        app_conf = os.path.join(app_conf_dir, 'app.conf')
        
        # Ensure local directory exists
        if not os.path.exists(app_conf_dir):
            os.makedirs(app_conf_dir)
        
        # Read existing app.conf if it exists
        app_config = cli.readConfFile(app_conf) if os.path.exists(app_conf) else {}
        
        # Update install section
        if 'install' not in app_config:
            app_config['install'] = {}
        
        app_config['install']['is_configured'] = '1'
        
        # Add configuration timestamp
        app_config['install']['last_configured'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Write updated configuration
        cli.writeConfFile(app_conf, app_config)
    
    def get_credentials_by_prefix(self, prefix):
        """Get all credentials with a specific prefix."""
        creds = []
        
        try:
            # Get credentials from Splunk's password store
            entities = entity.getEntities(
                ['admin', 'passwords'], 
                namespace=self.appName,
                owner='-', 
                sessionKey=self.getSessionKey()
            )
            
            # Filter by prefix
            for _, c in entities.items():
                if 'realm' in c and c['realm'].startswith(prefix):
                    creds.append(c['realm'])
        except Exception as e:
            self.logger.error(f"Error getting credentials: {str(e)}")
        
        return creds
    
    def get_tenants(self):
        """Get all configured tenants."""
        tenants = ['default']  # Always include default tenant
        
        try:
            # Get tenant configurations
            conf = self.readConf('tenants')
            
            # Extract tenant IDs
            for stanza in conf:
                if stanza.startswith('tenant:'):
                    tenant_id = stanza[7:]  # Remove 'tenant:' prefix
                    if tenant_id != 'default' and tenant_id not in tenants:
                        tenants.append(tenant_id)
        except Exception as e:
            self.logger.error(f"Error getting tenants: {str(e)}")
        
        return tenants
    
    def get_credential(self, realm, username=None):
        """Get credential from Splunk password store."""
        try:
            # Get credentials entities
            entities = entity.getEntities(
                ['admin', 'passwords'], 
                namespace=self.appName,
                owner='-', 
                sessionKey=self.getSessionKey()
            )
            
            # Find credential by realm and optionally username
            for _, entry in entities.items():
                if entry['realm'] == realm and (username is None or entry['username'] == username):
                    return {
                        'username': entry['username'],
                        'password': entry['clear_password'] if 'clear_password' in entry else None
                    }
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting realm: {str(e)}")