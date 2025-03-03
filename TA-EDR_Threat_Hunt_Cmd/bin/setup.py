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
from splunk.clilib import cli_common as cli

class SetupApp(admin.MConfigHandler):
    """
    Set up for the TA-EDR_Threat_Hunt_Cmd app.
    This handler follows the Splunk MVC pattern for setup pages.
    """
    
    # Define all the configuration parameters
    CONF_FILE = 'edr'

    # Define the parameters for all tabs
    SETTINGS_STANZA_MAP = {
        # General Settings
        'enable_logging': {'section': 'global', 'key': 'enable_logging', 'type': 'bool'},
        'log_level': {'section': 'global', 'key': 'log_level', 'type': 'string', 
                      'valid_values': ['INFO', 'DEBUG', 'WARNING', 'ERROR']},
        'default_threads': {'section': 'edrhunt', 'key': 'default_threads', 'type': 'int', 
                           'min': 1, 'max': 16},
        'default_batch_size': {'section': 'edrhunt', 'key': 'default_batch_size', 'type': 'int',
                              'min': 1, 'max': 100},
        
        # CrowdStrike Settings
        'crowdstrike_enabled': {'section': 'crowdstrike', 'key': 'enabled', 'type': 'bool'},
        'crowdstrike_api_url': {'section': 'crowdstrike', 'key': 'api_url', 'type': 'string'},
        'crowdstrike_max_rate': {'section': 'crowdstrike', 'key': 'max_rate', 'type': 'int',
                               'min': 1, 'max': 1000},
        'crowdstrike_api_timeout': {'section': 'crowdstrike', 'key': 'api_timeout', 'type': 'int',
                                  'min': 1, 'max': 300},
        
        # SentinelOne Settings
        'sentinelone_enabled': {'section': 'sentinelone', 'key': 'enabled', 'type': 'bool'},
        'sentinelone_api_url': {'section': 'sentinelone', 'key': 'api_url', 'type': 'string'},
        'sentinelone_max_rate': {'section': 'sentinelone', 'key': 'max_rate', 'type': 'int',
                               'min': 1, 'max': 1000},
        'sentinelone_api_timeout': {'section': 'sentinelone', 'key': 'api_timeout', 'type': 'int',
                                  'min': 1, 'max': 300},
        
        # Microsoft Defender Settings
        'defender_enabled': {'section': 'defender', 'key': 'enabled', 'type': 'bool'},
        'defender_api_url': {'section': 'defender', 'key': 'api_url', 'type': 'string'},
        'defender_max_rate': {'section': 'defender', 'key': 'max_rate', 'type': 'int',
                            'min': 1, 'max': 1000},
        'defender_api_timeout': {'section': 'defender', 'key': 'api_timeout', 'type': 'int',
                               'min': 1, 'max': 300},
        
        # KV Store Settings
        'kvstore_collection': {'section': 'edrhunt', 'key': 'collection_name', 'type': 'string'},
        'agent_ttl': {'section': 'agentdiscovery', 'key': 'default_ttl', 'type': 'int',
                     'min': 1, 'max': 365},
        'backup_to_csv': {'section': 'agentdiscovery', 'key': 'backup_to_csv', 'type': 'bool'},
        
        # Health Monitoring Settings
        'enable_health_monitoring': {'section': 'health', 'key': 'enabled', 'type': 'bool'},
        'health_check_interval': {'section': 'health', 'key': 'check_interval', 'type': 'int',
                                'min': 1, 'max': 168},
        'health_results_collection': {'section': 'health', 'key': 'results_collection', 'type': 'string'},
        'health_retention_days': {'section': 'health', 'key': 'retention_days', 'type': 'int',
                                'min': 1, 'max': 365},
        'alert_on_degradation': {'section': 'health', 'key': 'alert_on_degradation', 'type': 'bool'},
        'alert_email': {'section': 'health', 'key': 'alert_email', 'type': 'string'},
    }
    
    # Default values
    DEFAULTS = {
        'enable_logging': True,
        'log_level': 'INFO',
        'default_threads': 4,
        'default_batch_size': 20,
        'crowdstrike_enabled': True,
        'crowdstrike_api_url': 'https://api.crowdstrike.com',
        'crowdstrike_max_rate': 120,
        'crowdstrike_api_timeout': 30,
        'sentinelone_enabled': True,
        'sentinelone_api_url': 'https://management-api.sentinelone.net',
        'sentinelone_max_rate': 60,
        'sentinelone_api_timeout': 30,
        'defender_enabled': True,
        'defender_api_url': 'https://api.securitycenter.microsoft.com',
        'defender_max_rate': 100,
        'defender_api_timeout': 30,
        'kvstore_collection': 'edr_agents',
        'agent_ttl': 7,
        'backup_to_csv': True,
        'enable_health_monitoring': True,
        'health_check_interval': 24,
        'health_results_collection': 'edr_health_results',
        'health_retention_days': 30,
        'alert_on_degradation': True,
        'alert_email': '',
    }
    
    # Additional fields for credentials and tenants
    ADDITIONAL_FIELDS = [
        'crowdstrike_credentials_list',
        'sentinelone_credentials_list',
        'defender_credentials_list',
        'tenant_list',
    ]
    
    def setup(self):
        """Set up the app with all necessary parameters."""
        # Set up logging
        self.app_name = 'TA-EDR_Threat_Hunt_Cmd'
        
        try:
            # Try to import the app's logger if available
            from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
            self.logger = get_logger('setup_page')
        except ImportError:
            # Fall back to standard logging
            import logging
            self.logger = logging.getLogger('setup_page')
        
        # Initialize self.endpoints
        if self.requestedAction == admin.ACTION_EDIT:
            # Add all regular parameters
            for param in self.SETTINGS_STANZA_MAP:
                self.supportedArgs.addOptArg(param)
            
            # Add the credential and tenant lists
            for field in self.ADDITIONAL_FIELDS:
                self.supportedArgs.addOptArg(field)
    
    def handleList(self, confInfo):
        """
        List all the current settings.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        self.logger.info("Retrieving configuration")
        
        # Create a key for the configuration to return
        confDict = confInfo['settings']
        
        # Initialize with defaults
        for param, default in self.DEFAULTS.items():
            confDict[param] = self._format_value(default)
        
        # Read each relevant section from edr.conf
        try:
            # Get the existing configuration
            edr_conf = self.readConf(self.CONF_FILE)
            
            # Update with actual values from the configuration
            for param, mapping in self.SETTINGS_STANZA_MAP.items():
                section = mapping['section']
                key = mapping['key']
                
                if section in edr_conf and key in edr_conf[section]:
                    confDict[param] = self._normalize_value(
                        edr_conf[section][key], 
                        mapping['type']
                    )
        except Exception as e:
            self.logger.error(f"Error reading configuration: {str(e)}")
            confDict['error'] = f"Error reading configuration: {str(e)}"
        
        # Get credential lists
        try:
            # Get credentials from Splunk's password store
            credentials = entity.getEntities(
                ['admin', 'passwords'], 
                namespace=self.appName,
                owner='-', 
                sessionKey=self.getSessionKey()
            )
            
            # Extract credentials by prefix
            crowdstrike_creds = []
            sentinelone_creds = []
            defender_creds = []
            
            for _, entry in credentials.items():
                if 'realm' in entry:
                    realm = entry['realm']
                    if realm.startswith('crowdstrike_'):
                        crowdstrike_creds.append(realm)
                    elif realm.startswith('sentinelone_'):
                        sentinelone_creds.append(realm)
                    elif realm.startswith('defender_'):
                        defender_creds.append(realm)
            
            # Add to configuration
            confDict['crowdstrike_credentials_list'] = ','.join(crowdstrike_creds)
            confDict['sentinelone_credentials_list'] = ','.join(sentinelone_creds)
            confDict['defender_credentials_list'] = ','.join(defender_creds)
            
        except Exception as e:
            self.logger.error(f"Error retrieving credentials: {str(e)}")
            confDict['credential_error'] = f"Error retrieving credentials: {str(e)}"
        
        # Get tenant list
        try:
            # Get tenant configurations
            tenant_conf = self.readConf('tenants')
            tenants = ['default']  # Always include default
            
            # Extract tenant IDs
            for stanza in tenant_conf:
                if stanza.startswith('tenant:'):
                    tenant_id = stanza[7:]  # Remove 'tenant:' prefix
                    if tenant_id != 'default' and tenant_id not in tenants:
                        tenants.append(tenant_id)
            
            confDict['tenant_list'] = ','.join(tenants)
            
        except Exception as e:
            self.logger.error(f"Error retrieving tenants: {str(e)}")
            confDict['tenant_error'] = f"Error retrieving tenants: {str(e)}"
    
    def handleEdit(self, confInfo):
        """
        Handle the edit action from the UI.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        self.logger.info("Updating configuration")
        
        # Create response container
        confDict = confInfo['settings']
        
        try:
            # Get the form values and update configuration
            self._update_configuration()
            
            # Process credentials
            self._process_credentials()
            
            # Process tenants
            self._process_tenants()
            
            # Mark app as configured
            self._mark_configured()
            
            # Return success
            confDict['status'] = 'Configuration updated successfully'
            
        except Exception as e:
            self.logger.error(f"Error updating configuration: {str(e)}")
            confDict['error'] = f"Error updating configuration: {str(e)}"
    
    def _update_configuration(self):
        """Update the configuration files with form values."""
        # Group parameters by section
        sections = {}
        
        for param, mapping in self.SETTINGS_STANZA_MAP.items():
            section = mapping['section']
            key = mapping['key']
            
            if param in self.callerArgs.data:
                if section not in sections:
                    sections[section] = {}
                
                # Get and normalize the value
                raw_value = self.callerArgs.data[param][0]
                value = self._normalize_value(raw_value, mapping['type'])
                
                # Validate the value
                if mapping['type'] == 'int':
                    if 'min' in mapping and int(value) < mapping['min']:
                        raise ValueError(f"Value for {param} must be at least {mapping['min']}")
                    if 'max' in mapping and int(value) > mapping['max']:
                        raise ValueError(f"Value for {param} must be at most {mapping['max']}")
                
                # Convert to string for storage
                sections[section][key] = str(value)
        
        # Write to configuration file
        for section, params in sections.items():
            self.writeConf(self.CONF_FILE, section, params)
    
    def _process_credentials(self):
        """Process credential lists and update edr_credentials.conf."""
        if 'crowdstrike_credentials_list' in self.callerArgs.data:
            self._process_credential_list('crowdstrike', self.callerArgs.data['crowdstrike_credentials_list'][0])
        
        if 'sentinelone_credentials_list' in self.callerArgs.data:
            self._process_credential_list('sentinelone', self.callerArgs.data['sentinelone_credentials_list'][0])
        
        if 'defender_credentials_list' in self.callerArgs.data:
            self._process_credential_list('defender', self.callerArgs.data['defender_credentials_list'][0])
    
    def _process_credential_list(self, provider, creds_list):
        """
        Process a single provider's credential list.
        
        Arguments:
            provider: The EDR provider (crowdstrike, sentinelone, defender)
            creds_list: Comma-separated list of credential names
        """
        if not creds_list:
            return
        
        # Parse and validate credentials
        credentials = []
        for cred in creds_list.split(','):
            cred = cred.strip()
            if not cred:
                continue
            
            # Validate credential format
            if not re.match(f'^{provider}_[a-zA-Z0-9_-]+_[a-zA-Z0-9_-]+$', cred):
                self.logger.warning(f"Invalid credential format: {cred}")
                continue
                
            credentials.append(cred)
        
        # Create credential configuration
        cred_conf = {}
        
        # Add the list of credentials
        if 'credentials' not in cred_conf:
            cred_conf['credentials'] = {}
        cred_conf['credentials'] = {
            'credential_list': ','.join(credentials)
        }
        
        # Add each credential
        for cred in credentials:
            parts = cred.split('_', 2)
            tenant = parts[1] if len(parts) > 1 else 'default'
            console = parts[2] if len(parts) > 2 else 'primary'
            
            cred_conf[cred] = {
                'provider': provider,
                'tenant': tenant,
                'console': console
            }
        
        # Write to configuration
        for stanza, params in cred_conf.items():
            self.writeConf('edr_credentials', stanza, params)
    
    def _process_tenants(self):
        """Process tenant list and update tenants.conf."""
        if 'tenant_list' not in self.callerArgs.data:
            return
            
        tenants_list = self.callerArgs.data['tenant_list'][0]
        if not tenants_list:
            return
        
        # Parse and validate tenants
        tenants = []
        for tenant in tenants_list.split(','):
            tenant = tenant.strip()
            if not tenant:
                continue
                
            # Validate tenant name
            if not re.match('^[a-zA-Z0-9_-]+$', tenant):
                self.logger.warning(f"Invalid tenant name: {tenant}")
                continue
                
            tenants.append(tenant)
        
        # Create tenant configuration
        for tenant in tenants:
            stanza = f"tenant:{tenant}"
            self.writeConf('tenants', stanza, {
                'name': tenant.capitalize(),
                'description': f"{tenant.capitalize()} environment",
                'enabled': 'true'
            })
    
    def _mark_configured(self):
        """Mark the app as configured in app.conf."""
        # Get app.conf path
        app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'local')
        if not os.path.exists(app_path):
            os.makedirs(app_path)
            
        app_conf_path = os.path.join(app_path, 'app.conf')
        
        # Read existing app.conf if it exists
        app_conf = {}
        if os.path.exists(app_conf_path):
            try:
                app_conf = cli.readConfFile(app_conf_path)
            except Exception:
                app_conf = {}
        
        # Ensure install stanza exists
        if 'install' not in app_conf:
            app_conf['install'] = {}
            
        # Mark as configured
        app_conf['install']['is_configured'] = '1'
        
        # Add timestamp
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        app_conf['install']['configured_at'] = timestamp
        
        # Write updated app.conf
        cli.writeConfFile(app_conf_path, app_conf)
    
    def _normalize_value(self, value, value_type):
        """
        Normalize a value based on its type.
        
        Arguments:
            value: The value to normalize
            value_type: The type of the value (bool, int, string)
            
        Returns:
            The normalized value
        """
        if value_type == 'bool':
            # Convert to boolean
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ('1', 'true', 'yes', 'on')
            return bool(value)
        
        elif value_type == 'int':
            # Convert to integer
            try:
                return int(value)
            except (ValueError, TypeError):
                return 0
        
        # Default to string
        return str(value)
    
    def _format_value(self, value):
        """
        Format a value for returning to the UI.
        
        Arguments:
            value: The value to format
            
        Returns:
            The formatted value as a string
        """
        if isinstance(value, bool):
            return '1' if value else '0'
        return str(value)

# Script execution
if __name__ == "__main__":
    admin.init(SetupApp, admin.CONTEXT_NONE)
