#!/usr/bin/env python
# encoding=utf-8

"""
This module contains the REST handler for managing app settings.
"""

import os
import sys
import json
import logging
import splunk.admin as admin

# Add lib directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ta_edr_threat_hunt_cmd"))

from ta_edr_threat_hunt_cmd.rest_handler.base_handler import BaseRestHandler
from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger

class SettingsHandler(BaseRestHandler):
    """
    REST Handler for managing app settings.
    
    This handler manages the app-wide settings for the EDR Threat Hunt Command app.
    It handles retrieving and updating all settings in the ta_edr_threat_hunt_cmd_settings.conf file.
    """
    
    # Define supported arguments/fields
    def setup(self):
        """
        Set up the supported arguments for this REST handler.
        
        This method defines which fields are accepted by the handler for 
        different actions (list, edit, etc.).
        """
        # Set up logging
        self.logger = get_logger("settings_handler")
        
        if self.requestedAction == admin.ACTION_EDIT:
            # Add all settings fields as supported arguments
            
            # General settings
            self.supportedArgs.addOptArg('enable_logging')
            self.supportedArgs.addOptArg('log_level')
            self.supportedArgs.addOptArg('default_threads')
            self.supportedArgs.addOptArg('default_batch_size')
            self.supportedArgs.addOptArg('default_limit')
            self.supportedArgs.addOptArg('process_limit')
            self.supportedArgs.addOptArg('event_limit')
            self.supportedArgs.addOptArg('network_limit')
            self.supportedArgs.addOptArg('file_limit')
            self.supportedArgs.addOptArg('cache_ttl')
            
            # Performance settings
            self.supportedArgs.addOptArg('enable_response_compression')
            self.supportedArgs.addOptArg('enable_connection_pooling')
            self.supportedArgs.addOptArg('api_timeout')
            self.supportedArgs.addOptArg('include_raw_default')
            
            # Sampling settings
            self.supportedArgs.addOptArg('enable_sampling')
            self.supportedArgs.addOptArg('sample_threshold')
            self.supportedArgs.addOptArg('sample_size')
            
            # Cache settings
            self.supportedArgs.addOptArg('enable_cache')
            self.supportedArgs.addOptArg('cache_expiry')
            self.supportedArgs.addOptArg('cache_size_limit')
            
            # Provider settings - CrowdStrike
            self.supportedArgs.addOptArg('crowdstrike_enabled')
            self.supportedArgs.addOptArg('crowdstrike_api_url')
            self.supportedArgs.addOptArg('crowdstrike_max_rate')
            self.supportedArgs.addOptArg('crowdstrike_api_timeout')
            self.supportedArgs.addOptArg('crowdstrike_api_connect_timeout')
            self.supportedArgs.addOptArg('crowdstrike_api_read_timeout')
            self.supportedArgs.addOptArg('crowdstrike_default_batch_size')
            self.supportedArgs.addOptArg('crowdstrike_default_filter')
            
            # Provider settings - SentinelOne
            self.supportedArgs.addOptArg('sentinelone_enabled')
            self.supportedArgs.addOptArg('sentinelone_api_url')
            self.supportedArgs.addOptArg('sentinelone_max_rate')
            self.supportedArgs.addOptArg('sentinelone_api_timeout')
            self.supportedArgs.addOptArg('sentinelone_api_connect_timeout')
            self.supportedArgs.addOptArg('sentinelone_api_read_timeout')
            self.supportedArgs.addOptArg('sentinelone_default_batch_size')
            self.supportedArgs.addOptArg('sentinelone_default_filter')
            
            # Provider settings - Defender
            self.supportedArgs.addOptArg('defender_enabled')
            self.supportedArgs.addOptArg('defender_api_url')
            self.supportedArgs.addOptArg('defender_max_rate')
            self.supportedArgs.addOptArg('defender_api_timeout')
            self.supportedArgs.addOptArg('defender_api_connect_timeout')
            self.supportedArgs.addOptArg('defender_api_read_timeout')
            self.supportedArgs.addOptArg('defender_default_batch_size')
            self.supportedArgs.addOptArg('defender_default_filter')
            self.supportedArgs.addOptArg('defender_use_advanced_hunting')
            
            # KV Store settings
            self.supportedArgs.addOptArg('kvstore_collection')
            self.supportedArgs.addOptArg('agent_ttl')
            self.supportedArgs.addOptArg('backup_to_csv')
            self.supportedArgs.addOptArg('backup_frequency')
            self.supportedArgs.addOptArg('backup_path')
            self.supportedArgs.addOptArg('encrypted_fields')
            
            # Agent discovery settings
            self.supportedArgs.addOptArg('default_scan_interval')
            self.supportedArgs.addOptArg('schedule_scan')
            self.supportedArgs.addOptArg('auto_purge_stale')
            self.supportedArgs.addOptArg('stale_threshold')
            
            # Health monitoring settings
            self.supportedArgs.addOptArg('enable_health_monitoring')
            self.supportedArgs.addOptArg('health_check_interval')
            self.supportedArgs.addOptArg('health_results_collection')
            self.supportedArgs.addOptArg('health_retention_days')
            self.supportedArgs.addOptArg('alert_on_degradation')
            self.supportedArgs.addOptArg('alert_email')
    
    def handleList(self, confInfo):
        """
        Get all app settings.
        
        This method handles GET requests to retrieve the current app settings.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        self.logger.debug("Listing settings")
        
        # Configuration file details
        conf_file = "ta_edr_threat_hunt_cmd_settings"
        stanza = "settings"
        
        # Get existing settings (returns a dict of settings)
        try:
            settings = self.getConfigs(conf_file, stanza)
            
            # Apply defaults for missing settings
            self._apply_default_settings(settings)
            
            # Format certain fields for better display
            self._format_settings_for_display(settings)
            
            # Return all settings to UI
            confInfo['settings'] = settings
            
            self.logger.info("Successfully retrieved settings")
            
        except Exception as e:
            self.logger.error(f"Error retrieving settings: {str(e)}")
            raise
    
    def handleEdit(self, confInfo):
        """
        Update app settings.
        
        This method handles POST requests to update the app settings.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        self.logger.debug("Updating settings")
        
        # Configuration file details
        conf_file = "ta_edr_threat_hunt_cmd_settings"
        stanza = "settings"
        
        try:
            # Get settings from request data
            settings = {}
            for key in self.callerArgs.data:
                # Most settings are single-valued arrays
                settings[key] = self.callerArgs.data[key][0]
            
            # Validate settings
            self._validate_settings(settings)
            
            # Normalize settings (convert types, etc)
            self._normalize_settings(settings)
            
            # Save settings
            self.saveConfigs(conf_file, stanza, settings)
            
            # Return updated settings
            self._format_settings_for_display(settings)
            confInfo['settings'] = settings
            
            self.logger.info("Successfully updated settings")
            
        except Exception as e:
            self.logger.error(f"Error updating settings: {str(e)}")
            raise
    
    def _apply_default_settings(self, settings):
        """
        Apply default values for any missing settings.
        
        Arguments:
            settings (dict): The current settings
        """
        defaults = {
            # General settings
            'enable_logging': '1',
            'log_level': 'INFO',
            'default_threads': '8',
            'default_batch_size': '20',
            'default_limit': '500',
            'process_limit': '1000',
            'event_limit': '5000',
            'network_limit': '1000',
            'file_limit': '500',
            'cache_ttl': '3600',
            
            # Performance settings
            'enable_response_compression': '1',
            'enable_connection_pooling': '1',
            'api_timeout': '30',
            'include_raw_default': '0',
            
            # Sampling settings
            'enable_sampling': '0',
            'sample_threshold': '10000',
            'sample_size': '1000',
            
            # Cache settings
            'enable_cache': '1',
            'cache_expiry': '300',
            'cache_size_limit': '100000000',
            
            # Provider settings - CrowdStrike
            'crowdstrike_enabled': '1',
            'crowdstrike_api_url': 'https://api.crowdstrike.com',
            'crowdstrike_max_rate': '120',
            'crowdstrike_api_timeout': '30',
            'crowdstrike_api_connect_timeout': '10',
            'crowdstrike_api_read_timeout': '30',
            'crowdstrike_default_batch_size': '100',
            'crowdstrike_default_filter': "status:['normal','containment_pending','contained']",
            
            # Provider settings - SentinelOne
            'sentinelone_enabled': '1',
            'sentinelone_api_url': 'https://management-api.sentinelone.net',
            'sentinelone_max_rate': '60',
            'sentinelone_api_timeout': '30',
            'sentinelone_api_connect_timeout': '10',
            'sentinelone_api_read_timeout': '30',
            'sentinelone_default_batch_size': '100',
            'sentinelone_default_filter': 'agentStatus:active+isDecommissioned:false',
            
            # Provider settings - Defender
            'defender_enabled': '1',
            'defender_api_url': 'https://api.securitycenter.microsoft.com',
            'defender_max_rate': '100',
            'defender_api_timeout': '30',
            'defender_api_connect_timeout': '10',
            'defender_api_read_timeout': '30',
            'defender_default_batch_size': '100',
            'defender_default_filter': "healthStatus eq 'Active'",
            'defender_use_advanced_hunting': '1',
            
            # KV Store settings
            'kvstore_collection': 'edr_agents',
            'agent_ttl': '7',
            'backup_to_csv': '1',
            'backup_frequency': '86400',
            'backup_path': '$SPLUNK_HOME/etc/apps/TA-EDR_Threat_Hunt_Cmd/lookups/edr_agents.csv',
            'encrypted_fields': 'tags,site,criticality',
            
            # Agent discovery settings
            'default_scan_interval': '86400',
            'schedule_scan': '1',
            'auto_purge_stale': '1',
            'stale_threshold': '30',
            
            # Health monitoring settings
            'enable_health_monitoring': '1',
            'health_check_interval': '24',
            'health_results_collection': 'edr_health_results',
            'health_retention_days': '30',
            'alert_on_degradation': '1',
            'alert_email': ''
        }
        
        # Apply defaults for any missing settings
        for key, value in defaults.items():
            if key not in settings:
                settings[key] = value
    
    def _validate_settings(self, settings):
        """
        Validate settings to ensure they meet requirements.
        
        Arguments:
            settings (dict): The settings to validate
            
        Raises:
            admin.ArgValidationException: If validation fails
        """
        # Validate log level
        if 'log_level' in settings:
            valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if settings['log_level'] not in valid_log_levels:
                raise admin.ArgValidationException(f"Invalid log level: {settings['log_level']}. Must be one of: {', '.join(valid_log_levels)}")
        
        # Validate numeric fields
        numeric_fields = {
            'default_threads': {'min': 1, 'max': 32},
            'default_batch_size': {'min': 1, 'max': 1000},
            'default_limit': {'min': 1, 'max': 10000},
            'process_limit': {'min': 1, 'max': 10000},
            'event_limit': {'min': 1, 'max': 10000},
            'network_limit': {'min': 1, 'max': 10000},
            'file_limit': {'min': 1, 'max': 10000},
            'cache_ttl': {'min': 1, 'max': 86400},
            'cache_expiry': {'min': 1, 'max': 86400},
            'cache_size_limit': {'min': 1, 'max': 1000000000},
            'sample_threshold': {'min': 1, 'max': 1000000},
            'sample_size': {'min': 1, 'max': 100000},
            'api_timeout': {'min': 1, 'max': 300},
            'crowdstrike_max_rate': {'min': 1, 'max': 1000},
            'crowdstrike_api_timeout': {'min': 1, 'max': 300},
            'crowdstrike_api_connect_timeout': {'min': 1, 'max': 60},
            'crowdstrike_api_read_timeout': {'min': 1, 'max': 300},
            'crowdstrike_default_batch_size': {'min': 1, 'max': 1000},
            'sentinelone_max_rate': {'min': 1, 'max': 1000},
            'sentinelone_api_timeout': {'min': 1, 'max': 300},
            'sentinelone_api_connect_timeout': {'min': 1, 'max': 60},
            'sentinelone_api_read_timeout': {'min': 1, 'max': 300},
            'sentinelone_default_batch_size': {'min': 1, 'max': 1000},
            'defender_max_rate': {'min': 1, 'max': 1000},
            'defender_api_timeout': {'min': 1, 'max': 300},
            'defender_api_connect_timeout': {'min': 1, 'max': 60},
            'defender_api_read_timeout': {'min': 1, 'max': 300},
            'defender_default_batch_size': {'min': 1, 'max': 1000},
            'agent_ttl': {'min': 1, 'max': 365},
            'backup_frequency': {'min': 3600, 'max': 604800},
            'stale_threshold': {'min': 1, 'max': 365},
            'default_scan_interval': {'min': 3600, 'max': 604800},
            'health_check_interval': {'min': 1, 'max': 168},
            'health_retention_days': {'min': 1, 'max': 365}
        }
        
        for field, limits in numeric_fields.items():
            if field in settings:
                try:
                    value = int(settings[field])
                    if value < limits['min'] or value > limits['max']:
                        raise admin.ArgValidationException(
                            f"Invalid {field}: {value}. Must be between {limits['min']} and {limits['max']}"
                        )
                except ValueError:
                    raise admin.ArgValidationException(f"Invalid {field}: {settings[field]}. Must be an integer")
        
        # Validate URL fields
        url_fields = ['crowdstrike_api_url', 'sentinelone_api_url', 'defender_api_url']
        for field in url_fields:
            if field in settings and settings[field]:
                if not (settings[field].startswith('http://') or settings[field].startswith('https://')):
                    raise admin.ArgValidationException(f"Invalid {field}: {settings[field]}. Must be a valid URL starting with http:// or https://")
    
    def _normalize_settings(self, settings):
        """
        Normalize settings to ensure proper formats and types.
        
        Arguments:
            settings (dict): The settings to normalize
        """
        # Normalize boolean fields (stored as '0'/'1')
        boolean_fields = [
            'enable_logging', 'enable_response_compression', 'enable_connection_pooling', 
            'include_raw_default', 'enable_sampling', 'enable_cache',
            'crowdstrike_enabled', 'sentinelone_enabled', 'defender_enabled', 
            'backup_to_csv', 'schedule_scan', 'auto_purge_stale',
            'defender_use_advanced_hunting', 'enable_health_monitoring', 'alert_on_degradation'
        ]
        
        for field in boolean_fields:
            if field in settings:
                # Convert various boolean representations to '0'/'1'
                value = str(settings[field]).lower()
                if value in ('true', 'yes', 'y', '1', 'on', 'enabled'):
                    settings[field] = '1'
                else:
                    settings[field] = '0'
        
        # Normalize numeric fields (ensure they're strings)
        numeric_fields = [
            'default_threads', 'default_batch_size', 'default_limit',
            'process_limit', 'event_limit', 'network_limit', 'file_limit',
            'cache_ttl', 'cache_expiry', 'cache_size_limit',
            'sample_threshold', 'sample_size', 'api_timeout',
            'crowdstrike_max_rate', 'crowdstrike_api_timeout',
            'crowdstrike_api_connect_timeout', 'crowdstrike_api_read_timeout',
            'crowdstrike_default_batch_size',
            'sentinelone_max_rate', 'sentinelone_api_timeout',
            'sentinelone_api_connect_timeout', 'sentinelone_api_read_timeout',
            'sentinelone_default_batch_size',
            'defender_max_rate', 'defender_api_timeout',
            'defender_api_connect_timeout', 'defender_api_read_timeout',
            'defender_default_batch_size',
            'agent_ttl', 'backup_frequency', 'stale_threshold',
            'default_scan_interval', 'health_check_interval', 'health_retention_days'
        ]
        
        for field in numeric_fields:
            if field in settings:
                try:
                    # Convert to int and back to string to normalize
                    settings[field] = str(int(settings[field]))
                except ValueError:
                    # If conversion fails, leave as is (validation would have caught this)
                    pass
    
    def _format_settings_for_display(self, settings):
        """
        Format settings for UI display.
        
        Arguments:
            settings (dict): The settings to format
        """
        # For boolean fields, make sure they're using '0'/'1'
        boolean_fields = [
            'enable_logging', 'enable_response_compression', 'enable_connection_pooling',
            'include_raw_default', 'enable_sampling', 'enable_cache',
            'crowdstrike_enabled', 'sentinelone_enabled', 'defender_enabled',
            'backup_to_csv', 'schedule_scan', 'auto_purge_stale',
            'defender_use_advanced_hunting', 'enable_health_monitoring', 'alert_on_degradation'
        ]
        
        for field in boolean_fields:
            if field in settings:
                settings[field] = '1' if str(settings[field]).lower() in ('true', 'yes', 'y', '1', 'on', 'enabled') else '0'

# Initialize the handler
if __name__ == "__main__":
    admin.init(SettingsHandler, admin.CONTEXT_NONE)
