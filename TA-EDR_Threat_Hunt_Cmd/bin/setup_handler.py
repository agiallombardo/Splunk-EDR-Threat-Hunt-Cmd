#!/usr/bin/env python
# encoding=utf-8

import os
import re
import sys
import json
import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest

# Add bin directory to path
bin_dir = os.path.dirname(os.path.abspath(__file__))
if bin_dir not in sys.path:
    sys.path.insert(0, bin_dir)

from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
from ta_edr_threat_hunt_cmd.lib.utils.config_utils import ConfigManager

class SetupHandler(admin.MConfigHandler):
    """
    Setup handler for EDR Threat Hunt Command.
    This handler manages the initial setup of the app.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize the setup handler."""
        admin.MConfigHandler.__init__(self, *args, **kwargs)
        self.logger = get_logger('setup_handler')
        
        # Define setup stanza
        self.supportedArgs.addOptArg('log_level')
        self.supportedArgs.addOptArg('default_tenant')
        self.supportedArgs.addOptArg('enable_logging')
        
        # Add is_configured flag
        self.supportedArgs.addOptArg('is_configured')
    
    def setup(self):
        """
        Setup method called for edit and list actions.
        """
        # Add a settings stanza to confInfo if it doesn't exist
        if 'settings' not in self.confInfo:
            self.confInfo['settings'] = {}
            
        if self.requestedAction == admin.ACTION_LIST:
            # On list, return current configuration
            self.get_configuration()
        elif self.requestedAction == admin.ACTION_EDIT:
            # On edit, update configuration
            self.update_configuration()
    
    def handleList(self, confInfo):
        """
        Handler for list action
        """
        # Make sure confInfo has a settings stanza
        if 'settings' not in confInfo:
            confInfo['settings'] = {}
            
        # Get configuration
        self.get_configuration()
        
    def handleEdit(self, confInfo):
        """
        Handler for edit action
        """
        # Make sure confInfo has a settings stanza
        if 'settings' not in confInfo:
            confInfo['settings'] = {}
            
        # Update configuration
        self.update_configuration()
    
    def get_configuration(self):
        """
        Get the current configuration.
        """
        try:
            # Check if app is configured
            is_configured = self._is_app_configured()
            
            # Get settings
            settings = {}
            
            # If app is configured, get settings from conf
            if is_configured:
                settings = self._get_settings()
            
            # Add is_configured flag
            settings['is_configured'] = is_configured
            
            # Add settings to response
            for key, value in settings.items():
                self.confInfo['settings'][key] = value
                
        except Exception as e:
            self.logger.error(f"Error getting configuration: {str(e)}")
            raise admin.InternalException(f"Error getting configuration: {str(e)}")
    
    def update_configuration(self):
        """
        Update the configuration.
        """
        try:
            # Get session key for API calls
            session_key = self.getSessionKey()
            
            # Get settings from request
            settings = {}
            for arg in self.supportedArgs.keys():
                if arg in self.callerArgs and self.callerArgs[arg] and len(self.callerArgs[arg]) > 0:
                    settings[arg] = self.callerArgs[arg][0]
            
            # Update the settings
            self._update_settings(session_key, settings)
            
            # Mark app as configured
            self._mark_app_configured(session_key)
            
            # Update the confInfo
            self.confInfo['settings']['is_configured'] = "true"
            
        except Exception as e:
            self.logger.error(f"Error updating configuration: {str(e)}")
            raise admin.InternalException(f"Error updating configuration: {str(e)}")
    
    def _is_app_configured(self):
        """
        Check if the app is configured.
        
        Returns:
            bool: Whether the app is configured
        """
        try:
            app_name = "TA-EDR_Threat_Hunt_Cmd"
            session_key = self.getSessionKey()
            
            # Use Splunk's REST API to check app.conf [install] is_configured
            uri = f"/servicesNS/nobody/{app_name}/configs/conf-app/install"
            response, content = rest.simpleRequest(
                uri,
                sessionKey=session_key,
                getargs={'output_mode': 'json'}
            )
            
            if response.status == 200:
                content_json = json.loads(content)
                entry = content_json.get('entry', [{}])[0]
                content = entry.get('content', {})
                is_configured = content.get('is_configured', 'false').lower() == 'true'
                return is_configured
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking if app is configured: {str(e)}")
            return False
    
    def _mark_app_configured(self, session_key):
        """
        Mark the app as configured.
        
        Args:
            session_key: The Splunk session key
        """
        try:
            app_name = "TA-EDR_Threat_Hunt_Cmd"
            
            # Use Splunk's REST API to update app.conf [install] is_configured
            uri = f"/servicesNS/nobody/{app_name}/configs/conf-app/install"
            postargs = {
                'is_configured': 'true'
            }
            
            response, content = rest.simpleRequest(
                uri,
                sessionKey=session_key,
                method='POST',
                postargs=postargs
            )
            
            if response.status != 200:
                self.logger.error(f"Error marking app as configured: {response.status}")
                
        except Exception as e:
            self.logger.error(f"Error marking app as configured: {str(e)}")
    
    def _get_settings(self):
        """
        Get the current settings.
        
        Returns:
            dict: Current settings
        """
        try:
            # Use config manager to get settings
            session_key = self.getSessionKey()
            config_manager = ConfigManager(session_key, self.logger)
            
            # Get settings from ta_edr_threat_hunt_cmd_settings.conf
            settings_conf = config_manager._get_conf('ta_edr_threat_hunt_cmd_settings')
            
            # Extract settings from 'settings' stanza
            if settings_conf and 'settings' in settings_conf:
                settings = settings_conf['settings']
                
                # Extract specific settings we want to return
                return {
                    'log_level': settings.get('log_level', 'INFO'),
                    'enable_logging': settings.get('enable_logging', '1'),
                    'default_tenant': 'default'  # Default tenant is often not stored explicitly
                }
            
            return {
                'log_level': 'INFO',
                'enable_logging': '1',
                'default_tenant': 'default'
            }
                
        except Exception as e:
            self.logger.error(f"Error getting settings: {str(e)}")
            return {
                'log_level': 'INFO',
                'enable_logging': '1',
                'default_tenant': 'default'
            }
    
    def _update_settings(self, session_key, settings):
        """
        Update the settings.
        
        Args:
            session_key: The Splunk session key
            settings: The settings to update
        """
        try:
            # Use config manager to update settings
            config_manager = ConfigManager(session_key, self.logger)
            
            # Prepare settings for update
            update_settings = {}
            
            # Include specifically supported settings
            if 'log_level' in settings:
                update_settings['log_level'] = settings['log_level']
            
            if 'enable_logging' in settings:
                update_settings['enable_logging'] = settings['enable_logging']
            
            # Update settings in ta_edr_threat_hunt_cmd_settings.conf
            config_manager.create_config('ta_edr_threat_hunt_cmd_settings', 'settings', update_settings)
            
            # If default_tenant is provided, ensure it exists in tenants.conf
            if 'default_tenant' in settings and settings['default_tenant'] != 'default':
                tenant_exists = False
                
                # Check if tenant exists
                tenants_conf = config_manager._get_conf('ta_edr_threat_hunt_cmd_tenants')
                if tenants_conf:
                    for stanza, tenant_info in tenants_conf.items():
                        if stanza != 'settings' and stanza != 'default':
                            if tenant_info.get('name') == settings['default_tenant'] or stanza == settings['default_tenant']:
                                tenant_exists = True
                                break
                
                # If tenant doesn't exist, create it
                if not tenant_exists:
                    config_manager.create_config('ta_edr_threat_hunt_cmd_tenants', settings['default_tenant'], {
                        'name': settings['default_tenant'],
                        'description': 'Default tenant created during setup',
                        'enabled': '1'
                    })
                
        except Exception as e:
            self.logger.error(f"Error updating settings: {str(e)}")
            raise

# Register the handler
admin.init(SetupHandler, admin.CONTEXT_APP_AND_USER)
