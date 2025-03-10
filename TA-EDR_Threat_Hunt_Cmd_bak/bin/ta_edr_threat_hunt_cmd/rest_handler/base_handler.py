#!/usr/bin/env python
# encoding=utf-8

import json
import os
import sys
import splunk.admin as admin
import splunk.rest as rest

# Add bin directory to path
bin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if bin_dir not in sys.path:
    sys.path.insert(0, bin_dir)

# Import TA modules
from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger

class BaseRestHandler(admin.MConfigHandler):
    """
    Base REST handler for TA-EDR_Threat_Hunt_Cmd app.
    
    This base handler provides common functionality for all REST handlers in the app.
    It follows the UCC framework's handler pattern.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize the base REST handler."""
        super(BaseRestHandler, self).__init__(*args, **kwargs)
        self.logger = get_logger('base_rest_handler')
        
    def setup(self):
        """
        Set up the REST handler.
        
        This method is called by the Splunk REST framework.
        """
        try:
            if self.requestedAction == admin.ACTION_CREATE:
                # For creation, require the entity name
                self.supportedArgs.addReqArg('name')
                
            # Add standard optional arguments
            if self.requestedAction in (admin.ACTION_CREATE, admin.ACTION_EDIT):
                for arg in self.get_args():
                    self.supportedArgs.addOptArg(arg)
                
            # Handle custom actions
            if self.customAction == 'test_connection':
                for arg in ['provider', 'tenant', 'console', 'username', 'password']:
                    self.supportedArgs.addOptArg(arg)
                    
        except Exception as e:
            self.logger.error(f"Error in setup: {str(e)}")
            raise
    
    def get_args(self):
        """
        Get the list of supported arguments for this handler.
        
        This method should be overridden by subclasses to provide the list of
        supported arguments for the entity type.
        
        Returns:
            list: List of argument names
        """
        return []
    
    def readConf(self, confName, stanza=None, virtual=False):
        """
        Read a configuration file.
        
        This method extends the admin.MConfigHandler readConf method to handle
        exceptions and provide better logging.
        
        Arguments:
            confName: The name of the configuration file
            stanza: Optional stanza name
            virtual: Whether to include virtual settings
            
        Returns:
            dict: Dictionary of configuration settings
        """
        try:
            return super(BaseRestHandler, self).readConf(confName, stanza, virtual)
        except Exception as e:
            self.logger.error(f"Error reading {confName}: {str(e)}")
            return {}
    
    def writeConf(self, confName, stanza, stanzaArgs):
        """
        Write a configuration file.
        
        This method extends the admin.MConfigHandler writeConf method to handle
        exceptions and provide better logging.
        
        Arguments:
            confName: The name of the configuration file
            stanza: The stanza name
            stanzaArgs: Dictionary of stanza arguments
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            super(BaseRestHandler, self).writeConf(confName, stanza, stanzaArgs)
            return True
        except Exception as e:
            self.logger.error(f"Error writing {confName}/{stanza}: {str(e)}")
            return False
    
    def deleteConf(self, confName, stanza):
        """
        Delete a stanza from a configuration file.
        
        This method extends the admin.MConfigHandler writeConf method to handle
        stanza deletion.
        
        Arguments:
            confName: The name of the configuration file
            stanza: The stanza name
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get the existing configuration
            conf = self.readConf(confName)
            
            if stanza in conf:
                # Use the REST API to delete the stanza
                rest_path = f"/servicesNS/nobody/{self.appName}/configs/conf-{confName}/{stanza}"
                rest.simpleRequest(rest_path, sessionKey=self.getSessionKey(), method='DELETE')
                return True
            else:
                self.logger.warning(f"Stanza {stanza} not found in {confName}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error deleting {confName}/{stanza}: {str(e)}")
            return False
    
    def getEntities(self, path, namespace=None, owner=None, count=-1, sort_key=None, sort_desc=False, includeDisabled=True):
        """
        Get entities using the Splunk REST API.
        
        Arguments:
            path: The REST API path
            namespace: The app namespace
            owner: The entity owner
            count: Maximum number of entities to return
            sort_key: Key to sort by
            sort_desc: Whether to sort descending
            includeDisabled: Whether to include disabled entities
            
        Returns:
            list: List of entities
        """
        try:
            # Build the REST URL
            rest_path = path
            
            # Add query parameters
            params = {}
            
            if namespace is not None:
                params['namespace'] = namespace
                
            if owner is not None:
                params['owner'] = owner
                
            if count > 0:
                params['count'] = str(count)
                
            if not includeDisabled:
                params['includeDisabled'] = '0'
                
            # Add output mode
            params['output_mode'] = 'json'
            
            # Build query string
            query_string = '&'.join([f'{k}={v}' for k, v in params.items()])
            if query_string:
                rest_path = f"{rest_path}?{query_string}"
            
            # Make the request
            response, content = rest.simpleRequest(
                rest_path,
                sessionKey=self.getSessionKey(),
                method='GET'
            )
            
            if response.status != 200:
                self.logger.error(f"Error getting entities: HTTP {response.status} - {content}")
                return []
                
            # Parse the response
            try:
                content_json = json.loads(content)
                entities = content_json.get('entry', [])
                
                # Sort if requested
                if sort_key is not None:
                    reverse = sort_desc
                    entities = sorted(entities, key=lambda x: x.get('content', {}).get(sort_key, ''), reverse=reverse)
                
                return entities
            except json.JSONDecodeError:
                self.logger.error(f"Error parsing response: {content}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting entities: {str(e)}")
            return []
    
    def handleList(self, confInfo):
        """
        Handle list action from the UI.
        
        This method should be overridden by subclasses to provide the list of
        entities of the specific type.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        raise NotImplementedError("Subclasses must implement handleList")
    
    def handleCreate(self, confInfo):
        """
        Handle create action from the UI.
        
        This method should be overridden by subclasses to handle the creation
        of an entity of the specific type.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        raise NotImplementedError("Subclasses must implement handleCreate")
    
    def handleEdit(self, confInfo):
        """
        Handle edit action from the UI.
        
        This method should be overridden by subclasses to handle the editing
        of an entity of the specific type.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        raise NotImplementedError("Subclasses must implement handleEdit")
    
    def handleRemove(self, confInfo):
        """
        Handle remove action from the UI.
        
        This method should be overridden by subclasses to handle the removal
        of an entity of the specific type.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        raise NotImplementedError("Subclasses must implement handleRemove")
    
    def handleCustom(self, confInfo):
        """
        Handle custom actions from the UI.
        
        This method can be overridden by subclasses to handle custom actions
        for the specific entity type.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        if self.customAction == 'test_connection':
            self._handle_test_connection(confInfo)
        else:
            confInfo['error'] = f"Unsupported custom action: {self.customAction}"
    
    def _handle_test_connection(self, confInfo):
        """
        Handle test_connection custom action.
        
        This method tests the connection to an EDR provider using the provided
        credentials.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        try:
            # Get connection parameters
            provider = self._get_param('provider')
            tenant = self._get_param('tenant', 'default')
            console = self._get_param('console', 'primary')
            username = self._get_param('username')
            password = self._get_param('password')
            
            # Validate required parameters
            required_params = {
                'provider': provider,
                'username': username,
                'password': password
            }
            
            for param_name, param_value in required_params.items():
                if not param_value:
                    confInfo['error'] = f"Missing required parameter: {param_name}"
                    return
            
            # Test the connection
            test_result = self._test_credential(
                self.getSessionKey(),
                provider,
                tenant,
                console,
                username,
                password
            )
            
            # Return the result
            confInfo['result'] = {
                'success': test_result.get('success', False),
                'message': test_result.get('message', 'Unknown error'),
                'details': json.dumps(test_result.get('details', {}))
            }
            
        except Exception as e:
            self.logger.error(f"Error testing connection: {str(e)}")
            confInfo['error'] = f"Error testing connection: {str(e)}"
    
    def _get_param(self, name, default=None):
        """
        Get a parameter from the REST request.
        
        Arguments:
            name: The parameter name
            default: Default value if parameter is not present
        
        Returns:
            The parameter value or default
        """
        if name in self.callerArgs.data:
            return self.callerArgs.data[name][0]
        return default
    
    def _test_credential(self, session_key, provider, tenant, console, username, password):
        """
        Test a credential by connecting to the provider's API.
        
        This method should be overridden by subclasses that need to test
        connections to specific providers.
        
        Arguments:
            session_key: The Splunk session key
            provider: The EDR provider
            tenant: The tenant ID
            console: The console ID
            username: The username or client ID
            password: The password or client secret
            
        Returns:
            dict: Test result with success status and message
        """
        return {
            'success': False,
            'message': 'Not implemented'
        }