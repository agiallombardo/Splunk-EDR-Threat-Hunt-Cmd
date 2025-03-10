#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import re
import splunk.admin as admin

# Add bin directory to path
bin_dir = os.path.dirname(os.path.abspath(__file__))
if bin_dir not in sys.path:
    sys.path.insert(0, bin_dir)

# Import TA modules
from ta_edr_threat_hunt_cmd.lib.utils.logging_utils import get_logger
from ta_edr_threat_hunt_cmd.rest_handler.base_handler import BaseRestHandler

class TenantHandler(BaseRestHandler):
    """
    Tenant handler for EDR tenants.
    This handler follows the UCC pattern for managing tenant entities.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize the tenant handler."""
        super(TenantHandler, self).__init__(*args, **kwargs)
        self.logger = get_logger('tenant_handler')
        
    def handleList(self, confInfo):
        """
        List all tenants configured in the app.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        try:
            # Get all tenants
            tenants = self._get_tenants()
            
            # Add each tenant to confInfo
            for name, tenant in tenants.items():
                confInfo[name] = tenant
                
        except Exception as e:
            self.logger.error(f"Error listing tenants: {str(e)}")
            raise admin.InternalException(f"Error listing tenants: {str(e)}")
    
    def handleCreate(self, confInfo):
        """
        Create a new tenant.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        try:
            # Get tenant ID
            tenant_id = self.callerArgs.id
            
            if not tenant_id:
                raise admin.ArgValidationException("Tenant ID is required")
                
            # Validate tenant ID format
            if not re.match(r'^[a-zA-Z0-9_-]+$', tenant_id):
                raise admin.ArgValidationException("Tenant ID must contain only alphanumeric characters, underscores, and hyphens")
            
            # Get tenant parameters
            display_name = self._get_param('display_name', tenant_id.capitalize())
            description = self._get_param('description', f"{display_name} environment")
            enabled = self._get_param('enabled', 'true').lower() in ('true', '1', 'yes', 'y')
            
            # Update tenants.conf
            self._update_tenant_conf(tenant_id, display_name, description, enabled)
            
            # Return success
            confInfo[tenant_id] = {
                'name': tenant_id,
                'display_name': display_name,
                'description': description,
                'enabled': '1' if enabled else '0'
            }
            
        except Exception as e:
            self.logger.error(f"Error creating tenant: {str(e)}")
            raise admin.InternalException(f"Error creating tenant: {str(e)}")
    
    def handleEdit(self, confInfo):
        """
        Update an existing tenant.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        try:
            # Get tenant ID
            tenant_id = self.callerArgs.id
            
            if not tenant_id:
                raise admin.ArgValidationException("Tenant ID is required")
            
            # Get tenant parameters
            display_name = self._get_param('display_name')
            description = self._get_param('description')
            enabled = self._get_param('enabled')
            
            # Get current tenant config
            tenant_conf = self._get_tenant_conf()
            tenant_stanza = f"tenant:{tenant_id}"
            
            if tenant_stanza not in tenant_conf:
                raise admin.NotFoundException(f"Tenant '{tenant_id}' not found")
                
            current_config = tenant_conf[tenant_stanza]
            
            # Only update provided fields
            if display_name is None:
                display_name = current_config.get('name', tenant_id.capitalize())
                
            if description is None:
                description = current_config.get('description', f"{display_name} environment")
                
            if enabled is None:
                enabled = current_config.get('enabled', 'true').lower() in ('true', '1', 'yes', 'y')
            else:
                enabled = enabled.lower() in ('true', '1', 'yes', 'y')
            
            # Update tenants.conf
            self._update_tenant_conf(tenant_id, display_name, description, enabled)
            
            # Return success
            confInfo[tenant_id] = {
                'name': tenant_id,
                'display_name': display_name,
                'description': description,
                'enabled': '1' if enabled else '0'
            }
            
        except Exception as e:
            self.logger.error(f"Error updating tenant: {str(e)}")
            raise admin.InternalException(f"Error updating tenant: {str(e)}")
    
    def handleRemove(self, confInfo):
        """
        Delete a tenant.
        
        Arguments:
            confInfo: The object to be returned to the UI
        """
        try:
            # Get tenant ID
            tenant_id = self.callerArgs.id
            
            if not tenant_id:
                raise admin.ArgValidationException("Tenant ID is required")
                
            # Prevent deleting the default tenant
            if tenant_id == 'default':
                raise admin.ArgValidationException("Cannot delete the default tenant")
            
            # Delete from tenants.conf
            tenant_stanza = f"tenant:{tenant_id}"
            self._delete_from_tenant_conf(tenant_stanza)
            
            # Return success
            confInfo[tenant_id] = {
                'name': tenant_id,
                'status': 'deleted'
            }
            
        except Exception as e:
            self.logger.error(f"Error removing tenant: {str(e)}")
            raise admin.InternalException(f"Error removing tenant: {str(e)}")
    
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
    
    def _get_tenants(self):
        """
        Get all tenants configured in the app.
        
        Returns:
            dict: Dictionary of tenant info
        """
        # Get tenant configuration
        tenant_conf = self._get_tenant_conf()
        
        # Build result dictionary
        result = {}
        
        # Always include default tenant if not in configuration
        default_found = False
        
        for stanza, info in tenant_conf.items():
            if stanza.startswith('tenant:'):
                tenant_id = stanza[7:]  # Remove 'tenant:' prefix
                display_name = info.get('name', tenant_id.capitalize())
                description = info.get('description', f"{display_name} environment")
                enabled = info.get('enabled', 'true').lower() in ('true', '1', 'yes', 'y')
                
                result[tenant_id] = {
                    'name': tenant_id,
                    'display_name': display_name,
                    'description': description,
                    'enabled': '1' if enabled else '0'
                }
                
                if tenant_id == 'default':
                    default_found = True
        
        # Add default tenant if not found
        if not default_found:
            result['default'] = {
                'name': 'default',
                'display_name': 'Default',
                'description': 'Default environment',
                'enabled': '1'
            }
        
        return result
    
    def _get_tenant_conf(self):
        """
        Get tenant configuration from tenants.conf.
        
        Returns:
            dict: Dictionary of tenant configurations
        """
        try:
            return self.readConf('tenants')
        except Exception as e:
            self.logger.error(f"Error reading tenants.conf: {str(e)}")
            return {}
    
    def _update_tenant_conf(self, tenant_id, display_name, description, enabled):
        """
        Update tenants.conf with tenant info.
        
        Arguments:
            tenant_id: The tenant ID
            display_name: The display name
            description: The description
            enabled: Whether the tenant is enabled
        """
        stanza = f"tenant:{tenant_id}"
        config = {
            'name': display_name,
            'description': description,
            'enabled': 'true' if enabled else 'false'
        }
        
        self.writeConf('tenants', stanza, config)
    
    def _delete_from_tenant_conf(self, stanza):
        """
        Delete a tenant from tenants.conf.
        
        Arguments:
            stanza: The tenant stanza
        """
        try:
            self.deleteConf('tenants', stanza)
        except Exception as e:
            self.logger.error(f"Error deleting from tenants.conf: {str(e)}")

# Register handler
if __name__ == "__main__":
    admin.init(TenantHandler, admin.CONTEXT_APP_ONLY)
