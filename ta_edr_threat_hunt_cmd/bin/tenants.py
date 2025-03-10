#
# Copyright 2023 Your Company
#
import bootstrap
import sys
import json
import logging
import requests
from requests.packages import urllib3

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler.error import RestError
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
util.remove_http_proxy_env_vars()

APP_NAME = "ta_edr_threat_hunt_cmd"
app_internal_name = "ta_edr_threat_hunt_cmd"

# Define the tenant fields
fields = [
    field.RestField(
        "provider", required=True, encrypted=False, default=None, 
        validator=validator.String(
            min_len=1,
            max_len=20,
            choices=["crowdstrike", "sentinelone", "defender"]
        )
    ),
    field.RestField(
        "tenant", required=True, encrypted=False, default=None, 
        validator=validator.String(
            min_len=1,
            max_len=100
        )
    ),
    field.RestField(
        "console", required=False, encrypted=False, default=None, 
        validator=validator.String(
            min_len=0,
            max_len=100
        )
    ),
    field.RestField(
        "tenant_id", required=False, encrypted=False, default=None, 
        validator=validator.String(
            min_len=0,
            max_len=100
        )
    ),
    field.RestField(
        "client_id", required=True, encrypted=False, default=None, 
        validator=validator.String(
            min_len=1, 
            max_len=100
        )
    ),
    field.RestField(
        "change_client_secret", required=False, encrypted=False, default=0, 
        validator=None
    ),
    field.RestField(
        "client_secret", required=False, encrypted=True, default=None, 
        validator=None
    ),
    field.RestField(
        "api_url", required=True, encrypted=False, default=None, 
        validator=validator.String(
            min_len=1,
            max_len=200
        )
    ),
    field.RestField(
        "api_scope", required=False, encrypted=False, default=None, 
        validator=validator.String(
            min_len=0,
            max_len=200
        )
    ),
    field.RestField(
        "api_timeout", required=False, encrypted=False, default="300", 
        validator=validator.Number(
            min_val=30,
            max_val=1800
        )
    ),
    field.RestField(
        "default_batch_size", required=False, encrypted=False, default="100", 
        validator=validator.Number(
            min_val=10,
            max_val=10000
        )
    ),
    field.RestField(
        "default_filter", required=False, encrypted=False, default=None, 
        validator=validator.String(
            min_len=0,
            max_len=1000
        )
    ),
    field.RestField(
        "use_advanced_hunting", required=False, encrypted=False, default="0", 
        validator=validator.String(
            min_len=1,
            max_len=1,
            choices=["0", "1"]
        )
    )
]

model = RestModel(fields, name=None)
endpoint = SingleModel("ta_edr_threat_hunt_cmd_tenants", model, config_name="tenants")

class TenantValidator:
    def __init__(self, session_key, tenant_name=None, updated_tenant=None, is_create=False):
        self._session_key = session_key
        self._tenant_name = tenant_name
        self._updated_tenant = updated_tenant
        self._is_create = is_create

    def _response(self, status, data=None):
        if not data:
            data = {"status": status, "entry": []}
        payload = json.dumps(data)
        return {"status": status, "payload": payload}

    def _error(self, status, text=None, trace=None):
        payload = json.dumps(
            {"messages": [{"text": text, "type": "ERROR"}], "trace": trace}
        )
        return {"status": status, "payload": payload}

    def validate(self):
        """
        Validate the tenant configuration.
        
        Returns:
            dict: Response with status and payload.
        """
        try:
            # Extract tenant information
            provider = self._updated_tenant.get("provider")
            tenant = self._updated_tenant.get("tenant")
            client_id = self._updated_tenant.get("client_id")
            client_secret = self._updated_tenant.get("client_secret")
            api_url = self._updated_tenant.get("api_url")
            
            # Validate based on provider
            if provider == "crowdstrike":
                return self._validate_crowdstrike(api_url, client_id, client_secret)
            elif provider == "sentinelone":
                return self._validate_sentinelone(api_url, client_id, client_secret)
            elif provider == "defender":
                tenant_id = self._updated_tenant.get("tenant_id")
                if not tenant_id:
                    return self._error(400, "Tenant ID is required for Microsoft Defender.")
                return self._validate_defender(api_url, tenant_id, client_id, client_secret)
            else:
                return self._error(400, f"Unsupported provider: {provider}")
                
        except Exception as e:
            return self._error(500, str(e))

    def _validate_crowdstrike(self, api_url, client_id, client_secret):
        """
        Validate CrowdStrike credentials.
        
        Args:
            api_url (str): API URL.
            client_id (str): Client ID.
            client_secret (str): Client secret.
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # Check if URL ends with /oauth2/token, if not append path
            if not api_url.endswith('/oauth2/token'):
                auth_url = f"{api_url.rstrip('/')}/oauth2/token"
            else:
                auth_url = api_url
                
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials'
            }
            
            response = requests.post(auth_url, headers=headers, data=data, verify=False, timeout=30)
            
            if response.status_code == 201 or response.status_code == 200:
                return self._response(200)
            else:
                error_msg = f"Failed to authenticate with CrowdStrike API. Status code: {response.status_code}"
                try:
                    error_details = response.json()
                    if 'errors' in error_details and error_details['errors']:
                        error_msg = f"{error_msg}. Details: {error_details['errors'][0]['message']}"
                except:
                    pass
                
                return self._error(400, error_msg, response.text)
        
        except Exception as e:
            return self._error(500, f"Error validating CrowdStrike credentials: {str(e)}")

    def _validate_sentinelone(self, api_url, client_id, client_secret):
        """
        Validate SentinelOne credentials.
        
        Args:
            api_url (str): API URL.
            client_id (str): API Key.
            client_secret (str): Not used for SentinelOne, but kept for consistency.
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # For SentinelOne, client_id is the API key
            headers = {
                'Authorization': f'ApiToken {client_id}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Check if URL ends correctly, if not adjust
            if not api_url.endswith('/web/api/v2.1/system/info'):
                endpoint_url = f"{api_url.rstrip('/')}/web/api/v2.1/system/info"
            else:
                endpoint_url = api_url
                
            response = requests.get(endpoint_url, headers=headers, verify=False, timeout=30)
            
            if response.status_code == 200:
                return self._response(200)
            else:
                error_msg = f"Failed to authenticate with SentinelOne API. Status code: {response.status_code}"
                try:
                    error_details = response.json()
                    if 'errors' in error_details and error_details['errors']:
                        error_msg = f"{error_msg}. Details: {error_details['errors'][0]}"
                except:
                    pass
                
                return self._error(400, error_msg, response.text)
        
        except Exception as e:
            return self._error(500, f"Error validating SentinelOne credentials: {str(e)}")

    def _validate_defender(self, api_url, tenant_id, client_id, client_secret):
        """
        Validate Microsoft Defender credentials.
        
        Args:
            api_url (str): API URL.
            tenant_id (str): Tenant ID.
            client_id (str): Client ID.
            client_secret (str): Client secret.
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # For Defender, we need to authenticate using Azure AD
            auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials',
                'scope': 'https://api.securitycenter.microsoft.com/.default'
            }
            
            response = requests.post(auth_url, headers=headers, data=data, verify=False, timeout=30)
            
            if response.status_code == 200:
                return self._response(200)
            else:
                error_msg = f"Failed to authenticate with Microsoft Defender API. Status code: {response.status_code}"
                try:
                    error_details = response.json()
                    if 'error_description' in error_details:
                        error_msg = f"{error_msg}. Details: {error_details['error_description']}"
                except:
                    pass
                
                return self._error(400, error_msg, response.text)
        
        except Exception as e:
            return self._error(500, f"Error validating Microsoft Defender credentials: {str(e)}")


class TenantHandler(AdminExternalHandler):
    """
    Custom handler to handle Tenant operations
    """
    
    def _remove_change_secret_params(self):
        # remove change secret parameters which are required for UI behavior
        # and not in data collection
        if "change_client_secret" in self.payload:
            del self.payload["change_client_secret"]

    def _validate(self, name, updated_tenant, is_create=False):
        tenant_validator = TenantValidator(
            self.getSessionKey(), name, updated_tenant, is_create
        )
        result = tenant_validator.validate()
        if result.get("status") < 200 or result.get("status") >= 300:
            message = result.get("payload")
            try:
                payload_dict = json.loads(message)
                messages = payload_dict.get("messages")
                if messages:
                    message = messages[0].get("text")
            except Exception as e:
                msg = f"Error={e}, Error Detail={result}"
                logging.error(msg)
                return "Unexpected error", msg
            return result.get("status"), message
        return None, None

    def handleCreate(self, confInfo):
        name = self.callerArgs.id
        updated_tenant = self.payload.copy()
        status, message = self._validate(name, updated_tenant, is_create=True)
        if status:
            raise RestError(status, message)
        self._remove_change_secret_params()
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleEdit(self, confInfo):
        name = self.callerArgs.id
        updated_tenant = self.payload.copy()
        status, message = self._validate(name, updated_tenant, is_create=False)
        if status:
            raise RestError(status, message)
        if self.payload["change_client_secret"] == "0":
            del self.payload["client_secret"]
        self._remove_change_secret_params()
        AdminExternalHandler.handleEdit(self, confInfo)


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

if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=TenantHandler,
    )
