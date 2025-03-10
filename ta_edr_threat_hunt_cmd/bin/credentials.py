#
# Copyright 2023 Your Company
#
import bootstrap
import logging
import json
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

# Define the credential fields
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
        "api_key", required=False, encrypted=True, default=None, 
        validator=None
    ),
    field.RestField(
        "change_api_key", required=False, encrypted=False, default=0, 
        validator=None
    ),
    field.RestField(
        "api_secret", required=False, encrypted=True, default=None, 
        validator=None
    ),
    field.RestField(
        "change_api_secret", required=False, encrypted=False, default=0, 
        validator=None
    ),
    field.RestField(
        "username", required=False, encrypted=False, default=None, 
        validator=validator.String(
            min_len=0,
            max_len=100
        )
    ),
    field.RestField(
        "password", required=False, encrypted=True, default=None, 
        validator=None
    ),
    field.RestField(
        "change_password", required=False, encrypted=False, default=0, 
        validator=None
    ),
    field.RestField(
        "token", required=False, encrypted=True, default=None, 
        validator=None
    ),
    field.RestField(
        "change_token", required=False, encrypted=False, default=0, 
        validator=None
    )
]

model = RestModel(fields, name=None)
endpoint = SingleModel("ta_edr_threat_hunt_cmd_credentials", model, config_name="credentials")

class CredentialHandler(AdminExternalHandler):
    """
    Custom handler to handle Credential operations
    """
    
    def _remove_change_params(self):
        # Remove change parameters which are required for UI behavior
        # and not in data collection
        if "change_api_key" in self.payload:
            del self.payload["change_api_key"]
        if "change_api_secret" in self.payload:
            del self.payload["change_api_secret"]
        if "change_password" in self.payload:
            del self.payload["change_password"]
        if "change_token" in self.payload:
            del self.payload["change_token"]

    def _validate(self, name, updated_credential, is_create=False):
        credential_validator = CredentialValidator(
            self.getSessionKey(), name, updated_credential, is_create
        )
        result = credential_validator.validate()
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
        updated_credential = self.payload.copy()
        status, message = self._validate(name, updated_credential, is_create=True)
        if status:
            raise RestError(status, message)
        self._remove_change_params()
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleEdit(self, confInfo):
        name = self.callerArgs.id
        updated_credential = self.payload.copy()
        status, message = self._validate(name, updated_credential, is_create=False)
        if status:
            raise RestError(status, message)
        
        # Handle secret fields that shouldn't be updated
        if "change_api_key" in self.payload and self.payload["change_api_key"] == "0":
            del self.payload["api_key"]
        if "change_api_secret" in self.payload and self.payload["change_api_secret"] == "0":
            del self.payload["api_secret"]
        if "change_password" in self.payload and self.payload["change_password"] == "0":
            del self.payload["password"]
        if "change_token" in self.payload and self.payload["change_token"] == "0":
            del self.payload["token"]
            
        self._remove_change_params()
        AdminExternalHandler.handleEdit(self, confInfo)

class CredentialValidator:
    def __init__(self, session_key, credential_name=None, updated_credential=None, is_create=False):
        self._session_key = session_key
        self._credential_name = credential_name
        self._updated_credential = updated_credential
        self._is_create = is_create
        self._logger = logging.getLogger(f"{APP_NAME}.credential_validator")

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
        Validate the credential configuration.
        
        Returns:
            dict: Response with status and payload.
        """
        try:
            # Extract credential information
            provider = self._updated_credential.get("provider")
            tenant = self._updated_credential.get("tenant")
            
            # Validate based on provider
            if provider == "crowdstrike":
                api_key = self._updated_credential.get("api_key")
                api_secret = self._updated_credential.get("api_secret")
                if not api_key or not api_secret:
                    return self._error(400, "API Key and API Secret are required for CrowdStrike.")
                return self._validate_crowdstrike_creds(api_key, api_secret)
            elif provider == "sentinelone":
                api_key = self._updated_credential.get("api_key")
                if not api_key:
                    return self._error(400, "API Key is required for SentinelOne.")
                return self._validate_sentinelone_creds(api_key)
            elif provider == "defender":
                tenant_id = self._updated_credential.get("tenant_id")
                username = self._updated_credential.get("username")
                password = self._updated_credential.get("password")
                token = self._updated_credential.get("token")
                
                if not tenant_id:
                    return self._error(400, "Tenant ID is required for Microsoft Defender.")
                    
                if token:
                    # If token is provided, validate it
                    return self._validate_defender_token(tenant_id, token)
                elif username and password:
                    # If username and password are provided, validate them
                    return self._validate_defender_creds(tenant_id, username, password)
                else:
                    return self._error(400, "Either Token or Username/Password are required for Microsoft Defender.")
            else:
                return self._error(400, f"Unsupported provider: {provider}")
                
        except Exception as e:
            return self._error(500, str(e))

    def _validate_crowdstrike_creds(self, api_key, api_secret):
        """
        Validate CrowdStrike credentials.
        
        Args:
            api_key (str): API Key (Client ID).
            api_secret (str): API Secret (Client Secret).
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # In a real implementation, you would test these credentials
            # against the CrowdStrike API
            auth_url = "https://api.crowdstrike.com/oauth2/token"
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            data = {
                'client_id': api_key,
                'client_secret': api_secret,
                'grant_type': 'client_credentials'
            }
            
            # For demo purposes, we're just checking if the credentials are not empty
            if not api_key or not api_secret:
                return self._error(400, "API Key and API Secret cannot be empty for CrowdStrike.")
                
            # Note: In a real implementation, you would uncomment this code
            # to perform an actual validation against the CrowdStrike API
            """
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
            """
            
            # For now, return success if we have values
            return self._response(200)
            
        except Exception as e:
            return self._error(500, f"Error validating CrowdStrike credentials: {str(e)}")

    def _validate_sentinelone_creds(self, api_key):
        """
        Validate SentinelOne credentials.
        
        Args:
            api_key (str): API Key.
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # In a real implementation, you would test these credentials
            # against the SentinelOne API
            
            # For demo purposes, we're just checking if the API key is not empty
            if not api_key:
                return self._error(400, "API Key cannot be empty for SentinelOne.")
                
            # Note: In a real implementation, you would uncomment this code
            # to perform an actual validation against the SentinelOne API
            """
            headers = {
                'Authorization': f'ApiToken {api_key}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            endpoint_url = "https://your-sentinelone-instance.sentinelone.net/web/api/v2.1/system/info"
                
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
            """
            
            # For now, return success if we have a value
            return self._response(200)
            
        except Exception as e:
            return self._error(500, f"Error validating SentinelOne credentials: {str(e)}")
            
    def _validate_defender_creds(self, tenant_id, username, password):
        """
        Validate Microsoft Defender credentials using username/password.
        
        Args:
            tenant_id (str): Tenant ID.
            username (str): Username.
            password (str): Password.
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # In a real implementation, you would test these credentials
            # against the Microsoft Azure AD API
            
            # For demo purposes, we're just checking if the required fields are not empty
            if not tenant_id or not username or not password:
                return self._error(400, "Tenant ID, Username, and Password cannot be empty for Microsoft Defender.")
                
            # Note: In a real implementation, you would uncomment this code
            # to perform an actual validation against the Azure AD API
            """
            auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'grant_type': 'password',
                'client_id': '1950a258-227b-4e31-a9cf-717495945fc2',  # Microsoft Azure PowerShell client ID
                'username': username,
                'password': password,
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
            """
            
            # For now, return success if we have values
            return self._response(200)
            
        except Exception as e:
            return self._error(500, f"Error validating Microsoft Defender credentials: {str(e)}")
            
    def _validate_defender_token(self, tenant_id, token):
        """
        Validate Microsoft Defender credentials using token.
        
        Args:
            tenant_id (str): Tenant ID.
            token (str): Authentication token.
            
        Returns:
            dict: Response with status and payload.
        """
        try:
            # In a real implementation, you would test the token
            # against the Microsoft Defender API
            
            # For demo purposes, we're just checking if the required fields are not empty
            if not tenant_id or not token:
                return self._error(400, "Tenant ID and Token cannot be empty for Microsoft Defender.")
                
            # Note: In a real implementation, you would uncomment this code
            # to perform an actual validation against the Defender API
            """
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            endpoint_url = "https://api.securitycenter.microsoft.com/api/machines"
                
            response = requests.get(endpoint_url, headers=headers, verify=False, timeout=30, params={'$top': 1})
            
            if response.status_code == 200:
                return self._response(200)
            else:
                error_msg = f"Failed to authenticate with Microsoft Defender API. Status code: {response.status_code}"
                try:
                    error_details = response.json()
                    if 'error' in error_details:
                        error_msg = f"{error_msg}. Details: {error_details['error']['message']}"
                except:
                    pass
                
                return self._error(400, error_msg, response.text)
            """
            
            # For now, return success if we have values
            return self._response(200)
            
        except Exception as e:
            return self._error(500, f"Error validating Microsoft Defender token: {str(e)}")
        