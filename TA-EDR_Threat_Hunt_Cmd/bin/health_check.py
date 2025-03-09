#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import time
import datetime
import argparse
import logging
import requests
import csv
from urllib.parse import urljoin

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('edr_health_check.log')
    ]
)
logger = logging.getLogger('edr_health_check')

class EDRHealthCheck:
    """
    Health check utility for the TA-EDR_Threat_Hunt_Cmd app.
    Verifies configuration, API connectivity, and KV Store status.
    """
    
    def __init__(self, splunk_url, username, password, app_name='TA-EDR_Threat_Hunt_Cmd'):
        """
        Initialize the health check.
        
        Args:
            splunk_url (str): URL to Splunk instance (e.g., https://splunk.example.com:8089)
            username (str): Splunk username
            password (str): Splunk password
            app_name (str): App name (default: TA-EDR_Threat_Hunt_Cmd)
        """
        self.splunk_url = splunk_url.rstrip('/')
        self.username = username
        self.password = password
        self.app_name = app_name
        self.session = None
        self.session_key = None
        self.report = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'app_status': {},
            'credentials': {},
            'tenant_consoles': {},
            'kvstore': {},
            'api_connectivity': {},
            'search_commands': {}
        }
        
    def run(self):
        """
        Run all health checks.
        
        Returns:
            dict: Report of all health check results
        """
        try:
            # Create session and authenticate
            self.authenticate()
            
            # Run health checks
            self.check_app_status()
            self.check_credentials()
            self.check_tenant_consoles()
            self.check_kvstore()
            self.check_api_connectivity()
            self.check_search_commands()
            
            # Calculate overall health
            self.calculate_health_score()
            
            return self.report
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            self.report['overall_status'] = 'ERROR'
            self.report['error'] = str(e)
            return self.report
            
    def authenticate(self):
        """Authenticate with Splunk and get a session key."""
        logger.info("Authenticating with Splunk...")
        
        auth_url = f"{self.splunk_url}/services/auth/login"
        
        try:
            response = requests.post(
                auth_url,
                data={'username': self.username, 'password': self.password},
                verify=False,  # Disable SSL verification for testing
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            
            if response.status_code != 200:
                raise Exception(f"Authentication failed: {response.text}")
                
            # Parse XML response to get session key
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.text)
            self.session_key = root.find('.//sessionKey').text
            
            # Create session with auth header
            self.session = requests.Session()
            self.session.headers.update({
                'Authorization': f'Splunk {self.session_key}',
                'Content-Type': 'application/json'
            })
            self.session.verify = False  # Disable SSL verification for testing
            
            logger.info("Authentication successful")
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise
    
    def check_app_status(self):
        """Check if the app is installed and enabled."""
        logger.info("Checking app status...")
        
        apps_url = f"{self.splunk_url}/services/apps/local/{self.app_name}?output_mode=json"
        
        try:
            response = self.session.get(apps_url)
            
            if response.status_code == 200:
                app_data = response.json()
                entry = app_data.get('entry', [{}])[0]
                content = entry.get('content', {})
                
                self.report['app_status'] = {
                    'installed': True,
                    'version': content.get('version', 'unknown'),
                    'state': content.get('state', 'unknown'),
                    'configured': content.get('configured', 'unknown')
                }
                
                logger.info(f"App status: installed={True}, version={content.get('version', 'unknown')}, state={content.get('state', 'unknown')}")
                
            elif response.status_code == 404:
                self.report['app_status'] = {
                    'installed': False,
                    'error': 'App not found'
                }
                
                logger.warning("App is not installed")
                
            else:
                self.report['app_status'] = {
                    'installed': 'unknown',
                    'error': f"Failed to check app status: {response.status_code} {response.text}"
                }
                
                logger.error(f"Failed to check app status: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking app status: {str(e)}")
            self.report['app_status'] = {
                'installed': 'unknown',
                'error': str(e)
            }
    
    def check_credentials(self):
        """Check if required credentials are configured."""
        logger.info("Checking credentials...")
        
        passwords_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/storage/passwords?output_mode=json"
        
        try:
            response = self.session.get(passwords_url)
            
            if response.status_code == 200:
                creds_data = response.json()
                entries = creds_data.get('entry', [])
                
                # Group credentials by provider
                credentials = {
                    'crowdstrike': [],
                    'sentinelone': [],
                    'defender': []
                }
                
                for entry in entries:
                    name = entry.get('name', '')
                    content = entry.get('content', {})
                    realm = content.get('realm', '')
                    
                    if realm.startswith('crowdstrike_'):
                        credentials['crowdstrike'].append(realm)
                    elif realm.startswith('sentinelone_'):
                        credentials['sentinelone'].append(realm)
                    elif realm.startswith('defender_'):
                        credentials['defender'].append(realm)
                
                self.report['credentials'] = {
                    'crowdstrike': {
                        'count': len(credentials['crowdstrike']),
                        'credentials': credentials['crowdstrike']
                    },
                    'sentinelone': {
                        'count': len(credentials['sentinelone']),
                        'credentials': credentials['sentinelone']
                    },
                    'defender': {
                        'count': len(credentials['defender']),
                        'credentials': credentials['defender']
                    },
                    'status': 'ok' if any([
                        len(credentials['crowdstrike']) > 0,
                        len(credentials['sentinelone']) > 0,
                        len(credentials['defender']) > 0
                    ]) else 'warning'
                }
                
                logger.info(f"Credentials found: CrowdStrike={len(credentials['crowdstrike'])}, SentinelOne={len(credentials['sentinelone'])}, Defender={len(credentials['defender'])}")
                
            else:
                self.report['credentials'] = {
                    'status': 'error',
                    'error': f"Failed to check credentials: {response.status_code} {response.text}"
                }
                
                logger.error(f"Failed to check credentials: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking credentials: {str(e)}")
            self.report['credentials'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def check_tenant_consoles(self):
        """Check tenant and console configurations."""
        logger.info("Checking tenant and console configurations...")
        
        # Check tenants configuration - UCC format
        tenants_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/configs/conf-ta_edr_threat_hunt_cmd_tenants?output_mode=json"
        credentials_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/configs/conf-ta_edr_threat_hunt_cmd_credentials?output_mode=json"
        
        tenants = {}
        consoles = {}
        
        # Check tenants
        try:
            response = self.session.get(tenants_url)
            
            if response.status_code == 200:
                tenants_data = response.json()
                entries = tenants_data.get('entry', [])
                
                for entry in entries:
                    name = entry.get('name', '')
                    content = entry.get('content', {})
                    
                    # Skip settings and default stanzas
                    if name in ['settings', 'default']:
                        continue
                        
                    # Extract tenant info from UCC format
                    tenant_id = name
                    tenants[tenant_id] = {
                        'name': content.get('name', tenant_id),
                        'display_name': content.get('display_name', tenant_id),
                        'description': content.get('description', ''),
                        'enabled': content.get('enabled', '1') == '1'
                    }
                
                logger.info(f"Found {len(tenants)} tenant configurations")
                
            else:
                logger.warning(f"Failed to get tenant configurations: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking tenant configurations: {str(e)}")
        
        # Check credentials (used as consoles in UCC format)
        try:
            response = self.session.get(credentials_url)
            
            if response.status_code == 200:
                credentials_data = response.json()
                entries = credentials_data.get('entry', [])
                
                for entry in entries:
                    name = entry.get('name', '')
                    content = entry.get('content', {})
                    
                    # Skip settings and default stanzas
                    if name in ['settings', 'default']:
                        continue
                        
                    # Extract console info from UCC credential
                    tenant_id = content.get('tenant', 'default')
                    provider = content.get('provider', '')
                    console_id = content.get('console', 'primary')
                    
                    if not provider:
                        continue
                        
                    if tenant_id not in consoles:
                        consoles[tenant_id] = {}
                        
                    if provider not in consoles[tenant_id]:
                        consoles[tenant_id][provider] = {}
                        
                    # Build console info
                    consoles[tenant_id][provider][console_id] = {
                        'credential_name': name
                    }
                
                logger.info(f"Found credentials for {len(consoles)} tenants")
                
            else:
                logger.warning(f"Failed to get credential configurations: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking credential configurations: {str(e)}")
        
        # Get settings for provider-specific information
        settings_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/configs/conf-ta_edr_threat_hunt_cmd_settings?output_mode=json"
        
        try:
            response = self.session.get(settings_url)
            
            if response.status_code == 200:
                settings_data = response.json()
                settings = None
                
                # Extract settings
                for entry in settings_data.get('entry', []):
                    if entry.get('name') == 'settings':
                        settings = entry.get('content', {})
                        break
                
                if settings:
                    # Update console info with API URLs from settings
                    for tenant_id, providers in consoles.items():
                        for provider, provider_consoles in providers.items():
                            for console_id, console_info in provider_consoles.items():
                                # Add API URL from settings
                                api_url_key = f"{provider}_api_url"
                                if api_url_key in settings:
                                    console_info['api_url'] = settings[api_url_key]
                                
                                # Add rate limit from settings
                                rate_limit_key = f"{provider}_max_rate"
                                if rate_limit_key in settings:
                                    console_info['rate_limit'] = settings[rate_limit_key]
                                
                                # For Defender, add tenant_id if available
                                if provider == 'defender' and 'tenant_id' in console_info:
                                    console_info['tenant_id'] = console_info['tenant_id']
                                elif provider == 'defender':
                                    # Use default tenant ID
                                    console_info['tenant_id'] = '00000000-0000-0000-0000-000000000000'
                
                logger.info("Retrieved settings for API configuration")
                
            else:
                logger.warning(f"Failed to get settings configuration: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking settings configuration: {str(e)}")
        
        # Analyze configurations
        tenant_console_report = {
            'tenant_count': len(tenants),
            'tenants': tenants,
            'console_count': sum(len(providers) for providers in consoles.values()),
            'consoles': consoles,
            'status': 'ok' if len(tenants) > 0 and any(consoles.values()) else 'warning'
        }
        
        # Check for misconfigured tenants
        misconfigured = []
        for tenant_id, tenant_data in tenants.items():
            if tenant_data.get('enabled') and tenant_id not in consoles:
                misconfigured.append({
                    'tenant_id': tenant_id,
                    'issue': 'No consoles configured for this tenant'
                })
                
        tenant_console_report['misconfigured'] = misconfigured
        
        if misconfigured:
            tenant_console_report['status'] = 'warning'
            logger.warning(f"Found {len(misconfigured)} misconfigured tenants")
            
        self.report['tenant_consoles'] = tenant_console_report
    
    def check_kvstore(self):
        """Check KV Store status and count agents."""
        logger.info("Checking KV Store status...")
        
        # Check if KV Store is running
        kvstore_status_url = f"{self.splunk_url}/services/server/status/kvstore-status?output_mode=json"
        
        try:
            response = self.session.get(kvstore_status_url)
            
            if response.status_code == 200:
                status_data = response.json()
                entry = status_data.get('entry', [{}])[0]
                content = entry.get('content', {})
                
                kvstore_status = {
                    'running': content.get('current', {}).get('status') == 'ready',
                    'status': content.get('current', {}).get('status', 'unknown'),
                    'detailed_status': content
                }
                
                logger.info(f"KV Store status: {kvstore_status['status']}")
                
            else:
                kvstore_status = {
                    'running': False,
                    'status': 'error',
                    'error': f"Failed to check KV Store status: {response.status_code} {response.text}"
                }
                
                logger.error(f"Failed to check KV Store status: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking KV Store status: {str(e)}")
            kvstore_status = {
                'running': False,
                'status': 'error',
                'error': str(e)
            }
        
        # Get collection name from settings
        settings_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/configs/conf-ta_edr_threat_hunt_cmd_settings/settings?output_mode=json"
        collection_name = 'edr_agents'  # Default
        
        try:
            response = self.session.get(settings_url)
            
            if response.status_code == 200:
                settings_data = response.json()
                content = settings_data.get('entry', [{}])[0].get('content', {})
                
                # Get collection name from settings
                collection_name = content.get('kvstore_collection', collection_name)
                
                logger.info(f"Using KV Store collection: {collection_name}")
                
        except Exception as e:
            logger.error(f"Error getting collection name from settings: {str(e)}")
        
        # Check agent collection
        if kvstore_status.get('running'):
            collection_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/storage/collections/data/{collection_name}?output_mode=json"
            
            try:
                response = self.session.get(collection_url)
                
                if response.status_code == 200:
                    agents = response.json()
                    
                    # Group agents by provider and tenant
                    agent_counts = {}
                    
                    for agent in agents:
                        provider = agent.get('provider', 'unknown')
                        tenant = agent.get('tenant', 'unknown')
                        
                        if provider not in agent_counts:
                            agent_counts[provider] = {}
                            
                        if tenant not in agent_counts[provider]:
                            agent_counts[provider][tenant] = 0
                            
                        agent_counts[provider][tenant] += 1
                    
                    # Calculate totals
                    total_agents = len(agents)
                    
                    kvstore_status['agent_collection'] = {
                        'total_agents': total_agents,
                        'provider_counts': agent_counts,
                        'oldest_record': min([agent.get('updated_at', '2000-01-01T00:00:00Z') for agent in agents], default='n/a'),
                        'newest_record': max([agent.get('updated_at', '2000-01-01T00:00:00Z') for agent in agents], default='n/a')
                    }
                    
                    logger.info(f"Found {total_agents} agents in KV Store")
                    
                elif response.status_code == 404:
                    kvstore_status['agent_collection'] = {
                        'exists': False,
                        'error': 'Collection not found'
                    }
                    
                    logger.warning("Agent collection not found in KV Store")
                    
                else:
                    kvstore_status['agent_collection'] = {
                        'exists': 'unknown',
                        'error': f"Failed to access collection: {response.status_code} {response.text}"
                    }
                    
                    logger.error(f"Failed to access agent collection: {response.status_code} {response.text}")
                    
            except Exception as e:
                logger.error(f"Error accessing agent collection: {str(e)}")
                kvstore_status['agent_collection'] = {
                    'exists': 'unknown',
                    'error': str(e)
                }
        
        self.report['kvstore'] = kvstore_status
        
    def check_api_connectivity(self):
        """Test API connectivity to each configured provider."""
        logger.info("Testing API connectivity...")
        
        # Get configured consoles
        consoles = self.report.get('tenant_consoles', {}).get('consoles', {})
        credentials = self.report.get('credentials', {})
        
        api_results = {}
        
        # Check each console
        for tenant_id, providers in consoles.items():
            if tenant_id not in api_results:
                api_results[tenant_id] = {}
                
            for provider, provider_consoles in providers.items():
                if provider not in api_results[tenant_id]:
                    api_results[tenant_id][provider] = {}
                    
                for console_id, settings in provider_consoles.items():
                    logger.info(f"Testing connectivity for {tenant_id}/{provider}/{console_id}...")
                    
                    api_url = settings.get('api_url', '')
                    credential_name = settings.get('credential_name', '')
                    
                    # Skip if missing required settings
                    if not api_url or not credential_name:
                        api_results[tenant_id][provider][console_id] = {
                            'status': 'error',
                            'error': 'Missing API URL or credential name'
                        }
                        continue
                    
                    # Test API connection based on provider
                    result = self._test_api_connection(provider, api_url, credential_name)
                    api_results[tenant_id][provider][console_id] = result
        
        self.report['api_connectivity'] = api_results
    
    def _test_api_connection(self, provider, api_url, credential_name):
        """
        Test API connection for a specific provider.
        
        Args:
            provider (str): Provider name (crowdstrike, sentinelone, defender)
            api_url (str): API URL
            credential_name (str): Credential name
            
        Returns:
            dict: Connection test result
        """
        # Get credentials
        passwords_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/storage/passwords?output_mode=json"
        
        try:
            response = self.session.get(passwords_url)
            
            if response.status_code != 200:
                return {
                    'status': 'error',
                    'error': f"Failed to retrieve credentials: {response.status_code}"
                }
                
            creds_data = response.json()
            entries = creds_data.get('entry', [])
            
            credential = None
            for entry in entries:
                content = entry.get('content', {})
                if content.get('realm') == credential_name:
                    credential = {
                        'username': content.get('username'),
                        'password': content.get('clear_password', '')
                    }
                    break
            
            if not credential:
                return {
                    'status': 'error',
                    'error': f"Credential '{credential_name}' details not found"
                }
            
            # Test connection based on provider
            if provider == 'crowdstrike':
                return self._test_crowdstrike_connection(api_url, credential)
            elif provider == 'sentinelone':
                return self._test_sentinelone_connection(api_url, credential)
            elif provider == 'defender':
                return self._test_defender_connection(api_url, credential)
            else:
                return {
                    'status': 'error',
                    'error': f"Unsupported provider: {provider}"
                }
                
        except Exception as e:
            logger.error(f"Error testing API connection: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _test_crowdstrike_connection(self, api_url, credential):
        """Test CrowdStrike API connection."""
        try:
            # OAuth2 token endpoint
            token_url = f"{api_url}/oauth2/token"
            
            payload = {
                'client_id': credential['username'],
                'client_secret': credential['password']
            }
            
            response = requests.post(token_url, data=payload, timeout=30, verify=False)
            
            if response.status_code == 201:
                token_data = response.json()
                
                # Test a simple API call
                test_url = f"{api_url}/sensors/queries/installers/v1"
                headers = {
                    'Authorization': f"Bearer {token_data.get('access_token')}",
                    'Accept': 'application/json'
                }
                
                test_response = requests.get(test_url, headers=headers, timeout=30, verify=False)
                
                return {
                    'status': 'ok' if test_response.status_code in (200, 404) else 'error',
                    'auth_status_code': response.status_code,
                    'test_status_code': test_response.status_code,
                    'token_expires_in': token_data.get('expires_in', 0),
                    'latency_ms': int(response.elapsed.total_seconds() * 1000)
                }
                
            else:
                return {
                    'status': 'error',
                    'auth_status_code': response.status_code,
                    'error': f"Authentication failed: {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error testing CrowdStrike connection: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _test_sentinelone_connection(self, api_url, credential):
        """Test SentinelOne API connection."""
        try:
            # Login endpoint
            login_url = f"{api_url}/web/api/v2.1/users/login"
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            payload = {
                'data': {
                    'username': credential['username'],
                    'password': credential['password']
                }
            }
            
            # For SentinelOne API tokens
            if credential['username'] == 'apitoken':
                # Test with API token
                test_url = f"{api_url}/web/api/v2.1/system/info"
                headers['Authorization'] = f"ApiToken {credential['password']}"
                
                response = requests.get(test_url, headers=headers, timeout=30, verify=False)
                
                return {
                    'status': 'ok' if response.status_code == 200 else 'error',
                    'test_status_code': response.status_code,
                    'latency_ms': int(response.elapsed.total_seconds() * 1000)
                }
                
            # For username/password authentication
            response = requests.post(login_url, headers=headers, json=payload, timeout=30, verify=False)
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Test a simple API call
                test_url = f"{api_url}/web/api/v2.1/system/info"
                headers['Authorization'] = f"ApiToken {token_data.get('data', {}).get('token')}"
                
                test_response = requests.get(test_url, headers=headers, timeout=30, verify=False)
                
                return {
                    'status': 'ok' if test_response.status_code == 200 else 'error',
                    'auth_status_code': response.status_code,
                    'test_status_code': test_response.status_code,
                    'latency_ms': int(response.elapsed.total_seconds() * 1000)
                }
                
            else:
                return {
                    'status': 'error',
                    'auth_status_code': response.status_code,
                    'error': f"Authentication failed: {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error testing SentinelOne connection: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _test_defender_connection(self, api_url, credential):
        """Test Microsoft Defender API connection."""
        try:
            # We need the Azure AD tenant ID from console config
            consoles = self.report.get('tenant_consoles', {}).get('consoles', {})
            
            tenant_id = None
            for t_id, providers in consoles.items():
                if 'defender' in providers:
                    for c_id, settings in providers['defender'].items():
                        if settings.get('api_url') == api_url:
                            tenant_id = settings.get('tenant_id')
                            break
            
            if not tenant_id:
                return {
                    'status': 'error',
                    'error': 'Azure AD tenant ID not found in console configuration'
                }
            
            # Azure AD OAuth endpoint
            auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
            
            payload = {
                'client_id': credential['username'],
                'client_secret': credential['password'],
                'resource': 'https://api.securitycenter.microsoft.com',
                'grant_type': 'client_credentials'
            }
            
            response = requests.post(auth_url, data=payload, timeout=30, verify=False)
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Test a simple API call
                test_url = f"{api_url}/api/machines"
                headers = {
                    'Authorization': f"Bearer {token_data.get('access_token')}",
                    'Accept': 'application/json'
                }
                
                test_response = requests.get(test_url, headers=headers, params={'$top': 1}, timeout=30, verify=False)
                
                return {
                    'status': 'ok' if test_response.status_code == 200 else 'error',
                    'auth_status_code': response.status_code,
                    'test_status_code': test_response.status_code,
                    'token_expires_in': token_data.get('expires_in', 0),
                    'latency_ms': int(response.elapsed.total_seconds() * 1000)
                }
                
            else:
                return {
                    'status': 'error',
                    'auth_status_code': response.status_code,
                    'error': f"Authentication failed: {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error testing Microsoft Defender connection: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def check_search_commands(self):
        """Check if the search commands are registered and working."""
        logger.info("Checking search commands...")
        
                    # Check if commands are registered
        commands_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/configs/conf-commands?output_mode=json"
        
        try:
            response = self.session.get(commands_url)
            
            if response.status_code == 200:
                commands_data = response.json()
                entries = commands_data.get('entry', [])
                
                edrhunt_command = None
                agentdiscovery_command = None
                
                for entry in entries:
                    name = entry.get('name', '')
                    content = entry.get('content', {})
                    
                    if name == 'edrhunt':
                        edrhunt_command = content
                    elif name == 'agentdiscovery':
                        agentdiscovery_command = content
                
                command_info = {
                    'edrhunt': {
                        'registered': edrhunt_command is not None,
                        'details': edrhunt_command or {}
                    },
                    'agentdiscovery': {
                        'registered': agentdiscovery_command is not None,
                        'details': agentdiscovery_command or {}
                    }
                }
                
                logger.info(f"Search commands: edrhunt registered={command_info['edrhunt']['registered']}, agentdiscovery registered={command_info['agentdiscovery']['registered']}")
                
            else:
                command_info = {
                    'status': 'error',
                    'error': f"Failed to check commands: {response.status_code} {response.text}"
                }
                
                logger.error(f"Failed to check commands: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error checking commands: {str(e)}")
            command_info = {
                'status': 'error',
                'error': str(e)
            }
        
        # Test edrhunt command if registered
        if command_info.get('edrhunt', {}).get('registered'):
            logger.info("Testing edrhunt command...")
            
            try:
                # Run a simple test search
                search = '| makeresults | eval agent_id="test" | edrhunt provider="crowdstrike" data_type="summary" tenant="default" debug=true'
                result = self._run_search(search)
                
                command_info['edrhunt']['test'] = {
                    'ran': result.get('status') == 'ok',
                    'error': result.get('error')
                }
                
            except Exception as e:
                logger.error(f"Error testing edrhunt command: {str(e)}")
                command_info['edrhunt']['test'] = {
                    'ran': False,
                    'error': str(e)
                }
        
        # Test agentdiscovery command if registered
        if command_info.get('agentdiscovery', {}).get('registered'):
            logger.info("Testing agentdiscovery command...")
            
            try:
                # Run a simple test search
                search = '| agentdiscovery provider="crowdstrike" tenant="default" operation="list" debug=true'
                result = self._run_search(search)
                
                command_info['agentdiscovery']['test'] = {
                    'ran': result.get('status') == 'ok',
                    'error': result.get('error')
                }
                
            except Exception as e:
                logger.error(f"Error testing agentdiscovery command: {str(e)}")
                command_info['agentdiscovery']['test'] = {
                    'ran': False,
                    'error': str(e)
                }
        
        self.report['search_commands'] = command_info
    
    def _run_search(self, search, max_wait=20):
        """
        Run a search and wait for results.
        
        Args:
            search (str): Search to run
            max_wait (int): Maximum time to wait in seconds
            
        Returns:
            dict: Search results
        """
        # Create search job
        search_url = f"{self.splunk_url}/services/search/jobs"
        
        payload = {
            'search': search,
            'earliest_time': '-1m',
            'latest_time': 'now',
            'exec_mode': 'normal'
        }
        
        response = self.session.post(search_url, data=payload)
        
        if response.status_code != 201:
            return {
                'status': 'error',
                'error': f"Failed to create search job: {response.status_code} {response.text}"
            }
            
        # Extract job ID
        import xml.etree.ElementTree as ET
        root = ET.fromstring(response.text)
        sid = root.find('.//sid').text
        
        # Wait for job to complete
        job_url = f"{self.splunk_url}/services/search/jobs/{sid}?output_mode=json"
        
        for _ in range(max_wait):
            time.sleep(1)
            
            job_response = self.session.get(job_url)
            
            if job_response.status_code != 200:
                return {
                    'status': 'error',
                    'error': f"Failed to check job status: {job_response.status_code} {job_response.text}"
                }
                
            job_data = job_response.json()
            job_status = job_data.get('entry', [{}])[0].get('content', {})
            
            if job_status.get('isDone'):
                break
        else:
            # Job didn't complete in time
            return {
                'status': 'error',
                'error': 'Search job timed out'
            }
        
        # Check for errors
        if job_status.get('isFailed'):
            return {
                'status': 'error',
                'error': job_status.get('messages', [{'text': 'Unknown error'}])[0].get('text', 'Unknown error')
            }
            
        # Success
        return {
            'status': 'ok',
            'job_id': sid,
            'event_count': job_status.get('eventCount', 0)
        }
    
    def calculate_health_score(self):
        """Calculate an overall health score for the app."""
        # Initialize scores
        scores = {
            'app_status': 0,
            'credentials': 0,
            'tenant_consoles': 0,
            'kvstore': 0,
            'api_connectivity': 0,
            'search_commands': 0
        }
        
        # App status score
        if self.report.get('app_status', {}).get('installed'):
            scores['app_status'] = 100
        else:
            scores['app_status'] = 0
        
        # Credentials score
        creds = self.report.get('credentials', {})
        if creds.get('status') == 'ok':
            scores['credentials'] = 100
        elif creds.get('status') == 'warning':
            scores['credentials'] = 50
        else:
            scores['credentials'] = 0
        
        # Tenant consoles score
        tenant_consoles = self.report.get('tenant_consoles', {})
        if tenant_consoles.get('status') == 'ok':
            scores['tenant_consoles'] = 100
        elif tenant_consoles.get('status') == 'warning':
            scores['tenant_consoles'] = 50
        else:
            scores['tenant_consoles'] = 0
        
        # KVStore score
        kvstore = self.report.get('kvstore', {})
        if kvstore.get('running'):
            scores['kvstore'] = 100
        else:
            scores['kvstore'] = 0
        
        # API connectivity score
        api_connectivity = self.report.get('api_connectivity', {})
        if api_connectivity:
            # Count successful connections
            successful = 0
            total = 0
            
            for tenant, providers in api_connectivity.items():
                for provider, consoles in providers.items():
                    for console, result in consoles.items():
                        total += 1
                        if result.get('status') == 'ok':
                            successful += 1
            
            if total > 0:
                scores['api_connectivity'] = int((successful / total) * 100)
            else:
                scores['api_connectivity'] = 0
        else:
            scores['api_connectivity'] = 0
        
        # Search commands score
        search_commands = self.report.get('search_commands', {})
        if search_commands:
            commands_score = 0
            
            # Check edrhunt command
            if search_commands.get('edrhunt', {}).get('registered'):
                commands_score += 50
                if search_commands.get('edrhunt', {}).get('test', {}).get('ran'):
                    commands_score += 25
            
            # Check agentdiscovery command
            if search_commands.get('agentdiscovery', {}).get('registered'):
                commands_score += 50
                if search_commands.get('agentdiscovery', {}).get('test', {}).get('ran'):
                    commands_score += 25
            
            # Normalize to 100
            scores['search_commands'] = min(100, commands_score)
        else:
            scores['search_commands'] = 0
        
        # Calculate overall score
        weights = {
            'app_status': 1,
            'credentials': 2,
            'tenant_consoles': 2,
            'kvstore': 1,
            'api_connectivity': 3,
            'search_commands': 3
        }
        
        total_weight = sum(weights.values())
        weighted_sum = sum(scores[key] * weights[key] for key in scores)
        
        overall_score = int(weighted_sum / total_weight)
        
        # Determine overall health status
        if overall_score >= 80:
            health_status = 'healthy'
        elif overall_score >= 50:
            health_status = 'degraded'
        else:
            health_status = 'unhealthy'
        
        # Add scores to report
        self.report['health_scores'] = scores
        self.report['overall_score'] = overall_score
        self.report['health_status'] = health_status
        
        logger.info(f"Overall health score: {overall_score}/100 ({health_status})")
        
        return overall_score
    
    def save_to_kvstore(self, collection_name='edr_health_results'):
        """
        Save the health check report to KV Store.
        
        Args:
            collection_name (str): KV Store collection name
        """
        try:
            # Prepare the health check record
            health_record = {
                '_key': datetime.datetime.now().strftime('%Y%m%d%H%M%S'),
                'timestamp': self.report['timestamp'],
                'overall_score': self.report.get('overall_score', 0),
                'health_status': self.report.get('health_status', 'unknown'),
                'app_status': self.report.get('app_status', {}),
                'credential_counts': {
                    'crowdstrike': self.report.get('credentials', {}).get('crowdstrike', {}).get('count', 0),
                    'sentinelone': self.report.get('credentials', {}).get('sentinelone', {}).get('count', 0),
                    'defender': self.report.get('credentials', {}).get('defender', {}).get('count', 0)
                },
                'tenant_counts': {
                    'tenant_count': self.report.get('tenant_consoles', {}).get('tenant_count', 0),
                    'console_count': self.report.get('tenant_consoles', {}).get('console_count', 0)
                },
                'kvstore_status': self.report.get('kvstore', {}).get('status', 'unknown'),
                'agent_counts': {},
                'api_status': {},
                'command_status': {
                    'edrhunt': self.report.get('search_commands', {}).get('edrhunt', {}).get('registered', False),
                    'agentdiscovery': self.report.get('search_commands', {}).get('agentdiscovery', {}).get('registered', False)
                },
                'component_scores': self.report.get('health_scores', {}),
                'full_report': self.report
            }
            
            # Extract agent counts if available
            if 'agent_collection' in self.report.get('kvstore', {}):
                agent_collection = self.report['kvstore']['agent_collection']
                if 'provider_counts' in agent_collection:
                    health_record['agent_counts'] = agent_collection['provider_counts']
            
            # Extract API status
            for tenant, providers in self.report.get('api_connectivity', {}).items():
                if tenant not in health_record['api_status']:
                    health_record['api_status'][tenant] = {}
                    
                for provider, consoles in providers.items():
                    status_count = {'ok': 0, 'error': 0, 'total': 0}
                    
                    for console, result in consoles.items():
                        status_count['total'] += 1
                        if result.get('status') == 'ok':
                            status_count['ok'] += 1
                        else:
                            status_count['error'] += 1
                    
                    health_record['api_status'][tenant][provider] = status_count
            
            # Create or update the KV Store collection
            collection_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/storage/collections/data/{collection_name}"
            
            # Check if collection exists, create if not
            collections_url = f"{self.splunk_url}/servicesNS/nobody/{self.app_name}/storage/collections"
            collections_response = self.session.get(f"{collections_url}?output_mode=json")
            
            collections = []
            if collections_response.status_code == 200:
                collections_data = collections_response.json()
                for entry in collections_data.get('entry', []):
                    collections.append(entry.get('name'))
                    
            if collection_name not in collections:
                # Create collection
                self.session.post(
                    collections_url,
                    data={'name': collection_name},
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                logger.info(f"Created KV Store collection: {collection_name}")
            
            # Save health record to KV Store
            response = self.session.post(
                collection_url,
                data=json.dumps(health_record),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in (200, 201):
                logger.info(f"Health check report saved to KV Store collection: {collection_name}")
                return True
            else:
                logger.error(f"Failed to save health check report to KV Store: {response.status_code} {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error saving health check report to KV Store: {str(e)}")
            return False


# Main function
def main():
    parser = argparse.ArgumentParser(description='EDR Hunt App Health Check')
    parser.add_argument('--url', required=True, help='Splunk URL (e.g., https://splunk.example.com:8089)')
    parser.add_argument('--username', required=True, help='Splunk username')
    parser.add_argument('--password', required=True, help='Splunk password')
    parser.add_argument('--app', default='TA-EDR_Threat_Hunt_Cmd', help='App name (default: TA-EDR_Threat_Hunt_Cmd)')
    parser.add_argument('--collection', default='edr_health_results', help='KV Store collection for results (default: edr_health_results)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Run health check
        health_check = EDRHealthCheck(args.url, args.username, args.password, args.app)
        health_check.run()
        health_check.save_to_kvstore(args.collection)
        
        # Print summary
        print(f"\nEDR Hunt App Health Check Summary:")
        print(f"Overall Score: {health_check.report.get('overall_score', 0)}/100")
        print(f"Status: {health_check.report.get('health_status', 'unknown').upper()}")
        print(f"\nResults saved to KV Store collection: {args.collection}")
        
        # Exit with status code based on health
        if health_check.report.get('health_status') == 'healthy':
            sys.exit(0)
        elif health_check.report.get('health_status') == 'degraded':
            sys.exit(1)
        else:
            sys.exit(2)
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        print(f"Health check failed: {str(e)}")
        sys.exit(3)

if __name__ == "__main__":
    main()