# ta_edr_threat_hunt_cmd_tenants.conf.spec
#
# This file contains the configuration spec for EDR tenant configurations

[<tenant_name>]
provider = [crowdstrike|sentinelone|defender]
* EDR provider for this tenant
* Must be one of: crowdstrike, sentinelone, defender

tenant = <string>
* The display name for this tenant

console = <string>
* Console ID for the tenant (if applicable)
* Optional, relevant for CrowdStrike and SentinelOne

tenant_id = <string>
* Azure Tenant ID for the tenant
* Required for Microsoft Defender, optional for others

client_id = <string>
* Client ID for authentication
* This is the client ID for OAuth authentication (CrowdStrike, Defender)
* For SentinelOne, this is the API key

client_secret = <string>
* Client secret for authentication
* This field is encrypted when stored
* Required for CrowdStrike and Defender

api_url = <url>
* API endpoint URL for the provider
* Examples:
*   CrowdStrike: https://api.crowdstrike.com
*   SentinelOne: https://[tenant].sentinelone.net
*   Defender: https://api.securitycenter.microsoft.com

api_scope = <string>
* API scope for authentication
* Required for Microsoft Defender
* Example: https://api.securitycenter.microsoft.com/.default

api_timeout = <integer>
* Timeout for API calls in seconds
* Default: 300
* Range: 30-1800

default_batch_size = <integer>
* Number of records to process in each batch
* Default: 100
* Range: 10-10000

default_filter = <string>
* Default filter to apply to all queries for this tenant
* Optional

use_advanced_hunting = [0|1]
* Whether to use the Microsoft Defender Advanced Hunting API
* Only applicable for Microsoft Defender
* Default: 0
