# ta_edr_threat_hunt_cmd_credentials.conf.spec
#
# This file contains the configuration spec for EDR credentials

[<credential_name>]
provider = [crowdstrike|sentinelone|defender]
* EDR provider for this credential
* Must be one of: crowdstrike, sentinelone, defender

tenant = <string>
* The display name for this credential

console = <string>
* Console ID for the tenant (if applicable)
* Optional, relevant for CrowdStrike and SentinelOne

tenant_id = <string>
* Azure Tenant ID for the tenant
* Required for Microsoft Defender, optional for others

api_key = <string>
* API key for authentication
* Required for CrowdStrike and SentinelOne
* This field is encrypted when stored

api_secret = <string>
* API secret for authentication
* Required for CrowdStrike
* This field is encrypted when stored

username = <string>
* Username for authentication
* Relevant for Microsoft Defender

password = <string>
* Password for authentication
* Relevant for Microsoft Defender
* This field is encrypted when stored

token = <string>
* Authentication token
* An alternative to username/password for Microsoft Defender
* This field is encrypted when stored
