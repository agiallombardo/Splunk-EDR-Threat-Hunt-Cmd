#!/usr/bin/env python
# encoding=utf-8

import os
import sys
import json
import time
import logging
import splunk.rest as rest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('edr_agent_refresh.log')
    ]
)
logger = logging.getLogger('edr_agent_refresh')

def get_session_key():
    """Get Splunk session key from stdin."""
    session_key = sys.stdin.readline().strip()
    return session_key

def get_providers(session_key):
    """Get list of configured providers."""
    try:
        # Get providers from consoles.conf
        response, content = rest.simpleRequest(
            '/servicesNS/nobody/TA-EDR_Threat_Hunt_Cmd/configs/conf-consoles?output_mode=json',
            sessionKey=session_key
        )
        
        if response.status != 200:
            logger.error(f"Error getting console configurations: {response.status}")
            return ["crowdstrike", "sentinelone", "defender"]  # Default providers
            
        consoles_data = json.loads(content)
        providers = set()
        
        for entry in consoles_data.get('entry', []):
            name = entry.get('name', '')
            
            if name.startswith('console:'):
                # Parse console:<tenant>:<provider>:<console>
                parts = name.split(':')
                if len(parts) >= 4:
                    provider = parts[2]
                    providers.add(provider)
        
        if not providers:
            logger.warning("No providers found in configuration, using defaults")
            return ["crowdstrike", "sentinelone", "defender"]
            
        return list(providers)
        
    except Exception as e:
        logger.error(f"Error getting providers: {str(e)}")
        return ["crowdstrike", "sentinelone", "defender"]  # Default providers

def refresh_agents(session_key, provider, operation="update"):
    """Refresh agents for a specific provider."""
    try:
        logger.info(f"Refreshing agents for provider: {provider}")
        
        # Run agentdiscovery command
        search = f"| agentdiscovery provider=\"{provider}\" tenant=\"*\" console=\"*\" operation=\"{operation}\" ttl=7"
        
        # Create search job
        response, content = rest.simpleRequest(
            '/services/search/jobs',
            sessionKey=session_key,
            method='POST',
            postargs={
                'search': search,
                'earliest_time': '-1m',
                'latest_time': 'now',
                'exec_mode': 'normal'
            }
        )
        
        if response.status != 201:
            logger.error(f"Error creating search job: {response.status}")
            return False
            
        # Extract job ID
        import xml.etree.ElementTree as ET
        sid = ET.fromstring(content).findtext('.//sid')
        
        if not sid:
            logger.error("Failed to extract search job ID")
            return False
            
        # Wait for search to complete
        job_url = f"/services/search/jobs/{sid}"
        max_wait = 300  # 5 minutes timeout
        
        for _ in range(max_wait):
            # Sleep 1 second between checks
            time.sleep(1)
            
            response, content = rest.simpleRequest(
                f"{job_url}?output_mode=json",
                sessionKey=session_key
            )
            
            if response.status != 200:
                logger.error(f"Error checking job status: {response.status}")
                return False
                
            # Parse job status
            job_status = json.loads(content)
            job_content = job_status['entry'][0]['content']
            
            if job_content.get('isDone', False):
                # Job is complete
                if job_content.get('isFailed', False):
                    # Job failed
                    logger.error(f"Agent refresh job failed: {job_content.get('messages', [{'text': 'Unknown error'}])[0]['text']}")
                    return False
                    
                # Success
                event_count = job_content.get('eventCount', 0)
                logger.info(f"Successfully refreshed agents for {provider}. Events: {event_count}")
                return True
                
        # Timeout
        logger.error(f"Timeout waiting for agent refresh job to complete")
        return False
        
    except Exception as e:
        logger.error(f"Error refreshing agents for {provider}: {str(e)}")
        return False

def main():
    """Main function to refresh agents."""
    try:
        # Get session key
        session_key = get_session_key()
        
        if not session_key:
            logger.error("No session key provided")
            sys.exit(1)
            
        # Get providers
        providers = get_providers(session_key)
        
        # Refresh agents for each provider
        results = {}
        for provider in providers:
            success = refresh_agents(session_key, provider)
            results[provider] = "success" if success else "error"
            
            # Sleep between provider refreshes to avoid rate limiting
            if provider != providers[-1]:
                time.sleep(10)
        
        # Log summary
        successes = sum(1 for result in results.values() if result == "success")
        logger.info(f"Agent refresh complete. Success: {successes}/{len(providers)}")
        
        # Print results for Splunk to index
        print(json.dumps({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": results,
            "success_count": successes,
            "total_count": len(providers)
        }))
        
    except Exception as e:
        logger.error(f"Error in agent refresh: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
