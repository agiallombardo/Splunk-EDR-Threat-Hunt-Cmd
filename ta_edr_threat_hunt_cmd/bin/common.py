#
# Copyright 2023 Your Company
#

import re
import datetime
from splunktaucclib.rest_handler.error import RestError


class HostValidator(object):
    """
    Validator for host fields
    """
    def __call__(self, value, data):
        if not value:
            return True

        # Allow IP addresses and DNS names
        ip_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        hostname_pattern = r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
        
        # Check IP address format
        if re.match(ip_pattern, value):
            octets = value.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise RestError(400, f"Invalid IP address: {value}")
            return True
            
        # Check hostname format
        elif re.match(hostname_pattern, value):
            if len(value) > 255:
                raise RestError(400, f"Hostname too long: {value}")
            return True
            
        raise RestError(400, f"Invalid host: {value}")


class UTCDateValidator(object):
    """
    Validator for UTC date fields
    """
    def __call__(self, value, data):
        if not value:
            return True
            
        # Check date format
        try:
            # Try to parse date in ISO 8601 format
            datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
            return True
        except (ValueError, TypeError):
            pass
            
        # Try other common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S"
        ]
        
        for fmt in formats:
            try:
                datetime.datetime.strptime(value, fmt)
                return True
            except (ValueError, TypeError):
                continue
                
        raise RestError(400, f"Invalid UTC date format: {value}. Please use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ).")


class Provider:
    """
    EDR Provider Mapping
    """
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    DEFENDER = "defender"

    @classmethod
    def validate(cls, value):
        if value not in [cls.CROWDSTRIKE, cls.SENTINELONE, cls.DEFENDER]:
            raise RestError(400, f"Invalid provider: {value}. Must be one of: {cls.CROWDSTRIKE}, {cls.SENTINELONE}, {cls.DEFENDER}")
        return True
