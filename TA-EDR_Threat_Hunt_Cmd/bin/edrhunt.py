#!/usr/bin/env python
# encoding=utf-8

import os
import sys

# Import the actual implementation
from ta_edr_threat_hunt_cmd.commands.edrhunt_command import EDRHuntCommand

if __name__ == "__main__":
    # This is the entry point for the command when executed by Splunk
    from splunklib.searchcommands import dispatch
    dispatch(EDRHuntCommand, sys.argv, sys.stdin, sys.stdout, __name__)
