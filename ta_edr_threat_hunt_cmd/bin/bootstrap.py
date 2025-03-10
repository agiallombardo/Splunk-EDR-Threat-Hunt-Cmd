import os
import sys
import logging

# Define the app name
ta_name = "ta_edr_threat_hunt_cmd"
app_internal_name = "ta_edr_threat_hunt_cmd"

# Get the app root directory
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Set up path for libraries
lib_dir = os.path.join(app_root, 'lib')
bin_dir = os.path.join(app_root, 'bin')
app_lib_dir = os.path.join(bin_dir, app_internal_name, 'lib')

# Add the lib directories to the Python path
if lib_dir not in sys.path:
    sys.path.insert(0, lib_dir)
if bin_dir not in sys.path:
    sys.path.insert(0, bin_dir)
if app_lib_dir not in sys.path:
    sys.path.insert(0, app_lib_dir)

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