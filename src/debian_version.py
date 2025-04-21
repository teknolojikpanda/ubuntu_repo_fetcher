import re
import logging
import apt_pkg

logger = logging.getLogger(__name__)

def compare_debian_versions(v1, v2):
    """
    Compares two Debian version.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    apt_pkg.init_system()
    
    vc = apt_pkg.version_compare(v1, v2)

    if vc > 0: return 1
    if vc == 0: return 0
    if vc < 0: return -1
