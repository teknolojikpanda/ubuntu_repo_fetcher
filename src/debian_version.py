import logging
from debian.debian_support import Version, VersionError

logger = logging.getLogger(__name__)

def compare_debian_versions(version_str1, version_str2):
    """
    Compares two Debian version.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    try:
        v1 = Version(version_str1)
        v2 = Version(version_str2)
    except VersionError as e:
        # Re-raise as ValueError for clearer API or handle as needed
        logger.exception("Invalid Debian version string encountered")
        return 0

    if v1 > v2: return 1
    elif v1 < v2: return -1
    else: return 0
