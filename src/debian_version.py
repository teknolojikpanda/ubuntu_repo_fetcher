import re
import logging

logger = logging.getLogger(__name__)

def parse_debian_version(version_string):
    """
    Parses a Debian/Ubuntu version string into components.
    Returns a tuple: (epoch, upstream_version, debian_revision)
    Epoch defaults to 0 if not present.
    Revision defaults to None if not present.
    """
    epoch = 0
    debian_revision = None
    upstream_version = version_string

    # Extract epoch
    epoch_match = re.match(r"(\d+):", upstream_version)
    if epoch_match:
        epoch = int(epoch_match.group(1))
        upstream_version = upstream_version[len(epoch_match.group(0)):] # Remove epoch part

    # Extract debian revision (part after the last hyphen not preceded by common version markers)
    last_hyphen_idx = upstream_version.rfind('-')
    if last_hyphen_idx != -1:
        potential_revision = upstream_version[last_hyphen_idx+1:]
        potential_upstream = upstream_version[:last_hyphen_idx]

        # Simple check: revision part should ideally contain a digit or 'ubuntu'/'deb'
        # And upstream part should not obviously end with alpha/beta/rc/pre etc. right before the hyphen
        is_likely_revision = re.search(r'\d|ubuntu|deb', potential_revision, re.IGNORECASE)
        is_likely_part_of_upstream = re.search(r'(alpha|beta|rc|pre|dev|snap|git)\d*$', potential_upstream, re.IGNORECASE)

        if is_likely_revision and not is_likely_part_of_upstream:
            debian_revision = potential_revision
            upstream_version = potential_upstream
        # else: # Assume hyphen is part of the upstream version (e.g., "1.0-pre-1")
            # logger.debug(f"Treating hyphen as part of upstream: {version_string}")


    return (epoch, upstream_version, debian_revision)


def _compare_version_part(part1, part2):
    """
    Compares two parts (upstream or revision) of a Debian version string.
    Handles digits and non-digits, and the tilde '~'.
    Returns: -1 if part1 < part2, 0 if part1 == part2, 1 if part1 > part2
    Based on dpkg/lib/vercmp.c logic.
    """
    if part1 is None: part1 = ""
    if part2 is None: part2 = ""

    i, j = 0, 0
    len1, len2 = len(part1), len(part2)

    while i < len1 or j < len2:
        first_diff = 0

        # Compare non-digit sequences lexicographically
        start_i, start_j = i, j
        while i < len1 and not part1[i].isdigit(): i += 1
        while j < len2 and not part2[j].isdigit(): j += 1

        substr1 = part1[start_i:i]
        substr2 = part2[start_j:j]

        # '~' sorts before anything, even empty string represented by None comparison later
        # Replace tilde with a character that sorts very early. Null byte works well.
        cmp1 = substr1.replace('~', '\x00')
        cmp2 = substr2.replace('~', '\x00')

        if cmp1 < cmp2: return -1
        if cmp1 > cmp2: return 1

        # Compare digit sequences numerically
        start_i, start_j = i, j
        while i < len1 and part1[i].isdigit(): i += 1
        while j < len2 and part2[j].isdigit(): j += 1

        val1_str = part1[start_i:i]
        val2_str = part2[start_j:j]

        val1 = int(val1_str) if val1_str else 0
        val2 = int(val2_str) if val2_str else 0

        if val1 < val2: return -1
        if val1 > val2: return 1

        # If numbers are equal, length might matter implicitly but Python's int handles leading zeros.
        # Let's assume numerical equality is sufficient here unless specific edge cases arise.

    # If we exit the loop, the parts are identical
    return 0


def compare_debian_versions(v1_tuple, v2_tuple):
    """
    Compares two parsed Debian version tuples (epoch, upstream, revision).
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    e1, u1, r1 = v1_tuple
    e2, u2, r2 = v2_tuple

    # 1. Compare epochs
    if e1 < e2: return -1
    if e1 > e2: return 1

    # 2. Compare upstream versions
    up_cmp = _compare_version_part(u1, u2)
    if up_cmp != 0:
        return up_cmp

    # 3. Compare Debian revisions
    # None revision sorts lower than a real revision (unless the revision starts with '~')
    if r1 is None and r2 is None:
        return 0
    if r1 is None:
        # If r2 starts with tilde, None is considered newer, otherwise older.
        return 1 if (r2 and r2.startswith('~')) else -1
    if r2 is None:
        # If r1 starts with tilde, None is considered newer, otherwise older.
        return -1 if (r1 and r1.startswith('~')) else 1

    # Both have revisions, compare them
    rev_cmp = _compare_version_part(r1, r2)
    return rev_cmp