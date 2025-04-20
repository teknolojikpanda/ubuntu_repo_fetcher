from dataclasses import dataclass, field
from pathlib import Path
import logging

# Import parsing function from debian_version module
from .debian_version import parse_debian_version

logger = logging.getLogger(__name__)

@dataclass
class PackageInfo:
    """Holds information about a specific package version."""
    package: str
    version_str: str
    architecture: str # 'source' if type is source
    filename: str
    size: int
    sha256: str = ""
    debian_version_tuple: tuple = field(init=False) # Parsed (epoch, upstream, revision)
    component: str = ""
    pocket: str = "" # e.g. "", "-updates", "-security"
    type: str = "" # 'binary' or 'source'

    def __post_init__(self):
        # Parse using the dedicated function
        try:
            self.debian_version_tuple = parse_debian_version(self.version_str)
        except Exception as e:
            logger.error(f"Failed to parse version string '{self.version_str}' for {self.package}: {e}")
            # Assign a tuple that sorts very low as a fallback
            self.debian_version_tuple = (-1, "", None)

    def __hash__(self):
        # Hash based on identifying info; filename includes version details.
        return hash((self.package, self.version_str, self.architecture, self.filename))

    # Note: Comparison logic uses compare_debian_versions from the debian_version module externally

@dataclass
class RepoFile:
    """Represents a file to be downloaded from the repository."""
    url: str
    local_path: Path
    expected_size: int = 0 # Optional, for progress bar if known
    expected_sha256: str = "" # Optional, for verification
    is_index: bool = False # Mark index files for priority/structure

    # Make RepoFile hashable based on URL for use in sets
    def __hash__(self):
        return hash(self.url)

    def __eq__(self, other):
        if not isinstance(other, RepoFile):
            return NotImplemented
        return self.url == other.url