from dataclasses import dataclass, field
from pathlib import Path
import logging

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
    component: str = ""
    pocket: str = "" # e.g. "", "-updates", "-security"
    type: str = "" # 'binary' or 'source'

    def __hash__(self):
        # Hash based on identifying info; filename includes version details.
        return hash((self.package, self.version_str, self.architecture, self.filename))

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