# Recommended: Use an official mirror close to you or a reliable one.
# Find mirrors at: https://launchpad.net/ubuntu/+archivemirrors
DEFAULT_MIRROR_URL = "http://archive.ubuntu.com/ubuntu/"
DEFAULT_UBUNTU_VERSION = "jammy"  # e.g., "jammy" (22.04), "focal" (20.04), "noble" (24.04)
DEFAULT_COMPONENTS = ["main", "restricted", "universe", "multiverse"]
DEFAULT_ARCHITECTURES = ["amd64"] # Add others if needed, e.g., "arm64", "all"
DEFAULT_PACKAGE_TYPES = ["binary"] # Add "source" if needed
DEFAULT_POCKETS = ["", "-updates", "-security"] # "" is the base release pocket

DEFAULT_OUTPUT_DIR = "./ubuntu_mirror"
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds
CHUNK_SIZE = 8192 * 1024 # 8 MB chunks for download
CONNECT_TIMEOUT = 15 # seconds
READ_TIMEOUT = 60 # seconds
MAX_WORKERS = 8 # Default concurrent downloads