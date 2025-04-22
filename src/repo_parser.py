import re
import logging
from email.parser import BytesHeaderParser

from .models import PackageInfo

logger = logging.getLogger(__name__)

def parse_packages_file(content: bytes, component: str, pocket: str, file_arch: str = None, file_type: str = "binary") -> list[PackageInfo]:
    """
    Parses the content of a Packages.gz or Sources.gz file.
    Content should be the decompressed bytes.
    'pocket' is the suffix like "", "-updates", "-security".
    'file_arch' is the architecture from the filename (e.g., 'amd64', 'all', 'source').
    'file_type' is 'binary' or 'source' based on the filename.
    """
    packages = []
    parser = BytesHeaderParser()
    # Debian package paragraphs are separated by double newlines (\n\n)
    # Handle both \n\n and potential \r\n\r\n, ensure trailing newline for split
    if not content.endswith(b'\n'): content += b'\n\n'
    else: content += b'\n'
    paragraphs = re.split(b'\n\n+', content.strip())

    for paragraph_bytes in paragraphs:
        trimmed_paragraph = paragraph_bytes.strip()
        if not trimmed_paragraph:
            continue

        # Prepend a dummy header line because BytesHeaderParser expects it
        # Use a known header like 'Package' or 'Source' if the first line isn't one
        if not trimmed_paragraph.lower().startswith((b'package:', b'source:')):
             trimmed_paragraph = b'X-Dummy-Header: dummy\n' + trimmed_paragraph

        try:
            # Ensure trailing newline for parser
            if not trimmed_paragraph.endswith(b'\n'):
                trimmed_paragraph += b'\n'

            headers = parser.parsebytes(trimmed_paragraph)

            package_name = headers.get('Package') or headers.get('Source')
            version_str = headers.get('Version')
            # Get architecture from header, may differ from file_arch (e.g., 'any' vs 'amd64')
            header_architecture = headers.get('Architecture')
            filename = headers.get('Filename')
            size_str = headers.get('Size') # Size of the .deb/.dsc etc.
            sha256 = headers.get('SHA256')

            # Handle Sources files potentially missing direct fields
            if file_type == 'source' and not filename:
                files_section = headers.get('Files')
                if files_section:
                    for line in files_section.strip().split('\n'):
                        parts = line.strip().split()
                        if len(parts) == 3 and parts[2].endswith('.dsc'):
                            # filename = parts[2] # Use .dsc filename
                            # We need the Filename field that points to the pool path
                            # Let's rely on the main 'Filename' field if present, might be in Sources too
                            logger.warning(f"Source package {package_name} lists files but no main 'Filename'. Skipping.")
                            filename = None # Mark as unusable
                            break
                    if not filename: continue # Skip if no suitable filename found

            if not all([package_name, version_str, filename, size_str]):
                # logger.debug(f"Skipping incomplete package entry for {package_name or 'Unknown'}")
                continue

            try:
                size = int(size_str)
            except ValueError:
                logger.warning(f"Invalid size '{size_str}' for package {package_name} {version_str}. Skipping.")
                continue

            # Determine the 'effective' architecture for filtering/keying
            # For binaries, use the architecture from the header.
            # For sources, we use 'source' consistently.
            effective_arch = 'source' if file_type == 'source' else header_architecture

            # Filter based on the requested architecture(s) if it's a binary package
            # file_arch comes from the Packages-ARCH.gz filename (e.g., 'amd64', 'all')
            if file_type == 'binary':
                # We are processing Packages-ARCH file. Header arch must match ARCH or be 'all'.
                if file_arch and file_arch != 'all': # Processing specific arch file (e.g. Packages-amd64.gz)
                    if header_architecture != file_arch and header_architecture != 'all':
                         # logger.debug(f"Skipping {package_name}: Header arch {header_architecture} doesn't match file arch {file_arch}")
                         continue
                elif file_arch == 'all': # Processing Packages-all.gz
                     if header_architecture != 'all':
                         # logger.debug(f"Skipping {package_name}: Header arch {header_architecture} in Packages-all.gz is not 'all'")
                         continue
                # If file_arch is None (shouldn't happen with current logic), accept based on header? Risky.
                if not header_architecture: # Binary package must have an architecture
                    logger.warning(f"Skipping binary package {package_name} without Architecture field.")
                    continue


            # If we pass checks, create the PackageInfo object
            packages.append(PackageInfo(
                package=package_name,
                version_str=version_str,
                architecture=effective_arch, # Use 'source' or header_architecture
                filename=filename, # This should be the path relative to the pool usually
                size=size,
                sha256=sha256,
                component=component,
                pocket=pocket,
                type=file_type
            ))
        except Exception as e:
            logger.error(f"Failed to parse package paragraph: {e}\nParagraph (start): {trimmed_paragraph[:200]}...")
            # import traceback
            # logger.error(traceback.format_exc()) # Uncomment for deeper debug

    return packages


def parse_release_file(content: bytes) -> dict:
    """Parses the content of a Release or InRelease file."""
    parser = BytesHeaderParser()
    # Prepend dummy header if needed - check for common first lines
    if not content.strip().startswith((b'Origin:', b'Label:', b'Suite:', b'Codename:', b'Date:', b'Architectures:', b'Components:', b'Description:')):
        content = b'X-Dummy-Header: dummy\n' + content
    try:
        # Ensure final newline for robust parsing
        if not content.endswith(b'\n'):
            content += b'\n'
        headers = parser.parsebytes(content)

        release_info = {}
        for k, v in headers.items():
            key_lower = k.lower()
            # Strip whitespace. Handle multi-line values by replacing internal newlines if needed.
            # The BytesHeaderParser usually handles standard continuations.
            value_stripped = v.strip().replace('\r\n', '\n').replace('\n ', ' ') # Basic continuation handling
            release_info[key_lower] = value_stripped

        # Ensure hash sections are treated as multi-line strings if parser split them
        for hash_key in ['sha256', 'sha1', 'md5sum']:
            if hash_key in release_info:
                 # Re-fetch potentially multi-part value if parser stored only first line
                 full_value = headers.get(hash_key, '') # Case-sensitive get
                 if not full_value: full_value = headers.get(hash_key.upper(), '') # Try uppercase
                 if not full_value: full_value = headers.get(hash_key.capitalize(), '') # Try capitalized

                 release_info[hash_key] = full_value.strip().replace('\r\n', '\n').replace('\n ', '\n') # Preserve internal newlines

        return release_info
    except Exception as e:
        logger.error(f"Failed to parse Release file content: {e}")
        # import traceback
        # logger.error(traceback.format_exc()) # Uncomment for deeper debug
        return {}

def find_hashes_in_release(release_info: dict, filename_relative: str) -> tuple[int, str]:
    """
    Finds Size and SHA256 hash for a given relative filename within the Release file data.
    filename_relative is the path as listed in the Release file (e.g., main/binary-amd64/Packages.gz).
    """
    size = 0
    sha256 = ""
    # Look in SHA256 section first
    hash_key = 'sha256'
    if hash_key in release_info:
        # Split potentially multi-line hash block correctly
        hash_lines = release_info[hash_key].strip().split('\n')
        for line in hash_lines:
            parts = line.strip().split()
            if len(parts) == 3:
                r_sha256, r_size_str, r_filename = parts
                if r_filename == filename_relative:
                    try:
                        size = int(r_size_str)
                        sha256 = r_sha256
                        # logger.debug(f"Found hash for {filename_relative}: Size={size}, SHA256={sha256}")
                        return size, sha256
                    except ValueError:
                        logger.warning(f"Could not parse size '{r_size_str}' from Release file ({hash_key}) for {filename_relative}")
            # else: logger.debug(f"Skipping malformed {hash_key} line in Release file: '{line}'")

    # logger.debug(f"Hash/Size not found in Release ({hash_key}) for: {filename_relative}")
    return size, sha256 # Return 0/"" if not found