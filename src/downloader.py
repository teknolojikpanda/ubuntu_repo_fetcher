import hashlib
import logging
import time
import requests
from tqdm import tqdm
from pathlib import Path

from .models import RepoFile
from .config import MAX_RETRIES, RETRY_DELAY, CHUNK_SIZE, CONNECT_TIMEOUT, READ_TIMEOUT

logger = logging.getLogger(__name__)

def fetch_url(url: str, session: requests.Session, stream: bool = False, timeout: tuple = (CONNECT_TIMEOUT, READ_TIMEOUT)):
    """Fetches a URL with retries, returning the response object or None."""
    for attempt in range(MAX_RETRIES):
        try:
            response = session.get(url, stream=stream, timeout=timeout, allow_redirects=True)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            logger.debug(f"Successfully fetched (status {response.status_code}): {url}")
            return response
        except requests.exceptions.HTTPError as e:
            # Log 404 specifically as info/debug, others as warning/error
            if e.response.status_code == 404:
                logger.debug(f"File not found (404): {url}")
                return None # Don't retry 404
            else:
                 logger.warning(f"HTTP Error {e.response.status_code} on attempt {attempt + 1}/{MAX_RETRIES} for {url}: {e}")
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.RequestException) as e:
            logger.warning(f"Network/Request Error on attempt {attempt + 1}/{MAX_RETRIES} for {url}: {e}")

        if attempt + 1 == MAX_RETRIES:
            logger.error(f"Failed to fetch {url} after {MAX_RETRIES} attempts.")
            return None
        else:
            # Basic exponential backoff
            delay = RETRY_DELAY * (2 ** attempt)
            logger.debug(f"Retrying {url} in {delay} seconds...")
            time.sleep(delay)
    return None # Should not be reached normally

def calculate_sha256(file_path: Path) -> str | None:
    """Calculates the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logger.error(f"Cannot calculate SHA256, file not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error calculating SHA256 for {file_path}: {e}")
        return None

def download_file(repo_file: RepoFile, session: requests.Session, pbar: tqdm = None) -> tuple[bool, int]:
    """
    Downloads a single file described by RepoFile.
    Returns (success_status, bytes_downloaded_or_existing_size).
    """
    # Check if file exists and if size matches (if expected size is known)
    if repo_file.local_path.exists():
        existing_size = repo_file.local_path.stat().st_size
        if repo_file.expected_size > 0:
            if existing_size == repo_file.expected_size:
                # Optional: Verify hash of existing file if expected_sha256 is present
                # if repo_file.expected_sha256:
                #    actual_hash = calculate_sha256(repo_file.local_path)
                #    if actual_hash == repo_file.expected_sha256:
                #        logger.debug(f"File already exists, size and hash match: {repo_file.local_path}")
                #        if pbar: pbar.update(repo_file.expected_size)
                #        return True, repo_file.expected_size
                #    else:
                #        logger.warning(f"File exists, size matches but SHA256 mismatch for {repo_file.local_path}. Re-downloading.")
                # else: # No hash to verify, assume size match is enough
                logger.debug(f"File already exists and size matches: {repo_file.local_path}")
                if pbar: pbar.update(repo_file.expected_size)
                return True, repo_file.expected_size
            else:
                logger.info(f"File exists but size mismatch ({existing_size} vs {repo_file.expected_size}). Re-downloading: {repo_file.local_path}")
        else:
            # File exists but we don't know the expected size. Assume it's okay? Or always re-download?
            # Let's assume it's okay to avoid re-downloading indices fetched without size info.
            logger.debug(f"File already exists, unknown expected size: {repo_file.local_path}")
            # Don't update progress bar if size is unknown.
            # Return True, existing_size? Or True, 0 as we didn't 'download'? Let's return existing size.
            return True, existing_size


    repo_file.local_path.parent.mkdir(parents=True, exist_ok=True)
    downloaded_size = 0
    tmp_path = repo_file.local_path.with_suffix(repo_file.local_path.suffix + ".partial") # Use .partial extension

    try:
        logger.debug(f"Attempting download: {repo_file.url}")
        response = fetch_url(repo_file.url, session, stream=True)
        if not response:
            return False, 0 # Fetch failed after retries

        # Check Content-Length header if available, compare with expected size
        content_length_str = response.headers.get('Content-Length')
        if content_length_str and repo_file.expected_size > 0:
             try:
                 content_length = int(content_length_str)
                 if content_length != repo_file.expected_size:
                     logger.warning(f"Content-Length header ({content_length}) does not match expected size ({repo_file.expected_size}) for {repo_file.url}")
                     # Continue download anyway, but rely on hash check later if possible
             except ValueError:
                 logger.warning(f"Could not parse Content-Length header '{content_length_str}' for {repo_file.url}")


        with open(tmp_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                # chunk filter unnecessary with requests >= 2.1.0, but harmless
                # if chunk:
                f.write(chunk)
                chunk_len = len(chunk)
                downloaded_size += chunk_len
                if pbar:
                    # Update progress bar only by amount downloaded in this session
                    pbar.update(chunk_len)

        # Verify size after download matches Content-Length if available
        if content_length_str:
            try:
                if downloaded_size != int(content_length_str):
                     logger.error(f"Downloaded size ({downloaded_size}) differs from Content-Length ({content_length_str}) for {repo_file.local_path}. Deleting.")
                     tmp_path.unlink()
                     return False, downloaded_size
            except ValueError: pass # Already warned about parsing Content-Length

        # Verify SHA256 hash if expected hash is known
        if repo_file.expected_sha256:
            actual_hash = calculate_sha256(tmp_path)
            if actual_hash != repo_file.expected_sha256:
                 logger.error(f"SHA256 mismatch for {repo_file.local_path}! Expected {repo_file.expected_sha256}, got {actual_hash}. Deleting.")
                 tmp_path.unlink()
                 return False, downloaded_size
            else:
                 logger.debug(f"SHA256 verified for {repo_file.local_path}")

        # Rename temporary file to final destination only if all checks passed
        tmp_path.rename(repo_file.local_path)
        logger.debug(f"Successfully downloaded and verified {repo_file.local_path}")
        return True, downloaded_size

    except Exception as e:
        logger.error(f"Error during download/verification for {repo_file.url} -> {repo_file.local_path}: {e}")
        # Clean up temporary file if it exists on any exception during the download block
        if tmp_path.exists():
            try:
                tmp_path.unlink()
                logger.debug(f"Deleted temporary file on error: {tmp_path}")
            except OSError as unlink_err:
                 logger.error(f"Error deleting temporary file {tmp_path} after error: {unlink_err}")
        return False, downloaded_size # Return partial size for stats if needed
    finally:
        # Final check to ensure temporary file doesn't linger if rename failed silently
        if tmp_path.exists():
             try:
                 tmp_path.unlink()
                 logger.warning(f"Removed potentially lingering temporary file: {tmp_path}")
             except OSError:
                 pass # Ignore error if deletion fails here