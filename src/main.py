import argparse
import gzip
import logging
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from tqdm import tqdm

# Project internal imports
from . import config
from .models import PackageInfo, RepoFile
from .debian_version import compare_debian_versions
from .repo_parser import parse_packages_file, parse_release_file, find_hashes_in_release
from .downloader import fetch_url, download_file

# --- Logging Setup ---
# Place basicConfig here so logger instances in other modules inherit it
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s')
logger = logging.getLogger(__name__) # Get logger for this module


def run_mirror_process(args):
    """Orchestrates the mirror download process."""

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Starting partial mirror process.")
    # Log effective configuration
    logger.info(f"Mirror URL: {args.mirror}")
    logger.info(f"Distribution: {args.dist}")
    logger.info(f"Components: {', '.join(args.components)}")
    logger.info(f"Architectures: {', '.join(args.archs)}")
    logger.info(f"Package Types: {', '.join(args.types)}")
    logger.info(f"Pockets: {', '.join(p if p else '<release>' for p in args.pockets)}")
    logger.info(f"Output Directory: {output_dir}")
    logger.info(f"Max Size (GB): {args.max_size}")
    logger.info(f"Download Workers: {args.workers}")
    logger.info(f"Skip Package Download: {args.skip_deb_download}")

    max_size_bytes = args.max_size * 1024 * 1024 * 1024
    session = requests.Session()
    # Add a user-agent? Some mirrors might appreciate it.
    session.headers.update({'User-Agent': 'Python-Ubuntu-Partial-Mirror-Tool/1.0'})

    # Key: (package_name, arch, type). arch='source' for type='source'
    all_packages: dict[tuple[str, str, str], PackageInfo] = {}
    # Set of RepoFile objects representing initially targeted files
    files_to_target: set[RepoFile] = set()

    # --- Step 1: Target and Fetch Index Files ---
    logger.info("Targeting and fetching repository index files...")
    pbar_indices = tqdm(desc="Fetching Indices", unit="file", smoothing=0.1, disable=args.debug) # Disable pbar in debug
    index_download_futures = {} # future -> RepoFile

    # Cache fetched Release/InRelease content: key=(dist_pocket, url), value=content_bytes
    release_files_content: dict[tuple[str, str], bytes] = {}
    # Use a dedicated executor for index fetching
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="IndexFetch") as executor:
        # Target essential index files first
        for pocket_suffix in args.pockets:
            dist_pocket = f"{args.dist}{pocket_suffix}"
            dist_path = f"dists/{dist_pocket}/"
            base_dist_url = urljoin(args.mirror, dist_path)

            # Target Release, InRelease, Release.gpg
            for fname in ["InRelease", "Release", "Release.gpg"]: # Prefer InRelease if exists
                index_url = urljoin(base_dist_url, fname)
                local_path = output_dir / dist_path / fname
                repo_file = RepoFile(url=index_url, local_path=local_path, is_index=True)
                if repo_file not in files_to_target: # Check set before adding
                    files_to_target.add(repo_file)
                    future = executor.submit(fetch_url, repo_file.url, session)
                    index_download_futures[future] = repo_file

            # Target Packages/Sources files
            for component in args.components:
                for pkg_type in args.types:
                    if pkg_type == 'binary':
                        for arch in args.archs:
                            relative_path = f"{component}/{pkg_type}-{arch}/Packages.gz"
                            index_url = urljoin(base_dist_url, relative_path)
                            local_path = output_dir / dist_path / relative_path
                            repo_file = RepoFile(url=index_url, local_path=local_path, is_index=True)
                            if repo_file not in files_to_target:
                                files_to_target.add(repo_file)
                                future = executor.submit(fetch_url, repo_file.url, session)
                                index_download_futures[future] = repo_file
                    elif pkg_type == 'source':
                        relative_path = f"{component}/source/Sources.gz"
                        index_url = urljoin(base_dist_url, relative_path)
                        local_path = output_dir / dist_path / relative_path
                        repo_file = RepoFile(url=index_url, local_path=local_path, is_index=True)
                        if repo_file not in files_to_target:
                             files_to_target.add(repo_file)
                             future = executor.submit(fetch_url, repo_file.url, session)
                             index_download_futures[future] = repo_file

        logger.info(f"Submitted {len(index_download_futures)} index file fetch tasks.")

        # Process completed index fetches and parse content
        for future in as_completed(index_download_futures):
            repo_file = index_download_futures[future]
            pbar_indices.update(1)
            try:
                response = future.result()
                if response:
                    content = response.content

                    # Store Release/InRelease content by pocket/URL key
                    path_parts_rel = repo_file.local_path.parts
                    try:
                        rel_dists_idx = path_parts_rel.index('dists')
                        rel_dist_pocket = path_parts_rel[rel_dists_idx + 1]
                        if repo_file.local_path.name in ["Release", "InRelease"]:
                             release_files_content[(rel_dist_pocket, repo_file.url)] = content
                             logger.debug(f"Stored {len(content)} bytes for {repo_file.local_path.name} from {rel_dist_pocket}")
                    except (ValueError, IndexError):
                        logger.warning(f"Could not determine pocket for storing Release content: {repo_file.local_path}")

                    # Parse Packages/Sources files
                    if repo_file.local_path.name.endswith(".gz") and \
                       (repo_file.local_path.name.startswith("Packages") or repo_file.local_path.name.startswith("Sources")):
                        try:
                            decompressed_content = gzip.decompress(content)
                            # Determine components from path correctly
                            path_parts = repo_file.local_path.parts
                            actual_dist_pocket, relative_to_dist = None, None
                            file_arch, file_type = None, None
                            component, pocket_suffix = None, ""

                            try:
                                dists_index = path_parts.index('dists')
                                if dists_index + 1 < len(path_parts):
                                    actual_dist_pocket = path_parts[dists_index + 1]
                                else: raise ValueError("dist_pocket component not found after 'dists'")

                                start_index = path_parts.index(actual_dist_pocket) + 1
                                relative_to_dist = Path(*path_parts[start_index:])
                                component = relative_to_dist.parts[0]

                                # Determine file_type and file_arch from path structure
                                type_arch_part = relative_to_dist.parts[1]
                                if type_arch_part.startswith("binary-"):
                                    file_type = "binary"
                                    file_arch = type_arch_part.split("-", 1)[1]
                                elif type_arch_part == "source":
                                    file_type = "source"
                                    file_arch = "source" # Internal identifier
                                else: raise ValueError(f"Unknown type/arch structure: {type_arch_part}")

                                if actual_dist_pocket.startswith(args.dist):
                                     pocket_suffix = actual_dist_pocket[len(args.dist):]

                            except (ValueError, IndexError) as path_err:
                                logger.error(f"Path structure error processing {repo_file.local_path}: {path_err}")
                                continue # Skip this file

                            # Parse the file content
                            parsed_packages = parse_packages_file(
                                decompressed_content, component, pocket_suffix, file_arch, file_type
                            )
                            logger.debug(f"Parsed {len(parsed_packages)} entries from {repo_file.local_path}")

                            # Select latest version for each package/arch/type
                            for pkg_info in parsed_packages:
                                key = (pkg_info.package, pkg_info.architecture, pkg_info.type)
                                if key not in all_packages:
                                    all_packages[key] = pkg_info
                                else:
                                    current_best = all_packages[key]
                                    comp = compare_debian_versions(pkg_info.debian_version_tuple, current_best.debian_version_tuple)
                                    if comp > 0: # New one is newer
                                        all_packages[key] = pkg_info
                                    elif comp == 0: # Versions equal, prefer security > updates > release
                                         pocket_pref = {"-security": 3, "-updates": 2, "": 1}
                                         if pocket_pref.get(pkg_info.pocket, 0) > pocket_pref.get(current_best.pocket, 0):
                                             all_packages[key] = pkg_info # Replace if preferred pocket

                        except gzip.BadGzipFile:
                            logger.error(f"Failed to decompress {repo_file.url}.")
                        except Exception as parse_err:
                            logger.error(f"Error processing content of {repo_file.url}: {parse_err}")
                            logger.error(traceback.format_exc())
                else:
                    # Fetch failed, remove from target set if it was there
                    logger.warning(f"Failed index fetch: {repo_file.url}. Will not be included.")
                    files_to_target.discard(repo_file)

            except Exception as future_err:
                logger.error(f'{repo_file.url} generated an exception during fetch processing: {future_err}')
                logger.error(traceback.format_exc())
                files_to_target.discard(repo_file)

    pbar_indices.close()
    logger.info(f"Finished fetching indices. Found info for {len(all_packages)} unique latest package entries.")

    # --- Step 2: Determine Final Download List & Estimate Size ---
    logger.info("Calculating final download list and estimating size...")
    # Start with successfully fetched/processed index files that are essential
    # We need Release/InRelease/Release.gpg for apt to work.
    # We need the Packages/Sources files we parsed.
    final_index_files: set[RepoFile] = set()
    final_package_files: set[RepoFile] = set()
    release_file_cache: dict[tuple[str,str], dict] = {} # Cache parsed release data

    # Verify index files against Release data
    for repo_file in list(files_to_target): # Iterate copy of original targets
         if repo_file.is_index:
             # Check if content was fetched (implies fetch didn't fail)
             path_parts = repo_file.local_path.parts
             file_fetched = False
             file_content = None
             try:
                 idx_dists_idx = path_parts.index('dists')
                 idx_dist_pocket = path_parts[idx_dists_idx+1]

                 # Check if Release/InRelease content exists for this pocket
                 release_data = None
                 for (pocket_key, url_key), content_val in release_files_content.items():
                      if pocket_key == idx_dist_pocket:
                           # Check if the content is for the file itself (Release/InRelease)
                           if url_key == repo_file.url:
                               file_fetched = True
                               file_content = content_val

                           # Check if this content belongs to the Release file for this index's dir
                           # Parse if not already cached
                           if (pocket_key, url_key) not in release_file_cache:
                                release_file_cache[(pocket_key, url_key)] = parse_release_file(content_val)
                           current_release_data = release_file_cache.get((pocket_key, url_key))

                           # Is this the release data for the directory of the current repo_file?
                           if current_release_data and urlparse(url_key).path.rsplit('/',1)[0] == urlparse(repo_file.url).path.rsplit('/',1)[0]:
                                release_data = current_release_data


                 # If it's the Release/InRelease/GPG file itself and was fetched
                 if repo_file.local_path.name in ["Release", "InRelease", "Release.gpg"]:
                     if file_fetched:
                         repo_file.expected_size = len(file_content) if file_content else 0
                         # No SHA needed for Release itself usually checked by GPG/InRelease sig
                         final_index_files.add(repo_file)
                         logger.debug(f"Keeping essential index: {repo_file.local_path} (Size: {repo_file.expected_size})")
                     else:
                         logger.warning(f"Essential index file {repo_file.local_path} was targeted but fetch failed.")

                 # If it's Packages/Sources, verify against Release data
                 elif repo_file.local_path.name.endswith(".gz"):
                     if file_fetched: # Check if we likely have the content (fetch didn't fail)
                         if release_data:
                             rel_path = str(repo_file.local_path.relative_to(output_dir / "dists" / idx_dist_pocket))
                             size, sha256 = find_hashes_in_release(release_data, rel_path)
                             if size > 0:
                                 repo_file.expected_size = size
                                 repo_file.expected_sha256 = sha256
                                 final_index_files.add(repo_file)
                                 logger.debug(f"Verified index: {repo_file.local_path} Size: {size}")
                             else:
                                 logger.warning(f"Could not verify {repo_file.local_path} in Release data, excluding.")
                         else:
                              logger.warning(f"No Release data found for {idx_dist_pocket} to verify {repo_file.local_path}, excluding.")
                     # else: logger.debug(f"Skipping {repo_file.local_path} as fetch likely failed.")

             except (ValueError, IndexError) as path_err:
                  logger.warning(f"Path error verifying index {repo_file.local_path}: {path_err}, excluding.")


    # Add latest package files (.deb, .dsc, etc.)
    for pkg_info in all_packages.values():
        # filename field usually contains the pool path relative to mirror root
        pkg_url = urljoin(args.mirror, pkg_info.filename)
        local_pkg_path = output_dir / pkg_info.filename
        repo_file = RepoFile(
            url=pkg_url, local_path=local_pkg_path,
            expected_size=pkg_info.size, expected_sha256=pkg_info.sha256,
            is_index=False
        )
        final_package_files.add(repo_file)

    # Final list and size calculation
    files_to_download_final = final_index_files.union(final_package_files)
    total_estimated_size = sum(f.expected_size or 0 for f in files_to_download_final)
    total_index_size_final = sum(f.expected_size or 0 for f in final_index_files)
    total_package_size_final = sum(f.expected_size or 0 for f in final_package_files)

    total_estimated_size_gb = total_estimated_size / (1024 * 1024 * 1024)
    total_package_size_gb = total_package_size_final / (1024 * 1024 * 1024)

    logger.info(f"--- Final Download Plan ---")
    logger.info(f"Index files to download: {len(final_index_files)}")
    logger.info(f"Package files to download: {len(final_package_files)}")
    logger.info(f"Total unique files: {len(files_to_download_final)}")
    logger.info(f"Estimated size (Indices): {total_index_size_final / (1024 * 1024):.2f} MB")
    logger.info(f"Estimated size (Packages): {total_package_size_gb:.2f} GB")
    logger.info(f"Total estimated download size: {total_estimated_size_gb:.2f} GB")
    logger.info(f"---------------------------")

    if total_estimated_size > max_size_bytes:
        logger.error(f"Estimated size ({total_estimated_size_gb:.2f} GB) exceeds the limit of {args.max_size} GB.")
        logger.error("Aborting download. Consider reducing components, architectures, types, or increasing the size limit.")
        return 1 # Indicate error exit status

    files_to_actually_download = files_to_download_final
    progress_bar_total = total_estimated_size

    if args.skip_deb_download:
        logger.info("--skip-deb-download specified. Only downloading required index files.")
        files_to_actually_download = final_index_files
        progress_bar_total = total_index_size_final
        if not files_to_actually_download:
             logger.info("No index files verified or needed for download.")
             return 0 # Success, nothing to do
        logger.info(f"Index files to download: {len(files_to_actually_download)}")
        logger.info(f"Index download size: {progress_bar_total / (1024*1024):.2f} MB")

    # --- Step 3: Download Files ---
    if not files_to_actually_download:
        logger.info("No files selected for download.")
        return 0 # Success, nothing to do

    logger.info(f"Starting download of {len(files_to_actually_download)} files...")

    files_list = list(files_to_actually_download)
    total_downloaded_bytes = 0
    download_errors = 0

    # Use a dedicated executor for downloading packages/verified indices
    with tqdm(total=progress_bar_total, unit='B', unit_scale=True, desc="Downloading", smoothing=0.1, disable=args.debug) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="Download") as executor:
            future_to_repo_file = {
                executor.submit(download_file, repo_file, session, pbar): repo_file
                for repo_file in files_list
            }

            for future in as_completed(future_to_repo_file):
                repo_file = future_to_repo_file[future]
                try:
                    success, downloaded_or_existing_size = future.result()
                    # Only count bytes if download was successful *and* file didn't just exist previously
                    # Heuristic: assume if success=True and size>0 it was either downloaded or verified existing
                    if success and downloaded_or_existing_size > 0:
                         # This isn't perfect tracking of *newly* downloaded bytes vs existing, but ok for info
                         total_downloaded_bytes += downloaded_or_existing_size
                    if not success:
                        download_errors += 1
                        logger.warning(f"Failed download recorded for: {repo_file.url}")
                except Exception as exc:
                    download_errors += 1
                    logger.error(f'{repo_file.url} generated an exception during download task processing: {exc}')
                    logger.error(traceback.format_exc())

    logger.info("--- Download Summary ---")
    logger.info(f"Total bytes processed (downloaded/verified existing): {total_downloaded_bytes / (1024 * 1024 * 1024):.2f} GB")
    if download_errors > 0:
        logger.warning(f"Download process finished with {download_errors} errors. The mirror might be incomplete.")
        status = 1 # Indicate error
    else:
        logger.info("Download process finished successfully.")
        status = 0 # Indicate success

    logger.info("---")
    logger.info("To use this mirror on an offline machine:")
    logger.info(f"1. Transfer the entire output directory ({output_dir}) to the offline machine.")
    logger.info(f"2. Edit /etc/apt/sources.list on the offline machine.")
    logger.info("3. Remove or comment out all existing lines pointing to internet sources.")
    logger.info(f"4. Add lines for the distribution '{args.dist}' and its pockets:")

    base_path_str = f"file:{output_dir.as_posix()}" # Use POSIX path for file URI
    components_str = ' '.join(args.components)
    # Ensure correct pockets are added based on what was requested AND potentially downloaded indices for
    # Collect unique pockets for which index files were successfully added
    downloaded_pockets = set()
    for idx_file in final_index_files:
        try:
            parts = idx_file.local_path.parts
            pocket = parts[parts.index('dists') + 1]
            downloaded_pockets.add(pocket)
        except (ValueError, IndexError):
            pass

    if not downloaded_pockets:
         logger.warning("No index files seem to have been downloaded, cannot generate sources.list example.")
    else:
        # Sort pockets: base, then updates, then security
        pocket_order = {f"{args.dist}{p}": i for i, p in enumerate(config.DEFAULT_POCKETS)}
        sorted_pockets = sorted(list(downloaded_pockets), key=lambda p: pocket_order.get(p, 99))

        for pocket_name in sorted_pockets:
            logger.info(f"   deb [trusted=yes] {base_path_str} {pocket_name} {components_str}")

    logger.info("   (Ensure the components listed match what you intended for each pocket)")
    logger.info("5. Run: sudo apt-get update")
    logger.info("6. Run: sudo apt-get install <package-name>")
    logger.info("Note: [trusted=yes] bypasses GPG checks.")
    logger.info("Note: This mirror contains only the LATEST package versions found.")
    logger.info("---")

    return status


def main():
    """Parses arguments and starts the mirror process."""
    parser = argparse.ArgumentParser(
        description="Partially mirror an Ubuntu repository (latest packages).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )
    parser.add_argument("-m", "--mirror", default=config.DEFAULT_MIRROR_URL, help="Ubuntu mirror URL.")
    parser.add_argument("-d", "--dist", default=config.DEFAULT_UBUNTU_VERSION, help="Ubuntu distribution codename.")
    parser.add_argument("-c", "--components", nargs='+', default=config.DEFAULT_COMPONENTS, help="Repository components.")
    parser.add_argument("-a", "--archs", nargs='+', default=config.DEFAULT_ARCHITECTURES, help="Architectures (e.g., amd64, arm64, all).")
    parser.add_argument("-t", "--types", nargs='+', default=config.DEFAULT_PACKAGE_TYPES, choices=['binary', 'source'], help="Package types.")
    parser.add_argument("-p", "--pockets", nargs='+', default=config.DEFAULT_POCKETS, help="Distribution pockets/suffixes (e.g., '', -updates, -security).")
    parser.add_argument("-o", "--output", default=config.DEFAULT_OUTPUT_DIR, help="Output directory for the mirror.")
    parser.add_argument("--max-size", type=int, default=400, help="Maximum approximate size limit in GB.")
    parser.add_argument("--workers", type=int, default=config.MAX_WORKERS, help="Number of concurrent download workers.")
    parser.add_argument("--skip-deb-download", action="store_true", help="Only download index files and estimate size.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging (very verbose).")

    args = parser.parse_args()

    # Adjust logging level based on debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        # Potentially make requests/urllib3 less noisy even in debug?
        # logging.getLogger("requests").setLevel(logging.INFO)
        # logging.getLogger("urllib3").setLevel(logging.INFO)
        logger.debug("Debug logging enabled.")
    else:
        logging.getLogger().setLevel(logging.INFO)
        # Silence verbose logs from underlying libraries in info mode
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)


    try:
        exit_status = run_mirror_process(args)
        return exit_status
    except KeyboardInterrupt:
        logger.warning("Process interrupted by user.")
        return 1
    except Exception as e:
        logger.error(f"An unexpected critical error occurred: {e}")
        logger.error(traceback.format_exc())
        return 1

# Note: This file is intended to be imported by run_mirror.py,
# but can be run directly if needed (though run_mirror.py is cleaner)
if __name__ == "__main__":
     sys.exit(main())