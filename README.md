# Ubuntu Partial Mirror Tool

This tool downloads a partial mirror of an Ubuntu repository, focusing on the latest package versions for specified architectures and components to fit within a limited disk space (e.g., 400GB).

It is designed for creating offline repositories for private networks.

## Features

*   Downloads only the latest version of each package.
*   Selectable Ubuntu distribution, components, architectures, and package types.
*   Includes base release, updates, and security pockets.
*   Estimates download size before starting.
*   Uses concurrent downloads for speed.
*   Optional SHA256 verification.

## Installation

1.  Clone the repository or download the source code.
2.  Navigate to the project directory.
3.  (Optional but recommended) Create and activate a virtual environment:
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```
4.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the tool using `run_mirror.py`.

**1. Estimate Size Only:**

```bash
    python run_mirror.py \
        --mirror http://gb.archive.ubuntu.com/ubuntu/ \
        --dist noble \
        --components main restricted universe \
        --archs amd64 \
        --output ./ubuntu-noble-partial \
        --max-size 400 \
        --skip-deb-download
```

**2. Perform Full Download:**

If the estimated size is acceptable, run without --skip-deb-download:
```bash
    python run_mirror.py \
        --mirror http://gb.archive.ubuntu.com/ubuntu/ \
        --dist noble \
        --components main restricted universe \
        --archs amd64 \
        --output ./ubuntu-noble-partial \
        --max-size 400 \
        --workers 10
```

**Command-line Arguments:**

Use python run_mirror.py --help to see all available options:
-m, --mirror: Ubuntu mirror URL.
-d, --dist: Distribution codename (e.g., noble, jammy, focal).
-c, --components: Repository components (e.g., main, universe).
-a, --archs: Architectures (e.g., amd64, arm64, all).
-t, --types: Package types (binary, source).
-p, --pockets: Distribution suffixes ("", -updates, -security).
-o, --output: Output directory for the mirror.
--max-size: Maximum approximate size in GB.
--workers: Number of concurrent download workers.
--skip-deb-download: Only download index files and estimate size.
--debug: Enable debug logging.
Using the Mirror Offline
Transfer the entire output directory (e.g., ./ubuntu-noble-partial) to the offline machine.
Follow the instructions printed by the script upon completion to configure /etc/apt/sources.list on the offline clients.
Run sudo apt-get update on the offline clients.
Notes
This mirror contains only the latest package versions found. Specific older dependencies might be missing.
The Debian version comparison logic implemented is heuristic and aims for correctness but might differ from dpkg in extremely rare edge cases.
Using [trusted=yes] in sources.list bypasses GPG checks, which is simpler for offline use but less secure.
