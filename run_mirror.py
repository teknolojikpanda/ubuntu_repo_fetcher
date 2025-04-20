#!/usr/bin/env python

import sys
import os

# Ensure the src directory is in the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Now import and run the main function from the src package
try:
    from src.main import main as run_main_process # Import the main function from src.main
except ImportError as e:
    print(f"Error: Could not import the main application module. Is 'src' directory available?", file=sys.stderr)
    print(f"Details: {e}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    # Execute the main application logic and exit with its status code
    sys.exit(run_main_process())