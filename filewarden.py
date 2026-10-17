#!/usr/bin/env python3
"""FileWarden CLI launcher for running straight from a source checkout."""

import os
import sys

# realpath keeps the package importable when the launcher itself is symlinked
# into a directory that is on PATH (e.g. ~/.local/bin/filewarden -> repo/filewarden.py)
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from fwl.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
