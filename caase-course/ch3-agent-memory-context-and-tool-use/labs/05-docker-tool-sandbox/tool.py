"""A tiny example 'tool' to put in the container: reads a text file from /data and prints its word count.

Used only by the optional Docker guide in README.md. The repo tests never run it in Docker.
"""

import sys
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/input.txt")
print(f"words: {len(path.read_text().split())}")
