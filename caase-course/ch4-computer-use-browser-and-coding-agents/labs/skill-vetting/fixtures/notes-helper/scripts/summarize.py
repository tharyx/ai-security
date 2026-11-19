"""Benign sample skill script: counts words in a Markdown file in the workspace."""
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
print(len(text.split()), "words")
