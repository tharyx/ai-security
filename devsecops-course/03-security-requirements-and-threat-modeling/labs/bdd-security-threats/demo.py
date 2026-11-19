import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bddlite  # noqa: E402

for label, args in (("SECURE app", []), ("VULNERABLE app", ["--vulnerable"])):
    print(f"== {label}")
    code = bddlite.main(args)
    print("exit code:", code)
