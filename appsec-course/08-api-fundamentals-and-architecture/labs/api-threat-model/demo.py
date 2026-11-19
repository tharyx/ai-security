import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import apitm as m  # noqa: E402

print("### SIMPLE deployment (defenses skipped) ###\n")
print(m.report(m.simple_deployment()))
print("\n\n### HARDENED deployment (defenses declared) ###\n")
print(m.report(m.hardened_deployment()))
