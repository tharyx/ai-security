import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tmcode  # noqa: E402

model = tmcode.build_model(HERE / "fixtures" / "shop")
print(tmcode.report(model))
print()
print("```mermaid")
print(tmcode.mermaid(model))
print("```")
print()
print("gate exit code:", tmcode.gate(model))
