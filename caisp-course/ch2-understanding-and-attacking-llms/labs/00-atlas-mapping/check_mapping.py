"""Grade your own mapping file:  python check_mapping.py [my_mapping.json]"""
import sys
from pathlib import Path

import atlas_mapper as M

path = Path(sys.argv[1]) if len(sys.argv) > 1 else M.HERE / "my_mapping.json"
mapping = M.load_mapping(path)
result = M.grade(mapping, M.load_mapping(M.HERE / "answer_key.json"))
print(f"Score: {result['score']}/{result['total']}")
for sid in result["wrong"]:
    print("  WRONG   ", sid, "->", mapping[sid], "| text:", M.all_steps()[sid][:70], "...")
for sid in result["bad_names"]:
    print("  BAD NAME", sid)
print("  not yet mapped:", len(result["missing"]))
