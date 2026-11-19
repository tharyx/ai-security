import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import lifecycle as lc

c = lc.run("web", "nginx:1.27")
print("docker run   ->", c.ps_line())
c.do("pause");   print("docker pause ->", c.ps_line())
c.do("unpause"); c.do("stop"); print("docker stop  ->", c.ps_line())
try:
    c.do("pause")
except lc.LifecycleError as e:
    print("error        ->", e)
c.do("rm");      print("docker rm    ->", c.state, "| history:", " > ".join(c.history))
print()
for task, cmd in list(lc.COMMAND_FOR_TASK.items())[:4]:
    print(f"{task:<45} {cmd}")
