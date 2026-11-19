"""Demo: the docker-run policy generator, an unsafe policy refused, and the subprocess twin.

    .venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/05-docker-tool-sandbox/demo.py
"""

import os

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sandbox")

print("Generated command (never executed here):")
print("  " + " ".join(s.build_docker_args(s.SandboxPolicy(mounts=(("/srv/work/in", "/data", "ro"),)))))

bad = s.SandboxPolicy(network="bridge", user="root", privileged=True)
print("\nUnsafe policy problems:")
for p in s.validate_policy(bad):
    print("  -", p)

os.environ["DEMO_FAKE_SECRET_TOKEN"] = "FAKE-TOKEN-123"
code = "import os; print('secret visible:', os.environ.get('DEMO_FAKE_SECRET_TOKEN'))"
print("\nSubprocess twin, scrubbed env :", s.SubprocessSandbox().run_python(code).stdout.strip())
print("Subprocess twin, env passed   :", s.SubprocessSandbox(scrub_env=False).run_python(code).stdout.strip())
print("Runaway loop                  :", s.SubprocessSandbox(timeout_s=0.5).run_python("while True: pass"))
