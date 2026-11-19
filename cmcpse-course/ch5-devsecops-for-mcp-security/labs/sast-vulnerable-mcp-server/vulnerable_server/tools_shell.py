"""Shell tools. DELIBERATELY VULNERABLE: user text is pasted into a shell command line."""

import os
import subprocess


def ping_host(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


def archive_logs(name: str) -> str:
    os.system(f"tar czf {name}.tgz logs")
    return f"archived {name}.tgz"
