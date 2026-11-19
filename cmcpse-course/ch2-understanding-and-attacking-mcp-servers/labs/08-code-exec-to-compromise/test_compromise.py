"""Code execution to complete compromise, and the hardened version.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/08-code-exec-to-compromise -v
"""

import re
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "compromise")
rpc = c.rpc


def call(srv, tool, **args):
    return rpc.call_tool(srv.handle, tool, args)


# ----- the simulation itself is harmless -----
def test_the_lab_never_spawns_processes_or_evals():
    src = Path(c.__file__).read_text()
    assert not re.search(r"^\s*(import|from)\s+(subprocess|os)\b|os\.system|\beval\(|\bexec\(", src, re.M)


def test_shell_only_knows_a_few_pretend_commands():
    sh = c.FakeShell(c.VFS(), "svc")
    assert sh.run("echo hi; whoami") == "hi\nsvc"
    assert "not found" in sh.run("rm -rf /")


# ----- vulnerable server -----
def test_run_command_is_code_execution():
    assert call(c.vulnerable_server(), "run_command", command="echo hello") == "hello"


def test_run_command_reads_the_credentials_canary():
    assert c.CLOUD_KEY in call(c.vulnerable_server(), "run_command", command=f"cat {c.CREDS}")


def test_ping_host_command_injection():
    out = call(c.vulnerable_server(), "ping_host", host="127.0.0.1; cat " + c.CREDS)
    assert c.CLOUD_KEY in out


def test_prefix_bypass_reads_a_sibling_folder():
    assert "internal notes" in call(c.vulnerable_server(), "read_file", path="/srv/app/workspace-secrets/notes.txt")


def test_symlink_escape_reads_the_credentials():
    assert c.CLOUD_KEY in call(c.vulnerable_server(), "read_file", path=f"{c.ROOT}/shortcut")


def test_plain_traversal_is_normalised_and_rejected_even_by_the_vulnerable_check():
    with pytest.raises(RuntimeError, match="outside workspace"):
        call(c.vulnerable_server(), "read_file", path=f"{c.ROOT}/../../../home/svc/.cloud/credentials")


def test_full_chain_ends_with_an_attacker_admin_in_the_cloud():
    cloud = c.CloudAPI()
    report = c.attack(c.vulnerable_server(), cloud)
    assert report["key_stolen"] and report["compromised"] and cloud.admins == ["attacker-admin"]
    assert report["steps"][0].startswith("1 recon") and "created an admin user" in report["steps"][-1]


# ----- hardened server -----
def test_hardened_server_has_no_run_command():
    names = [t["name"] for t in rpc.request(c.hardened_server().handle, "tools/list")["result"]["tools"]]
    assert names == ["ping_host", "read_file"]


def test_hardened_ping_works_for_a_hostname_and_rejects_injection():
    s = c.hardened_server()
    assert "PING db.corp.example" in call(s, "ping_host", host="db.corp.example")
    for bad in ("127.0.0.1; cat " + c.CREDS, "a b", "$(id)", "-c9", ""):
        with pytest.raises(RuntimeError, match="invalid host"):
            call(s, "ping_host", host=bad)


@pytest.mark.parametrize("path", ["/srv/app/workspace-secrets/notes.txt", f"{c.ROOT}/shortcut",
                                  f"{c.ROOT}/../../../home/svc/.cloud/credentials", c.CREDS])
def test_hardened_read_file_blocks_every_escape(path):
    with pytest.raises(RuntimeError, match="outside workspace"):
        call(c.hardened_server(), "read_file", path=path)


def test_hardened_read_file_still_serves_workspace_files():
    assert call(c.hardened_server(), "read_file", path=f"{c.ROOT}/readme.txt") == "Project readme."


def test_least_privilege_user_still_cannot_read_credentials_if_the_path_check_is_buggy():
    s = c.hardened_server(contain_paths=False)
    for path in (f"{c.ROOT}/shortcut", c.CREDS):
        with pytest.raises(RuntimeError, match="cannot read"):
            call(s, "read_file", path=path)


def test_full_chain_fails_against_the_hardened_server():
    cloud = c.CloudAPI()
    report = c.attack(c.hardened_server(), cloud)
    assert not report["key_stolen"] and not report["compromised"] and cloud.admins == []


def test_a_scoped_read_only_key_limits_the_blast_radius_even_if_it_leaks():
    cloud = c.CloudAPI()
    ro = cloud.issue_key({"list_buckets"})
    assert cloud.request("list_buckets", ro)
    with pytest.raises(PermissionError):
        cloud.request("create_admin", ro, name="x")
    assert not cloud.compromised
