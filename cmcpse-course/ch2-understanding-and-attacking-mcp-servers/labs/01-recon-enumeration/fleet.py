"""A simulated network of fake MCP endpoints: one sloppy fleet and one hardened fleet.

Addresses use the reserved ``.example`` domain. Nothing here opens a socket (see
``http_transport.py`` for the optional localhost-only HTTP variant).
"""

from __future__ import annotations

from aisec_lab import load_lab_module, make_canary

rpc = load_lab_module(__file__, "rpc")

ENV_CANARY = make_canary("CANARY-DBPASS")
FAKE_FILES = {"/srv/app/readme.txt": "Welcome.", "/srv/app/.env": f"DB_PASSWORD={ENV_CANARY}"}
DEBUG_INFO = f"trace: /srv/app/handlers.py line 88; env DB_PASSWORD={ENV_CANARY}"


def _read_file(path: str) -> str:
    return FAKE_FILES[path]  # a missing file raises KeyError: the verbose server leaks details


def _run_shell(command: str) -> str:
    return f"(pretend output of: {command})"  # never executes anything


def _add_note(text: str) -> str:
    return "saved"


def _get_customer(id: int) -> str:
    return f"customer {id}"


def vulnerable_fleet() -> dict[str, "rpc.Server"]:
    S, T = rpc.Server, rpc.Tool
    return {
        "files.corp.example:8001": S(
            "file-helper", "0.3.0",
            [T("read_file", "Read any file on the server.", rpc.schema(path={"type": "string"}), _read_file),
             T("run_shell", "Run any shell command and return the output.", rpc.schema(command={"type": "string"}), _run_shell)],
            resources={"file:///srv/app/.env": FAKE_FILES["/srv/app/.env"]},
            prompts={"explain_error": "Explain this error to the user."},
            verbose_errors=True, debug_info=DEBUG_INFO),
        "notes.corp.example:8002": S(
            "notes-mcp", "1.1.0",
            [T("add_note", "Add a note.", rpc.schema(text={"type": "string", "maxLength": 2000}), _add_note)],
            prompts={"summarize_notes": "Summarize the notes."}),
        "crm.corp.example:8003": S(
            "crm-mcp", "2.0.0",
            [T("get_customer", "Get one customer by numeric id.",
               rpc.schema(id={"type": "integer", "minimum": 1, "maximum": 9999}), _get_customer)],
            token="crm-secret-token"),
    }


def hardened_fleet() -> dict[str, "rpc.Server"]:
    S, T = rpc.Server, rpc.Tool
    path_schema = {"type": "string", "pattern": r"^[\w./-]{1,100}$", "maxLength": 100}
    return {
        "files.corp.example:8001": S(
            "file-helper", "0.4.0",
            [T("read_file", "Read a text file inside the project folder.", rpc.schema(path=path_schema), _read_file)],
            token="files-secret-token"),
        "notes.corp.example:8002": S(
            "notes-mcp", "1.1.1",
            [T("add_note", "Add a note.", rpc.schema(text={"type": "string", "maxLength": 2000}), _add_note)],
            token="notes-secret-token"),
        "crm.corp.example:8003": S(
            "crm-mcp", "2.0.0",
            [T("get_customer", "Get one customer by numeric id.",
               rpc.schema(id={"type": "integer", "minimum": 1, "maximum": 9999}), _get_customer)],
            token="crm-secret-token"),
    }
