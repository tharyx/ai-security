"""A2A-style message exchange between two local agents (Chapter 7, lab 2).

"A2A-style" means: this is a SIMPLIFIED teaching model of the Agent2Agent protocol ideas, not the
official SDK and not a conformance-tested implementation. Real A2A v1.0 defines its own exact field
names, method names, transports and auth declarations: check the specification at a2a-protocol.org
before building anything real. Concepts kept here:

  * Agent Card at a well-known URL: name, description, skills, endpoint URL, auth schemes
  * JSON-RPC 2.0 over HTTP (here: http.server bound to 127.0.0.1, ephemeral port; or in-process)
  * a task with lifecycle states: submitted -> working -> (input-required) -> completed | failed | canceled
  * messages made of parts, and artifacts produced by the task
Nothing here touches the internet.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

CARD_PATH = "/.well-known/agent-card.json"  # the exact path moved between spec versions: verify
RPC_PATH = "/rpc"

SUBMITTED, WORKING, INPUT_REQUIRED, COMPLETED, FAILED, CANCELED = (
    "submitted", "working", "input-required", "completed", "failed", "canceled")
TERMINAL = {COMPLETED, FAILED, CANCELED}
ALLOWED = {
    SUBMITTED: {WORKING, FAILED, CANCELED},
    WORKING: {INPUT_REQUIRED, COMPLETED, FAILED, CANCELED},
    INPUT_REQUIRED: {WORKING, FAILED, CANCELED},
}


class InputRequired(Exception):
    """Raised by a skill that needs more information from the caller."""


def text_part(text: str) -> dict:
    return {"kind": "text", "text": text}


def rpc_error(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


class A2AAgent:
    def __init__(self, name: str, description: str, skills: dict[str, Callable[[str], str]], url: str = ""):
        self.name, self.description, self.skills, self.url = name, description, skills, url
        self.tasks: dict[str, dict] = {}

    # --- capability discovery -------------------------------------------------------------
    def card(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": "1.0.0",
            "url": self.url,
            "skills": [{"id": s, "name": s, "description": (fn.__doc__ or "").strip()} for s, fn in self.skills.items()],
            "capabilities": {"streaming": False, "pushNotifications": False},
            # Auth schemes are DECLARED in the card; enforcing them is the server's job (see labs 3 and 7).
            "securitySchemes": {"none": {"type": "none"}},
        }

    # --- JSON-RPC dispatch -------------------------------------------------------------------
    def handle_rpc(self, req: dict) -> dict:
        rid = req.get("id") if isinstance(req, dict) else None
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
            return rpc_error(rid, -32600, "invalid request")
        method, params = req["method"], req.get("params") or {}
        try:
            if method == "message/send":
                return {"jsonrpc": "2.0", "id": rid, "result": self._send(params)}
            if method == "tasks/get":
                return {"jsonrpc": "2.0", "id": rid, "result": self._get(params)}
            if method == "tasks/cancel":
                return {"jsonrpc": "2.0", "id": rid, "result": self._cancel(params)}
        except KeyError as exc:
            return rpc_error(rid, -32001, f"task not found: {exc.args[0]}")
        except ValueError as exc:
            return rpc_error(rid, -32602, str(exc))
        return rpc_error(rid, -32601, f"method not found: {method}")

    def _set_state(self, task: dict, state: str) -> None:
        if state not in ALLOWED.get(task["status"]["state"], set()):
            raise ValueError(f"illegal transition {task['status']['state']} -> {state}")
        task["status"] = {"state": state}
        task["statusLog"].append(state)

    def _send(self, params: dict) -> dict:
        msg = params.get("message")
        if not isinstance(msg, dict) or not isinstance(msg.get("parts"), list) or not msg["parts"]:
            raise ValueError("message.parts is required")
        task_id = msg.get("taskId")
        text = " ".join(p.get("text", "") for p in msg["parts"] if p.get("kind") == "text")
        if task_id:  # follow-up for a task waiting for input
            task = self.tasks[task_id]
            self._set_state(task, WORKING)
        else:
            skill = (msg.get("metadata") or {}).get("skill")
            if skill not in self.skills:
                raise ValueError(f"unknown skill: {skill}")
            task_id = uuid.uuid4().hex[:12]
            task = {"id": task_id, "skill": skill, "status": {"state": SUBMITTED}, "statusLog": [SUBMITTED],
                    "history": [], "artifacts": []}
            self.tasks[task_id] = task
            self._set_state(task, WORKING)
        task["history"].append(msg)
        try:
            out = self.skills[task["skill"]](text)
            task["artifacts"].append({"artifactId": uuid.uuid4().hex[:8], "name": f"{task['skill']}-result",
                                      "parts": [text_part(out)]})
            self._set_state(task, COMPLETED)
        except InputRequired as need:
            task["history"].append({"role": "agent", "parts": [text_part(str(need))]})
            self._set_state(task, INPUT_REQUIRED)
        except Exception as exc:  # a failing skill ends the task, not the server
            task["history"].append({"role": "agent", "parts": [text_part(f"error: {exc}")]})
            self._set_state(task, FAILED)
        return task

    def _get(self, params: dict) -> dict:
        return self.tasks[params["id"]]

    def _cancel(self, params: dict) -> dict:
        task = self.tasks[params["id"]]
        self._set_state(task, CANCELED)
        return task


# --- HTTP binding on 127.0.0.1 -------------------------------------------------------------------
def serve(agent: A2AAgent) -> tuple[ThreadingHTTPServer, str]:
    """Start the agent on 127.0.0.1 and an ephemeral port. Caller must shutdown()."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep test output clean
            pass

        def _json(self, code: int, body: dict) -> None:
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == CARD_PATH:
                self._json(200, agent.card())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path != RPC_PATH:
                return self._json(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(n))
            except json.JSONDecodeError:
                return self._json(400, rpc_error(None, -32700, "parse error"))
            self._json(200, agent.handle_rpc(req))

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    agent.url = url + RPC_PATH
    return srv, url


class A2AClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.card: dict | None = None
        self._id = 0

    def discover(self) -> dict:
        with urllib.request.urlopen(self.base + CARD_PATH, timeout=5) as r:
            self.card = json.loads(r.read())
        return self.card

    def _rpc(self, method: str, params: dict) -> dict:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.base + RPC_PATH, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            resp = json.loads(r.read())
        if "error" in resp:
            raise RuntimeError(resp["error"]["message"])
        return resp["result"]

    def send(self, skill: str, text: str, task_id: str | None = None) -> dict:
        if self.card is None:
            self.discover()
        if skill not in {s["id"] for s in self.card["skills"]}:
            raise RuntimeError(f"agent does not advertise skill {skill}")
        msg = {"messageId": uuid.uuid4().hex, "role": "user", "parts": [text_part(text)], "metadata": {"skill": skill}}
        if task_id:
            msg["taskId"] = task_id
        return self._rpc("message/send", {"message": msg})

    def get(self, task_id: str) -> dict:
        return self._rpc("tasks/get", {"id": task_id})

    def cancel(self, task_id: str) -> dict:
        return self._rpc("tasks/cancel", {"id": task_id})

    def wait(self, task_id: str, timeout: float = 3.0) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            t = self.get(task_id)
            if t["status"]["state"] in TERMINAL | {INPUT_REQUIRED}:
                return t
            time.sleep(0.05)
        raise TimeoutError(task_id)


# --- the two example agents -------------------------------------------------------------------
def summarize(text: str) -> str:
    """Return the first sentence of the input."""
    if not text.strip():
        raise InputRequired("please provide text to summarize")
    return text.split(".")[0].strip() + "."


def shout(text: str) -> str:
    """Upper-case the input."""
    return text.upper()


def make_summarizer() -> A2AAgent:
    return A2AAgent("summarizer-agent", "Summarizes text (course demo)", {"summarize": summarize, "shout": shout})
