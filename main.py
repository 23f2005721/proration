from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
from pathlib import PurePosixPath
import os
import shlex

app = FastAPI()


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: str


@app.get("/")
def home():
    return {"status": "running"}


@app.post("/charge")
def calculate(req: ProrationRequest):

    diff = req.new_price - req.old_price

    if req.spec == "v1":
        divisor = 30

    elif req.spec == "v2":
        divisor = req.days_in_actual_month

    else:
        return {"error": "Invalid spec"}

    charge = diff * (req.days_remaining / divisor)

    return {"charge": charge}


WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET = "/home/agent/service-account.json"
WRITE_ROOT = "/workspace/output"
ALLOWED_HOSTS = {"pypi.org", "huggingface.co"}


class ToolCall(BaseModel):
    tool: str

    command: Optional[str] = None

    path: Optional[str] = None
    content: Optional[str] = None

    method: Optional[str] = None
    url: Optional[str] = None


def normalize_path(path: str) -> str:
    path = path.replace("$HOME", HOME)
    path = path.replace("${HOME}", HOME)

    if path.startswith("~/"):
        path = HOME + path[1:]

    if not path.startswith("/"):
        path = os.path.join(WORKSPACE, path)

    return str(PurePosixPath(path))


@app.post("/check")
def guard(req: ToolCall):

    # HTTP Request Policy
    if req.tool == "http_request":
        host = urlparse(req.url).hostname or ""

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Host allowed"
            }

        return {
            "decision": "block",
            "reason": "Host not allowed"
        }

    # Write File Policy
    if req.tool == "write_file":
        p = normalize_path(req.path)

        if p == WRITE_ROOT or p.startswith(WRITE_ROOT + "/"):
            return {
                "decision": "allow",
                "reason": "Write allowed"
            }

        return {
            "decision": "block",
            "reason": "Write outside output directory"
        }

    # Bash Policy
    if req.tool == "bash":

        expanded = (
            req.command
            .replace("$HOME", HOME)
            .replace("${HOME}", HOME)
            .replace("~", HOME)
        )

        if SECRET in expanded:
            return {
                "decision": "block",
                "reason": "Secret file access blocked"
            }

        try:
            for token in shlex.split(expanded):
                if token.startswith("-"):
                    continue

                p = normalize_path(token)

                if p == SECRET:
                    return {
                        "decision": "block",
                        "reason": "Secret file access blocked"
                    }

        except Exception:
            pass

        return {
            "decision": "allow",
            "reason": "Command allowed"
        }

    return {
        "decision": "block",
        "reason": "Unknown tool"
    }
    }
