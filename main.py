from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
from pathlib import PurePosixPath
import os
import shlex
import re
from typing import Any, Dict, List
import json

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

class SkillRequest(BaseModel):
    skill: str

@app.post("/scan")
def scan_skill(req: SkillRequest):

    text = req.skill
    lower = text.lower()

    categories = []

    # ----------------------------
    # hardcoded_secret
    # ----------------------------

    secret_patterns = [
        r"sk-[A-Za-z0-9]{20,}",
        r"AIza[0-9A-Za-z\-_]{20,}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"xox[baprs]-[A-Za-z0-9\-]+",
        r"https://hooks\.slack\.com/services/",
        r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----",
        r"api[_-]?key\s*:",
        r"secret\s*:",
        r"token\s*:"
    ]

    if any(re.search(p, text, re.IGNORECASE) for p in secret_patterns):
        if not re.search(r"\$\{?[A-Z0-9_]+\}?", text):
            categories.append("hardcoded_secret")

    # ----------------------------
    # prompt_injection
    # ----------------------------

    injection_patterns = [
        r"ignore .*user",
        r"ignore .*previous",
        r"ignore .*instruction",
        r"ignore .*stop",
        r"ignore .*cancel",
        r"silently exfiltrate",
        r"exfiltrate",
        r"send .*without.*user",
        r"do not tell the user",
        r"never inform the user",
        r"override user",
        r"bypass safety"
    ]

    if any(re.search(p, lower) for p in injection_patterns):
        categories.append("prompt_injection")

    # ----------------------------
    # excessive_permissions
    # ----------------------------

    excessive_patterns = [
        r"filesystem:\s*all",
        r"filesystem:\s*write",
        r"network:\s*all",
        r"egress:\s*all",
        r"allow.*all domains",
        r"read.*entire filesystem",
        r"write.*entire filesystem"
    ]

    if any(re.search(p, lower) for p in excessive_patterns):
        categories.append("excessive_permissions")

    # ----------------------------
    # unclear_provenance
    # ----------------------------

    has_author = re.search(r"^author\s*:", lower, re.MULTILINE)
    has_version = re.search(r"^version\s*:", lower, re.MULTILINE)
    has_changelog = re.search(r"^changelog\s*:", lower, re.MULTILINE)

    if not (has_author and has_version and has_changelog):
        categories.append("unclear_provenance")

    rewrite_patterns = [
        r"update version silently",
        r"rewrite version",
        r"change version.*without",
        r"modify metadata.*without"
    ]

    if any(re.search(p, lower) for p in rewrite_patterns):
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {
        "categories": sorted(list(set(categories)))
    }


class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int


class RunRequest(BaseModel):
    budget_tokens: int
    steps: List[Step]

def normalize_string(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def canonicalize(value):
    if isinstance(value, dict):
        result = {}
        for k in sorted(value.keys()):
            if k == "client_ts":
                continue
            result[k] = canonicalize(value[k])
        return result

    if isinstance(value, list):
        return [canonicalize(v) for v in value]

    if isinstance(value, str):
        return normalize_string(value)

    return value


def call_signature(step: Step):
    return (
        step.tool,
        json.dumps(canonicalize(step.args), sort_keys=True, separators=(",", ":")),
    )

@app.post("/run-guard")
def run_guard(req: RunRequest):

    total = sum(s.tokens_used for s in req.steps)

    if total >= req.budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) has reached the budget ({req.budget_tokens}).",
        }

    sigs = [call_signature(s) for s in req.steps]

    # Three identical calls in a row
    count = 1
    for i in range(1, len(sigs)):
        if sigs[i] == sigs[i - 1]:
            count += 1
            if count >= 3:
                return {
                    "decision": "halt",
                    "reason": "Repeated identical tool call detected.",
                }
        else:
            count = 1

    # Trailing A,B,A,B,A,B cycle
    if len(sigs) >= 6:
        tail = sigs[-6:]
        if (
            tail[0] == tail[2] == tail[4]
            and tail[1] == tail[3] == tail[5]
            and tail[0] != tail[1]
        ):
            return {
                "decision": "halt",
                "reason": "Detected alternating two-step loop.",
            }

    return {
        "decision": "continue",
        "reason": "Budget available and no loop detected.",
    }
