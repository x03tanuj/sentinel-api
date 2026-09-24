"""Pytest configuration and session-scoped fixtures for SentinelAPI tests."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Generator

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TARGET_API_DIR = REPO_ROOT / "target_api"


def _find_free_port() -> int:
    """Find and return an available ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return int(port)


def _wait_for_server(url: str, timeout: float = 15.0) -> bool:
    """Poll health endpoint until server responds with 200 OK or timeout expires."""
    start_time = time.monotonic()
    health_url = f"{url.rstrip('/')}/health"
    while time.monotonic() - start_time < timeout:
        try:
            resp = httpx.get(health_url, timeout=1.0)
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


@pytest.fixture(scope="session")
def target_servers() -> Generator[dict[str, str], None, None]:
    """Start isolated background uvicorn servers for vulnerable and secure target instances.

    Runs target_api in child subprocesses using sys.executable to prevent Python module namespace collisions
    between backend/app and target_api/app.
    """
    port_vuln = _find_free_port()
    port_sec = _find_free_port()

    env_base = dict(os.environ)
    env_base["JWT_SECRET"] = "test-secret-key-1234567890"
    env_base["ALLOWED_HOSTS"] = '["localhost", "127.0.0.1"]'

    env_vuln = dict(env_base)
    env_vuln["SECURE"] = "false"

    env_sec = dict(env_base)
    env_sec["SECURE"] = "true"

    cmd_vuln = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--app-dir",
        str(TARGET_API_DIR),
        "--host",
        "127.0.0.1",
        "--port",
        str(port_vuln),
    ]

    cmd_sec = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--app-dir",
        str(TARGET_API_DIR),
        "--host",
        "127.0.0.1",
        "--port",
        str(port_sec),
    ]

    proc_vuln = subprocess.Popen(cmd_vuln, env=env_vuln, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc_sec = subprocess.Popen(cmd_sec, env=env_sec, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    url_vuln = f"http://127.0.0.1:{port_vuln}"
    url_sec = f"http://127.0.0.1:{port_sec}"

    vuln_ready = _wait_for_server(url_vuln)
    sec_ready = _wait_for_server(url_sec)

    if not vuln_ready or not sec_ready:
        proc_vuln.kill()
        proc_sec.kill()
        raise RuntimeError("Failed to start target_api uvicorn test servers within timeout.")

    try:
        yield {
            "vulnerable_url": url_vuln,
            "secure_url": url_sec,
        }
    finally:
        for p in (proc_vuln, proc_sec):
            p.terminate()
            try:
                p.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                p.kill()
