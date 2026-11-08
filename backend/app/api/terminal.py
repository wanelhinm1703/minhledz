"""Real Terminal execution engine supporting PowerShell, Linux command aliases,
real-time WebSocket streaming, and environment path injection for Nmap and Python tools.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import re
import shlex
import subprocess
import threading
import time
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

router = APIRouter(prefix="/terminal", tags=["terminal"])
ws_terminal_router = APIRouter(tags=["terminal_ws"])

root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent

# Maintain active working directory per session (default to workspace root)
CURRENT_CWD = root_dir

# Dangerous commands blacklist to prevent system destruction
BLOCKED_PATTERNS = [
    r"\bformat\b",
    r"\brmdir\s+/[sS]\s+/[qQ]\s+[cC]:",
    r"\bdel\s+/[fF]\s+/[sS]\s+/[qQ]\s+[cC]:\\windows",
    r"\bshutdown\b",
    r"\breboot\b",
    r":\(\)\s*\{",  # fork bomb
]


def get_terminal_env() -> dict:
    """Prepare complete execution environment with PYTHONPATH and tool PATHs."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root_dir)
    env["PYTHONUNBUFFERED"] = "1"
    nmap_dir = r"C:\Program Files (x86)\Nmap"
    if os.path.exists(nmap_dir):
        env["PATH"] = f"{nmap_dir};{env.get('PATH', '')}"
    return env


def translate_command(cmd: str, current_dir: pathlib.Path) -> tuple[str, Optional[pathlib.Path], bool]:
    """Translate Linux/Bash aliases to PowerShell and handle shell built-ins like cd."""
    trimmed = cmd.strip()

    # Built-in: cd
    if trimmed.startswith("cd ") or trimmed == "cd":
        parts = trimmed.split(maxsplit=1)
        if len(parts) == 1 or parts[1].strip() in ("~", ""):
            return "", root_dir, True
        target_path_str = parts[1].strip()
        if target_path_str == "..":
            new_dir = current_dir.parent
        else:
            new_dir = (current_dir / target_path_str).resolve()

        if new_dir.exists() and new_dir.is_dir():
            return f"Set-Location '{new_dir}'", new_dir, True
        else:
            raise FileNotFoundError(f"Directory not found: {target_path_str}")

    # Aliases translation
    cmd_lower = trimmed.lower()
    if cmd_lower in ("ls -la", "ls -l", "ll", "ls -a", "dir /a"):
        return "Get-ChildItem -Force | Format-Table Mode, Length, Name", current_dir, False
    elif cmd_lower == "ls":
        return "Get-ChildItem | Format-Table Mode, Length, Name", current_dir, False
    elif cmd_lower == "pwd":
        return "Get-Location", current_dir, False
    elif cmd_lower in ("ifconfig", "ip a", "ip addr"):
        return "ipconfig", current_dir, False
    elif cmd_lower.startswith("which "):
        bin_name = trimmed[6:].strip()
        return f"Get-Command {bin_name}", current_dir, False
    elif cmd_lower.startswith("rm -rf "):
        target = trimmed[7:].strip()
        return f"Remove-Item -Recurse -Force '{target}'", current_dir, False

    return trimmed, current_dir, False


def decode_output(raw: bytes) -> str:
    for enc in ["utf-8", "cp1252", "latin1"]:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace")


class ExecuteCommandRequest(BaseModel):
    command: str
    target_id: Optional[str] = None
    timeout_seconds: Optional[int] = 180


class ExecuteCommandResponse(BaseModel):
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    status: str
    cwd: str


@router.get("/presets")
def get_command_presets(target: Optional[str] = "192.168.100.153"):
    """Return recommended reconnaissance commands tailored to target."""
    clean_target = target.replace("http://", "").replace("https://", "").replace("/", "") if target else "127.0.0.1"
    host_only = clean_target.split(":")[0]

    return {
        "target": target,
        "presets": [
            {
                "id": "pipeline_full",
                "label": f"🚀 Full Pipeline ({host_only})",
                "command": f"python toolkit/scripts/pipeline_runner.py --target {host_only}",
                "description": "Chạy toàn bộ quy trình: Naabu -> Nmap -> HTTPx -> Nuclei -> Manifest",
            },
            {
                "id": "nmap_fast",
                "label": f"🔍 Nmap Scan ({host_only})",
                "command": f"python toolkit/scripts/run_nmap.py --target {host_only} --output-dir toolkit/03-network/scans/target-{host_only}/nmap",
                "description": "Quét dịch vụ & phiên bản bằng Nmap chính thức",
            },
            {
                "id": "naabu_fast",
                "label": f"⚡ Naabu Fast Port ({host_only})",
                "command": f"python toolkit/scripts/run_naabu.py --target {host_only} --output-dir toolkit/03-network/scans/target-{host_only}/naabu",
                "description": "Quét nhanh các cổng mở với tốc độ cao",
            },
            {
                "id": "httpx_probe",
                "label": f"🌐 HTTPx Web Probe ({host_only})",
                "command": f"python toolkit/scripts/run_httpx.py --target http://{host_only} --output-dir toolkit/04-web/scans/target-{host_only}/httpx",
                "description": "Thăm dò tiêu đề trang và công nghệ Web",
            },
            {
                "id": "whatweb_probe",
                "label": f"🔍 WhatWeb Fingerprint ({host_only})",
                "command": f"python toolkit/scripts/run_whatweb.py --url http://{host_only} --output-dir toolkit/04-web/scans/target-{host_only}/whatweb",
                "description": "Nhận diện công nghệ web, CMS và phiên bản máy chủ",
            },
            {
                "id": "nikto_check",
                "label": f"🛡️ Nikto Web Audit ({host_only})",
                "command": f"python toolkit/scripts/run_nikto.py --url http://{host_only} --output-dir toolkit/04-web/scans/target-{host_only}/nikto",
                "description": "Kiểm tra cấu hình bảo mật và header web server",
            },
            {
                "id": "masscan_discovery",
                "label": f"⚡ Masscan Port Scan ({host_only})",
                "command": f"python toolkit/scripts/run_masscan.py --host {host_only} --output-dir toolkit/03-network/scans/target-{host_only}/masscan",
                "description": "Quét mở cổng diện rộng tốc độ cao",
            },
            {
                "id": "enum4linux_smb",
                "label": f"📁 enum4linux SMB ({host_only})",
                "command": f"python toolkit/scripts/run_service_enum.py --tool enum4linux --host {host_only} --output-dir toolkit/06-service-enum/scans/target-{host_only}/enum4linux",
                "description": "Thu thập thông tin user và share qua giao thức SMB",
            },
            {
                "id": "ping_check",
                "label": f"📡 Ping Probe ({host_only})",
                "command": f"ping -n 4 {host_only}",
                "description": "Kiểm tra độ trễ và khả năng kết nối tới mục tiêu",
            },
        ],
    }


@router.post("/execute", response_model=ExecuteCommandResponse)
async def execute_command(req: ExecuteCommandRequest):
    """Execute a CLI command inside workspace with full PowerShell environment."""
    global CURRENT_CWD
    cmd = req.command.strip()
    if not cmd:
        raise HTTPException(status_code=400, detail="Command cannot be empty.")

    # Guardrail check
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            raise HTTPException(
                status_code=403,
                detail=f"Guardrail Refusal: Command contains restricted operation ('{pattern}').",
            )

    # Handle clear screen
    if cmd.lower() in ("clear", "cls"):
        return ExecuteCommandResponse(
            command=cmd,
            stdout="",
            stderr="",
            exit_code=0,
            duration_seconds=0.0,
            status="clear",
            cwd=str(CURRENT_CWD),
        )

    # Translate command & handle cd
    try:
        exec_cmd, new_dir, is_cd = translate_command(cmd, CURRENT_CWD)
        if is_cd:
            CURRENT_CWD = new_dir
            return ExecuteCommandResponse(
                command=cmd,
                stdout=f"Changed directory to: {CURRENT_CWD}",
                stderr="",
                exit_code=0,
                duration_seconds=0.01,
                status="completed",
                cwd=str(CURRENT_CWD),
            )
    except FileNotFoundError as fnf:
        return ExecuteCommandResponse(
            command=cmd,
            stdout="",
            stderr=str(fnf),
            exit_code=1,
            duration_seconds=0.01,
            status="failed",
            cwd=str(CURRENT_CWD),
        )

    start_time = time.time()
    env = get_terminal_env()

    try:
        # Wrap execution in PowerShell with UTF-8 encoding
        ps_command = f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {exec_cmd}"

        def run_sync():
            return subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"& {{ {ps_command} }}",
                ],
                capture_output=True,
                cwd=str(CURRENT_CWD),
                env=env,
                timeout=float(req.timeout_seconds or 180),
            )

        res = await asyncio.to_thread(run_sync)
        duration = round(time.time() - start_time, 2)
        stdout_str = decode_output(res.stdout)
        stderr_str = decode_output(res.stderr)
        exit_code = res.returncode

        return ExecuteCommandResponse(
            command=cmd,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            duration_seconds=duration,
            status="completed" if exit_code == 0 else "error",
            cwd=str(CURRENT_CWD),
        )

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail=f"Command execution timed out after {req.timeout_seconds} seconds.",
        )
    except HTTPException:
        raise
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        return ExecuteCommandResponse(
            command=cmd,
            stdout="",
            stderr=str(e),
            exit_code=1,
            duration_seconds=duration,
            status="failed",
            cwd=str(CURRENT_CWD),
        )


# WebSocket Terminal streaming endpoint
@ws_terminal_router.websocket("/ws/terminal")
async def terminal_websocket(websocket: WebSocket):
    global CURRENT_CWD
    await websocket.accept()
    active_process: Optional[subprocess.Popen] = None
    exec_task: Optional[asyncio.Task] = None
    loop = asyncio.get_running_loop()

    async def run_command_stream(exec_cmd: str, raw_cmd: str):
        nonlocal active_process
        start_time = time.time()
        env = get_terminal_env()
        ps_command = f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {exec_cmd}"
        queue: asyncio.Queue[Optional[tuple[str, str]]] = asyncio.Queue()

        try:
            active_process = subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"& {{ {ps_command} }}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(CURRENT_CWD),
                env=env,
                bufsize=1,
            )

            def reader(pipe, stream_name):
                try:
                    for line in iter(pipe.readline, b""):
                        text = decode_output(line).rstrip("\r\n")
                        loop.call_soon_threadsafe(queue.put_nowait, (stream_name, text))
                except Exception:
                    pass
                finally:
                    try:
                        pipe.close()
                    except Exception:
                        pass

            t1 = threading.Thread(target=reader, args=(active_process.stdout, "stdout"), daemon=True)
            t2 = threading.Thread(target=reader, args=(active_process.stderr, "stderr"), daemon=True)
            t1.start()
            t2.start()

            async def monitor_exit():
                if active_process:
                    await asyncio.to_thread(active_process.wait)
                await asyncio.to_thread(t1.join)
                await asyncio.to_thread(t2.join)
                await queue.put(None)

            asyncio.create_task(monitor_exit())

            while True:
                item = await queue.get()
                if item is None:
                    break
                stream_type, text = item
                await websocket.send_json({"type": stream_type, "data": text})

            duration = round(time.time() - start_time, 2)
            exit_code = active_process.returncode if active_process and active_process.returncode is not None else 0
            await websocket.send_json({
                "type": "exit",
                "code": exit_code,
                "duration": duration,
                "cwd": str(CURRENT_CWD),
            })
        except asyncio.CancelledError:
            if active_process and active_process.poll() is None:
                try:
                    active_process.kill()
                except Exception:
                    pass
            raise
        except Exception as err:
            await websocket.send_json({"type": "stderr", "data": str(err)})
            await websocket.send_json({"type": "exit", "code": 1, "duration": 0.0, "cwd": str(CURRENT_CWD)})
        finally:
            active_process = None

    try:
        # Send initial connection info
        await websocket.send_json({
            "type": "ready",
            "cwd": str(CURRENT_CWD),
            "message": "AI-Pentest Copilot Terminal Engine Connected (PowerShell 5.1 / Python 3.14)",
        })

        while True:
            msg = await websocket.receive_json()
            msg_type = msg.get("type", "execute")

            if msg_type == "kill":
                if active_process and active_process.poll() is None:
                    try:
                        active_process.kill()
                    except Exception:
                        pass
                if exec_task and not exec_task.done():
                    exec_task.cancel()
                await websocket.send_json({"type": "stderr", "data": "\n[!] Process terminated by user (SIGINT/Ctrl+C)"})
                await websocket.send_json({"type": "exit", "code": -1, "duration": 0.0, "cwd": str(CURRENT_CWD)})
                continue

            if msg_type == "execute":
                cmd = msg.get("command", "").strip()
                if not cmd:
                    continue

                if active_process and active_process.poll() is None:
                    await websocket.send_json({"type": "stderr", "data": "[!] Another process is already running. Please cancel or wait."})
                    continue

                # Guardrail check
                is_blocked = False
                for pattern in BLOCKED_PATTERNS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        await websocket.send_json({
                            "type": "stderr",
                            "data": f"[!] Guardrail Refusal: Command contains restricted dangerous operation ('{pattern}').",
                        })
                        await websocket.send_json({"type": "exit", "code": 1, "duration": 0.0, "cwd": str(CURRENT_CWD)})
                        is_blocked = True
                        break
                if is_blocked:
                    continue

                # Clear screen
                if cmd.lower() in ("clear", "cls"):
                    await websocket.send_json({"type": "clear"})
                    await websocket.send_json({"type": "exit", "code": 0, "duration": 0.0, "cwd": str(CURRENT_CWD)})
                    continue

                # Translate command & cd
                try:
                    exec_cmd, new_dir, is_cd = translate_command(cmd, CURRENT_CWD)
                    if is_cd:
                        CURRENT_CWD = new_dir
                        await websocket.send_json({"type": "stdout", "data": f"Changed directory to: {CURRENT_CWD}"})
                        await websocket.send_json({"type": "exit", "code": 0, "duration": 0.01, "cwd": str(CURRENT_CWD)})
                        continue
                except FileNotFoundError as fnf:
                    await websocket.send_json({"type": "stderr", "data": str(fnf)})
                    await websocket.send_json({"type": "exit", "code": 1, "duration": 0.01, "cwd": str(CURRENT_CWD)})
                    continue

                # Execute with real-time streaming
                exec_task = asyncio.create_task(run_command_stream(exec_cmd, cmd))

    except WebSocketDisconnect:
        if active_process and active_process.poll() is None:
            try:
                active_process.kill()
            except Exception:
                pass
        if exec_task and not exec_task.done():
            exec_task.cancel()
    except Exception:
        if active_process and active_process.poll() is None:
            try:
                active_process.kill()
            except Exception:
                pass
        if exec_task and not exec_task.done():
            exec_task.cancel()
