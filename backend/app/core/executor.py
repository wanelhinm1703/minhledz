"""AI-Pentest Copilot - Dual-Mode Execution Engine.
Supports executing security tools either:
1. Locally (native subprocess on host)
2. In Docker Sandbox (isolated container mounting project workspace)
3. Auto mode: chooses Local if binary exists on host, otherwise routes to Docker sandbox.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ExecutionMode(str, Enum):
    LOCAL = "local"
    DOCKER = "docker"
    AUTO = "auto"


class ExecutionBackend(str, Enum):
    LOCAL = "local"
    DOCKER = "docker"
    SIMULATED = "simulated"
    FAILED = "failed"


class ExecutionResult(BaseModel):
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    backend_used: ExecutionBackend
    error: str | None = None
    container_id: str | None = None


class ExecutionEngine:
    """Manages command dispatching across Local and Docker execution backends."""

    DEFAULT_DOCKER_IMAGE = "ai-pentest-tools:latest"

    def __init__(
        self,
        project_root: pathlib.Path | None = None,
        default_mode: ExecutionMode | None = None,
    ):
        self.project_root = (
            project_root or pathlib.Path(__file__).resolve().parent.parent.parent.parent
        )
        mode_env = os.getenv("EXECUTION_MODE", "auto").lower().strip()
        if mode_env == "local":
            self.mode = ExecutionMode.LOCAL
        elif mode_env == "docker":
            self.mode = ExecutionMode.DOCKER
        else:
            self.mode = default_mode or ExecutionMode.AUTO

        self._docker_available: bool | None = None

    def is_docker_available(self) -> bool:
        """Check if Docker CLI is installed and Docker daemon is responsive."""
        if self._docker_available is not None:
            return self._docker_available

        docker_bin = shutil.which("docker")
        if not docker_bin:
            self._docker_available = False
            return False

        try:
            res = subprocess.run(
                [docker_bin, "info"],
                capture_output=True,
                text=True,
                timeout=4,
            )
            self._docker_available = (res.returncode == 0)
        except Exception:
            self._docker_available = False

        return self._docker_available

    def is_docker_image_available(self, image_name: str) -> bool:
        """Check if a specific Docker image is present locally."""
        if not self.is_docker_available():
            return False
        try:
            res = subprocess.run(
                ["docker", "image", "inspect", image_name],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return res.returncode == 0
        except Exception:
            return False

    def host_to_container_path(self, path_str: str) -> str:
        """Convert a host filesystem path into a container workspace relative path."""
        p = pathlib.Path(path_str)
        try:
            rel = p.relative_to(self.project_root)
            return f"/workspace/{str(rel).replace(os.sep, '/')}"
        except ValueError:
            # Not under project root, return unchanged or sanitized
            return path_str.replace("\\", "/")

    def translate_cmd_for_container(self, cmd_args: list[str]) -> list[str]:
        """Translates host file path arguments into container path equivalents."""
        translated: list[str] = []
        root_str = str(self.project_root).lower()

        for arg in cmd_args:
            # Check if arg contains project root path
            if root_str in arg.lower() or (":" in arg and ("\\" in arg or "/" in arg)):
                translated.append(self.host_to_container_path(arg))
            else:
                translated.append(arg)
        return translated

    def run_local(
        self,
        cmd_args: list[str],
        timeout: int = 120,
        cwd: pathlib.Path | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute command natively on the host system."""
        start_time = time.time()
        run_cwd = cwd or self.project_root
        cmd_str = " ".join(cmd_args)

        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(run_cwd),
                env=env,
            )
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=res.returncode,
                stdout=res.stdout or "",
                stderr=res.stderr or "",
                duration_seconds=duration,
                backend_used=ExecutionBackend.LOCAL,
                error=res.stderr.strip() if res.returncode != 0 else None,
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=124,
                duration_seconds=duration,
                backend_used=ExecutionBackend.LOCAL,
                error=f"Command timed out after {timeout} seconds.",
            )
        except FileNotFoundError as e:
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=127,
                duration_seconds=duration,
                backend_used=ExecutionBackend.FAILED,
                error=f"Binary not found locally: {e}",
            )
        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=1,
                duration_seconds=duration,
                backend_used=ExecutionBackend.FAILED,
                error=str(e),
            )

    def run_docker(
        self,
        cmd_args: list[str],
        docker_image: str | None = None,
        timeout: int = 180,
        network: str = "bridge",
        extra_mounts: list[str] | None = None,
    ) -> ExecutionResult:
        """Execute command inside an isolated Docker sandbox container."""
        start_time = time.time()
        image = docker_image or self.DEFAULT_DOCKER_IMAGE

        if not self.is_docker_available():
            duration = time.time() - start_time
            return ExecutionResult(
                command=" ".join(cmd_args),
                exit_code=127,
                duration_seconds=duration,
                backend_used=ExecutionBackend.FAILED,
                error="Docker daemon is not reachable or Docker CLI is not installed.",
            )

        container_cmd = self.translate_cmd_for_container(cmd_args)
        workspace_mount = f"{str(self.project_root)}:/workspace"

        docker_args = [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "-v",
            workspace_mount,
            "-w",
            "/workspace",
        ]

        if extra_mounts:
            for m in extra_mounts:
                docker_args.extend(["-v", m])

        docker_args.append(image)
        docker_args.extend(container_cmd)

        cmd_str = " ".join(docker_args)

        try:
            res = subprocess.run(
                docker_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=res.returncode,
                stdout=res.stdout or "",
                stderr=res.stderr or "",
                duration_seconds=duration,
                backend_used=ExecutionBackend.DOCKER,
                error=res.stderr.strip() if res.returncode != 0 else None,
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=124,
                duration_seconds=duration,
                backend_used=ExecutionBackend.DOCKER,
                error=f"Docker container execution timed out after {timeout} seconds.",
            )
        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                command=cmd_str,
                exit_code=1,
                duration_seconds=duration,
                backend_used=ExecutionBackend.FAILED,
                error=str(e),
            )

    def execute(
        self,
        cmd_args: list[str],
        tool_id: str | None = None,
        docker_image: str | None = None,
        local_binary_path: str | None = None,
        timeout: int = 120,
        preferred_mode: ExecutionMode | None = None,
    ) -> ExecutionResult:
        """
        Main entry point for tool execution.
        Routes according to configured or preferred execution mode.
        """
        mode = preferred_mode or self.mode
        binary_name = cmd_args[0] if cmd_args else ""

        # Determine if local binary is available
        local_available = bool(local_binary_path and os.path.exists(local_binary_path))
        if not local_available and binary_name:
            local_available = bool(shutil.which(binary_name))

        if mode == ExecutionMode.LOCAL:
            if local_available:
                target_cmd = cmd_args.copy()
                if local_binary_path:
                    target_cmd[0] = local_binary_path
                return self.run_local(target_cmd, timeout=timeout)
            return ExecutionResult(
                command=" ".join(cmd_args),
                exit_code=127,
                backend_used=ExecutionBackend.FAILED,
                error=f"Local execution requested, but binary '{binary_name}' is not installed.",
            )

        if mode == ExecutionMode.DOCKER:
            return self.run_docker(cmd_args, docker_image=docker_image, timeout=timeout)

        # AUTO Mode
        if local_available:
            target_cmd = cmd_args.copy()
            if local_binary_path:
                target_cmd[0] = local_binary_path
            return self.run_local(target_cmd, timeout=timeout)

        # Fallback to Docker if Docker is active
        if self.is_docker_available():
            return self.run_docker(cmd_args, docker_image=docker_image, timeout=timeout)

        # Neither is available -> fail gracefully with diagnostic error
        return ExecutionResult(
            command=" ".join(cmd_args),
            exit_code=127,
            backend_used=ExecutionBackend.FAILED,
            error=(
                f"Binary '{binary_name}' is not installed locally, and Docker daemon is not available "
                f"to execute via container sandbox."
            ),
        )


execution_engine = ExecutionEngine()
