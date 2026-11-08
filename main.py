import ast
import asyncio
import json
import os
import re
import shutil
import sys
import time
import zipfile
from abc import ABC, abstractmethod
from collections import deque
from pathlib import Path

import aiosqlite
import psutil
from cryptography.fernet import Fernet, InvalidToken
from telethon import Button, TelegramClient, events
from telethon.errors import SessionPasswordNeededError
from telethon.sessions import MemorySession, StringSession

from config import (
    ALLOWED_PIP_PACKAGES,
    API_HASH,
    API_ID,
    DB_PATH,
    HOSTER_BOT_TOKEN,
    LOGS_DIR,
    MAX_CRASH_RESTARTS,
    MAX_RAM_MB_PER_BOT,
    MAX_UPLOAD_BYTES,
    MAX_ZIP_EXTRACTED_BYTES,
    MAX_ZIP_FILES,
    SECRET_KEY_FILE,
    WORKSPACES_DIR,
    get_venv_python,
)


# =====================================================================
# SECTION 1: FERNET AES SESSION & TOKEN ENCRYPTION VAULT
# =====================================================================
class SessionVault:
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        if SECRET_KEY_FILE.exists():
            return SECRET_KEY_FILE.read_bytes().strip()
        key = Fernet.generate_key()
        SECRET_KEY_FILE.write_bytes(key)
        return key

    def encrypt(self, raw_value: str) -> str:
        if not raw_value:
            return ""
        return self.cipher.encrypt(raw_value.encode("utf-8")).decode("utf-8")

    def decrypt(self, token_str: str) -> str:
        if not token_str:
            return ""
        try:
            return self.cipher.decrypt(token_str.encode("utf-8")).decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Corrupted or invalid encryption key for session.") from e


vault = SessionVault()


# =====================================================================
# SECTION 2: ASYNC SQLITE DATABASE ENGINE
# =====================================================================
class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = str(db_path)

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    phone TEXT,
                    encrypted_session TEXT,
                    created_at REAL
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bot_instances (
                    instance_id TEXT PRIMARY KEY,
                    owner_id INTEGER,
                    bot_type TEXT,          -- 'userbot_script' or 'bot_script'
                    name TEXT,
                    workdir TEXT,
                    entrypoint TEXT,
                    encrypted_token TEXT,
                    status TEXT,            -- 'running', 'paused', 'stopped', 'crashed'
                    ram_limit_mb INTEGER DEFAULT 150,
                    created_at REAL
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS flowbots (
                    instance_id TEXT PRIMARY KEY,
                    owner_id INTEGER,
                    encrypted_token TEXT,
                    flow_json TEXT,
                    status TEXT
                )
            """)
            await conn.commit()

    async def save_user_session(self, user_id: int, phone: str, session_str: str):
        enc = vault.encrypt(session_str)
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO users (user_id, phone, encrypted_session, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    phone = excluded.phone,
                    encrypted_session = excluded.encrypted_session
            """, (user_id, phone, enc, time.time()))
            await conn.commit()

    async def get_user_session(self, user_id: int) -> str | None:
        async with aiosqlite.connect(self.db_path) as conn:
            async with conn.execute("SELECT encrypted_session FROM users WHERE user_id = ?", (user_id,)) as cur:
                row = await cur.fetchone()
                return vault.decrypt(row[0]) if row and row[0] else None

    async def register_instance(
        self, instance_id: str, owner_id: int, bot_type: str,
        name: str, workdir: str, entrypoint: str, raw_token: str = "", ram_limit_mb: int = MAX_RAM_MB_PER_BOT
    ):
        enc_token = vault.encrypt(raw_token) if raw_token else ""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO bot_instances
                (instance_id, owner_id, bot_type, name, workdir, entrypoint, encrypted_token, status, ram_limit_mb, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    workdir = excluded.workdir,
                    entrypoint = excluded.entrypoint,
                    encrypted_token = excluded.encrypted_token,
                    status = 'running'
            """, (instance_id, owner_id, bot_type, name, workdir, entrypoint, enc_token, ram_limit_mb, time.time()))
            await conn.commit()

    async def update_instance_status(self, instance_id: str, status: str):
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("UPDATE bot_instances SET status = ? WHERE instance_id = ?", (status, instance_id))
            await conn.commit()

    async def delete_instance(self, instance_id: str):
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("DELETE FROM bot_instances WHERE instance_id = ?", (instance_id,))
            await conn.commit()

    async def get_user_instances(self, owner_id: int) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM bot_instances WHERE owner_id = ? ORDER BY created_at DESC", (owner_id,)) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_instance(self, instance_id: str) -> dict | None:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM bot_instances WHERE instance_id = ?", (instance_id,)) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def get_all_active_instances(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM bot_instances WHERE status = 'running'") as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def save_flowbot(self, instance_id: str, owner_id: int, raw_token: str, flow_config: dict):
        enc_token = vault.encrypt(raw_token)
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO flowbots (instance_id, owner_id, encrypted_token, flow_json, status)
                VALUES (?, ?, ?, ?, 'running')
                ON CONFLICT(instance_id) DO UPDATE SET
                    flow_json = excluded.flow_json, status = 'running'
            """, (instance_id, owner_id, enc_token, json.dumps(flow_config)))
            await conn.commit()

    async def get_all_flowbots(self) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM flowbots WHERE status = 'running'") as cur:
                return [dict(r) for r in await cur.fetchall()]


db = Database()


# =====================================================================
# SECTION 3: AST MALWARE SCANNER & SAFE ZIP EXTRACTOR
# =====================================================================
BANNED_MODULES = {
    "subprocess", "shutil", "pty", "ctypes", "multiprocessing",
    "socketserver", "http.server", "xmlrpc", "webbrowser", "tkinter"
}
BANNED_BUILTINS = {"eval", "exec", "compile", "__import__"}
BANNED_OS_CALLS = {
    "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "execv", "execve",
    "execvp", "execvpe", "fork", "kill", "killpg", "remove", "unlink", "rmdir"
}


class SecurityViolation(Exception):
    pass


def scan_python_source(code_str: str, filename: str = "script.py") -> None:
    """Scans Python source code via AST before execution to block dangerous calls."""
    try:
        tree = ast.parse(code_str, filename=filename)
    except SyntaxError as e:
        raise SecurityViolation(f"Syntax error in {filename} (line {e.lineno}): {e.msg}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BANNED_MODULES:
                    raise SecurityViolation(f"[{filename}] Restricted import: '{root}'")

        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in BANNED_MODULES:
                raise SecurityViolation(f"[{filename}] Restricted module import: '{root}'")

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in BANNED_BUILTINS:
                raise SecurityViolation(f"[{filename}] Restricted builtin call: '{node.func.id}()'")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in BANNED_OS_CALLS:
                raise SecurityViolation(f"[{filename}] Restricted system call: '.{node.func.attr}()'")

        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "../" in node.value or "..\\" in node.value or ".secret.key" in node.value:
                raise SecurityViolation(f"[{filename}] Path traversal attempt blocked: '{node.value}'")


def safe_extract_and_scan_zip(zip_path: Path, extract_to: Path) -> str:
    """Extracts a .zip archive safely, scans all .py files, and returns the entrypoint."""
    total_size = 0
    file_count = 0
    target_root = extract_to.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            file_count += 1
            if file_count > MAX_ZIP_FILES:
                raise SecurityViolation(f"Zip archive exceeds max file count ({MAX_ZIP_FILES}).")

            total_size += info.file_size
            if total_size > MAX_ZIP_EXTRACTED_BYTES:
                raise SecurityViolation("Zip archive uncompressed size exceeds 35 MB limit.")

            dest_path = (target_root / info.filename).resolve()
            if os.path.commonpath([str(target_root), str(dest_path)]) != str(target_root):
                raise SecurityViolation(f"Zip-Slip path traversal blocked: {info.filename}")

        zf.extractall(target_root)

    zip_path.unlink(missing_ok=True)

    py_files = list(target_root.rglob("*.py"))
    if not py_files:
        raise SecurityViolation("No Python (.py) files found inside the uploaded archive.")

    for py_file in py_files:
        code = py_file.read_text(encoding="utf-8", errors="ignore")
        rel_name = str(py_file.relative_to(target_root))
        scan_python_source(code, filename=rel_name)

    for preferred in ("main.py", "bot.py", "app.py", "runner.py", "start.py"):
        candidate = target_root / preferred
        if candidate.exists():
            return str(candidate.relative_to(target_root))

    root_py = [p for p in py_files if p.parent == target_root]
    chosen = root_py[0] if root_py else py_files[0]
    return str(chosen.relative_to(target_root))


def parse_and_validate_requirements(req_file: Path) -> list[str]:
    """Validates requirements.txt against ALLOWED_PIP_PACKAGES."""
    if not req_file.exists():
        return []

    validated = []
    for raw_line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.split("#")[0].strip()
        if not line:
            continue
        if any(bad in line for bad in ("git+", "http:", "https:", "-e", "--", "/", "\\")):
            raise SecurityViolation(f"Custom URLs or flags not permitted in requirements.txt: '{line}'")

        pkg_match = re.match(r"^([A-Za-z0-9_\-]+)", line)
        if not pkg_match:
            raise SecurityViolation(f"Invalid requirement syntax: '{line}'")

        pkg_name = pkg_match.group(1).lower()
        if pkg_name not in ALLOWED_PIP_PACKAGES:
            raise SecurityViolation(f"Package '{pkg_name}' is not in ALLOWED_PIP_PACKAGES.")
        validated.append(line)

    return validated


# =====================================================================
# SECTION 4: SUBPROCESS HOSTING ENGINE & WATCHDOG MONITOR
# =====================================================================
class ManagedProcess:
    def __init__(
        self,
        instance_id: str,
        owner_id: int,
        workdir: Path,
        entrypoint: str,
        env_vars: dict[str, str],
        ram_limit_mb: int = MAX_RAM_MB_PER_BOT,
        auto_restart: bool = True,
    ):
        self.instance_id = instance_id
        self.owner_id = owner_id
        self.workdir = Path(workdir).resolve()
        self.entrypoint = entrypoint
        self.env_vars = env_vars
        self.ram_limit_mb = ram_limit_mb
        self.auto_restart = auto_restart

        self.process: asyncio.subprocess.Process | None = None
        self.ps_handle: psutil.Process | None = None
        self.status: str = "stopped"
        self.started_at: float = 0.0
        self.crash_count: int = 0
        self.manual_stop: bool = False

        self.log_buffer = deque(maxlen=250)
        self.log_file_path = LOGS_DIR / f"{self.instance_id}.log"

    def _append_log(self, line: str):
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {line}"
        self.log_buffer.append(formatted)
        with open(self.log_file_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(formatted + "\n")

    async def prepare_environment(self) -> str:
        req_path = self.workdir / "requirements.txt"
        packages = parse_and_validate_requirements(req_path)
        venv_dir = self.workdir / ".venv"

        if packages:
            self.status = "installing"
            self._append_log(f"📦 Validated requirements.txt: {', '.join(packages)}")
            if not venv_dir.exists():
                self._append_log("⚙️ Creating isolated virtual environment...")
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "venv", str(venv_dir),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
                )
                await proc.wait()

            py_bin = get_venv_python(venv_dir)
            self._append_log("📥 Installing dependencies via pip...")
            pip_proc = await asyncio.create_subprocess_exec(
                py_bin, "-m", "pip", "install", "--no-cache-dir", "--quiet", *packages,
                cwd=str(self.workdir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
            )
            stdout, _ = await pip_proc.communicate()
            if pip_proc.returncode != 0:
                err_out = stdout.decode("utf-8", errors="replace")
                self._append_log(f"❌ Pip install failed:\n{err_out}")
                raise RuntimeError(f"Pip install error: {err_out[:250]}")
            self._append_log("✅ Dependencies installed.")
            return py_bin

        return get_venv_python(venv_dir)

    async def start(self):
        if self.process and self.process.returncode is None:
            return

        self.manual_stop = False
        py_exec = await self.prepare_environment()

        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "HOME": str(self.workdir),
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
            "API_ID": str(API_ID),
            "API_HASH": API_HASH,
            **self.env_vars,
        }

        script_target = str(self.workdir / self.entrypoint)
        self._append_log(f"🚀 Launching {self.entrypoint}...")

        self.process = await asyncio.create_subprocess_exec(
            py_exec,
            script_target,
            cwd=str(self.workdir),
            env=safe_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.ps_handle = psutil.Process(self.process.pid)
        self.started_at = time.time()
        self.status = "running"
        await db.update_instance_status(self.instance_id, "running")
        asyncio.create_task(self._read_stdout())

    async def _read_stdout(self):
        if not self.process or not self.process.stdout:
            return
        try:
            async for raw_line in self.process.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if line:
                    self._append_log(line)
        except Exception as e:
            self._append_log(f"⚠️ Log stream closed: {e}")

    def pause(self) -> bool:
        if self.ps_handle and self.ps_handle.is_running() and self.status == "running":
            self.ps_handle.suspend()
            self.status = "paused"
            self._append_log("⏸️ Process paused by user.")
            return True
        return False

    def resume(self) -> bool:
        if self.ps_handle and self.ps_handle.is_running() and self.status == "paused":
            self.ps_handle.resume()
            self.status = "running"
            self._append_log("▶️ Process resumed by user.")
            return True
        return False

    async def stop(self):
        self.manual_stop = True
        self.status = "stopped"
        await db.update_instance_status(self.instance_id, "stopped")

        if not self.ps_handle or not self.ps_handle.is_running():
            return

        self._append_log("🛑 Stopping process tree...")
        try:
            children = self.ps_handle.children(recursive=True)
            for child in children:
                child.terminate()
            self.ps_handle.terminate()

            _, alive = psutil.wait_procs([self.ps_handle, *children], timeout=4.0)
            for p in alive:
                p.kill()
        except psutil.NoSuchProcess:
            pass
        self._append_log("🛑 Process terminated.")

    async def restart(self):
        self._append_log("🔄 Restarting instance...")
        await self.stop()
        await asyncio.sleep(1.0)
        self.crash_count = 0
        await self.start()

    def get_metrics(self) -> dict:
        if not self.ps_handle or not self.ps_handle.is_running() or self.status in ("stopped", "crashed"):
            return {"pid": None, "ram_mb": 0.0, "cpu_percent": 0.0, "uptime_sec": 0, "status": self.status}
        try:
            with self.ps_handle.oneshot():
                mem_bytes = self.ps_handle.memory_info().rss
                for child in self.ps_handle.children(recursive=True):
                    try:
                        mem_bytes += child.memory_info().rss
                    except psutil.NoSuchProcess:
                        pass
                return {
                    "pid": self.process.pid if self.process else None,
                    "ram_mb": round(mem_bytes / (1024 * 1024), 2),
                    "cpu_percent": round(self.ps_handle.cpu_percent(interval=0.05), 1),
                    "uptime_sec": int(time.time() - self.started_at),
                    "status": self.status,
                }
        except psutil.NoSuchProcess:
            return {"pid": None, "ram_mb": 0.0, "cpu_percent": 0.0, "uptime_sec": 0, "status": "stopped"}


class ProcessHostingEngine:
    def __init__(self):
        self.registry: dict[str, ManagedProcess] = {}
        self._watchdog_task: asyncio.Task | None = None

    def start_watchdog(self):
        if not self._watchdog_task:
            self._watchdog_task = asyncio.create_task(self._watchdog_loop())

    async def spawn_instance(
        self, instance_id: str, owner_id: int, workdir: Path,
        entrypoint: str, env_vars: dict, ram_limit_mb: int = MAX_RAM_MB_PER_BOT
    ) -> ManagedProcess:
        if instance_id in self.registry:
            await self.registry[instance_id].stop()

        managed = ManagedProcess(
            instance_id=instance_id,
            owner_id=owner_id,
            workdir=workdir,
            entrypoint=entrypoint,
            env_vars=env_vars,
            ram_limit_mb=ram_limit_mb,
        )
        self.registry[instance_id] = managed
        await managed.start()
        return managed

    async def purge_instance(self, instance_id: str):
        managed = self.registry.pop(instance_id, None)
        if managed:
            await managed.stop()
            shutil.rmtree(managed.workdir, ignore_errors=True)
            managed.log_file_path.unlink(missing_ok=True)
        await db.delete_instance(instance_id)

    async def _watchdog_loop(self):
        while True:
            await asyncio.sleep(5.0)
            for inst_id, managed in list(self.registry.items()):
                if managed.manual_stop or managed.status in ("stopped", "paused", "installing", "crashed"):
                    continue

                if managed.process and managed.process.returncode is not None:
                    code = managed.process.returncode
                    managed._append_log(f"⚠️ Process exited with code {code}.")
                    if managed.auto_restart and managed.crash_count < MAX_CRASH_RESTARTS:
                        managed.crash_count += 1
                        backoff = min(2 ** managed.crash_count, 30)
                        managed._append_log(
                            f"🔄 Watchdog auto-restart #{managed.crash_count}/{MAX_CRASH_RESTARTS} in {backoff}s..."
                        )
                        await asyncio.sleep(backoff)
                        await managed.start()
                    else:
                        managed.status = "crashed"
                        await db.update_instance_status(inst_id, "crashed")
                        managed._append_log("❌ Max crash restarts reached. Marked as CRASHED.")
                    continue

                metrics = managed.get_metrics()
                if metrics["ram_mb"] > managed.ram_limit_mb:
                    managed._append_log(
                        f"🚨 OOM Protection triggered: {metrics['ram_mb']} MB exceeds {managed.ram_limit_mb} MB limit."
                    )
                    await managed.stop()
                    managed.status = "crashed"
                    await db.update_instance_status(inst_id, "crashed")


process_engine = ProcessHostingEngine()


# =====================================================================
# SECTION 5: SELF-CONTAINED USERBOT TEMPLATE & FLOWBOT ENGINE
# =====================================================================
USERBOT_RUNNER_TEMPLATE = '''import ast
import importlib.util
import os
import sys
import time
from pathlib import Path
from telethon import TelegramClient, events
from telethon.sessions import StringSession

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
SESSION_STRING = os.environ["SESSION_STRING"]
PLUGINS_DIR = Path("./plugins")
PLUGINS_DIR.mkdir(exist_ok=True)

BANNED = {"subprocess", "shutil", "pty", "ctypes", "multiprocessing"}

def verify_plugin_ast(code_str: str, fname: str):
    tree = ast.parse(code_str, filename=fname)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in BANNED:
                    raise ValueError(f"Restricted import: {a.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in BANNED:
                raise ValueError(f"Restricted module: {node.module}")

client = TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH)
loaded_plugins = {}
START_TIME = time.time()

def load_plugin_file(py_path: Path) -> int:
    name = py_path.stem
    if name in loaded_plugins:
        unload_plugin(name)
    code = py_path.read_text(encoding="utf-8", errors="ignore")
    verify_plugin_ast(code, py_path.name)

    spec = importlib.util.spec_from_file_location(f"plugins.{name}", str(py_path))
    mod = importlib.util.module_from_spec(spec)
    registered = []

    def reg(ev):
        def dec(func):
            client.add_event_handler(func, ev)
            registered.append((func, ev))
            return func
        return dec

    mod.client = client
    mod.events = events
    mod.on_cmd = lambda pat: reg(events.NewMessage(outgoing=True, pattern=pat))
    mod.register = reg

    sys.modules[f"plugins.{name}"] = mod
    spec.loader.exec_module(mod)
    loaded_plugins[name] = registered
    return len(registered)

def unload_plugin(name: str) -> bool:
    handlers = loaded_plugins.pop(name, None)
    if not handlers:
        return False
    for func, ev in handlers:
        client.remove_event_handler(func, ev)
    sys.modules.pop(f"plugins.{name}", None)
    return True

@client.on(events.NewMessage(outgoing=True, pattern=r"^\\.ping$"))
async def cmd_ping(event):
    t0 = time.perf_counter()
    await event.edit("⚡ *Measuring...*")
    ms = round((time.perf_counter() - t0) * 1000, 2)
    uptime_m = int((time.time() - START_TIME) // 60)
    await event.edit(
        f"🔥 **Userbot Online!**\\n"
        f"⏱ **Latency:** `{ms} ms`\\n"
        f"⏳ **Uptime:** `{uptime_m} mins`\\n"
        f"🧩 **Plugins:** `{len(loaded_plugins)}`"
    )

@client.on(events.NewMessage(outgoing=True, pattern=r"^\\.install$"))
async def cmd_install(event):
    reply = await event.get_reply_message()
    if not reply or not reply.file or not reply.file.name.endswith(".py"):
        return await event.edit("⚠️ **Reply to a `.py` plugin file with `.install`**")
    await event.edit("🔍 *Scanning & hot-loading plugin...*")
    dest = PLUGINS_DIR / reply.file.name
    await reply.download_media(file=str(dest))
    try:
        cnt = load_plugin_file(dest)
        await event.edit(f"✅ **Plugin `{dest.stem}` Hot-Loaded!** (`{cnt}` handlers active)")
    except Exception as e:
        dest.unlink(missing_ok=True)
        await event.edit(f"🛡️ **Plugin Blocked / Failed:** `{e}`")

@client.on(events.NewMessage(outgoing=True, pattern=r"^\\.unload (\\w+)$"))
async def cmd_unload(event):
    name = event.pattern_match.group(1).strip()
    if unload_plugin(name):
        (PLUGINS_DIR / f"{name}.py").unlink(missing_ok=True)
        await event.edit(f"🗑️ **Plugin `{name}` unloaded and removed.**")
    else:
        await event.edit(f"❌ **Plugin `{name}` not found.**")

if __name__ == "__main__":
    for p in PLUGINS_DIR.glob("*.py"):
        try:
            load_plugin_file(p)
        except Exception as err:
            print(f"Failed loading {p.name}: {err}")
    print("Modular Userbot started and listening for commands (.ping, .install, .unload)...")
    client.start()
    client.run_until_disconnected()
'''


class BaseBotEngine(ABC):
    def __init__(self, instance_id: str, owner_id: int):
        self.instance_id = instance_id
        self.owner_id = owner_id

    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass


class FlowBotInstance(BaseBotEngine):
    def __init__(self, instance_id: str, owner_id: int, bot_token: str, flow_config: dict):
        super().__init__(instance_id, owner_id)
        self.bot_token = bot_token
        self.flow_config = flow_config
        self.client = TelegramClient(MemorySession(), API_ID, API_HASH)

    def _build_home_buttons(self):
        nodes = self.flow_config.get("nodes", {})
        btns = []
        for key, node in nodes.items():
            label = node.get("label", key.capitalize())
            btns.append([Button.inline(label, data=f"flow:{key}".encode())])
        return btns or None

    async def start(self):
        await self.client.start(bot_token=self.bot_token)

        @self.client.on(events.NewMessage(pattern=r"^/start$"))
        async def on_start(event):
            welcome = self.flow_config.get("welcome", "👋 Welcome! Choose an option:")
            await event.respond(welcome, buttons=self._build_home_buttons())

        @self.client.on(events.CallbackQuery(pattern=rb"^flow:(.+)"))
        async def on_flow_step(event):
            node_key = event.pattern_match.group(1).decode("utf-8")
            if node_key == "home":
                welcome = self.flow_config.get("welcome", "👋 Welcome! Choose an option:")
                return await event.edit(welcome, buttons=self._build_home_buttons())

            node = self.flow_config.get("nodes", {}).get(node_key)
            if not node:
                return await event.answer("Option not found.", alert=True)

            markup = [
                [Button.inline(btn[0], data=f"flow:{btn[1]}".encode()) for btn in row]
                for row in node.get("buttons", [[["🔙 Main Menu", "home"]]])
            ]
            await event.edit(node.get("text", "..."), buttons=markup)

    async def stop(self):
        await self.client.disconnect()


flowbot_registry: dict[str, FlowBotInstance] = {}


# =====================================================================
# SECTION 6: MASTER HOSTER BOT (OTP LOGIN, UPLOADER & CONTROLS)
# =====================================================================
hoster_client = TelegramClient(str(WORKSPACES_DIR / "master_hoster"), API_ID, API_HASH)
otp_login_states: dict[int, dict] = {}
pending_upload_mode: dict[int, dict] = {}


def instance_control_keyboard(instance_id: str) -> list[list[Button]]:
    return [
        [
            Button.inline("▶️ Start / Resume", data=f"ctl:resume:{instance_id}".encode()),
            Button.inline("⏸️ Pause", data=f"ctl:pause:{instance_id}".encode()),
        ],
        [
            Button.inline("🔄 Restart", data=f"ctl:restart:{instance_id}".encode()),
            Button.inline("🛑 Stop", data=f"ctl:stop:{instance_id}".encode()),
        ],
        [
            Button.inline("📜 Live Logs", data=f"ctl:logs:{instance_id}".encode()),
            Button.inline("📊 RAM / CPU", data=f"ctl:stats:{instance_id}".encode()),
        ],
        [
            Button.inline("🗑️ Delete Bot & Files", data=f"ctl:delete:{instance_id}".encode()),
        ],
    ]


@hoster_client.on(events.NewMessage(pattern=r"^/start$"))
async def start_dashboard(event):
    user_id = event.sender_id
    instances = await db.get_user_instances(user_id)
    has_session = bool(await db.get_user_session(user_id))

    buttons = [
        [Button.inline("🔐 1. Connect Userbot (OTP Login)", data=b"menu:login")],
        [
            Button.inline("⚡ Deploy Built-in Userbot", data=b"menu:deploy_template_ub"),
            Button.inline("📤 Host Custom Userbot (.py/.zip)", data=b"menu:upload_ub"),
        ],
        [
            Button.inline("🤖 Host Normal Bot (.py/.zip)", data=b"menu:upload_bot"),
            Button.inline("🔀 Create JSON Flowbot", data=b"menu:new_flow"),
        ],
        [Button.inline(f"🎛 My Hosted Bots ({len(instances)})", data=b"menu:my_bots")],
    ]
    await event.respond(
        "🚀 **Unified Telegram Bot & Userbot Hosting Platform**\n\n"
        f"👤 **User ID:** `{user_id}`\n"
        f"🔑 **Userbot Session:** `{'✅ Encrypted & Ready' if has_session else '❌ Not Linked'}`\n"
        f"⚙️ **Hosted Instances:** `{len(instances)}`\n\n"
        "Select an action below or upload a `.py` / `.zip` file:",
        buttons=buttons,
    )


@hoster_client.on(events.NewMessage(pattern=r"^/login (\+\d+)$"))
async def handle_login_phone(event):
    phone = event.pattern_match.group(1).strip()
    user_id = event.sender_id

    temp = TelegramClient(StringSession(), API_ID, API_HASH)
    await temp.connect()
    try:
        sent = await temp.send_code_request(phone)
        otp_login_states[user_id] = {
            "client": temp,
            "phone": phone,
            "hash": sent.phone_code_hash,
        }
        await event.respond(
            "📲 **Verification Code Sent!**\n"
            "Send `/otp 1 2 3 4 5` *(include spaces between digits so Telegram does not block the session)*."
        )
    except Exception as e:
        await temp.disconnect()
        await event.respond(f"❌ **Failed to request OTP:** `{e}`")


@hoster_client.on(events.NewMessage(pattern=r"^/otp (.+)$"))
async def handle_login_otp(event):
    user_id = event.sender_id
    state = otp_login_states.get(user_id)
    if not state:
        return await event.respond("⚠️ Start with `/login +91XXXXXXXXXX` first.")

    code = event.pattern_match.group(1).replace(" ", "").strip()
    temp: TelegramClient = state["client"]
    try:
        await temp.sign_in(phone=state["phone"], code=code, phone_code_hash=state["hash"])
    except SessionPasswordNeededError:
        return await event.respond("🔐 **Two-Step Verification (2FA) Enabled!**\nReply with `/2fa <your_password>`")
    except Exception as e:
        return await event.respond(f"❌ **OTP Verification Failed:** `{e}`")

    session_str = temp.session.save()
    await db.save_user_session(user_id, state["phone"], session_str)
    await temp.disconnect()
    otp_login_states.pop(user_id, None)
    await event.respond(
        "✅ **Userbot Session Encrypted & Stored!**\n"
        "You can now deploy the built-in Userbot or upload any `.py` / `.zip` script."
    )


@hoster_client.on(events.NewMessage(pattern=r"^/2fa (.+)$"))
async def handle_login_2fa(event):
    user_id = event.sender_id
    state = otp_login_states.get(user_id)
    if not state:
        return await event.respond("⚠️ No active login session.")

    password = event.pattern_match.group(1).strip()
    temp: TelegramClient = state["client"]
    try:
        await temp.sign_in(password=password)
        session_str = temp.session.save()
        await db.save_user_session(user_id, state["phone"], session_str)
        await temp.disconnect()
        otp_login_states.pop(user_id, None)
        await event.respond("✅ **2FA Verified & Userbot Session Encrypted!**")
    except Exception as e:
        await event.respond(f"❌ **2FA Error:** `{e}`")


@hoster_client.on(events.CallbackQuery(pattern=rb"^menu:(.+)"))
async def handle_menu_callbacks(event):
    user_id = event.sender_id
    action = event.pattern_match.group(1).decode("utf-8")

    if action == "login":
        await event.respond("📲 Send `/login +919876543210` with your country code to connect your Userbot.")

    elif action == "deploy_template_ub":
        session_str = await db.get_user_session(user_id)
        if not session_str:
            return await event.answer("Connect your Userbot first using /login!", alert=True)

        instance_id = f"ub_tpl_{user_id}"
        workdir = WORKSPACES_DIR / f"user_{user_id}" / instance_id
        workdir.mkdir(parents=True, exist_ok=True)

        runner_file = workdir / "runner.py"
        runner_file.write_text(USERBOT_RUNNER_TEMPLATE, encoding="utf-8")

        await db.register_instance(
            instance_id=instance_id,
            owner_id=user_id,
            bot_type="userbot_script",
            name="Modular Userbot",
            workdir=str(workdir),
            entrypoint="runner.py",
        )
        managed = await process_engine.spawn_instance(
            instance_id=instance_id,
            owner_id=user_id,
            workdir=workdir,
            entrypoint="runner.py",
            env_vars={"SESSION_STRING": session_str},
        )
        await event.respond(
            f"🔥 **Built-in Modular Userbot Deployed!**\n"
            f"🆔 **Instance:** `{instance_id}`\n"
            f"🔢 **PID:** `{managed.process.pid if managed.process else 'Starting'}`\n\n"
            f"💡 *Type `.ping` in any chat, or reply `.install` to any `.py` plugin file!*",
            buttons=instance_control_keyboard(instance_id),
        )

    elif action == "upload_ub":
        session_str = await db.get_user_session(user_id)
        if not session_str:
            return await event.answer("Connect your Userbot first using /login!", alert=True)
        pending_upload_mode[user_id] = {"mode": "userbot_script", "token": ""}
        await event.respond(
            "📤 **Ready for Userbot Script Upload!**\n"
            "Upload a `.py` file or `.zip` project archive.\n"
            "*(Your `SESSION_STRING`, `API_ID`, and `API_HASH` are injected automatically via `os.environ`)*."
        )

    elif action == "upload_bot":
        await event.respond(
            "🤖 **Host a Standard Bot Script**\n"
            "First, stage your BotFather token by sending:\n"
            "`/settoken 123456:ABC-DEF...`"
        )

    elif action == "new_flow":
        await event.respond(
            "🔀 **Create a Zero-Code JSON Flowbot**\n"
            "Send `/newflow <BOT_TOKEN>` to launch an interactive button-menu bot."
        )

    elif action == "my_bots":
        instances = await db.get_user_instances(user_id)
        if not instances:
            return await event.answer("You have no hosted bots yet.", alert=True)
        btns = [
            [Button.inline(f"⚙️ {inst['name']} ({inst['instance_id']})", data=f"ctl:view:{inst['instance_id']}".encode())]
            for inst in instances
        ]
        await event.respond("🎛 **Select an instance to control:**", buttons=btns)


@hoster_client.on(events.NewMessage(pattern=r"^/settoken (\d+:[A-Za-z0-9_\-]+)$"))
async def handle_set_bot_token(event):
    token = event.pattern_match.group(1).strip()
    pending_upload_mode[event.sender_id] = {"mode": "bot_script", "token": token}
    await event.respond(
        "✅ **Bot Token Staged!**\n"
        "Now **upload your `.py` script or `.zip` archive** to deploy it.\n"
        "*(Read `os.environ['BOT_TOKEN']`, `os.environ['API_ID']`, and `os.environ['API_HASH']` in your code)*."
    )


@hoster_client.on(events.NewMessage(func=lambda e: bool(e.file and e.file.name)))
async def handle_script_or_zip_upload(event):
    fname = event.file.name
    if not (fname.endswith(".py") or fname.endswith(".zip")):
        return

    user_id = event.sender_id
    if event.file.size > MAX_UPLOAD_BYTES:
        return await event.respond("❌ **File exceeds 15 MB upload limit.**")

    mode_info = pending_upload_mode.get(user_id, {"mode": "userbot_script", "token": ""})
    bot_type = mode_info["mode"]
    raw_token = mode_info.get("token", "")

    session_str = ""
    if bot_type == "userbot_script":
        session_str = await db.get_user_session(user_id)
        if not session_str:
            return await event.respond(
                "⚠️ Link your Userbot first (`/login +91...`) or stage a Bot token (`/settoken <token>`)."
            )

    status_msg = await event.respond(f"📥 **Downloading `{fname}` & initializing sandbox...**")

    clean_stem = "".join(c for c in Path(fname).stem if c.isalnum() or c in ("_", "-"))[:20]
    instance_id = f"{'ub' if bot_type == 'userbot_script' else 'bot'}_{user_id}_{clean_stem}"
    workdir = WORKSPACES_DIR / f"user_{user_id}" / instance_id

    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)

    downloaded_path = workdir / fname
    await event.download_media(file=str(downloaded_path))

    try:
        if fname.endswith(".zip"):
            await status_msg.edit("🔍 **Extracting `.zip` & scanning all `.py` files with AST security engine...**")
            entrypoint = safe_extract_and_scan_zip(downloaded_path, workdir)
        else:
            await status_msg.edit("🔍 **Running AST static security scan on `.py` file...**")
            code = downloaded_path.read_text(encoding="utf-8", errors="ignore")
            scan_python_source(code, filename=fname)
            entrypoint = fname

        await status_msg.edit(f"⚙️ **AST Verified! Entrypoint: `{entrypoint}`. Spawning isolated process...**")

        env_vars = {}
        if session_str:
            env_vars["SESSION_STRING"] = session_str
        if raw_token:
            env_vars["BOT_TOKEN"] = raw_token

        await db.register_instance(
            instance_id=instance_id,
            owner_id=user_id,
            bot_type=bot_type,
            name=clean_stem,
            workdir=str(workdir),
            entrypoint=entrypoint,
            raw_token=raw_token,
            ram_limit_mb=MAX_RAM_MB_PER_BOT,
        )

        managed = await process_engine.spawn_instance(
            instance_id=instance_id,
            owner_id=user_id,
            workdir=workdir,
            entrypoint=entrypoint,
            env_vars=env_vars,
        )
        pending_upload_mode.pop(user_id, None)

        metrics = managed.get_metrics()
        await status_msg.edit(
            f"✅ **Script Hosted & Running!**\n\n"
            f"🏷 **Instance ID:** `{instance_id}`\n"
            f"📂 **Entrypoint:** `{entrypoint}`\n"
            f"🔢 **PID:** `{metrics['pid']}`\n"
            f"🛡 **RAM Quota:** `{MAX_RAM_MB_PER_BOT} MB`",
            buttons=instance_control_keyboard(instance_id),
        )
    except SecurityViolation as sec_err:
        shutil.rmtree(workdir, ignore_errors=True)
        await status_msg.edit(f"🛡️ **Blocked by AST Security Scanner:**\n`{sec_err}`")
    except Exception as exc:
        await status_msg.edit(f"❌ **Deployment Error:**\n`{exc}`")


@hoster_client.on(events.CallbackQuery(pattern=rb"^ctl:(\w+):(.+)"))
async def handle_process_controls(event):
    action = event.pattern_match.group(1).decode("utf-8")
    instance_id = event.pattern_match.group(2).decode("utf-8")
    user_id = event.sender_id

    inst_record = await db.get_instance(instance_id)
    if not inst_record or inst_record["owner_id"] != user_id:
        return await event.answer("❌ Instance not found or access denied.", alert=True)

    managed = process_engine.registry.get(instance_id)

    if action == "view":
        metrics = (
            managed.get_metrics()
            if managed
            else {"status": inst_record["status"], "pid": None, "ram_mb": 0, "cpu_percent": 0}
        )
        return await event.edit(
            f"🎛 **Instance Manager: `{instance_id}`**\n"
            f"• **Status:** `{metrics['status'].upper()}`\n"
            f"• **Entrypoint:** `{inst_record['entrypoint']}`\n"
            f"• **PID:** `{metrics['pid']}`\n"
            f"• **RAM:** `{metrics['ram_mb']} / {inst_record['ram_limit_mb']} MB`\n"
            f"• **CPU:** `{metrics['cpu_percent']}%`",
            buttons=instance_control_keyboard(instance_id),
        )

    if action == "pause" and managed:
        ok = managed.pause()
        await event.answer("⏸️ Process paused!" if ok else "Process is not running.", alert=True)

    elif action == "resume":
        if managed and managed.status == "paused":
            managed.resume()
            await event.answer("▶️ Process resumed!", alert=True)
        elif managed:
            await managed.start()
            await event.answer("🚀 Process started!", alert=True)
        else:
            # Cold-spawn from SQLite if not yet in memory
            env_vars = {}
            if inst_record["bot_type"] == "userbot_script":
                sess = await db.get_user_session(user_id)
                if sess:
                    env_vars["SESSION_STRING"] = sess
            if inst_record["encrypted_token"]:
                env_vars["BOT_TOKEN"] = vault.decrypt(inst_record["encrypted_token"])
            managed = await process_engine.spawn_instance(
                instance_id=instance_id,
                owner_id=user_id,
                workdir=Path(inst_record["workdir"]),
                entrypoint=inst_record["entrypoint"],
                env_vars=env_vars,
                ram_limit_mb=inst_record["ram_limit_mb"],
            )
            await event.answer("🚀 Process cold-started!", alert=True)

    elif action == "restart" and managed:
        await event.answer("🔄 Restarting process...")
        await managed.restart()

    elif action == "stop" and managed:
        await managed.stop()
        await event.answer("🛑 Process stopped.", alert=True)

    elif action == "stats" and managed:
        m = managed.get_metrics()
        return await event.answer(
            f"📊 Live Metrics\nStatus: {m['status'].upper()}\nPID: {m['pid']}\n"
            f"RAM: {m['ram_mb']} MB\nCPU: {m['cpu_percent']}%\nUptime: {m['uptime_sec']}s",
            alert=True,
        )

    elif action == "logs" and managed:
        tail = "\n".join(list(managed.log_buffer)[-25:]) or "No stdout/stderr logs emitted yet."
        return await event.respond(
            f"📜 **Live Log Tail (`{instance_id}`):**\n```text\n{tail[-3500:]}\n```",
            buttons=[[Button.inline("🔄 Refresh Logs", data=f"ctl:logs:{instance_id}".encode())]],
        )

    elif action == "delete":
        await process_engine.purge_instance(instance_id)
        return await event.edit(f"🗑️ **Instance `{instance_id}` and its workspace files were permanently deleted.**")

    if managed:
        m = managed.get_metrics()
        await event.edit(
            f"🎛 **Instance Manager: `{instance_id}`**\n"
            f"• **Status:** `{m['status'].upper()}`\n"
            f"• **PID:** `{m['pid']}`\n"
            f"• **RAM:** `{m['ram_mb']} MB` | **CPU:** `{m['cpu_percent']}%`",
            buttons=instance_control_keyboard(instance_id),
        )


@hoster_client.on(events.NewMessage(pattern=r"^/newflow (\d+:[A-Za-z0-9_\-]+)$"))
async def handle_create_flowbot(event):
    token = event.pattern_match.group(1).strip()
    bot_id = token.split(":")[0]
    instance_id = f"flow_{bot_id}"

    default_flow = {
        "welcome": "👋 **Welcome to our Automated Assistant!**\nChoose an option below:",
        "nodes": {
            "services": {
                "label": "📦 Services & Pricing",
                "text": "⚡ **Cloud Bot & Userbot Hosting**\n• 24/7 Watchdog Uptime\n• Isolated Sandboxes",
                "buttons": [[["🔙 Back", "home"]]],
            },
            "support": {
                "label": "🛠 Contact Support",
                "text": "📩 Leave a message here and an admin will get back to you.",
                "buttons": [[["🔙 Back", "home"]]],
            },
        },
    }

    if instance_id in flowbot_registry:
        await flowbot_registry[instance_id].stop()

    fb = FlowBotInstance(instance_id, event.sender_id, token, default_flow)
    await fb.start()
    flowbot_registry[instance_id] = fb
    await db.save_flowbot(instance_id, event.sender_id, token, default_flow)

    await event.respond(f"✅ **Flowbot `{instance_id}` is Live!**\nOpen your bot and send `/start` to test the menu.")


# =====================================================================
# SECTION 7: MAIN ORCHESTRATOR & AUTO-RESTORE ON BOOT
# =====================================================================
async def restore_persisted_bots():
    """Re-spawns all bots marked as 'running' in SQLite when main.py starts."""
    for rec in await db.get_all_active_instances():
        workdir = Path(rec["workdir"])
        if not workdir.exists():
            await db.update_instance_status(rec["instance_id"], "stopped")
            continue

        env_vars = {}
        if rec["bot_type"] == "userbot_script":
            session_str = await db.get_user_session(rec["owner_id"])
            if session_str:
                env_vars["SESSION_STRING"] = session_str
        if rec["encrypted_token"]:
            env_vars["BOT_TOKEN"] = vault.decrypt(rec["encrypted_token"])

        try:
            await process_engine.spawn_instance(
                instance_id=rec["instance_id"],
                owner_id=rec["owner_id"],
                workdir=workdir,
                entrypoint=rec["entrypoint"],
                env_vars=env_vars,
                ram_limit_mb=rec["ram_limit_mb"],
            )
            print(f"[Restored Subprocess] {rec['instance_id']}")
        except Exception as e:
            print(f"[Restore Failed] {rec['instance_id']}: {e}")

    for fb_rec in await db.get_all_flowbots():
        try:
            token = vault.decrypt(fb_rec["encrypted_token"])
            flow_cfg = json.loads(fb_rec["flow_json"])
            fb = FlowBotInstance(fb_rec["instance_id"], fb_rec["owner_id"], token, flow_cfg)
            await fb.start()
            flowbot_registry[fb_rec["instance_id"]] = fb
            print(f"[Restored Flowbot] {fb_rec['instance_id']}")
        except Exception as e:
            print(f"[Flowbot Restore Failed] {fb_rec['instance_id']}: {e}")


async def main():
    print("1. Initializing SQLite Database...")
    await db.init_db()

    print("2. Starting Process Watchdog & OOM Monitor...")
    process_engine.start_watchdog()

    print("3. Restoring Previously Running Bots & Userbots...")
    await restore_persisted_bots()

    print("4. Starting Master Hoster Bot...")
    await hoster_client.start(bot_token=HOSTER_BOT_TOKEN)
    me = await hoster_client.get_me()
    print(f"✅ Hoster Bot Online as @{me.username}! Listening for commands...")

    try:
        await hoster_client.run_until_disconnected()
    finally:
        print("Shutting down all hosted processes gracefully...")
        for managed in list(process_engine.registry.values()):
            await managed.stop()
        for fb in list(flowbot_registry.values()):
            await fb.stop()


if __name__ == "__main__":
    asyncio.run(main())
