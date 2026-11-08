import ast
import asyncio
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
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
    ADMIN_IDS,
    ALLOWED_PIP_PACKAGES,
    API_HASH,
    API_ID,
    DATABASE_URL,
    DB_PATH,
    HOSTER_BOT_TOKEN,
    LOGS_DIR,
    MAX_CRASH_RESTARTS,
    MAX_RAM_MB_PER_BOT,
    MAX_UPLOAD_BYTES,
    MAX_ZIP_EXTRACTED_BYTES,
    MAX_ZIP_FILES,
    MONGO_URI,
    REDIS_HOST,
    REDIS_PASSWORD,
    REDIS_URI,
    SECRET_KEY_FILE,
    SID_HOSTER_REPO,
    SID_USERBOT_REPO,
    STRICT_AST_SCAN,
    TRUSTED_GITHUB_REPOS,
    WORKSPACES_DIR,
    get_venv_python,
)


# =====================================================================
# SECTION 1: FERNET VAULT & BOT API 9.4+ COLORED BUTTON ENGINE
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


class BotAPI94UI:
    """
    Sends and edits messages using Telegram Bot API 9.4+ native colored inline buttons
    ('style': 'primary' | 'success' | 'danger' | 'secondary').
    Automatically falls back to standard inline buttons if the client/server rejects styles.
    """
    BASE_URL = f"https://api.telegram.org/bot{HOSTER_BOT_TOKEN}"

    @staticmethod
    def btn(text: str, data: str, style: str = "primary") -> dict:
        return {"text": text, "callback_data": data, "style": style}

    @staticmethod
    def url_btn(text: str, url: str, style: str = "primary") -> dict:
        return {"text": text, "url": url, "style": style}

    @classmethod
    def _post_json(cls, method: str, payload: dict) -> dict:
        url = f"{cls.BASE_URL}/{method}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            if "reply_markup" in payload and "inline_keyboard" in payload["reply_markup"]:
                clean_kb = [
                    [{k: v for k, v in b.items() if k != "style"} for b in row]
                    for row in payload["reply_markup"]["inline_keyboard"]
                ]
                payload["reply_markup"]["inline_keyboard"] = clean_kb
                body_retry = json.dumps(payload).encode("utf-8")
                req_retry = urllib.request.Request(url, data=body_retry, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req_retry, timeout=8) as resp2:
                    return json.loads(resp2.read().decode("utf-8"))
            raise err

    @classmethod
    async def send(cls, chat_id: int, text: str, rows: list[list[dict]] | None = None) -> dict:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        if rows:
            payload["reply_markup"] = {"inline_keyboard": rows}
        return await asyncio.to_thread(cls._post_json, "sendMessage", payload)

    @classmethod
    async def edit(cls, chat_id: int, message_id: int, text: str, rows: list[list[dict]] | None = None) -> dict:
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        if rows:
            payload["reply_markup"] = {"inline_keyboard": rows}
        try:
            return await asyncio.to_thread(cls._post_json, "editMessageText", payload)
        except Exception:
            return await cls.send(chat_id, text, rows)


# =====================================================================
# SECTION 2: ASYNC SQLITE DATABASE (MULTI-ACCOUNT & DB CONFIGS)
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
                    custom_mongo_uri TEXT DEFAULT '',
                    custom_redis_uri TEXT DEFAULT '',
                    created_at REAL
                )
            """)
            for col_sql in (
                "ALTER TABLE users ADD COLUMN custom_mongo_uri TEXT DEFAULT ''",
                "ALTER TABLE users ADD COLUMN custom_redis_uri TEXT DEFAULT ''",
            ):
                try:
                    await conn.execute(col_sql)
                except Exception:
                    pass

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS user_accounts (
                    account_id TEXT PRIMARY KEY,
                    owner_id INTEGER,
                    phone TEXT,
                    tg_uid INTEGER DEFAULT 0,
                    tg_name TEXT DEFAULT '',
                    encrypted_session TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at REAL
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bot_instances (
                    instance_id TEXT PRIMARY KEY,
                    owner_id INTEGER,
                    account_id TEXT DEFAULT '',
                    bot_type TEXT,          -- 'userbot_script' or 'bot_script'
                    name TEXT,
                    workdir TEXT,
                    entrypoint TEXT,
                    repo_url TEXT DEFAULT '',
                    encrypted_token TEXT,
                    encrypted_session TEXT DEFAULT '',
                    status TEXT,            -- 'running', 'paused', 'stopped', 'crashed'
                    ram_limit_mb INTEGER DEFAULT 300,
                    created_at REAL
                )
            """)
            for col_sql in (
                "ALTER TABLE bot_instances ADD COLUMN repo_url TEXT DEFAULT ''",
                "ALTER TABLE bot_instances ADD COLUMN account_id TEXT DEFAULT ''",
                "ALTER TABLE bot_instances ADD COLUMN encrypted_session TEXT DEFAULT ''",
            ):
                try:
                    await conn.execute(col_sql)
                except Exception:
                    pass

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

    async def save_user_account(
        self, owner_id: int, phone: str, session_str: str, tg_uid: int = 0, tg_name: str = ""
    ) -> str:
        enc = vault.encrypt(session_str)
        clean_phone = re.sub(r"[^\d]", "", phone)[-10:] or str(int(time.time()))
        account_id = f"acc_{owner_id}_{clean_phone}"

        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("UPDATE user_accounts SET is_active = 0 WHERE owner_id = ?", (owner_id,))
            await conn.execute("""
                INSERT INTO user_accounts
                (account_id, owner_id, phone, tg_uid, tg_name, encrypted_session, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    phone = excluded.phone,
                    tg_uid = excluded.tg_uid,
                    tg_name = excluded.tg_name,
                    encrypted_session = excluded.encrypted_session,
                    is_active = 1
            """, (account_id, owner_id, phone, tg_uid, tg_name or phone, enc, time.time()))

            await conn.execute("""
                INSERT INTO users (user_id, phone, encrypted_session, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    phone = excluded.phone,
                    encrypted_session = excluded.encrypted_session
            """, (owner_id, phone, enc, time.time()))
            await conn.commit()
        return account_id

    async def save_user_session(self, user_id: int, phone: str, session_str: str):
        await self.save_user_account(user_id, phone, session_str)

    async def get_user_accounts(self, owner_id: int) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT * FROM user_accounts WHERE owner_id = ? ORDER BY is_active DESC, created_at DESC",
                (owner_id,)
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]

        if not rows:
            async with aiosqlite.connect(self.db_path) as conn:
                async with conn.execute(
                    "SELECT phone, encrypted_session FROM users WHERE user_id = ?", (owner_id,)
                ) as cur:
                    legacy = await cur.fetchone()
                    if legacy and legacy[1]:
                        raw_sess = vault.decrypt(legacy[1])
                        await self.save_user_account(owner_id, legacy[0] or "+00000", raw_sess, tg_name="Primary Account")
                        return await self.get_user_accounts(owner_id)
        return rows

    async def get_active_account(self, owner_id: int) -> dict | None:
        accounts = await self.get_user_accounts(owner_id)
        if not accounts:
            return None
        for acc in accounts:
            if acc["is_active"]:
                return acc
        return accounts[0]

    async def get_account_by_id(self, account_id: str) -> dict | None:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM user_accounts WHERE account_id = ?", (account_id,)) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def set_active_account(self, owner_id: int, account_id: str) -> bool:
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("UPDATE user_accounts SET is_active = 0 WHERE owner_id = ?", (owner_id,))
            await conn.execute(
                "UPDATE user_accounts SET is_active = 1 WHERE owner_id = ? AND account_id = ?",
                (owner_id, account_id)
            )
            async with conn.execute(
                "SELECT phone, encrypted_session FROM user_accounts WHERE account_id = ?", (account_id,)
            ) as cur:
                row = await cur.fetchone()
                if row:
                    await conn.execute(
                        "UPDATE users SET phone = ?, encrypted_session = ? WHERE user_id = ?",
                        (row[0], row[1], owner_id)
                    )
            await conn.commit()
            return True

    async def delete_user_account(self, owner_id: int, account_id: str):
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                "DELETE FROM user_accounts WHERE owner_id = ? AND account_id = ?", (owner_id, account_id)
            )
            await conn.commit()
        remaining = await self.get_user_accounts(owner_id)
        if remaining:
            await self.set_active_account(owner_id, remaining[0]["account_id"])
        else:
            async with aiosqlite.connect(self.db_path) as conn:
                await conn.execute("UPDATE users SET encrypted_session = '' WHERE user_id = ?", (owner_id,))
                await conn.commit()

    async def get_user_session(self, user_id: int, account_id: str = "") -> str | None:
        if account_id:
            acc = await self.get_account_by_id(account_id)
            if acc and acc.get("encrypted_session"):
                return vault.decrypt(acc["encrypted_session"])
        active = await self.get_active_account(user_id)
        if active and active.get("encrypted_session"):
            return vault.decrypt(active["encrypted_session"])
        return None

    async def set_user_db_urls(self, user_id: int, mongo_uri: str | None = None, redis_uri: str | None = None):
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                "INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING",
                (user_id, time.time())
            )
            if mongo_uri is not None:
                await conn.execute("UPDATE users SET custom_mongo_uri = ? WHERE user_id = ?", (mongo_uri, user_id))
            if redis_uri is not None:
                await conn.execute("UPDATE users SET custom_redis_uri = ? WHERE user_id = ?", (redis_uri, user_id))
            await conn.commit()

    async def get_user_db_urls(self, user_id: int) -> dict[str, str]:
        async with aiosqlite.connect(self.db_path) as conn:
            async with conn.execute(
                "SELECT custom_mongo_uri, custom_redis_uri FROM users WHERE user_id = ?", (user_id,)
            ) as cur:
                row = await cur.fetchone()
                return {
                    "mongo_uri": (row[0] if row and row[0] else MONGO_URI),
                    "redis_uri": (row[1] if row and row[1] else REDIS_URI),
                }

    async def register_instance(
        self, instance_id: str, owner_id: int, bot_type: str,
        name: str, workdir: str, entrypoint: str, raw_token: str = "",
        repo_url: str = "", ram_limit_mb: int = MAX_RAM_MB_PER_BOT,
        account_id: str = "", raw_session: str = ""
    ):
        enc_token = vault.encrypt(raw_token) if raw_token else ""
        enc_sess = vault.encrypt(raw_session) if raw_session else ""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO bot_instances
                (instance_id, owner_id, account_id, bot_type, name, workdir, entrypoint, repo_url, encrypted_token, encrypted_session, status, ram_limit_mb, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    account_id = CASE WHEN excluded.account_id != '' THEN excluded.account_id ELSE bot_instances.account_id END,
                    workdir = excluded.workdir,
                    entrypoint = excluded.entrypoint,
                    repo_url = excluded.repo_url,
                    encrypted_token = CASE WHEN excluded.encrypted_token != '' THEN excluded.encrypted_token ELSE bot_instances.encrypted_token END,
                    encrypted_session = CASE WHEN excluded.encrypted_session != '' THEN excluded.encrypted_session ELSE bot_instances.encrypted_session END,
                    status = 'running'
            """, (instance_id, owner_id, account_id, bot_type, name, workdir, entrypoint, repo_url, enc_token, enc_sess, ram_limit_mb, time.time()))
            await conn.commit()

    async def update_instance_token(self, instance_id: str, new_raw_token: str):
        enc_token = vault.encrypt(new_raw_token)
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                "UPDATE bot_instances SET encrypted_token = ? WHERE instance_id = ?",
                (enc_token, instance_id)
            )
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
# SECTION 3: SOURCE-CODE TOKEN/SESSION REPLACER & AST SCANNER
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

BOT_TOKEN_REGEX = re.compile(r"\b(\d{8,11}:[A-Za-z0-9_-]{30,45})\b")


class SecurityViolation(Exception):
    pass


def extract_hardcoded_token_from_dir(workdir: Path) -> str:
    """Scans uploaded .py / .env files to see if a BotFather token is already hardcoded inside."""
    for file_path in workdir.rglob("*"):
        if not file_path.is_file() or ".venv" in file_path.parts:
            continue
        if file_path.suffix in (".py", ".env", ".json", ".yaml", ".yml", ".txt"):
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            match = BOT_TOKEN_REGEX.search(content)
            if match:
                return match.group(1)
    return ""


def auto_patch_workspace_credentials(
    workdir: Path,
    owner_id: int,
    bot_token: str = "",
    session_str: str = "",
    mongo_uri: str = "",
    redis_uri: str = "",
) -> int:
    """
    Directly patches hardcoded BOT_TOKEN, SESSION_STRING, API_ID, API_HASH,
    OWNER_ID, MONGO_URI, and REDIS_URI inside uploaded/cloned .py and config files
    so scripts that do NOT use os.getenv() still run with the user's credentials!
    Returns the number of files patched.
    """
    patched_files = 0
    for py_file in workdir.rglob("*.py"):
        if ".venv" in py_file.parts or "venv" in py_file.parts:
            continue

        original = py_file.read_text(encoding="utf-8", errors="ignore")
        updated = original

        # 1. Replace any hardcoded @BotFather token literal (123456789:ABC...) with new bot_token
        if bot_token:
            updated = BOT_TOKEN_REGEX.sub(bot_token, updated)
            # Also replace BOT_TOKEN / TOKEN / TG_BOT_TOKEN / HOSTER_BOT_TOKEN string assignments
            updated = re.sub(
                r'^(\s*(?:BOT_TOKEN|TOKEN|TG_BOT_TOKEN|HOSTER_BOT_TOKEN|BOT_API_TOKEN)\s*=\s*)(?:["\'][^"\']*["\']|None)',
                rf'\g<1>os.environ.get("BOT_TOKEN", "{bot_token}")',
                updated,
                flags=re.MULTILINE,
            )

        # 2. Replace hardcoded Userbot Session string assignments
        if session_str:
            updated = re.sub(
                r'^(\s*(?:SESSION_STRING|STRING_SESSION|SESSION|PYROGRAM_SESSION|TELETHON_SESSION)\s*=\s*)(?:["\'][^"\']*["\']|None)',
                rf'\g<1>os.environ.get("SESSION_STRING", "{session_str}")',
                updated,
                flags=re.MULTILINE,
            )

        # 3. Replace hardcoded API_ID, API_HASH, and OWNER_ID assignments
        updated = re.sub(
            r'^(\s*(?:API_ID|APP_ID|TELEGRAM_API_ID)\s*=\s*)(?:\d+|["\']\d+["\'])',
            f'\\g<1>{API_ID}',
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r'^(\s*(?:API_HASH|TELEGRAM_API_HASH)\s*=\s*)["\'][A-Za-z0-9_]+["\']',
            f'\\g<1>"{API_HASH}"',
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r'^(\s*(?:OWNER_ID|ADMIN_ID)\s*=\s*)(?:\d+|["\']\d+["\'])',
            f'\\g<1>{owner_id}',
            updated,
            flags=re.MULTILINE,
        )

        # 4. Replace hardcoded MONGO_URI / REDIS_URI assignments
        if mongo_uri:
            updated = re.sub(
                r'^(\s*(?:MONGO_URI|MONGO_URL|MONGODB_URI|MONGO_DB_URI)\s*=\s*)["\'][^"\']*["\']',
                f'\\g<1>"{mongo_uri}"',
                updated,
                flags=re.MULTILINE,
            )
        if redis_uri:
            updated = re.sub(
                r'^(\s*(?:REDIS_URI|REDIS_URL)\s*=\s*)["\'][^"\']*["\']',
                f'\\g<1>"{redis_uri}"',
                updated,
                flags=re.MULTILINE,
            )

        # Ensure `import os` exists if we injected os.environ.get(...)
        if 'os.environ.get(' in updated and not re.search(r'^\s*import\s+os\b', updated, re.MULTILINE):
            updated = "import os\n" + updated

        if updated != original:
            # Verify our patch didn't break Python syntax before writing
            try:
                ast.parse(updated)
                py_file.write_text(updated, encoding="utf-8")
                patched_files += 1
            except SyntaxError:
                pass

    return patched_files


def scan_python_source(code_str: str, filename: str = "script.py", strict: bool = STRICT_AST_SCAN) -> None:
    try:
        tree = ast.parse(code_str, filename=filename)
    except SyntaxError as e:
        raise SecurityViolation(f"Syntax error in {filename} (line {e.lineno}): {e.msg}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if ".secret.key" in node.value or "platform.sqlite3" in node.value:
                raise SecurityViolation(f"[{filename}] Attempt to access host database/key blocked.")

        if not strict:
            continue

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


def detect_project_entrypoint(project_root: Path) -> str:
    procfile = project_root / "Procfile"
    if procfile.exists():
        content = procfile.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"python3?\s+(-m\s+[A-Za-z0-9_.\-]+|[A-Za-z0-9_./\-]+\.py)", content)
        if match:
            return match.group(1).strip()

    for sh_name in ("start.sh", "run.sh", "startup.sh"):
        sh_file = project_root / sh_name
        if sh_file.exists():
            content = sh_file.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r"python3?\s+(-m\s+[A-Za-z0-9_.\-]+|[A-Za-z0-9_./\-]+\.py)", content)
            if match:
                return match.group(1).strip()

    priority_files = [
        "main.py", "bot.py", "userbot.py", "hoster.py",
        "sidbot.py", "siduserbot.py", "app.py", "runner.py", "start.py", "__main__.py"
    ]
    for fname in priority_files:
        if (project_root / fname).exists():
            return fname

    for main_mod in project_root.rglob("__main__.py"):
        if ".venv" not in main_mod.parts and "venv" not in main_mod.parts:
            rel_pkg = main_mod.parent.relative_to(project_root)
            if str(rel_pkg) != ".":
                pkg_dots = ".".join(rel_pkg.parts)
                return f"-m {pkg_dots}"

    py_files = [p for p in project_root.rglob("*.py") if ".venv" not in p.parts]
    if not py_files:
        raise SecurityViolation("No Python (.py) files found in repository/archive.")

    root_candidates = [
        p for p in py_files
        if p.parent == project_root and p.name.lower() not in ("config.py", "setup.py", "vars.py")
    ]
    chosen = root_candidates[0] if root_candidates else py_files[0]
    return str(chosen.relative_to(project_root))


async def clone_github_repository(repo_url: str, target_dir: Path) -> str:
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)
    target_dir.mkdir(parents=True, exist_ok=True)

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", repo_url, str(target_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        err_msg = stdout.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git clone failed:\n{err_msg[:350]}")

    is_trusted = repo_url.lower().strip() in TRUSTED_GITHUB_REPOS
    for py_file in target_dir.rglob("*.py"):
        if ".venv" in py_file.parts:
            continue
        code = py_file.read_text(encoding="utf-8", errors="ignore")
        scan_python_source(code, filename=py_file.name, strict=(STRICT_AST_SCAN and not is_trusted))

    return detect_project_entrypoint(target_dir)


def safe_extract_and_scan_zip(zip_path: Path, extract_to: Path) -> str:
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
                raise SecurityViolation("Zip archive uncompressed size exceeds 60 MB limit.")

            dest_path = (target_root / info.filename).resolve()
            if os.path.commonpath([str(target_root), str(dest_path)]) != str(target_root):
                raise SecurityViolation(f"Zip-Slip path traversal blocked: {info.filename}")

        zf.extractall(target_root)

    zip_path.unlink(missing_ok=True)

    subdirs = [d for d in target_root.iterdir() if d.is_dir() and d.name != "__MACOSX"]
    files_in_root = [f for f in target_root.iterdir() if f.is_file()]
    if len(subdirs) == 1 and not files_in_root:
        nested = subdirs[0]
        for item in nested.iterdir():
            shutil.move(str(item), str(target_root / item.name))
        nested.rmdir()

    for py_file in target_root.rglob("*.py"):
        code = py_file.read_text(encoding="utf-8", errors="ignore")
        scan_python_source(code, filename=py_file.name)

    return detect_project_entrypoint(target_root)


def parse_requirements_file(req_file: Path, trusted: bool = True) -> list[str]:
    if not req_file.exists():
        return []

    packages = []
    for raw_line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        if not trusted:
            pkg_match = re.match(r"^([A-Za-z0-9_\-]+)", line)
            if not pkg_match or pkg_match.group(1).lower() not in ALLOWED_PIP_PACKAGES:
                raise SecurityViolation(f"Package '{line}' is not in ALLOWED_PIP_PACKAGES.")
        packages.append(line)
    return packages


# =====================================================================
# SECTION 4: ADVANCED SUBPROCESS TASK MANAGER & WATCHDOG ENGINE
# =====================================================================
class ManagedProcess:
    def __init__(
        self,
        instance_id: str,
        owner_id: int,
        workdir: Path,
        entrypoint: str,
        env_vars: dict[str, str],
        repo_url: str = "",
        ram_limit_mb: int = MAX_RAM_MB_PER_BOT,
        auto_restart: bool = True,
    ):
        self.instance_id = instance_id
        self.owner_id = owner_id
        self.workdir = Path(workdir).resolve()
        self.entrypoint = entrypoint
        self.env_vars = env_vars
        self.repo_url = repo_url
        self.ram_limit_mb = ram_limit_mb
        self.auto_restart = auto_restart

        self.process: asyncio.subprocess.Process | None = None
        self.ps_handle: psutil.Process | None = None
        self.status: str = "stopped"
        self.started_at: float = 0.0
        self.crash_count: int = 0
        self.manual_stop: bool = False

        self.log_buffer = deque(maxlen=300)
        self.log_file_path = LOGS_DIR / f"{self.instance_id}.log"

    def _append_log(self, line: str):
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {line}"
        self.log_buffer.append(formatted)
        with open(self.log_file_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(formatted + "\n")

    def _write_universal_dotenv(self, full_env: dict[str, str]):
        dotenv_path = self.workdir / ".env"
        lines = []
        for k, v in full_env.items():
            if k in ("PATH", "SYSTEMROOT", "HOME", "PYTHONUNBUFFERED", "PYTHONIOENCODING"):
                continue
            lines.append(f'{k}="{v}"')
        dotenv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    async def prepare_environment(self) -> str:
        req_path = self.workdir / "requirements.txt"
        packages = parse_requirements_file(req_path, trusted=True)
        venv_dir = self.workdir / ".venv"

        if packages:
            self.status = "installing"
            self._append_log(f"📦 Found requirements.txt ({len(packages)} packages)...")
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
                self._append_log(f"⚠️ Pip warning/error:\n{err_out[:300]}")
            else:
                self._append_log("✅ All dependencies installed.")
            return py_bin

        return get_venv_python(venv_dir)

    async def start(self):
        if self.process and self.process.returncode is None:
            return

        self.manual_stop = False
        py_exec = await self.prepare_environment()

        db_urls = await db.get_user_db_urls(self.owner_id)
        mongo_url = self.env_vars.get("MONGO_URI") or db_urls["mongo_uri"] or MONGO_URI
        redis_url = self.env_vars.get("REDIS_URI") or db_urls["redis_uri"] or REDIS_URI

        sess = self.env_vars.get("SESSION_STRING", "")
        token = self.env_vars.get("BOT_TOKEN", "")

        # Auto-patch hardcoded tokens, sessions, API_ID/HASH & DB URLs inside workspace .py files!
        patched_count = auto_patch_workspace_credentials(
            workdir=self.workdir,
            owner_id=self.owner_id,
            bot_token=token,
            session_str=sess,
            mongo_uri=mongo_url,
            redis_uri=redis_url,
        )
        if patched_count > 0:
            self._append_log(f"🔧 Auto-replaced hardcoded credentials/tokens in {patched_count} Python file(s).")

        universal_creds = {
            "API_ID": str(API_ID),
            "APP_ID": str(API_ID),
            "TELEGRAM_API_ID": str(API_ID),
            "API_HASH": API_HASH,
            "TELEGRAM_API_HASH": API_HASH,
            "OWNER_ID": str(self.owner_id),
            "ADMIN_ID": str(self.owner_id),
            "SUDO_USERS": str(self.owner_id),
            # Auto-injected MongoDB URLs
            "MONGO_URI": mongo_url,
            "MONGO_URL": mongo_url,
            "MONGODB_URI": mongo_url,
            "MONGO_DB_URI": mongo_url,
            "MONGODB_URL": mongo_url,
            # Auto-injected SQL / Database URLs
            "DATABASE_URL": DATABASE_URL,
            "DB_URI": DATABASE_URL,
            "SQL_URL": DATABASE_URL,
            # Auto-injected Redis URLs
            "REDIS_URI": redis_url,
            "REDIS_URL": redis_url,
            "REDIS_HOST": REDIS_HOST,
            "REDIS_PASSWORD": REDIS_PASSWORD,
            "REDIS_PASS": REDIS_PASSWORD,
        }
        if sess:
            universal_creds.update({
                "SESSION_STRING": sess,
                "STRING_SESSION": sess,
                "SESSION": sess,
                "TELETHON_SESSION": sess,
                "PYROGRAM_SESSION": sess,
            })
        if token:
            universal_creds.update({
                "BOT_TOKEN": token,
                "TOKEN": token,
                "TG_BOT_TOKEN": token,
                "HOSTER_BOT_TOKEN": token,
            })

        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "HOME": str(self.workdir),
            "PYTHONPATH": str(self.workdir),
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
            **universal_creds,
            **self.env_vars,
        }

        self._write_universal_dotenv(safe_env)
        self._append_log("🗄️ Injected MONGO_URI, REDIS_URI, TOKEN & SESSION into .env and process env.")

        if self.entrypoint.startswith("-m "):
            mod_name = self.entrypoint.split("-m ", 1)[1].strip()
            cmd_args = [py_exec, "-m", mod_name]
        else:
            cmd_args = [py_exec, str(self.workdir / self.entrypoint)]

        self._append_log(f"🚀 Launching entrypoint: {self.entrypoint} ...")

        self.process = await asyncio.create_subprocess_exec(
            *cmd_args,
            cwd=str(self.workdir),
            env=safe_env,
            stdin=asyncio.subprocess.PIPE,
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

    async def send_stdin(self, text: str) -> bool:
        if self.process and self.process.returncode is None and self.process.stdin:
            self.process.stdin.write((text + "\n").encode("utf-8"))
            await self.process.stdin.drain()
            self._append_log(f"⌨️ [STDIN Sent]: {text}")
            return True
        return False

    def pause(self) -> bool:
        if self.ps_handle and self.ps_handle.is_running() and self.status == "running":
            for child in self.ps_handle.children(recursive=True):
                try:
                    child.suspend()
                except psutil.NoSuchProcess:
                    pass
            self.ps_handle.suspend()
            self.status = "paused"
            self._append_log("⏸️ Process tree suspended (PAUSED).")
            return True
        return False

    def resume(self) -> bool:
        if self.ps_handle and self.ps_handle.is_running() and self.status == "paused":
            self.ps_handle.resume()
            for child in self.ps_handle.children(recursive=True):
                try:
                    child.resume()
                except psutil.NoSuchProcess:
                    pass
            self.status = "running"
            self._append_log("▶️ Process tree resumed (RUNNING).")
            return True
        return False

    async def stop(self):
        self.manual_stop = True
        self.status = "stopped"
        await db.update_instance_status(self.instance_id, "stopped")

        if not self.ps_handle or not self.ps_handle.is_running():
            return

        self._append_log("🛑 Sending SIGTERM to process tree...")
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
        self._append_log("🛑 Process tree stopped.")

    async def force_kill(self):
        self.manual_stop = True
        self.status = "stopped"
        await db.update_instance_status(self.instance_id, "stopped")

        if not self.ps_handle or not self.ps_handle.is_running():
            return

        self._append_log("💀 Executing immediate SIGKILL on process tree...")
        try:
            for child in self.ps_handle.children(recursive=True):
                child.kill()
            self.ps_handle.kill()
        except psutil.NoSuchProcess:
            pass
        self._append_log("💀 Process force-killed.")

    async def restart(self):
        self._append_log("🔄 Restarting process instance...")
        await self.stop()
        await asyncio.sleep(1.0)
        self.crash_count = 0
        await self.start()

    async def git_pull_update(self) -> str:
        if not (self.workdir / ".git").exists():
            return "❌ This instance was not deployed from a Git repository."

        self._append_log("📥 Running 'git pull' to fetch latest commits...")
        proc = await asyncio.create_subprocess_exec(
            "git", "pull",
            cwd=str(self.workdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode("utf-8", errors="replace").strip()
        self._append_log(f"📥 Git output: {output}")
        await self.restart()
        return output or "Already up to date."

    def get_metrics(self) -> dict:
        if not self.ps_handle or not self.ps_handle.is_running() or self.status in ("stopped", "crashed"):
            return {
                "pid": None, "ram_mb": 0.0, "vms_mb": 0.0, "cpu_percent": 0.0,
                "threads": 0, "children": 0, "uptime_sec": 0, "status": self.status
            }
        try:
            with self.ps_handle.oneshot():
                mem_info = self.ps_handle.memory_info()
                rss_bytes = mem_info.rss
                vms_bytes = mem_info.vms
                threads = self.ps_handle.num_threads()
                children = self.ps_handle.children(recursive=True)
                for c in children:
                    try:
                        rss_bytes += c.memory_info().rss
                        threads += c.num_threads()
                    except psutil.NoSuchProcess:
                        pass
                return {
                    "pid": self.process.pid if self.process else None,
                    "ram_mb": round(rss_bytes / (1024 * 1024), 2),
                    "vms_mb": round(vms_bytes / (1024 * 1024), 2),
                    "cpu_percent": round(self.ps_handle.cpu_percent(interval=0.05), 1),
                    "threads": threads,
                    "children": len(children),
                    "uptime_sec": int(time.time() - self.started_at),
                    "status": self.status,
                }
        except psutil.NoSuchProcess:
            return {
                "pid": None, "ram_mb": 0.0, "vms_mb": 0.0, "cpu_percent": 0.0,
                "threads": 0, "children": 0, "uptime_sec": 0, "status": "stopped"
            }


class ProcessHostingEngine:
    def __init__(self):
        self.registry: dict[str, ManagedProcess] = {}
        self._watchdog_task: asyncio.Task | None = None

    def start_watchdog(self):
        if not self._watchdog_task:
            self._watchdog_task = asyncio.create_task(self._watchdog_loop())

    async def spawn_instance(
        self, instance_id: str, owner_id: int, workdir: Path,
        entrypoint: str, env_vars: dict, repo_url: str = "", ram_limit_mb: int = MAX_RAM_MB_PER_BOT
    ) -> ManagedProcess:
        if instance_id in self.registry:
            await self.registry[instance_id].stop()

        managed = ManagedProcess(
            instance_id=instance_id,
            owner_id=owner_id,
            workdir=workdir,
            entrypoint=entrypoint,
            env_vars=env_vars,
            repo_url=repo_url,
            ram_limit_mb=ram_limit_mb,
        )
        self.registry[instance_id] = managed
        await managed.start()
        return managed

    async def purge_instance(self, instance_id: str):
        managed = self.registry.pop(instance_id, None)
        if managed:
            await managed.force_kill()
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
                    managed._append_log(f"⚠️ Process exited with return code {code}.")
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
                        f"🚨 OOM Protection triggered: {metrics['ram_mb']} MB > {managed.ram_limit_mb} MB limit."
                    )
                    await managed.force_kill()
                    managed.status = "crashed"
                    await db.update_instance_status(inst_id, "crashed")


process_engine = ProcessHostingEngine()


# =====================================================================
# SECTION 5: FLOWBOT ENGINE
# =====================================================================
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
        return [[Button.inline(n.get("label", k.capitalize()), data=f"flow:{k}".encode())] for k, n in nodes.items()] or None

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
# SECTION 6: CONVERSATIONAL STATE MACHINE & COLORED BUTTON UI
# =====================================================================
hoster_client = TelegramClient(str(WORKSPACES_DIR / "master_hoster"), API_ID, API_HASH)

user_conv_state: dict[int, dict] = {}
pending_upload_mode: dict[int, dict] = {}


def build_home_colored_keyboard(user_id: int, account_count: int, active_label: str, bot_count: int) -> list[list[dict]]:
    return [
        [
            BotAPI94UI.btn(
                "🔐 1. Connect Userbot (Auto-OTP)" if account_count == 0 else f"➕ Add Account ({account_count} Linked)",
                "menu:login",
                style="success" if account_count > 0 else "primary",
            ),
            BotAPI94UI.btn(
                f"🤖 Auto-Userbot Menu ({active_label[:12]})",
                "menu:accounts",
                style="primary",
            ),
        ],
        [
            BotAPI94UI.btn("⚡ Auto-Deploy siduserlast (Active Acc)", "menu:git_siduserbot", style="success"),
            BotAPI94UI.btn("🛸 Auto-Deploy sidhosterextrem", "menu:git_sidhoster", style="primary"),
        ],
        [
            BotAPI94UI.btn("🚀 Launch siduserlast on ALL Accounts", "sw:deploy_all_sid", style="success"),
        ],
        [
            BotAPI94UI.btn("🌐 Clone Any GitHub Repo URL", "menu:git_custom", style="primary"),
            BotAPI94UI.btn("📤 Upload .py / .zip File", "menu:upload_ub", style="secondary"),
        ],
        [
            BotAPI94UI.btn("🤖 Host Standard Bot (.py/.zip)", "menu:upload_bot", style="secondary"),
            BotAPI94UI.btn("🗄️ Mongo / Redis URLs", "menu:db_config", style="secondary"),
        ],
        [
            BotAPI94UI.btn(f"🎛 Process Task Manager ({bot_count} Active)", "menu:my_bots", style="primary"),
            BotAPI94UI.btn("🖥️ Server RAM / CPU Stats", "menu:server_stats", style="secondary"),
        ],
    ]


def build_instance_colored_keyboard(instance_id: str, has_git: bool = True, is_bot: bool = False) -> list[list[dict]]:
    rows = [
        [
            BotAPI94UI.btn("▶️ Start / Resume", f"ctl:resume:{instance_id}", style="success"),
            BotAPI94UI.btn("⏸️ Pause Tree", f"ctl:pause:{instance_id}", style="secondary"),
        ],
        [
            BotAPI94UI.btn("🔄 Restart", f"ctl:restart:{instance_id}", style="primary"),
            BotAPI94UI.btn("🛑 Stop", f"ctl:stop:{instance_id}", style="danger"),
            BotAPI94UI.btn("💀 Force Kill", f"ctl:kill:{instance_id}", style="danger"),
        ],
        [
            BotAPI94UI.btn("🔴 Live Log Stream", f"ctl:livelog:{instance_id}", style="success"),
            BotAPI94UI.btn("📜 Tail Logs", f"ctl:logs:{instance_id}", style="secondary"),
            BotAPI94UI.btn("📄 .log File", f"ctl:dl_log:{instance_id}", style="secondary"),
        ],
        [
            BotAPI94UI.btn("🔑 Replace Bot Token / Session", f"ctl:chtoken:{instance_id}", style="primary"),
            BotAPI94UI.btn("🔬 Task Info", f"ctl:stats:{instance_id}", style="secondary"),
        ],
    ]
    if has_git:
        rows.append([
            BotAPI94UI.btn("📥 Git Pull & Hot-Restart", f"ctl:gitpull:{instance_id}", style="primary"),
            BotAPI94UI.btn("⌨️ Send STDIN", f"ctl:stdin:{instance_id}", style="secondary"),
        ])
    rows.append([
        BotAPI94UI.btn("🤖 Auto-Userbot Menu", "menu:accounts", style="primary"),
        BotAPI94UI.btn("🗑️ Delete Process", f"ctl:delete:{instance_id}", style="danger"),
        BotAPI94UI.btn("🏠 Home", "menu:home", style="secondary"),
    ])
    return rows


async def send_home_dashboard(chat_id: int, user_id: int, edit_msg_id: int | None = None):
    instances = await db.get_user_instances(user_id)
    accounts = await db.get_user_accounts(user_id)
    active_acc = await db.get_active_account(user_id)
    active_label = f"{active_acc['tg_name']} ({active_acc['phone']})" if active_acc else "None"

    text = (
        "⚡ **Unified Multi-Account Userbot & GitHub Cloud Hoster**\n\n"
        f"👤 **Owner ID:** `{user_id}`\n"
        f"👥 **Linked Accounts:** `{len(accounts)}` | **Active:** `{active_label}`\n"
        f"🗄️ **Auto-Injected DBs:** `MongoDB ✅` | `Redis ✅`\n"
        f"🔧 **Auto-Token/Session Patcher:** `Active ✅`\n"
        f"⚙️ **Managed Processes:** `{len(instances)}`\n\n"
        "• **Auto Token & Session Replacer:** Any hardcoded token or session inside uploaded `.py`/`.zip` files or cloned repos is automatically replaced.\n"
        "• **Auto-Userbot Menu:** View all linked accounts AND their live running userbot processes in one menu."
    )
    kb = build_home_colored_keyboard(
        user_id,
        len(accounts),
        active_acc["tg_name"] if active_acc else "None",
        len(instances),
    )
    if edit_msg_id:
        await BotAPI94UI.edit(chat_id, edit_msg_id, text, kb)
    else:
        await BotAPI94UI.send(chat_id, text, kb)


async def send_account_switcher_menu(chat_id: int, user_id: int, edit_msg_id: int | None = None):
    """
    Upgraded Auto-Userbot & Account Switcher Menu:
    Cross-references `user_accounts` with `bot_instances` and `process_engine.registry`
    so every deployed/uploaded Userbot really shows up here with live status & controls!
    """
    accounts = await db.get_user_accounts(user_id)
    instances = await db.get_user_instances(user_id)
    ub_instances = [i for i in instances if i["bot_type"] == "userbot_script"]

    if not accounts:
        text = (
            "🤖 **Auto-Userbot & Multi-Account Menu**\n\n"
            "You haven't linked any Userbot accounts yet. Click below to link your first phone number via Auto-OTP:"
        )
        rows = [
            [BotAPI94UI.btn("➕ Connect First Userbot Account", "menu:login", style="success")],
            [BotAPI94UI.btn("🔙 Back to Dashboard", "menu:home", style="secondary")],
        ]
    else:
        lines = [
            f"🤖 **Auto-Userbot Menu & Account Switcher (`{len(accounts)}` Accounts | `{len(ub_instances)}` Userbots)**\n"
        ]
        rows = []

        for acc in accounts:
            acc_id = acc["account_id"]
            is_act = bool(acc["is_active"])
            badge = "🟢 [ACTIVE]" if is_act else "⚪"
            phone_tail = re.sub(r"[^\d]", "", acc["phone"])[-4:]

            # Find all userbot instances running on this account
            acc_bots = [
                inst for inst in ub_instances
                if inst.get("account_id") == acc_id or (phone_tail and f"_{phone_tail}_" in inst["instance_id"])
            ]

            lines.append(f"{badge} **{acc['tg_name']}** (`{acc['phone']}`)")
            rows.append([
                BotAPI94UI.btn(
                    f"{badge} Account: {acc['tg_name']} ({acc['phone']})",
                    f"sw:select:{acc_id}",
                    style="success" if is_act else "primary",
                )
            ])

            if acc_bots:
                for b in acc_bots:
                    iid = b["instance_id"]
                    managed = process_engine.registry.get(iid)
                    m = managed.get_metrics() if managed else {"status": b["status"], "pid": None, "ram_mb": 0}
                    st_icon = "🔥" if m["status"] == "running" else ("⏸️" if m["status"] == "paused" else "🔴")
                    lines.append(
                        f"   ╰─ {st_icon} `{iid}` — **{m['status'].upper()}** (PID: `{m['pid'] or 'Off'}` | `{m['ram_mb']} MB`)"
                    )
                    rows.append([
                        BotAPI94UI.btn(
                            f"{st_icon} Manage {b['name']} [{m['status'].upper()}]",
                            f"ctl:view:{iid}",
                            style="success" if m["status"] == "running" else "danger",
                        ),
                        BotAPI94UI.btn("🔴 Live Logs", f"ctl:livelog:{iid}", style="primary"),
                        BotAPI94UI.btn("🔄 Restart", f"ctl:restart:{iid}", style="secondary"),
                    ])
            else:
                lines.append("   ╰─ *No Userbot deployed on this account yet.*")

            rows.append([
                BotAPI94UI.btn("⚡ Auto-Deploy siduserlast", f"sw:deploy_sid:{acc_id}", style="primary"),
                BotAPI94UI.btn("📤 Upload .py/.zip to Acc", f"sw:upload_acc:{acc_id}", style="secondary"),
                BotAPI94UI.btn("🗑️ Unlink", f"sw:del:{acc_id}", style="danger"),
            ])

        rows.append([
            BotAPI94UI.btn("🚀 Launch siduserlast on ALL Accounts", "sw:deploy_all_sid", style="success"),
        ])
        rows.append([
            BotAPI94UI.btn("➕ Add New Phone Account", "menu:login", style="primary"),
            BotAPI94UI.btn("🏠 Main Dashboard", "menu:home", style="secondary"),
        ])
        text = "\n".join(lines)

    if edit_msg_id:
        await BotAPI94UI.edit(chat_id, edit_msg_id, text, rows)
    else:
        await BotAPI94UI.send(chat_id, text, rows)


@hoster_client.on(events.NewMessage(pattern=r"^/start$"))
async def on_start_cmd(event):
    user_conv_state.pop(event.sender_id, None)
    await send_home_dashboard(event.chat_id, event.sender_id)


# =====================================================================
# SECTION 7: AUTOMATED GITHUB CLONING & MULTI-SESSION DEPLOYMENT HELPER
# =====================================================================
async def deploy_github_repo_for_user(
    chat_id: int,
    user_id: int,
    repo_url: str,
    bot_type: str,
    raw_token: str = "",
    custom_name: str = "",
    account_id: str = "",
):
    session_str = ""
    acc_tag = ""
    acc_label = ""

    if bot_type == "userbot_script":
        target_acc = (
            await db.get_account_by_id(account_id)
            if account_id
            else await db.get_active_account(user_id)
        )
        if not target_acc:
            return await BotAPI94UI.send(
                chat_id,
                "⚠️ **No Userbot Account Linked!**\nClick **🔐 Connect Userbot (Auto-OTP)** first so we can inject your `SESSION_STRING`.",
                [[BotAPI94UI.btn("🔐 Connect Userbot Now", "menu:login", style="success")]],
            )
        account_id = target_acc["account_id"]
        session_str = vault.decrypt(target_acc["encrypted_session"])
        phone_digits = re.sub(r"[^\d]", "", target_acc["phone"])[-4:] or "acct"
        acc_tag = f"_{phone_digits}"
        acc_label = f"{target_acc['tg_name']} ({target_acc['phone']})"

    repo_name = custom_name or repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    clean_stem = "".join(c for c in repo_name if c.isalnum() or c in ("_", "-"))[:18]
    prefix = "ub" if bot_type == "userbot_script" else "bot"
    instance_id = f"{prefix}_{user_id}{acc_tag}_{clean_stem}"
    workdir = WORKSPACES_DIR / f"user_{user_id}" / instance_id

    status_res = await BotAPI94UI.send(
        chat_id,
        f"🌐 **Cloning GitHub Repository...**\n"
        f"🔗 **Repo:** `{repo_url}`\n"
        f"👤 **Account:** `{acc_label or 'Bot Token'}`\n"
        f"📂 **Instance ID:** `{instance_id}`",
    )
    msg_id = status_res.get("result", {}).get("message_id")

    try:
        entrypoint = await clone_github_repository(repo_url, workdir)
        if msg_id:
            await BotAPI94UI.edit(
                chat_id,
                msg_id,
                f"📦 **Repository Cloned Successfully!**\n"
                f"🎯 **Detected Entrypoint:** `{entrypoint}`\n"
                f"🔧 *Auto-replacing hardcoded tokens/sessions, injecting `MONGO_URI` & `REDIS_URI`, and starting...*",
            )

        db_urls = await db.get_user_db_urls(user_id)
        env_vars = {
            "MONGO_URI": db_urls["mongo_uri"],
            "REDIS_URI": db_urls["redis_uri"],
        }
        if session_str:
            env_vars["SESSION_STRING"] = session_str
        if raw_token:
            env_vars["BOT_TOKEN"] = raw_token

        display_name = f"{clean_stem}{acc_tag}"
        await db.register_instance(
            instance_id=instance_id,
            owner_id=user_id,
            bot_type=bot_type,
            name=display_name,
            workdir=str(workdir),
            entrypoint=entrypoint,
            raw_token=raw_token,
            repo_url=repo_url,
            ram_limit_mb=MAX_RAM_MB_PER_BOT,
            account_id=account_id,
            raw_session=session_str,
        )

        managed = await process_engine.spawn_instance(
            instance_id=instance_id,
            owner_id=user_id,
            workdir=workdir,
            entrypoint=entrypoint,
            env_vars=env_vars,
            repo_url=repo_url,
            ram_limit_mb=MAX_RAM_MB_PER_BOT,
        )

        await asyncio.sleep(1.5)
        m = managed.get_metrics()
        done_text = (
            f"✅ **GitHub Repository Hosted & Visible in Auto-Userbot Menu!**\n\n"
            f"🏷 **Instance ID:** `{instance_id}`\n"
            f"👤 **Account:** `{acc_label or 'Standard Bot'}`\n"
            f"🔗 **Repo:** `{repo_url}`\n"
            f"🚀 **Entrypoint:** `{entrypoint}`\n"
            f"🔧 **Token/Session Auto-Patch:** `Verified ✅`\n"
            f"🗄️ **Injected DBs:** `MONGO_URI` & `REDIS_URI` ✅\n"
            f"🔢 **PID:** `{m['pid']}` | **Status:** `{m['status'].upper()}`\n"
            f"💾 **RAM:** `{m['ram_mb']} / {MAX_RAM_MB_PER_BOT} MB`"
        )
        kb = build_instance_colored_keyboard(instance_id, has_git=True)
        if msg_id:
            await BotAPI94UI.edit(chat_id, msg_id, done_text, kb)
        else:
            await BotAPI94UI.send(chat_id, done_text, kb)

    except Exception as exc:
        err_text = f"❌ **GitHub Deployment Failed (`{instance_id}`):**\n`{exc}`"
        if msg_id:
            await BotAPI94UI.edit(chat_id, msg_id, err_text, [[BotAPI94UI.btn("🔙 Back", "menu:home", style="secondary")]])
        else:
            await BotAPI94UI.send(chat_id, err_text)


# =====================================================================
# SECTION 8: CONVERSATIONAL MESSAGE ROUTER (NO COMMANDS NEEDED!)
# =====================================================================
@hoster_client.on(events.NewMessage(func=lambda e: e.is_private and not e.file))
async def conversational_router(event):
    text = (event.raw_text or "").strip()
    if not text or text.startswith("/start"):
        return

    user_id = event.sender_id
    chat_id = event.chat_id

    if text.lower() in ("cancel", "/cancel", "stop"):
        state = user_conv_state.pop(user_id, None)
        if state and "client" in state:
            await state["client"].disconnect()
        return await BotAPI94UI.send(chat_id, "🚫 **Operation cancelled.**", [[BotAPI94UI.btn("🏠 Dashboard", "menu:home", style="primary")]])

    git_match = re.match(r"^(https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)(?:\.git)?/?$", text)
    if git_match and user_id not in user_conv_state:
        repo_url = git_match.group(1) + ".git"
        user_conv_state[user_id] = {"step": "CHOOSE_GIT_MODE", "repo_url": repo_url}
        return await BotAPI94UI.send(
            chat_id,
            f"🔗 **GitHub Repository Detected!**\n`{repo_url}`\n\nHow should we run this repository?",
            [
                [
                    BotAPI94UI.btn("👤 Run on Active Userbot", "gitmode:ub", style="success"),
                    BotAPI94UI.btn("🤖 Run as Bot (Replace Token)", "gitmode:bot", style="primary"),
                ],
                [BotAPI94UI.btn("🚫 Cancel", "menu:home", style="danger")],
            ],
        )

    state = user_conv_state.get(user_id)
    if not state:
        return

    step = state.get("step")

    # ---------------------------------------------------------
    # STEP 1: Phone Number Input (Multi-Account Auto-OTP)
    # ---------------------------------------------------------
    if step == "WAIT_PHONE":
        phone = re.sub(r"[^\d+]", "", text)
        if not phone.startswith("+") or len(phone) < 8:
            return await BotAPI94UI.send(
                chat_id,
                "⚠️ **Invalid Phone Format!**\nPlease send your phone number with country code (e.g. `+919876543210`), or type `cancel`.",
            )

        wait_msg = await event.respond("📡 *Connecting to Telegram MTProto & requesting OTP code...*")
        temp_client = TelegramClient(StringSession(), API_ID, API_HASH)
        await temp_client.connect()
        try:
            sent = await temp.send_code_request(phone) if hasattr(temp_client, "send_code_request") else await temp_client.send_code_request(phone)
            user_conv_state[user_id] = {
                "step": "WAIT_OTP",
                "client": temp_client,
                "phone": phone,
                "hash": sent.phone_code_hash,
            }
            await wait_msg.edit(
                "📲 **OTP Code Sent to Your Telegram!**\n\n"
                "👉 **Just reply with the 5-digit code directly in this chat** (no `/otp` command needed!).\n"
                "💡 *Tip: Put spaces between digits like `1 2 3 4 5` so Telegram doesn't block the login.*"
            )
        except Exception as e:
            await temp_client.disconnect()
            user_conv_state.pop(user_id, None)
            await wait_msg.edit(f"❌ **Failed to send OTP:** `{e}`")

    # ---------------------------------------------------------
    # STEP 2: Automatic OTP Code Detection
    # ---------------------------------------------------------
    elif step == "WAIT_OTP":
        digits = "".join(re.findall(r"\d", text))
        if len(digits) < 5:
            return await event.respond("⚠️ Please send the 5-digit OTP code you received (e.g. `1 2 3 4 5`).")

        otp_code = digits[:5]
        temp_client: TelegramClient = state["client"]
        try:
            await temp_client.sign_in(phone=state["phone"], code=otp_code, phone_code_hash=state["hash"])
        except SessionPasswordNeededError:
            user_conv_state[user_id]["step"] = "WAIT_2FA"
            return await event.respond(
                "🔐 **Two-Step Verification (2FA) Detected!**\n"
                "👉 **Send your 2FA cloud password directly as a message** (we will auto-delete your message immediately)."
            )
        except Exception as e:
            return await event.respond(f"❌ **OTP Verification Failed:** `{e}`\nTry sending the code again or type `cancel`.")

        me = await temp_client.get_me()
        session_str = temp_client.session.save()
        acc_id = await db.save_user_account(
            user_id, state["phone"], session_str, tg_uid=me.id, tg_name=me.first_name or "Userbot"
        )
        await temp_client.disconnect()
        user_conv_state.pop(user_id, None)

        await BotAPI94UI.send(
            chat_id,
            f"✅ **Account Linked & Added to Auto-Userbot Menu!**\n\n"
            f"👤 **Account:** `{me.first_name}` (`{state['phone']}`)\n"
            f"🆔 **Account Key:** `{acc_id}`\n\n"
            f"Would you like to clone and start **`siduserlast`** on this account right now?",
            [
                [BotAPI94UI.btn("🚀 Auto-Deploy siduserlast on This Account", f"sw:deploy_sid:{acc_id}", style="success")],
                [
                    BotAPI94UI.btn("🤖 Open Auto-Userbot Menu", "menu:accounts", style="primary"),
                    BotAPI94UI.btn("🏠 Dashboard", "menu:home", style="secondary"),
                ],
            ],
        )

    # ---------------------------------------------------------
    # STEP 3: Automatic 2FA Password Verification
    # ---------------------------------------------------------
    elif step == "WAIT_2FA":
        password = text
        try:
            await event.delete()
        except Exception:
            pass

        temp_client: TelegramClient = state["client"]
        try:
            await temp_client.sign_in(password=password)
            me = await temp_client.get_me()
            session_str = temp_client.session.save()
            acc_id = await db.save_user_account(
                user_id, state["phone"], session_str, tg_uid=me.id, tg_name=me.first_name or "Userbot"
            )
            await temp_client.disconnect()
            user_conv_state.pop(user_id, None)

            await BotAPI94UI.send(
                chat_id,
                f"✅ **2FA Verified & Account Added to Auto-Userbot Menu!**\n\n"
                f"👤 **Account:** `{me.first_name}` (`{state['phone']}`)\n"
                f"🆔 **Account Key:** `{acc_id}`",
                [
                    [BotAPI94UI.btn("🚀 Auto-Deploy siduserlast on This Account", f"sw:deploy_sid:{acc_id}", style="success")],
                    [
                        BotAPI94UI.btn("🤖 Open Auto-Userbot Menu", "menu:accounts", style="primary"),
                        BotAPI94UI.btn("🏠 Dashboard", "menu:home", style="secondary"),
                    ],
                ],
            )
        except Exception as e:
            await event.respond(f"❌ **Incorrect 2FA Password:** `{e}`\nPlease try again or type `cancel`.")

    # ---------------------------------------------------------
    # STEP 4: Replace Token / Session Inside an Existing Instance
    # ---------------------------------------------------------
    elif step == "WAIT_REPLACE_TOKEN":
        instance_id = state["instance_id"]
        user_conv_state.pop(user_id, None)
        managed = process_engine.registry.get(instance_id)
        inst_record = await db.get_instance(instance_id)
        if not inst_record:
            return await event.respond("❌ Instance not found.")

        workdir = Path(inst_record["workdir"])
        token_match = BOT_TOKEN_REGEX.search(text)
        if token_match:
            new_token = token_match.group(1)
            await db.update_instance_token(instance_id, new_token)
            patched = auto_patch_workspace_credentials(workdir, user_id, bot_token=new_token)
            if managed:
                managed.env_vars["BOT_TOKEN"] = new_token
                await managed.restart()
            return await BotAPI94UI.send(
                chat_id,
                f"✅ **Token Replaced & Bot Hot-Restarted!**\n"
                f"🔧 Patched `{patched}` file(s) inside `{instance_id}` with your new `@BotFather` token.",
                build_instance_colored_keyboard(instance_id, bool(inst_record.get("repo_url"))),
            )
        else:
            return await event.respond("⚠️ Invalid BotFather token format. Please send a valid token like `123456789:AAH...`.")

    # ---------------------------------------------------------
    # STEP 5: Custom MongoDB / Redis URI Update
    # ---------------------------------------------------------
    elif step == "WAIT_MONGO_URI":
        await db.set_user_db_urls(user_id, mongo_uri=text.strip())
        user_conv_state.pop(user_id, None)
        await BotAPI94UI.send(
            chat_id,
            "✅ **Custom `MONGO_URI` Saved!**\nAll newly deployed or restarted repos will automatically receive this MongoDB connection string.",
            [[BotAPI94UI.btn("🔙 Back to DB Config", "menu:db_config", style="primary")]],
        )

    elif step == "WAIT_REDIS_URI":
        await db.set_user_db_urls(user_id, redis_uri=text.strip())
        user_conv_state.pop(user_id, None)
        await BotAPI94UI.send(
            chat_id,
            "✅ **Custom `REDIS_URI` Saved!**\nAll newly deployed or restarted repos will automatically receive this Redis URL.",
            [[BotAPI94UI.btn("🔙 Back to DB Config", "menu:db_config", style="primary")]],
        )

    # ---------------------------------------------------------
    # STEP 6: Token Input for sidhosterextrem or Custom Git Bot
    # ---------------------------------------------------------
    elif step == "WAIT_GIT_BOT_TOKEN":
        token_match = BOT_TOKEN_REGEX.search(text)
        if not token_match:
            return await event.respond("⚠️ Invalid BotFather token format. Send a token like `12345678:ABC-DEF...` or type `cancel`.")
        raw_token = token_match.group(1)
        repo_url = state["repo_url"]
        custom_name = state.get("custom_name", "")
        user_conv_state.pop(user_id, None)
        await deploy_github_repo_for_user(chat_id, user_id, repo_url, "bot_script", raw_token=raw_token, custom_name=custom_name)

    # ---------------------------------------------------------
    # STEP 7: Custom GitHub URL Input
    # ---------------------------------------------------------
    elif step == "WAIT_GIT_URL":
        match = re.match(r"^(https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)(?:\.git)?/?$", text)
        if not match:
            return await event.respond("⚠️ Please send a valid GitHub repository URL (e.g. `https://github.com/user/repo.git`).")
        repo_url = match.group(1) + ".git"
        user_conv_state[user_id] = {"step": "CHOOSE_GIT_MODE", "repo_url": repo_url}
        await BotAPI94UI.send(
            chat_id,
            f"🔗 **Repository Staged:** `{repo_url}`\nChoose how to run this repository:",
            [
                [
                    BotAPI94UI.btn("👤 Run on Active Userbot", "gitmode:ub", style="success"),
                    BotAPI94UI.btn("🤖 Run as Bot (Replace Token)", "gitmode:bot", style="primary"),
                ],
                [BotAPI94UI.btn("🚫 Cancel", "menu:home", style="danger")],
            ],
        )

    # ---------------------------------------------------------
    # STEP 8: Staging Bot Token for File Upload (.py / .zip)
    # ---------------------------------------------------------
    elif step == "WAIT_UPLOAD_BOT_TOKEN":
        token_match = BOT_TOKEN_REGEX.search(text)
        if not token_match:
            return await event.respond("⚠️ Send a valid `@BotFather` token (e.g. `123456:ABC...`).")
        pending_upload_mode[user_id] = {"mode": "bot_script", "token": token_match.group(1)}
        user_conv_state.pop(user_id, None)
        await event.respond(
            "✅ **New Bot Token Staged!**\n"
            "Now **upload your `.py` script or `.zip` archive**—any old hardcoded token inside the uploaded files will be **automatically replaced** with your new token!"
        )

    # ---------------------------------------------------------
    # STEP 9: Send STDIN to Running Process
    # ---------------------------------------------------------
    elif step == "WAIT_STDIN":
        instance_id = state["instance_id"]
        user_conv_state.pop(user_id, None)
        managed = process_engine.registry.get(instance_id)
        if managed and await managed.send_stdin(text):
            await BotAPI94UI.send(
                chat_id,
                f"⌨️ **Sent to `{instance_id}` STDIN:** `{text}`",
                build_instance_colored_keyboard(instance_id, bool(managed.repo_url)),
            )
        else:
            await event.respond("❌ Process is not running or STDIN is closed.")


# =====================================================================
# SECTION 9: MULTI-ACCOUNT SWITCHER & MENU CALLBACK HANDLERS
# =====================================================================
@hoster_client.on(events.CallbackQuery(pattern=rb"^sw:(\w+)(?::(.+))?$"))
async def handle_account_switcher_callbacks(event):
    user_id = event.sender_id
    chat_id = event.chat_id
    sub_action = event.pattern_match.group(1).decode("utf-8")
    acc_id = event.pattern_match.group(2).decode("utf-8") if event.pattern_match.group(2) else ""

    if sub_action == "select" and acc_id:
        await db.set_active_account(user_id, acc_id)
        acc = await db.get_account_by_id(acc_id)
        await event.answer(f"Switched active account to {acc['tg_name'] if acc else acc_id}!")
        return await send_account_switcher_menu(chat_id, user_id, edit_msg_id=event.message_id)

    elif sub_action == "del" and acc_id:
        await db.delete_user_account(user_id, acc_id)
        await event.answer("🗑️ Account unlinked!", alert=True)
        return await send_account_switcher_menu(chat_id, user_id, edit_msg_id=event.message_id)

    elif sub_action == "upload_acc" and acc_id:
        await db.set_active_account(user_id, acc_id)
        acc = await db.get_account_by_id(acc_id)
        pending_upload_mode[user_id] = {"mode": "userbot_script", "token": "", "account_id": acc_id}
        await event.answer()
        return await event.respond(
            f"📤 **Upload `.py` or `.zip` for Account `{acc['tg_name'] if acc else acc_id}`**\n"
            "Send your file now—we will auto-replace any hardcoded session/API keys inside the code and add it to your Auto-Userbot menu!"
        )

    elif sub_action == "deploy_sid" and acc_id:
        await db.set_active_account(user_id, acc_id)
        await event.answer("Launching siduserlast on selected account...")
        return await deploy_github_repo_for_user(
            chat_id=chat_id,
            user_id=user_id,
            repo_url=SID_USERBOT_REPO,
            bot_type="userbot_script",
            custom_name="siduserlast",
            account_id=acc_id,
        )

    elif sub_action == "deploy_all_sid":
        accounts = await db.get_user_accounts(user_id)
        if not accounts:
            return await event.answer("⚠️ Link at least one Userbot account first!", alert=True)
        await event.answer(f"🚀 Deploying siduserlast across all {len(accounts)} linked accounts...")
        for acc in accounts:
            await deploy_github_repo_for_user(
                chat_id=chat_id,
                user_id=user_id,
                repo_url=SID_USERBOT_REPO,
                bot_type="userbot_script",
                custom_name="siduserlast",
                account_id=acc["account_id"],
            )


@hoster_client.on(events.CallbackQuery(pattern=rb"^gitmode:(ub|bot)$"))
async def handle_git_mode_choice(event):
    user_id = event.sender_id
    mode = event.pattern_match.group(1).decode("utf-8")
    state = user_conv_state.get(user_id)
    if not state or "repo_url" not in state:
        return await event.answer("Session expired. Send the GitHub URL again.", alert=True)

    repo_url = state["repo_url"]
    if mode == "ub":
        user_conv_state.pop(user_id, None)
        await event.answer("Cloning Userbot repository...")
        await deploy_github_repo_for_user(event.chat_id, user_id, repo_url, "userbot_script")
    else:
        user_conv_state[user_id] = {"step": "WAIT_GIT_BOT_TOKEN", "repo_url": repo_url}
        await event.answer()
        await event.respond(
            f"🤖 **Send the `@BotFather` Token** you want to inject/replace inside `{repo_url}`:\n*(Just paste the token as a message)*"
        )


@hoster_client.on(events.CallbackQuery(pattern=rb"^menu:(.+)"))
async def handle_menu_callbacks(event):
    user_id = event.sender_id
    chat_id = event.chat_id
    action = event.pattern_match.group(1).decode("utf-8")

    if action == "home":
        user_conv_state.pop(user_id, None)
        await event.answer()
        return await send_home_dashboard(chat_id, user_id, edit_msg_id=event.message_id)

    elif action == "accounts":
        await event.answer()
        return await send_account_switcher_menu(chat_id, user_id, edit_msg_id=event.message_id)

    elif action == "db_config":
        await event.answer()
        urls = await db.get_user_db_urls(user_id)
        text = (
            "🗄️ **Auto-Injected MongoDB & Redis Configuration**\n\n"
            f"• **`MONGO_URI`:** `{urls['mongo_uri'][:45]}...`\n"
            f"• **`REDIS_URI`:** `{urls['redis_uri']}`\n\n"
            "Every cloned GitHub repository (`siduserlast`, `sidhosterextrem`, etc.) and uploaded script automatically has its `.env` and hardcoded `MONGO_URI`/`REDIS_URI` patched."
        )
        rows = [
            [
                BotAPI94UI.btn("✏️ Set Custom MONGO_URI", "menu:set_mongo", style="primary"),
                BotAPI94UI.btn("✏️ Set Custom REDIS_URI", "menu:set_redis", style="primary"),
            ],
            [BotAPI94UI.btn("🔙 Back to Dashboard", "menu:home", style="secondary")],
        ]
        return await BotAPI94UI.edit(chat_id, event.message_id, text, rows)

    elif action == "set_mongo":
        user_conv_state[user_id] = {"step": "WAIT_MONGO_URI"}
        await event.answer()
        return await event.respond("🗄️ **Send your `mongodb+srv://...` URI** directly as a message (or type `cancel`):")

    elif action == "set_redis":
        user_conv_state[user_id] = {"step": "WAIT_REDIS_URI"}
        await event.answer()
        return await event.respond("⚡ **Send your `redis://...` URI** directly as a message (or type `cancel`):")

    elif action == "login":
        user_conv_state[user_id] = {"step": "WAIT_PHONE"}
        await event.answer()
        await BotAPI94UI.send(
            chat_id,
            "📱 **Add / Connect a Userbot Account (Zero-Command Login)**\n\n"
            "👉 **Send your phone number with country code** right now as a normal message (e.g. `+919876543210`).\n"
            "*(You can add multiple accounts and manage all of them inside the Auto-Userbot Menu!)*",
            [[BotAPI94UI.btn("🚫 Cancel", "menu:home", style="danger")]],
        )

    elif action == "git_siduserbot":
        await event.answer("Launching siduserlast on your Active Account...")
        await deploy_github_repo_for_user(
            chat_id=chat_id,
            user_id=user_id,
            repo_url=SID_USERBOT_REPO,
            bot_type="userbot_script",
            custom_name="siduserlast",
        )

    elif action == "git_sidhoster":
        user_conv_state[user_id] = {
            "step": "WAIT_GIT_BOT_TOKEN",
            "repo_url": SID_HOSTER_REPO,
            "custom_name": "sidhosterextrem",
        }
        await event.answer()
        await BotAPI94UI.send(
            chat_id,
            f"🛸 **Auto-Deploy `sidhosterextrem` from GitHub**\n"
            f"🔗 Repo: `{SID_HOSTER_REPO}`\n\n"
            "👉 **Send the `@BotFather` Token** for this hoster bot directly in chat (we will auto-replace any token inside the cloned repo):",
            [[BotAPI94UI.btn("🚫 Cancel", "menu:home", style="danger")]],
        )

    elif action == "git_custom":
        user_conv_state[user_id] = {"step": "WAIT_GIT_URL"}
        await event.answer()
        await BotAPI94UI.send(
            chat_id,
            "🌐 **Clone & Host Any GitHub Repository**\n\n"
            "👉 **Paste the GitHub repository URL** directly in chat (e.g. `https://github.com/username/repo.git`):",
            [[BotAPI94UI.btn("🚫 Cancel", "menu:home", style="danger")]],
        )

    elif action == "upload_ub":
        active_acc = await db.get_active_account(user_id)
        if not active_acc:
            return await event.answer("Connect a Userbot account first!", alert=True)
        pending_upload_mode[user_id] = {"mode": "userbot_script", "token": "", "account_id": active_acc["account_id"]}
        await event.answer()
        await event.respond(
            f"📤 **Upload Your Userbot `.py` or `.zip` File**\n"
            f"👤 Target Account: `{active_acc['tg_name']} ({active_acc['phone']})`\n"
            "Simply send the file here—we will auto-replace any hardcoded session/API keys inside the code, inject `MONGO_URI` & `REDIS_URI`, and show it inside your **Auto-Userbot Menu**!"
        )

    elif action == "upload_bot":
        user_conv_state[user_id] = {"step": "WAIT_UPLOAD_BOT_TOKEN"}
        await event.answer()
        await event.respond(
            "🤖 **Send your new `@BotFather` token** as a normal message first, then upload your `.py` or `.zip` file.\n"
            "*(Even if your uploaded script has an old hardcoded token inside it, we will automatically replace it with your new token!)*"
        )

    elif action == "new_flow":
        await event.answer()
        await event.respond("🔀 Send `/newflow <BOT_TOKEN>` to spin up an instant JSON menu Flowbot.")

    elif action == "server_stats":
        vm = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=0.1)
        running_cnt = sum(1 for m in process_engine.registry.values() if m.status == "running")
        await event.answer(
            f"🖥️ Host Server Telemetry\n"
            f"• CPU Load: {cpu}%\n"
            f"• RAM Used: {round(vm.used / (1024**2))} / {round(vm.total / (1024**2))} MB ({vm.percent}%)\n"
            f"• Active Subprocesses: {running_cnt} / {len(process_engine.registry)}\n"
            f"• Active Flowbots: {len(flowbot_registry)}",
            alert=True,
        )

    elif action == "my_bots":
        instances = await db.get_user_instances(user_id)
        if not instances:
            return await event.answer("You have no hosted processes yet!", alert=True)

        rows = []
        for inst in instances:
            iid = inst["instance_id"]
            managed = process_engine.registry.get(iid)
            status = managed.status if managed else inst["status"]
            style = "success" if status == "running" else ("danger" if status in ("stopped", "crashed") else "secondary")
            icon = "🟢" if status == "running" else ("⏸️" if status == "paused" else "🔴")
            rows.append([BotAPI94UI.btn(f"{icon} {inst['name']} ({iid})", f"ctl:view:{iid}", style=style)])

        rows.append([BotAPI94UI.btn("🤖 Auto-Userbot Menu", "menu:accounts", style="primary")])
        rows.append([BotAPI94UI.btn("🔙 Back to Dashboard", "menu:home", style="secondary")])
        await event.answer()
        await BotAPI94UI.edit(chat_id, event.message_id, "🎛 **Process & Task Manager — Select an Instance:**", rows)


# =====================================================================
# SECTION 10: FILE UPLOADER (.py / .zip) WITH AUTO TOKEN REPLACER
# =====================================================================
@hoster_client.on(events.NewMessage(func=lambda e: bool(e.file and e.file.name)))
async def handle_script_or_zip_upload(event):
    fname = event.file.name
    if not (fname.endswith(".py") or fname.endswith(".zip")):
        return

    user_id = event.sender_id
    chat_id = event.chat_id
    if event.file.size > MAX_UPLOAD_BYTES:
        return await event.respond("❌ **File exceeds 25 MB upload limit.**")

    mode_info = pending_upload_mode.get(user_id, {"mode": "userbot_script", "token": "", "account_id": ""})
    bot_type = mode_info["mode"]
    raw_token = mode_info.get("token", "")
    account_id = mode_info.get("account_id", "")

    status_msg = await event.respond(f"📥 **Downloading `{fname}` & scanning credentials...**")

    clean_stem = "".join(c for c in Path(fname).stem if c.isalnum() or c in ("_", "-"))[:18]
    temp_dir = WORKSPACES_DIR / f"user_{user_id}" / f"tmp_{clean_stem}_{int(time.time())}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    downloaded_path = temp_dir / fname
    await event.download_media(file=str(downloaded_path))

    try:
        if fname.endswith(".zip"):
            entrypoint = safe_extract_and_scan_zip(downloaded_path, temp_dir)
        else:
            code = downloaded_path.read_text(encoding="utf-8", errors="ignore")
            scan_python_source(code, filename=fname)
            entrypoint = fname

        # Check if the uploaded file already has a hardcoded BotFather token inside!
        detected_file_token = extract_hardcoded_token_from_dir(temp_dir)
        if detected_file_token and not raw_token and user_id not in pending_upload_mode:
            bot_type = "bot_script"
            raw_token = detected_file_token

        session_str = ""
        acc_tag = ""
        if bot_type == "userbot_script":
            target_acc = await db.get_account_by_id(account_id) if account_id else await db.get_active_account(user_id)
            if not target_acc:
                shutil.rmtree(temp_dir, ignore_errors=True)
                await status_msg.delete()
                return await BotAPI94UI.send(
                    chat_id,
                    "⚠️ **No Userbot Account Linked!**\nConnect a Userbot account first or stage a Bot token via **🤖 Host Standard Bot**.",
                    [[BotAPI94UI.btn("🔐 Connect Userbot Now", "menu:login", style="success")]],
                )
            account_id = target_acc["account_id"]
            session_str = vault.decrypt(target_acc["encrypted_session"])
            phone_digits = re.sub(r"[^\d]", "", target_acc["phone"])[-4:] or "acct"
            acc_tag = f"_{phone_digits}"

        instance_id = f"{'ub' if bot_type == 'userbot_script' else 'bot'}_{user_id}{acc_tag}_{clean_stem}"
        workdir = WORKSPACES_DIR / f"user_{user_id}" / instance_id
        if workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
        shutil.move(str(temp_dir), str(workdir))

        # Auto-replace hardcoded token/session/API_ID/API_HASH/DB URLs inside the uploaded files
        db_urls = await db.get_user_db_urls(user_id)
        patched_files = auto_patch_workspace_credentials(
            workdir=workdir,
            owner_id=user_id,
            bot_token=raw_token,
            session_str=session_str,
            mongo_uri=db_urls["mongo_uri"],
            redis_uri=db_urls["redis_uri"],
        )

        env_vars = {
            "MONGO_URI": db_urls["mongo_uri"],
            "REDIS_URI": db_urls["redis_uri"],
        }
        if session_str:
            env_vars["SESSION_STRING"] = session_str
        if raw_token:
            env_vars["BOT_TOKEN"] = raw_token

        await db.register_instance(
            instance_id=instance_id,
            owner_id=user_id,
            bot_type=bot_type,
            name=f"{clean_stem}{acc_tag}",
            workdir=str(workdir),
            entrypoint=entrypoint,
            raw_token=raw_token,
            ram_limit_mb=MAX_RAM_MB_PER_BOT,
            account_id=account_id,
            raw_session=session_str,
        )

        managed = await process_engine.spawn_instance(
            instance_id=instance_id,
            owner_id=user_id,
            workdir=workdir,
            entrypoint=entrypoint,
            env_vars=env_vars,
        )
        pending_upload_mode.pop(user_id, None)
        await status_msg.delete()

        m = managed.get_metrics()
        await BotAPI94UI.send(
            chat_id,
            f"✅ **Uploaded Script Hosted & Added to Menus!**\n\n"
            f"🏷 **Instance ID:** `{instance_id}`\n"
            f"📂 **Entrypoint:** `{entrypoint}`\n"
            f"🔧 **Auto-Patched Files:** `{patched_files} file(s) updated with your Token/Session`\n"
            f"🗄️ **Injected DBs:** `MONGO_URI` & `REDIS_URI` ✅\n"
            f"🔢 **PID:** `{m['pid']}` | **RAM:** `{m['ram_mb']} MB`\n\n"
            f"💡 *Click **🔑 Replace Bot Token / Session** below anytime to swap the token inside this bot on the fly!*",
            build_instance_colored_keyboard(instance_id, has_git=False, is_bot=(bot_type == "bot_script")),
        )
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        await status_msg.edit(f"❌ **Deployment Error:**\n`{exc}`")


@hoster_client.on(events.CallbackQuery(pattern=rb"^ctl:(\w+):(.+)"))
async def handle_process_controls(event):
    action = event.pattern_match.group(1).decode("utf-8")
    instance_id = event.pattern_match.group(2).decode("utf-8")
    user_id = event.sender_id
    chat_id = event.chat_id

    inst_record = await db.get_instance(instance_id)
    if not inst_record or (inst_record["owner_id"] != user_id and user_id not in ADMIN_IDS):
        return await event.answer("❌ Instance not found or access denied.", alert=True)

    managed = process_engine.registry.get(instance_id)
    has_git = bool(inst_record.get("repo_url")) or (Path(inst_record["workdir"]) / ".git").exists()

    if action == "view":
        await event.answer()
        m = managed.get_metrics() if managed else {
            "status": inst_record["status"], "pid": None, "ram_mb": 0, "vms_mb": 0,
            "cpu_percent": 0, "threads": 0, "children": 0, "uptime_sec": 0
        }
        return await BotAPI94UI.edit(
            chat_id,
            event.message_id,
            f"🎛 **Task Manager: `{instance_id}`**\n\n"
            f"• **Status:** `{m['status'].upper()}`\n"
            f"• **Account Key:** `{inst_record.get('account_id') or 'Bot Token'}`\n"
            f"• **Entrypoint:** `{inst_record['entrypoint']}`\n"
            f"• **GitHub Repo:** `{inst_record.get('repo_url') or 'Local Upload'}`\n"
            f"• **PID:** `{m['pid']}` (Children: `{m['children']}`, Threads: `{m['threads']}`)\n"
            f"• **Memory:** `{m['ram_mb']} / {inst_record['ram_limit_mb']} MB` (VMS: `{m['vms_mb']} MB`)\n"
            f"• **CPU:** `{m['cpu_percent']}%` | **Uptime:** `{m['uptime_sec']}s`",
            build_instance_colored_keyboard(instance_id, has_git=has_git),
        )

    elif action == "chtoken":
        user_conv_state[user_id] = {"step": "WAIT_REPLACE_TOKEN", "instance_id": instance_id}
        await event.answer()
        return await event.respond(
            f"🔑 **Replace Token Inside `{instance_id}`**\n\n"
            "👉 **Send the new `@BotFather` token** right now as a message.\n"
            "We will automatically rewrite the hardcoded token inside the bot's `.py` and `.env` files and hot-restart the process!"
        )

    elif action == "pause" and managed:
        ok = managed.pause()
        await event.answer("⏸️ Process tree suspended!" if ok else "Process is not running.", alert=True)

    elif action == "resume":
        if managed and managed.status == "paused":
            managed.resume()
            await event.answer("▶️ Process tree resumed!", alert=True)
        elif managed:
            await managed.start()
            await event.answer("🚀 Process started!", alert=True)
        else:
            db_urls = await db.get_user_db_urls(inst_record["owner_id"])
            env_vars = {
                "MONGO_URI": db_urls["mongo_uri"],
                "REDIS_URI": db_urls["redis_uri"],
            }
            if inst_record.get("encrypted_session"):
                env_vars["SESSION_STRING"] = vault.decrypt(inst_record["encrypted_session"])
            elif inst_record["bot_type"] == "userbot_script":
                sess = await db.get_user_session(inst_record["owner_id"], inst_record.get("account_id", ""))
                if sess:
                    env_vars["SESSION_STRING"] = sess
            if inst_record["encrypted_token"]:
                env_vars["BOT_TOKEN"] = vault.decrypt(inst_record["encrypted_token"])
            managed = await process_engine.spawn_instance(
                instance_id=instance_id,
                owner_id=inst_record["owner_id"],
                workdir=Path(inst_record["workdir"]),
                entrypoint=inst_record["entrypoint"],
                env_vars=env_vars,
                repo_url=inst_record.get("repo_url", ""),
                ram_limit_mb=inst_record["ram_limit_mb"],
            )
            await event.answer("🚀 Process cold-spawned from DB!", alert=True)

    elif action == "restart" and managed:
        await event.answer("🔄 Restarting process tree...")
        await managed.restart()

    elif action == "stop" and managed:
        await managed.stop()
        await event.answer("🛑 Graceful SIGTERM completed.", alert=True)

    elif action == "kill" and managed:
        await managed.force_kill()
        await event.answer("💀 Immediate SIGKILL (-9) executed!", alert=True)

    elif action == "gitpull" and managed:
        await event.answer("📥 Pulling latest commits from GitHub & restarting...")
        git_out = await managed.git_pull_update()
        await BotAPI94UI.send(
            chat_id,
            f"📥 **Git Pull Result (`{instance_id}`):**\n```text\n{git_out[:3000]}\n```",
            [[BotAPI94UI.btn("🎛 Back to Task Manager", f"ctl:view:{instance_id}", style="primary")]],
        )

    elif action == "stdin" and managed:
        user_conv_state[user_id] = {"step": "WAIT_STDIN", "instance_id": instance_id}
        await event.answer()
        return await event.respond(f"⌨️ **Send the line of text** you want to pipe into `{instance_id}`'s STDIN (or type `cancel`):")

    elif action == "stats" and managed:
        m = managed.get_metrics()
        return await event.answer(
            f"🔬 Deep Task Inspector\n"
            f"• Status: {m['status'].upper()}\n"
            f"• PID: {m['pid']} | Threads: {m['threads']}\n"
            f"• Child Subprocesses: {m['children']}\n"
            f"• RSS RAM: {m['ram_mb']} MB | VMS: {m['vms_mb']} MB\n"
            f"• CPU Usage: {m['cpu_percent']}%\n"
            f"• Uptime: {m['uptime_sec']} sec",
            alert=True,
        )

    elif action == "livelog" and managed:
        await event.answer("🔴 Starting 15s Live Log Stream...")
        for _ in range(7):
            tail = "\n".join(list(managed.log_buffer)[-25:]) or "Waiting for stdout/stderr output..."
            m = managed.get_metrics()
            stream_kb = [
                [
                    BotAPI94UI.btn("🔄 Stream Again (15s)", f"ctl:livelog:{instance_id}", style="success"),
                    BotAPI94UI.btn("📄 Download .log", f"ctl:dl_log:{instance_id}", style="primary"),
                ],
                [
                    BotAPI94UI.btn("🤖 Auto-Userbot Menu", "menu:accounts", style="primary"),
                    BotAPI94UI.btn("🎛 Task Manager", f"ctl:view:{instance_id}", style="secondary"),
                ],
            ]
            await BotAPI94UI.edit(
                chat_id,
                event.message_id,
                f"🔴 **LIVE LOG STREAM (`{instance_id}`) — {m['status'].upper()} [PID: `{m['pid']}`]**\n"
                f"```text\n{tail[-3400:]}\n```",
                stream_kb,
            )
            await asyncio.sleep(2.0)
        return

    elif action == "logs" and managed:
        await event.answer()
        tail = "\n".join(list(managed.log_buffer)[-30:]) or "No stdout/stderr logs emitted yet."
        return await BotAPI94UI.send(
            chat_id,
            f"📜 **Live Log Tail (`{instance_id}`):**\n```text\n{tail[-3500:]}\n```",
            [
                [
                    BotAPI94UI.btn("🔴 Live Stream (15s)", f"ctl:livelog:{instance_id}", style="success"),
                    BotAPI94UI.btn("🔄 Refresh Tail", f"ctl:logs:{instance_id}", style="primary"),
                    BotAPI94UI.btn("📄 Full .log", f"ctl:dl_log:{instance_id}", style="secondary"),
                ],
                [BotAPI94UI.btn("🎛 Back to Task Manager", f"ctl:view:{instance_id}", style="secondary")],
            ],
        )

    elif action == "dl_log":
        log_path = LOGS_DIR / f"{instance_id}.log"
        if not log_path.exists() or log_path.stat().st_size == 0:
            return await event.answer("Log file is empty or does not exist yet.", alert=True)
        await event.answer("📤 Uploading full .log file...")
        return await hoster_client.send_file(
            chat_id,
            file=str(log_path),
            caption=f"📄 **Full Log File:** `{instance_id}.log`",
        )

    elif action == "delete":
        await process_engine.purge_instance(instance_id)
        await event.answer("🗑️ Instance deleted!", alert=True)
        return await send_home_dashboard(chat_id, user_id, edit_msg_id=event.message_id)

    if managed:
        m = managed.get_metrics()
        await BotAPI94UI.edit(
            chat_id,
            event.message_id,
            f"🎛 **Task Manager: `{instance_id}`**\n\n"
            f"• **Status:** `{m['status'].upper()}`\n"
            f"• **Account Key:** `{inst_record.get('account_id') or 'Bot Token'}`\n"
            f"• **Entrypoint:** `{inst_record['entrypoint']}`\n"
            f"• **PID:** `{m['pid']}` (Children: `{m['children']}`, Threads: `{m['threads']}`)\n"
            f"• **Memory:** `{m['ram_mb']} / {inst_record['ram_limit_mb']} MB`\n"
            f"• **CPU:** `{m['cpu_percent']}%` | **Uptime:** `{m['uptime_sec']}s`",
            build_instance_colored_keyboard(instance_id, has_git=has_git),
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
                "text": "⚡ **Cloud Bot & Userbot Hosting**\n• 24/7 Watchdog Uptime\n• GitHub Auto-Deploy",
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
# SECTION 11: MAIN ORCHESTRATOR & AUTO-RESTORE ON BOOT
# =====================================================================
async def restore_persisted_bots():
    for rec in await db.get_all_active_instances():
        workdir = Path(rec["workdir"])
        if not workdir.exists():
            await db.update_instance_status(rec["instance_id"], "stopped")
            continue

        db_urls = await db.get_user_db_urls(rec["owner_id"])
        env_vars = {
            "MONGO_URI": db_urls["mongo_uri"],
            "REDIS_URI": db_urls["redis_uri"],
        }
        if rec.get("encrypted_session"):
            env_vars["SESSION_STRING"] = vault.decrypt(rec["encrypted_session"])
        elif rec["bot_type"] == "userbot_script":
            session_str = await db.get_user_session(rec["owner_id"], rec.get("account_id", ""))
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
                repo_url=rec.get("repo_url", ""),
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
    print("1. Initializing SQLite Database (Multi-Account & DB URLs)...")
    await db.init_db()

    print("2. Starting Process Watchdog & OOM Monitor...")
    process_engine.start_watchdog()

    print("3. Restoring Previously Running Multi-Account Bots & GitHub Repos...")
    await restore_persisted_bots()

    print("4. Starting Master Hoster Bot...")
    await hoster_client.start(bot_token=HOSTER_BOT_TOKEN)
    me = await hoster_client.get_me()
    print(f"✅ Hoster Bot Online as @{me.username}! Auto-Token Replacer & Auto-Userbot Menu Active...")

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
