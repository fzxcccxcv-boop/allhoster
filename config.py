import os
import sys
from pathlib import Path

# =========================================================
# 1. DIRECTORY PATHS (Auto-created on boot)
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
WORKSPACES_DIR = BASE_DIR / "workspaces"
LOGS_DIR = BASE_DIR / "logs"
DB_DIR = BASE_DIR / "db"
DB_PATH = DB_DIR / "platform.sqlite3"
SECRET_KEY_FILE = BASE_DIR / ".secret.key"

for folder in (WORKSPACES_DIR, LOGS_DIR, DB_DIR):
    folder.mkdir(parents=True, exist_ok=True)

# =========================================================
# 2. TELEGRAM API & BOT CREDENTIALS
# =========================================================
API_ID = int(os.getenv("API_ID", "33491590"))  # Replace or set in ENV
API_HASH = os.getenv("API_HASH", "35eb3cd440c7ad282cfdc2ce557e37f6")
HOSTER_BOT_TOKEN = os.getenv("HOSTER_BOT_TOKEN", "9071346261:AAEfem_w7JBCvy11cIZAC7vYc6x8Kqq0cYI")

# Optional: Comma-separated Telegram user IDs of platform admins
ADMIN_IDS = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "8684812026").split(",")
    if x.strip().isdigit()
}

# =========================================================
# 3. PROCESS QUOTAS & SECURITY LIMITS
# =========================================================
MAX_RAM_MB_PER_BOT = 150                    # Auto-kill subprocess if RAM exceeds 150 MB
MAX_UPLOAD_BYTES = 15 * 1024 * 1024         # 15 MB max file upload size (.py or .zip)
MAX_ZIP_EXTRACTED_BYTES = 35 * 1024 * 1024  # 35 MB Zip-Bomb extraction ceiling
MAX_ZIP_FILES = 60                          # Max files allowed inside a .zip upload
MAX_CRASH_RESTARTS = 5                      # Max auto-restarts before marking 'crashed'

# Whitelisted pip packages allowed in user-uploaded requirements.txt
ALLOWED_PIP_PACKAGES = {
    "telethon", "pyrogram", "kurigram", "aiogram", "pytgcalls",
    "aiohttp", "httpx", "requests", "beautifulsoup4", "lxml",
    "pillow", "pytz", "python-dotenv", "motor", "pymongo",
    "aiosqlite", "sqlalchemy", "pydantic", "humanize", "psutil"
}

def get_venv_python(venv_dir: Path) -> str:
    """Returns the correct Python interpreter path for Windows or Linux virtual environments."""
    if sys.platform == "win32":
        py_exe = venv_dir / "Scripts" / "python.exe"
    else:
        py_exe = venv_dir / "bin" / "python"
    return str(py_exe if py_exe.exists() else Path(sys.executable))
