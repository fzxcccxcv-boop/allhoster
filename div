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
API_ID = int(os.getenv("API_ID", "33491590"))  # Replace with your API_ID from my.telegram.org
API_HASH = os.getenv("API_HASH", "35eb3cd440c7ad282cfdc2ce557e37f6")
HOSTER_BOT_TOKEN = os.getenv("HOSTER_BOT_TOKEN", "9071346261:AAEfem_w7JBCvy11cIZAC7vYc6x8Kqq0cYI")

ADMIN_IDS = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "8684812026").split(",")
    if x.strip().isdigit()
}

# =========================================================
# 3. INTEGRATED GITHUB REPOSITORIES
# =========================================================
SID_USERBOT_REPO = os.getenv(
    "SID_USERBOT_REPO",
    "https://github.com/fzxcccxcv-boop/siduserlast.git"
)
SID_HOSTER_REPO = os.getenv(
    "SID_HOSTER_REPO",
    "https://github.com/fzxcccxcv-boop/sidhosterextrem.git"
)

TRUSTED_GITHUB_REPOS = {
    SID_USERBOT_REPO.lower(),
    SID_HOSTER_REPO.lower(),
}

# =========================================================
# 4. AUTO-INJECTED MONGODB, SQL & REDIS URLS
# =========================================================
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://username:password@cluster0.mongodb.net/sidbot_db?retryWrites=true&w=majority"
)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///bot_database.sqlite3")
REDIS_URI = os.getenv("REDIS_URI", "redis://localhost:6379/0")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost:6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# =========================================================
# 5. PROCESS QUOTAS & SECURITY LIMITS
# =========================================================
MAX_RAM_MB_PER_BOT = int(os.getenv("MAX_RAM_MB_PER_BOT", "300"))
MAX_UPLOAD_BYTES = 25 * 1024 * 1024         # 25 MB max file upload size (.py or .zip)
MAX_ZIP_EXTRACTED_BYTES = 60 * 1024 * 1024  # 60 MB Zip extraction ceiling
MAX_ZIP_FILES = 150                         # Max files inside a .zip upload
MAX_CRASH_RESTARTS = 5                      # Max auto-restarts before marking 'crashed'

STRICT_AST_SCAN = False

ALLOWED_PIP_PACKAGES = {
    "telethon", "pyrogram", "kurigram", "aiogram", "pytgcalls", "ntgcalls",
    "aiohttp", "httpx", "requests", "beautifulsoup4", "lxml", "pillow",
    "pytz", "python-dotenv", "motor", "pymongo", "dnspython", "aiosqlite",
    "sqlalchemy", "pydantic", "humanize", "psutil", "cryptg", "tgcrypto",
    "cryptography", "gitpython", "heroku3", "speedtest-cli", "yt-dlp",
    "search-engine-parser", "gtts", "telegraph", "pyyaml", "colorama", "redis", "aioredis"
}

def get_venv_python(venv_dir: Path) -> str:
    """Returns the correct Python interpreter path for Windows or Linux virtual environments."""
    if sys.platform == "win32":
        py_exe = venv_dir / "Scripts" / "python.exe"
    else:
        py_exe = venv_dir / "bin" / "python"
    return str(py_exe if py_exe.exists() else Path(sys.executable))
