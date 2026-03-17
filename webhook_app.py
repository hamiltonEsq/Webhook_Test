# webhook_app.py
# --------------------------------------------------------------
# Webhook‑сервер, принимающий push‑события от GitHub и
# выполняющий пользовательский скрипт.
# --------------------------------------------------------------

import os
import hmac
import hashlib
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Header, BackgroundTasks
from dotenv import load_dotenv

# -------------------------- 1️⃣ Загрузка .env -------------------------- #
load_dotenv()                         # читаем .env из текущей директории
SCRIPT_PATH   = Path(os.getenv("SCRIPT_PATH", "./script.sh")).resolve()
REPO_PATH     = Path(os.getenv("REPO_PATH", ".")).resolve()
GITHUB_SECRET = os.getenv("GITHUB_SECRET", "MY_SUPER_SECRET")
SERVICE_NAME  = os.getenv("SERVICE_NAME", "")

# -------------------------- 2️⃣ Настройка логирования ------------------- #
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("webhook.log"),   # запись в файл
        logging.StreamHandler()               # и вывод в консоль
    ],
)
log = logging.getLogger("webhook")

# -------------------------- 3️⃣ FastAPI приложение ---------------------- #
app = FastAPI()


# -------------------------- 4️⃣ Утилиты -------------------------------- #
def get_secret() -> bytes:
    """Возвращает текущий секрет в виде bytes (читаем каждый раз)."""
    return GITHUB_SECRET.encode()


def verify_signature(payload: bytes, signature: str) -> bool:
    """Проверка подписи X‑Hub‑Signature‑256."""
    mac = hmac.new(get_secret(), payload, hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, signature)


def notify(message: str) -> None:
    """
    Плейсхолдер для отправки уведомлений (Telegram, Slack, Email и т.д.).
    Реализуйте по‑своему, например, через python‑telegram‑bot.
    """
    # пример:
    # telegram_bot.send_message(chat_id=CHAT_ID, text=message)
    pass


# -------------------------- 5️⃣ Запуск пользовательского скрипта ---------- #
def run_script() -> None:
    """Запускает скрипт, логирует stdout/stderr и сохраняет время последнего успеха."""
    if not SCRIPT_PATH.is_file():
        log.error("Script %s not found!", SCRIPT_PATH)
        notify(f"❌ Script not found: {SCRIPT_PATH}")
        return

    log.info("🚀 Starting script %s …", SCRIPT_PATH)

    try:
        proc = subprocess.run(
            [str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            env=os.environ,                # передаём переменные окружения
            timeout=300,                   # 5 минут – защита от зависания
        )
    except subprocess.TimeoutExpired:
        log.error("⏰ Script %s timed‑out after 300 s", SCRIPT_PATH)
        notify(f"⏰ Script timed‑out: {SCRIPT_PATH}")
        return
    except Exception as exc:
        log.exception("💥 Unexpected error while running %s", SCRIPT_PATH)
        notify(f"💥 Error while running script: {exc}")
        return

    if proc.returncode == 0:
        log.info("✅ Script %s completed successfully.", SCRIPT_PATH)
        log.debug("stdout:\n%s", proc.stdout.strip())
        # сохраняем время последнего успешного запуска
        run_script.last_success = datetime.utcnow()
        notify(f"✅ Script finished: {SCRIPT_PATH}")
    else:
        log.error(
            "❌ Script %s failed (rc=%s).",
            SCRIPT_PATH,
            proc.returncode,
        )
        log.error("stderr:\n%s", proc.stderr.strip())
        notify(f"❌ Script failed ({SCRIPT_PATH}): {proc.stderr.strip()}")


# Атрибут для health‑эндпоинта
run_script.last_success: Optional[datetime] = None


# -------------------------- 6️⃣ Обработка push‑события ------------------- #
def handle_push(payload: dict) -> None:
    """Обрабатывает событие push: git pull + запуск скрипта."""
    if not (REPO_PATH / ".git").exists():
        log.error("Repo not found at %s", REPO_PATH)
        notify(f"❌ Repo not found: {REPO_PATH}")
        return

    # 1️⃣ git pull (можно отключить, если скрипт делает всё сам)
    log.info("🔄 Running 'git pull' in %s …", REPO_PATH)
    pull_res = subprocess.run(
        ["git", "pull"],
        cwd=REPO_PATH,
        capture_output=True,
        text=True,
        timeout=60,
    )
    log.info(
        "[git pull] rc=%s out=%s err=%s",
        pull_res.returncode,
        pull_res.stdout.strip(),
        pull_res.stderr.strip(),
    )

    # 2️⃣ Запуск пользовательского скрипта
    run_script()


# -------------------------- 7️⃣ Маршрут webhook ------------------------ #
@app.post("/github-webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(..., alias="X-Hub-Signature-256"),
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
):
    # 7️⃣1️⃣ Проверка типа контента
    if request.headers.get("content-type") != "application/json":
        raise HTTPException(status_code=415, detail="Unsupported Media Type")

    # 7️⃣2️⃣ Читаем тело запроса
    body = await request.body()

    # 7️⃣3️⃣ Валидация подписи
    if not verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=400, detail="Invalid signature")

    # 7️⃣4️⃣ Партим JSON‑payload
    payload = await request.json()
    log.info("=== Received %s event ===", x_github_event)

    # 7️⃣5️⃣ Обрабатываем только push
    if x_github_event == "push":
        background_tasks.add_task(handle_push, payload)

    # GitHub не ждет результата выполнения скрипта, просто подтверждаем прием
    return {"status": "queued"}


# -------------------------- 8️⃣ Health‑эндпоинт ------------------------ #
@app.get("/health")
async def health():
    """Возвращает информацию о последнем успешном запуске скрипта."""
    last = run_script.last_success.isoformat() if run_script.last_success else None
    return {
        "status": "ok",
        "script_last_success_utc": last,
        "script_path": str(SCRIPT_PATH),
        "repo_path": str(REPO_PATH),
    }