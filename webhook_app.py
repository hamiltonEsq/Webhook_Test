# webhook_app.py
import os
import hmac
import hashlib
import subprocess
import logging
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Header, BackgroundTasks
from dotenv import load_dotenv  # <-- добавляем загрузку .env

# --------------------------------------------------------------------------- #
# 1️⃣  Загрузка переменных окружения из .env
# --------------------------------------------------------------------------- #
load_dotenv()                     # читает .env в текущей директории
SCRIPT_PATH = os.getenv("SCRIPT_PATH")
# --------------------------------------------------------------------------- #

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("webhook")

app = FastAPI()


def get_secret() -> bytes:
    """Читаем секрет каждый раз – безопаснее при перезапуске контейнера."""
    return os.getenv("GITHUB_SECRET", "MY_SUPER_SECRET").encode()


def verify_signature(payload: bytes, signature: str) -> bool:
    mac = hmac.new(get_secret(), payload, hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, signature)


def run_script() -> None:
    """Запускает скрипт и логирует вывод."""
    if not SCRIPT_PATH.is_file():
        log.error("Script %s not found!", SCRIPT_PATH)
        return

    # Запускаем скрипт без оболочки (чтобы избежать проблем с `shell=True`)
    proc = subprocess.run(
        [str(SCRIPT_PATH)],
        capture_output=True,
        text=True,
        env=os.environ,  # передаём переменные окружения (REPO_PATH, SERVICE_NAME …)
    )

    if proc.returncode == 0:
        log.info("✅ Script %s completed successfully.", SCRIPT_PATH)
        log.debug("Script stdout:\n%s", proc.stdout.strip())
    else:
        log.error(
            "❌ Script %s failed with rc=%s.",
            SCRIPT_PATH,
            proc.returncode,
        )
        log.error("stderr:\n%s", proc.stderr.strip())


def handle_push(payload: dict) -> None:
    """
    Обрабатываем push‑событие:
    1. Делаете git pull (можно оставить, если скрипт делает то же самое).
    2. Запускаем пользовательский скрипт.
    """
    repo_dir = Path(os.getenv("REPO_PATH", ".")).resolve()
    if not (repo_dir / ".git").exists():
        log.error("Repo not found at %s", repo_dir)
        return

    # --- 1️⃣ Git pull (необязательно, если скрипт всё делает) ---
    pull_res = subprocess.run(
        ["git", "pull"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    log.info(
        "[git pull] rc=%s out=%s err=%s",
        pull_res.returncode,
        pull_res.stdout.strip(),
        pull_res.stderr.strip(),
    )

    # --- 2️⃣ Запуск кастомного скрипта ---
    run_script()


@app.post("/github-webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(..., alias="X-Hub-Signature-256"),
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
):
    # проверяем тип контента
    if request.headers.get("content-type") != "application/json":
        raise HTTPException(status_code=415, detail="Unsupported Media Type")

    body = await request.body()
    if not verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=400, detail="Invalid signature")

    payload = await request.json()
    log.info("=== Received %s ===", x_github_event)

    if x_github_event == "push":
        background_tasks.add_task(handle_push, payload)

    return {"status": "queued"}