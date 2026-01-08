import os, hmac, hashlib, subprocess, pathlib, logging
from fastapi import FastAPI, Request, HTTPException, Header, BackgroundTasks

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


def handle_push(payload: dict):
    repo_dir = pathlib.Path(os.getenv("REPO_PATH", ".")).resolve()
    if not (repo_dir / ".git").exists():
        log.error("Repo not found at %s", repo_dir)
        return

    # 1️⃣ git pull
    result = subprocess.run(
        ["git", "pull"], cwd=repo_dir, capture_output=True, text=True
    )
    log.info("[git pull] rc=%s out=%s err=%s",
             result.returncode, result.stdout.strip(), result.stderr.strip())

    # 2️⃣ restart service (if any)
    svc = os.getenv("SERVICE_NAME")
    if svc and result.returncode == 0:
        restart = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True)
        log.info("[service] restarted %s rc=%s", svc, restart.returncode)


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