from fastapi import FastAPI, Request, HTTPException, Header
import hmac, hashlib, os

app = FastAPI()
# Секрет, указанный в настройках GitHub webhook
SECRET = os.getenv("GITHUB_SECRET", "MY_SUPER_SECRET").encode()


def verify_signature(payload: bytes, signature: str) -> bool:
    """Проверка подписи X‑Hub‑Signature‑256"""
    mac = hmac.new(SECRET, payload, hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, signature)



@app.post("/github-webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: str = Header(None, alias="X-GitHub-Event"),
):
    body = await request.body()
    if x_hub_signature_256 is None or not verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=400, detail="Invalid signature")

    # ---- обработка события ----
    payload = await request.json()
    print(f"\n=== Received {x_github_event} ===")
    # Здесь можно запускать скрипт, делать pull, CI и т.п.
    print(payload)

    return {"status": "ok"}
