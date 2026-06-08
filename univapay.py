import os, httpx, json, hmac, hashlib
from datetime import datetime

def _load_env(path):
    env = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

_env = _load_env(os.path.expanduser("~/.secrets/univapay.env"))

APP_TOKEN     = _env.get("UNIVAPAY_APP_TOKEN", "")
SECRET        = _env.get("UNIVAPAY_SECRET", "")
WIDGET_APP_ID = _env.get("UNIVAPAY_WIDGET_APP_ID", "")
STORE_ID      = _env.get("UNIVAPAY_STORE_ID", "")

# 福祉SaaS価格
PRICE_STANDARD = 9800
PRICE_PRO      = 14800
PRICE_HQ       = 19800

BASE_URL = "https://api.univapay.com"

def _headers():
    auth = f"{APP_TOKEN}|{SECRET}" if SECRET else APP_TOKEN
    return {"Authorization": f"Bearer {auth}", "Content-Type": "application/json"}

PLAN_AMOUNTS = {"standard": PRICE_STANDARD, "pro": PRICE_PRO, "hq": PRICE_HQ}

async def create_subscription(card_token: str, plan: str, email: str, office_name: str, app_name: str) -> dict:
    amount = PLAN_AMOUNTS.get(plan, PRICE_PRO)
    payload = {
        "payment_type": "card",
        "token": card_token,
        "amount": amount,
        "currency": "jpy",
        "period": "monthly",
        "initial_amount": amount,
        "metadata": {"plan": plan, "office": office_name, "email": email, "app": app_name},
        "descriptor": app_name,
    }
    async with httpx.AsyncClient() as client:
        res = await client.post(f"{BASE_URL}/subscriptions", headers=_headers(), json=payload, timeout=30)
        res.raise_for_status()
        return res.json()

async def cancel_subscription(subscription_id: str) -> dict:
    async with httpx.AsyncClient() as client:
        res = await client.delete(f"{BASE_URL}/subscriptions/{subscription_id}", headers=_headers(), timeout=30)
        res.raise_for_status()
        return res.json()

def parse_webhook(body: bytes, signature: str) -> dict:
    if signature and APP_TOKEN:
        expected = hmac.new(APP_TOKEN.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid webhook signature")
    return json.loads(body)
