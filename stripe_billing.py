import os
from pathlib import Path

def _load_env(path):
    env = {}
    p = Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

_env = _load_env(os.path.expanduser("~/.secrets/stripe.env"))

SECRET_KEY     = _env.get("STRIPE_SECRET_KEY", "")
WEBHOOK_SECRET = _env.get("STRIPE_WEBHOOK_SECRET_HOUMON", "") or _env.get("STRIPE_WEBHOOK_SECRET", "")
PRICE_STANDARD = _env.get("STRIPE_PRICE_STANDARD", "")
PRICE_PRO      = _env.get("STRIPE_PRICE_PRO", "")
PRICE_HQ       = _env.get("STRIPE_PRICE_HQ", "")

PRICES = {"standard": PRICE_STANDARD, "pro": PRICE_PRO, "hq": PRICE_HQ}

def get_stripe():
    if not SECRET_KEY:
        return None
    try:
        import stripe as _s
        _s.api_key = SECRET_KEY
        return _s
    except ImportError:
        return None
