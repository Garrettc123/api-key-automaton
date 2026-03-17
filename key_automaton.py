#!/usr/bin/env python3
# key_automaton.py - API Key Management Service
# AI-powered intelligent credential management with autonomous allocation and rotation

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import stripe
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# ─── Encryption Setup ─────────────────────────────────────────────────────────
_FERNET_KEY_ENV = os.getenv("FERNET_KEY", "")
if _FERNET_KEY_ENV:
    fernet = Fernet(_FERNET_KEY_ENV.encode())
else:
    _ephemeral_key = Fernet.generate_key()
    fernet = Fernet(_ephemeral_key)
    print(
        "WARNING: No FERNET_KEY env var set. "
        "Generated ephemeral key – encrypted values will be unreadable after restart. "
        f"Set FERNET_KEY={_ephemeral_key.decode()} to persist."
    )


def encrypt_value(value: str) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()


# ─── Stripe Setup ─────────────────────────────────────────────────────────────
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

PLANS: Dict[str, Dict[str, Any]] = {
    "solo": {
        "name": "Solo",
        "price_cents": 4900,
        "price_id": os.getenv("STRIPE_PRICE_SOLO", ""),
    },
    "team": {
        "name": "Team",
        "price_cents": 14900,
        "price_id": os.getenv("STRIPE_PRICE_TEAM", ""),
    },
    "enterprise": {
        "name": "Enterprise",
        "price_cents": 49900,
        "price_id": os.getenv("STRIPE_PRICE_ENTERPRISE", ""),
    },
}

STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# ─── Supported Providers ──────────────────────────────────────────────────────
SUPPORTED_PROVIDERS: Dict[str, Dict[str, int]] = {
    "openai":    {"rate_limit": 10000, "rate_window_secs": 60},
    "anthropic": {"rate_limit": 1000,  "rate_window_secs": 60},
    "stripe":    {"rate_limit": 100,   "rate_window_secs": 1},
    "github":    {"rate_limit": 5000,  "rate_window_secs": 3600},
    "linear":    {"rate_limit": 1500,  "rate_window_secs": 3600},
    "notion":    {"rate_limit": 3,     "rate_window_secs": 1},
    "sendgrid":  {"rate_limit": 600,   "rate_window_secs": 60},
    "twilio":    {"rate_limit": 100,   "rate_window_secs": 1},
    "other":     {"rate_limit": 1000,  "rate_window_secs": 60},
}

# ─── In-Memory Storage ────────────────────────────────────────────────────────
# Each key entry:
#   id, name, provider, env, status, encrypted_value,
#   rate_limit, rate_window_secs, requests_count, window_start,
#   last_used_at, last_rotated_at, expires_at, allocated_to, tags
api_keys_db:        List[Dict[str, Any]] = []
allocations_db:     List[Dict[str, Any]] = []
audit_log_db:       List[Dict[str, Any]] = []
alerts_db:          List[Dict[str, Any]] = []
rotation_events_db: List[Dict[str, Any]] = []
subscriptions_db:   List[Dict[str, Any]] = []

# ─── Security (early definition needed by require_admin) ─────────────────────
admin_api_key_header = APIKeyHeader(name="x-admin-api-key", auto_error=False)
ADMIN_KEYS = {
    k for k in os.getenv("ADMIN_API_KEY", "demo-admin-key-change-me").split(",") if k
}

_DEFAULT_KEY = "demo-admin-key-change-me"
if _DEFAULT_KEY in ADMIN_KEYS:
    import warnings
    warnings.warn(
        "SECURITY WARNING: ADMIN_API_KEY is set to the insecure default "
        f"'{_DEFAULT_KEY}'. Set the ADMIN_API_KEY environment variable to a "
        "strong random value before deploying to production.",
        UserWarning,
        stacklevel=1,
    )


def require_admin(api_key: str = Depends(admin_api_key_header)) -> str:
    if api_key not in ADMIN_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin API key",
        )
    return api_key


# ─── Pydantic Models ──────────────────────────────────────────────────────────
class KeyCreate(BaseModel):
    name: str
    provider: str  # openai | anthropic | stripe | github | linear | notion | sendgrid | twilio | other
    env: str
    key_value: str  # actual secret – will be encrypted at rest
    expires_in_days: Optional[int] = None
    tags: Optional[List[str]] = []


class KeyUpdate(BaseModel):
    status: Optional[str] = None
    tags: Optional[List[str]] = None


class AllocationCreate(BaseModel):
    provider: str
    env: str
    consumer_id: str
    consumer_type: str = "service"


class RotateRequest(BaseModel):
    new_key_value: str


class CheckoutRequest(BaseModel):
    plan: str
    success_url: str
    cancel_url: str
    customer_email: Optional[str] = None


# ─── Internal Helpers ─────────────────────────────────────────────────────────
def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _find_key(key_id: str) -> Optional[Dict[str, Any]]:
    for k in api_keys_db:
        if k["id"] == key_id:
            return k
    return None


def _log_audit(
    action: str,
    key_id: Optional[str] = None,
    details: str = "",
) -> None:
    audit_log_db.append(
        {
            "id": str(uuid.uuid4()),
            "timestamp": _now().isoformat(),
            "action": action,
            "key_id": key_id,
            "details": details,
        }
    )


def _add_alert(alert_type: str, key_id: str, message: str) -> None:
    alerts_db.append(
        {
            "id": str(uuid.uuid4()),
            "type": alert_type,
            "key_id": key_id,
            "message": message,
            "created_at": _now().isoformat(),
            "resolved": False,
        }
    )


def _is_rate_limited(key: Dict[str, Any]) -> bool:
    window_start = key.get("window_start")
    if window_start is None:
        return False
    if isinstance(window_start, str):
        window_start = datetime.fromisoformat(window_start)
    window_secs = key.get("rate_window_secs", 60)
    if (_now() - window_start).total_seconds() > window_secs:
        key["requests_count"] = 0
        key["window_start"] = _now().isoformat()
        return False
    return key.get("requests_count", 0) >= key.get("rate_limit", 9_999_999)


def _increment_usage(key: Dict[str, Any]) -> None:
    now = _now()
    window_start = key.get("window_start")
    if window_start is None:
        key["window_start"] = now.isoformat()
        key["requests_count"] = 0
    else:
        ws = (
            datetime.fromisoformat(window_start)
            if isinstance(window_start, str)
            else window_start
        )
        if (now - ws).total_seconds() > key.get("rate_window_secs", 60):
            key["window_start"] = now.isoformat()
            key["requests_count"] = 0
    key["requests_count"] = key.get("requests_count", 0) + 1
    key["last_used_at"] = now.isoformat()


def _select_best_key(provider: str, env: str) -> Optional[Dict[str, Any]]:
    """Auto-allocate: pick the least-used active, non-expired, non-rate-limited key."""
    candidates = [
        k
        for k in api_keys_db
        if k["provider"] == provider
        and k["env"] == env
        and k["status"] == "active"
        and not _is_rate_limited(k)
        and (
            k.get("expires_at") is None
            or datetime.fromisoformat(k["expires_at"]) > _now()
        )
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda k: k.get("requests_count", 0))
    return candidates[0]


def _key_out(k: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": k["id"],
        "name": k["name"],
        "provider": k["provider"],
        "env": k["env"],
        "status": k["status"],
        "rate_limit": k.get("rate_limit", 0),
        "rate_window_secs": k.get("rate_window_secs", 60),
        "requests_count": k.get("requests_count", 0),
        "last_used_at": k.get("last_used_at"),
        "last_rotated_at": k.get("last_rotated_at"),
        "expires_at": k.get("expires_at"),
        "allocated_to": k.get("allocated_to", []),
        "tags": k.get("tags", []),
    }


# ─── Background Jobs ──────────────────────────────────────────────────────────
def _check_key_health() -> None:
    """Detect expired / soon-to-expire / rate-limited keys and emit alerts."""
    now = _now()
    for key in api_keys_db:
        expires_at = key.get("expires_at")
        if expires_at:
            exp = (
                datetime.fromisoformat(expires_at)
                if isinstance(expires_at, str)
                else expires_at
            )
            if exp < now and key["status"] == "active":
                key["status"] = "expired"
                _add_alert("expired", key["id"], f"Key '{key['name']}' has expired")
                _log_audit("key_expired", key["id"], f"Key '{key['name']}' auto-expired")
            elif exp < now + timedelta(days=7) and key["status"] == "active":
                _add_alert(
                    "expiring_soon",
                    key["id"],
                    f"Key '{key['name']}' expires in < 7 days",
                )
        if _is_rate_limited(key) and key["status"] == "active":
            _add_alert("rate_limited", key["id"], f"Key '{key['name']}' is rate-limited")


def _auto_rotate_check() -> None:
    """Flag keys older than 30 days for rotation."""
    now = _now()
    for key in api_keys_db:
        if key["status"] != "active":
            continue
        last_rotated = key.get("last_rotated_at")
        if last_rotated:
            lr = (
                datetime.fromisoformat(last_rotated)
                if isinstance(last_rotated, str)
                else last_rotated
            )
            if (now - lr).days >= 30:
                _add_alert(
                    "rotation_due",
                    key["id"],
                    f"Key '{key['name']}' is due for rotation (>30 days old)",
                )
                _log_audit(
                    "rotation_due",
                    key["id"],
                    f"Key '{key['name']}' flagged for rotation",
                )


scheduler = BackgroundScheduler()
scheduler.add_job(_check_key_health,  "interval", minutes=5)
scheduler.add_job(_auto_rotate_check, "interval", hours=1)


@asynccontextmanager
async def _lifespan(application: FastAPI):
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


# ─── FastAPI Setup ────────────────────────────────────────────────────────────
app = FastAPI(
    title="API Key Automaton",
    description=(
        "AI-powered intelligent credential management "
        "with autonomous allocation and rotation"
    ),
    version="2.0.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


# ─── Routes: Core ─────────────────────────────────────────────────────────────
@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": "API Key Automaton",
        "version": "2.0.0",
        "status": "running",
        "providers": list(SUPPORTED_PROVIDERS.keys()),
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    active = sum(1 for k in api_keys_db if k["status"] == "active")
    return {
        "status": "healthy",
        "timestamp": _now().isoformat(),
        "keys_total": len(api_keys_db),
        "keys_active": active,
        "alerts_open": sum(1 for a in alerts_db if not a["resolved"]),
    }


# ─── Routes: Key Management ───────────────────────────────────────────────────
@app.post("/keys", dependencies=[Depends(require_admin)])
def create_key(payload: KeyCreate) -> Dict[str, Any]:
    provider = payload.provider.lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider. Choose from: {list(SUPPORTED_PROVIDERS.keys())}",
        )
    provider_cfg = SUPPORTED_PROVIDERS[provider]
    now = _now()
    expires_at = (
        (now + timedelta(days=payload.expires_in_days)).isoformat()
        if payload.expires_in_days is not None
        else None
    )
    key_id = str(uuid.uuid4())
    new_key: Dict[str, Any] = {
        "id": key_id,
        "name": payload.name,
        "provider": provider,
        "env": payload.env,
        "status": "active",
        "encrypted_value": encrypt_value(payload.key_value),
        "rate_limit": provider_cfg["rate_limit"],
        "rate_window_secs": provider_cfg["rate_window_secs"],
        "requests_count": 0,
        "window_start": None,
        "last_used_at": None,
        "last_rotated_at": now.isoformat(),
        "expires_at": expires_at,
        "allocated_to": [],
        "tags": payload.tags or [],
    }
    api_keys_db.append(new_key)
    _log_audit("create_key", key_id, f"Created '{payload.name}' for {provider}")
    return {"status": "created", "key_id": key_id}


@app.get("/keys", dependencies=[Depends(require_admin)])
def list_keys(
    provider: Optional[str] = None,
    env: Optional[str] = None,
    key_status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    result = api_keys_db
    if provider:
        result = [k for k in result if k["provider"] == provider.lower()]
    if env:
        result = [k for k in result if k["env"] == env]
    if key_status:
        result = [k for k in result if k["status"] == key_status]
    return [_key_out(k) for k in result]


@app.get("/keys/{key_id}", dependencies=[Depends(require_admin)])
def get_key(key_id: str) -> Dict[str, Any]:
    key = _find_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return _key_out(key)


@app.patch("/keys/{key_id}", dependencies=[Depends(require_admin)])
def update_key(key_id: str, payload: KeyUpdate) -> Dict[str, Any]:
    key = _find_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    if payload.status is not None:
        valid_statuses = {"active", "inactive", "compromised", "expired"}
        if payload.status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Choose from: {sorted(valid_statuses)}",
            )
        old_status = key["status"]
        key["status"] = payload.status
        _log_audit(
            "update_key_status",
            key_id,
            f"Status changed {old_status} -> {payload.status}",
        )
        if payload.status == "compromised":
            _add_alert("compromised", key_id, f"Key '{key['name']}' marked as compromised")
    if payload.tags is not None:
        key["tags"] = payload.tags
    return {"status": "updated", "key_id": key_id}


@app.delete("/keys/{key_id}", dependencies=[Depends(require_admin)])
def delete_key(key_id: str) -> Dict[str, Any]:
    global api_keys_db
    key = _find_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    api_keys_db = [k for k in api_keys_db if k["id"] != key_id]
    _log_audit("delete_key", key_id, f"Deleted '{key['name']}'")
    return {"status": "deleted"}


@app.post("/keys/{key_id}/rotate", dependencies=[Depends(require_admin)])
def rotate_key(key_id: str, payload: RotateRequest) -> Dict[str, Any]:
    key = _find_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key["encrypted_value"] = encrypt_value(payload.new_key_value)
    key["last_rotated_at"] = _now().isoformat()
    key["status"] = "active"
    rotation_events_db.append(
        {
            "id": str(uuid.uuid4()),
            "key_id": key_id,
            "key_name": key["name"],
            "rotated_at": _now().isoformat(),
            "trigger": "manual",
        }
    )
    # Resolve any pending rotation_due alerts for this key
    for alert in alerts_db:
        if alert["key_id"] == key_id and alert["type"] == "rotation_due":
            alert["resolved"] = True
    _log_audit("rotate_key", key_id, f"Rotated '{key['name']}'")
    return {"status": "rotated", "key_id": key_id}


@app.get("/keys/{key_id}/reveal", dependencies=[Depends(require_admin)])
def reveal_key(key_id: str) -> Dict[str, Any]:
    """Return the decrypted key value (use with caution – logged)."""
    key = _find_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    _log_audit("reveal_key", key_id, f"Revealed '{key['name']}'")
    return {"key_id": key_id, "value": decrypt_value(key["encrypted_value"])}


# ─── Routes: Auto-Allocation ──────────────────────────────────────────────────
@app.post("/allocate", dependencies=[Depends(require_admin)])
def auto_allocate(payload: AllocationCreate) -> Dict[str, Any]:
    """Assign the best available key for the given provider/env."""
    key = _select_best_key(payload.provider.lower(), payload.env)
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                f"No available key for provider '{payload.provider}' "
                f"in env '{payload.env}'"
            ),
        )
    if payload.consumer_id not in key["allocated_to"]:
        key["allocated_to"].append(payload.consumer_id)
    _increment_usage(key)
    allocation: Dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "key_id": key["id"],
        "key_name": key["name"],
        "provider": key["provider"],
        "consumer_type": payload.consumer_type,
        "consumer_id": payload.consumer_id,
        "created_at": _now().isoformat(),
    }
    allocations_db.append(allocation)
    _log_audit(
        "auto_allocate",
        key["id"],
        f"Allocated '{key['name']}' to {payload.consumer_id}",
    )
    return {
        "status": "allocated",
        "allocation_id": allocation["id"],
        "key_id": key["id"],
        "key_name": key["name"],
    }


@app.get("/allocations", dependencies=[Depends(require_admin)])
def list_allocations() -> List[Dict[str, Any]]:
    return allocations_db


# ─── Routes: Alerts ───────────────────────────────────────────────────────────
@app.get("/alerts", dependencies=[Depends(require_admin)])
def list_alerts(resolved: Optional[bool] = None) -> List[Dict[str, Any]]:
    result = alerts_db
    if resolved is not None:
        result = [a for a in result if a["resolved"] == resolved]
    return result


@app.post("/alerts/{alert_id}/resolve", dependencies=[Depends(require_admin)])
def resolve_alert(alert_id: str) -> Dict[str, Any]:
    for alert in alerts_db:
        if alert["id"] == alert_id:
            alert["resolved"] = True
            return {"status": "resolved"}
    raise HTTPException(status_code=404, detail="Alert not found")


# ─── Routes: Audit Log & Rotation Events ─────────────────────────────────────
@app.get("/audit-log", dependencies=[Depends(require_admin)])
def get_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    return audit_log_db[-limit:]


@app.get("/rotation-events", dependencies=[Depends(require_admin)])
def list_rotation_events() -> List[Dict[str, Any]]:
    return rotation_events_db


# ─── Routes: Stripe Billing ───────────────────────────────────────────────────
@app.get("/plans")
def list_plans() -> List[Dict[str, Any]]:
    return [
        {"plan": k, "name": v["name"], "price_usd": v["price_cents"] / 100}
        for k, v in PLANS.items()
    ]


@app.post("/billing/checkout", dependencies=[Depends(require_admin)])
def create_checkout(payload: CheckoutRequest) -> Dict[str, Any]:
    if not stripe.api_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    plan = payload.plan.lower()
    if plan not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan. Choose from: {list(PLANS.keys())}",
        )
    price_id = PLANS[plan]["price_id"]
    if not price_id:
        raise HTTPException(
            status_code=503,
            detail=f"Stripe price ID not configured for plan '{plan}'",
        )
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=payload.success_url,
            cancel_url=payload.cancel_url,
            customer_email=payload.customer_email,
        )
    except stripe.StripeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"checkout_url": session.url, "session_id": session.id}


@app.post("/billing/webhook")
async def stripe_webhook(request: Request) -> Dict[str, Any]:
    payload_bytes = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook secret not configured")
    try:
        event = stripe.Webhook.construct_event(
            payload_bytes, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    if event["type"] == "checkout.session.completed":
        data = event["data"]["object"]
        subscriptions_db.append(
            {
                "id": str(uuid.uuid4()),
                "stripe_subscription_id": data.get("subscription"),
                "customer_email": data.get("customer_email"),
                "status": "active",
                "created_at": _now().isoformat(),
            }
        )
        _log_audit(
            "subscription_created",
            details=f"New subscription for {data.get('customer_email')}",
        )
    elif event["type"] in (
        "customer.subscription.deleted",
        "customer.subscription.updated",
    ):
        sub_id = event["data"]["object"]["id"]
        sub_status = event["data"]["object"]["status"]
        for sub in subscriptions_db:
            if sub["stripe_subscription_id"] == sub_id:
                sub["status"] = sub_status
    return {"received": True}


@app.get("/billing/subscriptions", dependencies=[Depends(require_admin)])
def list_subscriptions() -> List[Dict[str, Any]]:
    return subscriptions_db


# ─── Routes: Dashboard ────────────────────────────────────────────────────────
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    api_key: str = Depends(admin_api_key_header),
) -> HTMLResponse:
    if api_key not in ADMIN_KEYS:
        return HTMLResponse("<h1>401 Unauthorized</h1>", status_code=401)
    open_alerts = [a for a in alerts_db if not a["resolved"]]
    recent_rotations = rotation_events_db[-10:]
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "keys": [_key_out(k) for k in api_keys_db],
            "active_count": sum(1 for k in api_keys_db if k["status"] == "active"),
            "total_count": len(api_keys_db),
            "open_alerts": open_alerts,
            "recent_rotations": recent_rotations,
            "audit_log": audit_log_db[-20:],
            "providers": list(SUPPORTED_PROVIDERS.keys()),
            "plans": list_plans(),
        },
    )


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
