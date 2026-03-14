"""
tests/test_key_automaton.py
Pytest test suite for API Key Automaton.
"""
import os
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

# Fixed Fernet key so encrypted values remain stable across the entire test run.
_TEST_FERNET_KEY = "rfNpC6ONij8VRQVKISlIWjESHYqFJvux8u83TTsf4hM="
os.environ["FERNET_KEY"] = _TEST_FERNET_KEY
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")

# Import after setting env vars so module-level constants pick them up
import key_automaton as ka
from key_automaton import app, encrypt_value, decrypt_value

ADMIN = {"x-admin-api-key": "test-admin-key"}

# ─── Fixture: fresh in-memory state per test ─────────────────────────────────

@pytest.fixture(autouse=True)
def reset_db():
    """Reset all in-memory stores before each test."""
    ka.api_keys_db.clear()
    ka.allocations_db.clear()
    ka.audit_log_db.clear()
    ka.alerts_db.clear()
    ka.rotation_events_db.clear()
    ka.subscriptions_db.clear()
    yield


@pytest.fixture()
def client():
    # Disable scheduler during tests
    if ka.scheduler.running:
        ka.scheduler.shutdown(wait=False)
    return TestClient(app, raise_server_exceptions=True)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _create_key(client, name="Test Key", provider="openai", env="test", key_value="sk-test"):
    resp = client.post(
        "/keys",
        json={"name": name, "provider": provider, "env": env, "key_value": key_value},
        headers=ADMIN,
    )
    assert resp.status_code == 200
    return resp.json()["key_id"]


# ─── Encryption ───────────────────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    secret = "super-secret-api-key-12345"
    token = encrypt_value(secret)
    assert token != secret
    assert decrypt_value(token) == secret


# ─── Root & Health ────────────────────────────────────────────────────────────

def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "API Key Automaton"
    assert data["version"] == "2.0.0"
    assert "providers" in data


def test_health_empty(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["keys_total"] == 0
    assert data["keys_active"] == 0


def test_health_with_keys(client):
    _create_key(client)
    resp = client.get("/health")
    data = resp.json()
    assert data["keys_total"] == 1
    assert data["keys_active"] == 1


# ─── Auth Guard ───────────────────────────────────────────────────────────────

def test_no_auth_rejected(client):
    resp = client.get("/keys")
    assert resp.status_code == 401


def test_wrong_auth_rejected(client):
    resp = client.get("/keys", headers={"x-admin-api-key": "wrong"})
    assert resp.status_code == 401


# ─── Key CRUD ─────────────────────────────────────────────────────────────────

def test_create_key_all_providers(client):
    providers = list(ka.SUPPORTED_PROVIDERS.keys())
    for p in providers:
        resp = client.post(
            "/keys",
            json={"name": f"{p} key", "provider": p, "env": "test", "key_value": "val"},
            headers=ADMIN,
        )
        assert resp.status_code == 200, f"Failed for provider {p}: {resp.text}"
        assert resp.json()["status"] == "created"


def test_create_key_unsupported_provider(client):
    resp = client.post(
        "/keys",
        json={"name": "bad", "provider": "unsupported_xyz", "env": "test", "key_value": "val"},
        headers=ADMIN,
    )
    assert resp.status_code == 400


def test_create_key_with_expiry(client):
    resp = client.post(
        "/keys",
        json={
            "name": "Expiring Key",
            "provider": "github",
            "env": "test",
            "key_value": "ghp_test",
            "expires_in_days": 30,
        },
        headers=ADMIN,
    )
    assert resp.status_code == 200
    key_id = resp.json()["key_id"]
    key = client.get(f"/keys/{key_id}", headers=ADMIN).json()
    assert key["expires_at"] is not None


def test_list_keys(client):
    _create_key(client, name="Key A", provider="openai")
    _create_key(client, name="Key B", provider="github")
    resp = client.get("/keys", headers=ADMIN)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_list_keys_filter_by_provider(client):
    _create_key(client, name="OpenAI Key", provider="openai")
    _create_key(client, name="GitHub Key", provider="github")
    resp = client.get("/keys?provider=openai", headers=ADMIN)
    keys = resp.json()
    assert len(keys) == 1
    assert keys[0]["provider"] == "openai"


def test_get_key(client):
    key_id = _create_key(client, name="My Key", provider="stripe")
    resp = client.get(f"/keys/{key_id}", headers=ADMIN)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == key_id
    assert data["provider"] == "stripe"
    assert data["status"] == "active"


def test_get_key_not_found(client):
    resp = client.get("/keys/nonexistent-id", headers=ADMIN)
    assert resp.status_code == 404


def test_update_key_status_compromised(client):
    key_id = _create_key(client)
    resp = client.patch(
        f"/keys/{key_id}",
        json={"status": "compromised"},
        headers=ADMIN,
    )
    assert resp.status_code == 200
    key = client.get(f"/keys/{key_id}", headers=ADMIN).json()
    assert key["status"] == "compromised"
    # Should have created an alert
    alerts = client.get("/alerts", headers=ADMIN).json()
    assert any(a["type"] == "compromised" for a in alerts)


def test_update_key_invalid_status(client):
    key_id = _create_key(client)
    resp = client.patch(
        f"/keys/{key_id}",
        json={"status": "unknown_status"},
        headers=ADMIN,
    )
    assert resp.status_code == 400


def test_update_key_tags(client):
    key_id = _create_key(client)
    resp = client.patch(
        f"/keys/{key_id}",
        json={"tags": ["prod", "critical"]},
        headers=ADMIN,
    )
    assert resp.status_code == 200
    key = client.get(f"/keys/{key_id}", headers=ADMIN).json()
    assert "prod" in key["tags"]


def test_delete_key(client):
    key_id = _create_key(client)
    resp = client.delete(f"/keys/{key_id}", headers=ADMIN)
    assert resp.status_code == 200
    assert client.get(f"/keys/{key_id}", headers=ADMIN).status_code == 404


# ─── Key Reveal (Encrypted at Rest) ──────────────────────────────────────────

def test_key_encrypted_at_rest(client):
    key_id = _create_key(client, key_value="my-secret-value")
    # Raw DB entry should NOT contain plaintext
    raw = ka._find_key(key_id)
    assert raw is not None
    assert "my-secret-value" not in raw.get("encrypted_value", "")
    assert raw["encrypted_value"] != "my-secret-value"


def test_reveal_key(client):
    key_id = _create_key(client, key_value="reveal-me-123")
    resp = client.get(f"/keys/{key_id}/reveal", headers=ADMIN)
    assert resp.status_code == 200
    assert resp.json()["value"] == "reveal-me-123"


# ─── Key Rotation ─────────────────────────────────────────────────────────────

def test_rotate_key(client):
    key_id = _create_key(client, key_value="old-key-value")
    resp = client.post(
        f"/keys/{key_id}/rotate",
        json={"new_key_value": "new-key-value"},
        headers=ADMIN,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "rotated"
    # Verify new value was stored
    reveal = client.get(f"/keys/{key_id}/reveal", headers=ADMIN).json()
    assert reveal["value"] == "new-key-value"


def test_rotate_key_creates_rotation_event(client):
    key_id = _create_key(client)
    client.post(
        f"/keys/{key_id}/rotate",
        json={"new_key_value": "new-val"},
        headers=ADMIN,
    )
    events = client.get("/rotation-events", headers=ADMIN).json()
    assert len(events) == 1
    assert events[0]["key_id"] == key_id
    assert events[0]["trigger"] == "manual"


def test_rotate_key_resolves_rotation_due_alert(client):
    key_id = _create_key(client)
    # Inject a rotation_due alert
    ka.alerts_db.append({
        "id": "alert-001",
        "type": "rotation_due",
        "key_id": key_id,
        "message": "due",
        "created_at": ka._now().isoformat(),
        "resolved": False,
    })
    client.post(
        f"/keys/{key_id}/rotate",
        json={"new_key_value": "new-val"},
        headers=ADMIN,
    )
    alerts = client.get("/alerts", headers=ADMIN).json()
    rotation_due = [a for a in alerts if a["type"] == "rotation_due"]
    assert all(a["resolved"] for a in rotation_due)


# ─── Auto-Allocation ──────────────────────────────────────────────────────────

def test_auto_allocate_picks_best_key(client):
    _create_key(client, name="OpenAI 1", provider="openai", env="prod")
    _create_key(client, name="OpenAI 2", provider="openai", env="prod")
    resp = client.post(
        "/allocate",
        json={"provider": "openai", "env": "prod", "consumer_id": "svc-a"},
        headers=ADMIN,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "allocated"
    assert "key_id" in data


def test_auto_allocate_no_key_available(client):
    resp = client.post(
        "/allocate",
        json={"provider": "openai", "env": "prod", "consumer_id": "svc-x"},
        headers=ADMIN,
    )
    assert resp.status_code == 503


def test_auto_allocate_skips_inactive_key(client):
    key_id = _create_key(client, name="Inactive", provider="anthropic", env="prod")
    client.patch(f"/keys/{key_id}", json={"status": "inactive"}, headers=ADMIN)
    resp = client.post(
        "/allocate",
        json={"provider": "anthropic", "env": "prod", "consumer_id": "svc-b"},
        headers=ADMIN,
    )
    assert resp.status_code == 503


def test_auto_allocate_increments_usage(client):
    _create_key(client, name="Notion Key", provider="notion", env="test")
    client.post(
        "/allocate",
        json={"provider": "notion", "env": "test", "consumer_id": "svc-c"},
        headers=ADMIN,
    )
    keys = client.get("/keys?provider=notion", headers=ADMIN).json()
    assert keys[0]["requests_count"] == 1


# ─── Rate Limit Tracking ─────────────────────────────────────────────────────

def test_rate_limit_tracking(client):
    """A key with rate_limit=1 should refuse second allocation."""
    key_id = _create_key(client, name="Rate Key", provider="notion", env="staging")
    # Force rate limit to 1 for testing
    raw = ka._find_key(key_id)
    assert raw is not None
    raw["rate_limit"] = 1

    # First allocation should succeed
    resp1 = client.post(
        "/allocate",
        json={"provider": "notion", "env": "staging", "consumer_id": "svc-1"},
        headers=ADMIN,
    )
    assert resp1.status_code == 200

    # Second should fail (rate limited)
    resp2 = client.post(
        "/allocate",
        json={"provider": "notion", "env": "staging", "consumer_id": "svc-2"},
        headers=ADMIN,
    )
    assert resp2.status_code == 503


# ─── Alerts ───────────────────────────────────────────────────────────────────

def test_list_alerts_empty(client):
    resp = client.get("/alerts", headers=ADMIN)
    assert resp.status_code == 200
    assert resp.json() == []


def test_resolve_alert(client):
    key_id = _create_key(client)
    client.patch(f"/keys/{key_id}", json={"status": "compromised"}, headers=ADMIN)
    alerts = client.get("/alerts?resolved=false", headers=ADMIN).json()
    assert len(alerts) > 0
    alert_id = alerts[0]["id"]
    resp = client.post(f"/alerts/{alert_id}/resolve", headers=ADMIN)
    assert resp.status_code == 200
    # Should no longer appear in open alerts
    open_alerts = client.get("/alerts?resolved=false", headers=ADMIN).json()
    assert all(a["id"] != alert_id for a in open_alerts)


def test_resolve_alert_not_found(client):
    resp = client.post("/alerts/nonexistent-id/resolve", headers=ADMIN)
    assert resp.status_code == 404


# ─── Background Health Check ─────────────────────────────────────────────────

def test_health_check_expires_key():
    from datetime import datetime, timezone, timedelta
    import key_automaton as ka2

    ka2.api_keys_db.clear()
    ka2.alerts_db.clear()
    ka2.audit_log_db.clear()

    # Insert a key that expired 1 day ago
    past = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    ka2.api_keys_db.append({
        "id": "exp-key",
        "name": "Old Key",
        "provider": "github",
        "env": "test",
        "status": "active",
        "encrypted_value": encrypt_value("tok"),
        "rate_limit": 5000,
        "rate_window_secs": 3600,
        "requests_count": 0,
        "window_start": None,
        "last_used_at": None,
        "last_rotated_at": past,
        "expires_at": past,
        "allocated_to": [],
        "tags": [],
    })
    ka2._check_key_health()
    assert ka2.api_keys_db[0]["status"] == "expired"
    assert any(a["type"] == "expired" for a in ka2.alerts_db)


def test_auto_rotate_check_flags_old_key():
    from datetime import datetime, timezone, timedelta
    import key_automaton as ka2

    ka2.api_keys_db.clear()
    ka2.alerts_db.clear()
    ka2.audit_log_db.clear()

    old_ts = (datetime.now(timezone.utc) - timedelta(days=35)).replace(tzinfo=None).isoformat()
    ka2.api_keys_db.append({
        "id": "old-key",
        "name": "Stale Key",
        "provider": "openai",
        "env": "prod",
        "status": "active",
        "encrypted_value": encrypt_value("sk-old"),
        "rate_limit": 10000,
        "rate_window_secs": 60,
        "requests_count": 0,
        "window_start": None,
        "last_used_at": None,
        "last_rotated_at": old_ts,
        "expires_at": None,
        "allocated_to": [],
        "tags": [],
    })
    ka2._auto_rotate_check()
    assert any(a["type"] == "rotation_due" for a in ka2.alerts_db)


# ─── Audit Log ────────────────────────────────────────────────────────────────

def test_audit_log_populated(client):
    _create_key(client)
    resp = client.get("/audit-log", headers=ADMIN)
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) >= 1
    assert entries[-1]["action"] == "create_key"


def test_audit_log_limit(client):
    for i in range(5):
        _create_key(client, name=f"Key {i}")
    resp = client.get("/audit-log?limit=3", headers=ADMIN)
    assert len(resp.json()) <= 3


# ─── Plans ────────────────────────────────────────────────────────────────────

def test_list_plans(client):
    resp = client.get("/plans")
    assert resp.status_code == 200
    plans = resp.json()
    plan_names = {p["plan"] for p in plans}
    assert {"solo", "team", "enterprise"} == plan_names
    solo = next(p for p in plans if p["plan"] == "solo")
    assert solo["price_usd"] == 49.0
    team = next(p for p in plans if p["plan"] == "team")
    assert team["price_usd"] == 149.0
    enterprise = next(p for p in plans if p["plan"] == "enterprise")
    assert enterprise["price_usd"] == 499.0


# ─── Dashboard ────────────────────────────────────────────────────────────────

def test_dashboard_requires_auth(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 401


def test_dashboard_renders(client):
    _create_key(client, name="Dash Key", provider="sendgrid", env="prod")
    resp = client.get("/dashboard", headers=ADMIN)
    assert resp.status_code == 200
    assert "API Key Automaton" in resp.text
    assert "Dash Key" in resp.text


# ─── Allocations List ─────────────────────────────────────────────────────────

def test_list_allocations(client):
    _create_key(client, name="Twilio Key", provider="twilio", env="prod")
    client.post(
        "/allocate",
        json={"provider": "twilio", "env": "prod", "consumer_id": "worker-1"},
        headers=ADMIN,
    )
    resp = client.get("/allocations", headers=ADMIN)
    assert resp.status_code == 200
    allocs = resp.json()
    assert len(allocs) == 1
    assert allocs[0]["consumer_id"] == "worker-1"
