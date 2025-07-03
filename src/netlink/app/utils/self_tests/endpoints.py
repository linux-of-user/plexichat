import time
import requests
from datetime import datetime
from typing import Dict, Any, Tuple
from sqlmodel import Session, select
from requests.exceptions import JSONDecodeError

from app.logger_config import logger, settings
from app.db import engine
from app.models.user import User

def get_token(username: str, password: str) -> Any:
    url = f"{settings.BASE_URL}/v1/auth/login"
    try:
        r = requests.post(url, json={"username": username, "password": password}, timeout=2)
        r.raise_for_status()
        token = r.json().get("access_token")
        logger.trace("[ET-Token] %s → %s", username, r.status_code)
        return token
    except Exception as e:
        logger.error("[ET-Token] %s failed: %s", username, e)
        return None

def ensure_test_users() -> Tuple[int, int]:
    """Create testuser and testuser2 if they don't exist, return their IDs."""
    test_users = [
        {"username": "testuser", "email": "testuser@example.com", "password": "TestPass123!", "display_name": "Test User", "public_key": "test_key_1"},
        {"username": "testuser2", "email": "testuser2@example.com", "password": "TestPass123!", "display_name": "Test User 2", "public_key": "test_key_2"},
    ]
    user_ids = []

    with Session(engine) as session:
        for user_data in test_users:
            username = user_data["username"]
            # Check if user exists
            user = session.exec(select(User).where(User.username == username)).first()
            if user:
                logger.debug("[ET-User-Exists] %s found with ID %d", username, user.id)
                user_ids.append(user.id)
                continue

            # Create user via API
            try:
                response = requests.post(
                    f"{settings.BASE_URL}/v1/users/",
                    json=user_data,
                    timeout=2
                )
                if response.status_code == 201:
                    user_id = response.json().get("id")
                    logger.info("[ET-User-Created] %s created with ID %d", username, user_id)
                elif response.status_code == 422 and "already exists" in response.text.lower():
                    logger.warning("[ET-User-Exists-API] %s already exists via API", username)
                    # Query again to get ID
                    user = session.exec(select(User).where(User.username == username)).first()
                    if user:
                        user_id = user.id
                    else:
                        raise Exception(f"{username} not found in database after API conflict")
                else:
                    logger.error("[ET-User-Create-Failed] %s: %s", username, response.text[:200])
                    raise Exception(f"Failed to create {username}: {response.status_code}")
                user_ids.append(user_id)
            except Exception as e:
                logger.critical("[ET-User-Create-Error] %s: %s", username, e)
                raise

            # Verify user in database
            user = session.exec(select(User).where(User.username == username)).first()
            if not user:
                logger.critical("[ET-User-Not-Found] %s not in database after creation", username)
                raise Exception(f"{username} not found in database")

    return user_ids[0], user_ids[1]

def test_user_crud() -> Dict[str, Any]:
    ts = int(time.time())
    tmp = f"tmp_{ts}"
    base = settings.BASE_URL
    out = {}
    t0 = time.time()

    # CREATE
    r1 = requests.post(f"{base}/v1/users/", json={
        "username": tmp,
        "email": f"{tmp}@x",
        "password": "P!23abc",
        "public_key": "k",
        "display_name": "t"
    }, timeout=2)
    out["create"] = {"code": r1.status_code, "ok": r1.status_code == 201}

    if r1.status_code != 201:
        return out

    uid = r1.json().get("id")

    # LOGIN
    tok = get_token(tmp, "P!23abc")
    out["login"] = {"ok": bool(tok)}

    hdr = {"Authorization": f"Bearer {tok}"} if tok else {}

    # FETCH
    r2 = requests.get(f"{base}/v1/users/{uid}", headers=hdr, timeout=2)
    out["fetch"] = {"code": r2.status_code, "ok": r2.status_code == 200}

    # DELETE
    r3 = requests.delete(f"{base}/v1/users/{uid}", headers=hdr, timeout=2)
    out["delete"] = {"code": r3.status_code, "ok": r3.status_code in (200, 204)}

    # VERIFY
    r4 = requests.get(f"{base}/v1/users/{uid}", headers=hdr, timeout=2)
    out["verify"] = {"code": r4.status_code, "ok": r4.status_code == 404}

    dt = time.time() - t0
    logger.info("[ET-User-CRUD] Done in %.2fs", dt)
    return out

def test_messages_flow(token: str, test_user2_id: int) -> Dict[str, Any]:
    base = settings.BASE_URL
    hdr = {"Authorization": f"Bearer {token}"}
    out = {}
    t0 = time.time()

    # POST
    r1 = requests.post(f"{base}/v1/messages/", json={"recipient_id": test_user2_id, "content": "ping"}, headers=hdr, timeout=2)
    out["post"] = {"code": r1.status_code, "ok": r1.status_code == 201}
    if r1.status_code != 201:
        return out
    mid = r1.json().get("id")

    # LIST
    try:
        r2 = requests.get(f"{base}/v1/messages/?limit=5&offset=0", headers=hdr, timeout=2)
        out["list"] = {
            "code": r2.status_code,
            "count": len(r2.json().get("messages", [])) if r2.status_code == 200 else 0,
            "error": r2.text[:200] if r2.status_code != 200 else None
        }
    except JSONDecodeError as e:
        logger.error("[ET-Msg-List] Failed to parse JSON: %s", e)
        out["list"] = {"code": r2.status_code, "count": 0, "error": str(e)}
    except Exception as e:
        logger.error("[ET-Msg-List] Unexpected error: %s", e)
        out["list"] = {"code": r2.status_code if 'r2' in locals() else 0, "count": 0, "error": str(e)}

    # GET
    r3 = requests.get(f"{base}/v1/messages/{mid}", headers=hdr, timeout=2)
    out["get"] = {"code": r3.status_code, "ok": r3.status_code == 200}

    # DELETE & VERIFY
    r4 = requests.delete(f"{base}/v1/messages/{mid}", headers=hdr, timeout=2)
    out["delete"] = {"code": r4.status_code, "ok": r4.status_code in (200, 204)}
    r5 = requests.get(f"{base}/v1/messages/{mid}", headers=hdr, timeout=2)
    out["verify"] = {"code": r5.status_code, "ok": r5.status_code == 404}

    dt = time.time() - t0
    logger.info("[ET-Msg] Done in %.2fs", dt)
    return out

def run_endpoint_tests() -> Dict[str, Any]:
    start = datetime.utcnow()
    logger.info("[ET-Run] Starting endpoint suite at %sZ", start.isoformat())
    out: Dict[str, Any] = {}

    try:
        test_user_id, test_user2_id = ensure_test_users()
    except Exception as e:
        logger.critical("[ET-Run] Aborting: failed to ensure test users: %s", e)
        return out

    token = get_token("testuser", "TestPass123!")
    if not token:
        logger.critical("[ET-Run] Aborting: no token")
        return out

    out["user_crud"] = test_user_crud()
    out["messages"] = test_messages_flow(token, test_user2_id)

    # status endpoints
    for ep in ("health", "uptime", "metrics"):
        r = requests.get(f"{settings.BASE_URL}/v1/status/{ep}", timeout=2)
        out[f"status_{ep}"] = {"code": r.status_code, "ok": r.status_code == 200}

    dur = (datetime.utcnow() - start).total_seconds()
    logger.info("[ET-Run-Done] Completed in %.2fs", dur)
    return out
