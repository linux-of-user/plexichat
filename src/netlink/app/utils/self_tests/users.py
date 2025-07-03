import time
from datetime import datetime
from typing import Dict, Any, Tuple
from sqlmodel import Session, select

import requests

from app.logger_config import logger, settings
from app.db import engine
from app.models.user import User

def ensure_test_users() -> Tuple[int, int]:
    """Create testuser and testuser2 if they don't exist, return their IDs."""
    test_users = [
        {"username": "testuser", "email": "testuser@example.com", "password": "TestPass123!", "display_name": "Test User", "public_key": "selftest_key_1"},
        {"username": "testuser2", "email": "testuser2@example.com", "password": "TestPass123!", "display_name": "Test User 2", "public_key": "selftest_key_2"},
    ]
    user_ids = []

    with Session(engine) as session:
        for user_data in test_users:
            username = user_data["username"]
            # Check if user exists
            user = session.exec(select(User).where(User.username == username)).first()
            if user:
                logger.debug("[US-User-Exists] %s found with ID %d", username, user.id)
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
                    logger.info("[US-User-Created] %s created with ID %d", username, user_id)
                elif response.status_code == 422 and "already exists" in response.text.lower():
                    logger.warning("[US-User-Exists-API] %s already exists via API", username)
                    # Query again to get ID
                    user = session.exec(select(User).where(User.username == username)).first()
                    if user:
                        user_id = user.id
                    else:
                        raise Exception(f"{username} not found in database after API conflict")
                else:
                    logger.error("[US-User-Create-Failed] %s: %s", username, response.text[:200])
                    raise Exception(f"Failed to create {username}: {response.status_code}")
                user_ids.append(user_id)
            except Exception as e:
                logger.critical("[US-User-Create-Error] %s: %s", username, e)
                raise

            # Verify user in database
            user = session.exec(select(User).where(User.username == username)).first()
            if not user:
                logger.critical("[US-User-Not-Found] %s not in database after creation", username)
                raise Exception(f"{username} not found in database")

    return user_ids[0], user_ids[1]

def run_user_tests() -> Dict[str, Dict[str, Any]]:
    start = datetime.utcnow()
    logger.info("[US-Run] Starting user tests at %sZ", start.isoformat())
    out: Dict[str, Dict[str, Any]] = {}

    try:
        test_user_id, test_user2_id = ensure_test_users()
    except Exception as e:
        logger.critical("[US-Run] Aborting: failed to ensure test users: %s", e)
        return out

    for uname, pwd, email, display in [
        ("testuser", "TestPass123!", "testuser@example.com", "Test User"),
        ("testuser2", "TestPass123!", "testuser2@example.com", "Test User 2"),
    ]:
        key = f"user:{uname}"
        t0 = time.time()
        out[key] = {"login_before": None, "registered": None, "login_after": None, "duration_ms": None, "error": None}

        login_url = f"{settings.BASE_URL}/v1/auth/login"
        reg_url = f"{settings.BASE_URL}/v1/users/"

        # first login
        try:
            r1 = requests.post(login_url, json={"username": uname, "password": pwd}, timeout=2)
            out[key]["login_before"] = {"code": r1.status_code, "ok": r1.ok}
            logger.trace("[US-Login1] %s → %s", uname, r1.status_code)
        except Exception as e:
            out[key]["error"] = str(e)
            logger.error("[US-Login1] %s exception: %s", uname, e)

        # register if needed
        if not out[key]["login_before"].get("ok"):
            try:
                r2 = requests.post(reg_url, json={
                    "username": uname,
                    "email": email,
                    "password": pwd,
                    "public_key": "selftest_key",
                    "display_name": display
                }, timeout=2)
                out[key]["registered"] = {"code": r2.status_code, "ok": r2.status_code == 201}
                logger.trace("[US-Register] %s → %s", uname, r2.status_code)
            except Exception as e:
                out[key]["error"] = (out[key]["error"] or "") + f" | register:{e}"
                logger.error("[US-Register] %s exception: %s", uname, e)
        else:
            out[key]["registered"] = {"skipped": True}

        # second login
        try:
            r3 = requests.post(login_url, json={"username": uname, "password": pwd}, timeout=2)
            out[key]["login_after"] = {"code": r3.status_code, "ok": r3.ok}
            logger.trace("[US-Login2] %s → %s", uname, r3.status_code)
        except Exception as e:
            out[key]["error"] = (out[key]["error"] or "") + f" | login2:{e}"
            logger.error("[US-Login2] %s exception: %s", uname, e)

        out[key]["duration_ms"] = int((time.time() - t0) * 1000)

    dur = (datetime.utcnow() - start).total_seconds()
    logger.info("[US-Done] User tests completed in %.2fs", dur)
    return out
