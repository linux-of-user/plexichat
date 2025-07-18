from typing import Optional
class GovernmentAuth:
    def authenticate(self, username, password, totp_code=None):
        # Dummy authentication logic for demonstration
        if username == "admin" and password == "admin123":
            return {
                "success": True,
                "session_token": "dummy-token",
                "user": username,
                "must_change_password": False,
                "requires_2fa": False
            }
        return {
            "success": False,
            "error": "Invalid credentials",
            "requires_2fa": False
        }

    def validate_session(self, session_token):
        # Dummy session validation
        if session_token == "dummy-token":
            return {"username": "admin"}
        return None

def get_government_auth():
    return GovernmentAuth()
