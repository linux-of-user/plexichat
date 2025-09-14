import logging
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from plexichat.interfaces.cli.cli_manager import UnifiedCLI

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/cli", tags=["cli"])
security = HTTPBearer()

# In-memory rate limiter: {user_or_ip: [timestamps]}
RATE_LIMIT: dict[str, list] = {}
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds


# Pydantic models
class CLIExecuteRequest(BaseModel):
    command: str


class CLIExecuteResponse(BaseModel):
    success: bool
    output: str = ""
    error: str = ""
    output_type: str = "info"


# Dummy admin check (replace with real auth system)
def is_admin(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    # TODO: Integrate with real session/auth system
    if not token or token != "admin-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required",
        )
    return "admin"


def sanitize_command(cmd: str) -> str:
    # Only allow safe characters (letters, numbers, space, dash, underscore, dot, colon)
    if not re.match(r"^[\w\s\-\_\.:]+$", cmd):
        raise HTTPException(status_code=400, detail="Invalid command syntax")
    return cmd.strip()


def check_rate_limit(user: str, ip: str):
    key = f"{user}:{ip}"
    now = time.time()
    timestamps = RATE_LIMIT.get(key, [])
    # Remove old timestamps
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429, detail="Rate limit exceeded. Try again later."
        )
    timestamps.append(now)
    RATE_LIMIT[key] = timestamps


@router.post("/execute", response_model=CLIExecuteResponse)
async def execute_cli_command(
    req: CLIExecuteRequest, request: Request, user: str = Depends(is_admin)
) -> CLIExecuteResponse:
    """
    Execute a CLI command securely using the UnifiedCLI system.
    Requires admin authentication and is rate-limited.
    """
    client_ip = request.client.host if request.client else "unknown"
    command = sanitize_command(req.command)
    check_rate_limit(user, client_ip)
    logger.info(f"[CLI] User '{user}' from {client_ip} executing command: {command}")

    cli = UnifiedCLI()
    try:
        # Run the command in the unified CLI system
        # (simulate terminal mode, capture output)
        result = cli.execute_system_command(command, {"user": user, "ip": client_ip})
        output = result.get("message", "")
        return CLIExecuteResponse(success=True, output=output, output_type="info")
    except Exception as e:
        logger.error(f"[CLI] Command execution error: {e}")
        return CLIExecuteResponse(success=False, error=str(e), output_type="error")
