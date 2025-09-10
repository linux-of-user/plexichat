# Server Accessibility Fix Plan

## Overview

The server accessibility issue manifests as "connection refused" when attempting to access http://0.0.0.0:8000, despite uvicorn logs indicating the server is running. This occurs post-refactors in the full testing phase. The root cause is likely a mismatch between the intended binding (host='0.0.0.0', port=8000) and actual network behavior, possibly due to:

- Default host binding to localhost (127.0.0.1) instead of 0.0.0.0 if config is not loaded properly.
- Port conflict or failure to bind to port 8000 (e.g., another process using it).
- Firewall rules on Windows 11 blocking inbound connections on port 8000.
- Network configuration issues, such as IPv6 preferences or loopback restrictions.

The fix focuses on ensuring explicit binding in run.py, verifying port availability, and checking/adjusting firewall settings. This resolves accessibility without altering core logic, plugins, or features. The change is low-risk, primarily config/network adjustments, and enables MCP testing by making the server reachable via curl or browser.

Verification: Updating uvicorn.run in run.py to explicitly pass host='0.0.0.0' and port=8000 (overriding config if needed) should resolve binding issues. Firewall checks ensure external access without adding bloat (no new dependencies or complex scripts).

Commit message for code changes: "Fix server accessibility: ensure uvicorn binds to 0.0.0.0:8000 in run.py with port conflict handling"

## Affected Files

- **run.py**: Primary file starting the uvicorn server via threading.Thread(target=run_server). Currently uses api_config.get("host", "0.0.0.0") and api_port, but may fail if config loading skips or defaults incorrectly. Update the run_server function to explicitly enforce host='0.0.0.0', port=8000, and add try-except for binding errors (e.g., OSError for port in use). Also, add logging for actual bound address.
  
- **src/plexichat/core/config.py** (or equivalent config loader): If api host/port are overridden here (e.g., defaulting to '127.0.0.1'), update defaults to '0.0.0.0' and 8000. Scan confirms no direct uvicorn calls here, but config affects run.py.

- No changes to main.py or API routers: These provide the FastAPI app but do not start uvicorn. Commented uvicorn.run lines in v1 routers are irrelevant (not executed).

- Potential: Windows Firewall script (new, if needed): A simple batch or Python script to temporarily allow port 8000 inbound, but prefer manual check to avoid bloat.

No core logic files (e.g., plugins, database) affected; changes are isolated to startup config.

## Fix Steps

1. **Verify Current Binding (Diagnostic)**:
   - In run.py, enhance logging in run_server: After uvicorn.run, log the bound address (e.g., logger.info(f"Server bound to {host}:{port}")). No code change yet; run and check logs to confirm if it's binding to 127.0.0.1 vs 0.0.0.0.

2. **Update run.py for Explicit Binding**:
   - In the run_server function (around line 1243), modify uvicorn.run to always use host='0.0.0.0', port=8000, regardless of config:
     ```
     uvicorn.run(
         app,
         host='0.0.0.0',
         port=8000,
         timeout_keep_alive=network_config.timeout_keep_alive if hasattr(network_config, 'timeout_keep_alive') else 60,
         log_level='info'
     )
     ```
   - Wrap in try-except for binding errors:
     ```
     try:
         uvicorn.run(...)
     except OSError as e:
         if "Address already in use" in str(e):
             logger.error("Port 8000 in use; try a different port or kill conflicting process.")
             sys.exit(1)
         raise
     ```
   - This ensures accessibility without breaking if config is misloaded. Preserve existing timeout_keep_alive for no functional loss.

3. **Config Fallback Enhancement**:
   - If src/plexichat/core/config.py sets api host to '127.0.0.1', change default to '0.0.0.0'. Add validation in get_config to warn if host != '0.0.0.0'.

4. **Firewall Adjustment (Non-Code)**:
   - Manually add Windows Firewall rule: Allow inbound TCP on port 8000 for private/public networks. Command: `netsh advfirewall firewall add rule name="PlexiChat API" dir=in action=allow protocol=TCP localport=8000`.
   - No code change; document in plan for manual execution.

5. **Port Conflict Handling**:
   - Add dynamic port fallback in run.py: If port 8000 fails, try 8001 and log the new port. Update curl tests accordingly.

These steps ensure the server binds correctly and is accessible externally.

## Risk Mitigation

- **Low Risk Overall**: Changes are config/network-focused; no impact on core logic, database, plugins, or auth. run.py modifications are isolated to startup.

- **Potential Issues**:
  - **Port Conflict**: If 8000 is used (e.g., by another app), binding fails. Impact: Server doesn't start. Mitigation: Try-except in run.py detects and logs; suggest `netstat -ano | findstr :8000` to identify/kill process (Windows). Test on different OS (e.g., Linux binds more permissively).
  - **Config Override**: If external config forces '127.0.0.1', explicit override in run.py may conflict. Impact: Minor logging noise. Mitigation: Add config validation in run.py to warn and override.
  - **Firewall Block**: Windows 11 may block despite binding. Impact: Still connection refused. Mitigation: Manual rule addition; test with `telnet localhost 8000` (internal) vs `curl http://0.0.0.0:8000` (external). No persistent changes; user can revert.
  - **Threading Issues**: uvicorn in thread may not log binding properly. Impact: Hard to debug. Mitigation: Add explicit logging post-start; test startup time <5s.
  - **Cross-OS**: Windows firewall differs from Linux iptables. Impact: Fix works on Windows but needs iptables rule on Linux. Mitigation: Document OS-specific steps; test binding with `netstat -tuln | grep 8000`.

- **No Functionality Removal**: All features (API routes, plugins, WebUI) remain; only startup accessibility improved. Backup plan: Revert run.py changes if issues arise (git revert).

- **Testing Impact**: Low; run.py changes testable in isolation without full app.

## Testing Steps

1. **Pre-Fix Verification**:
   - Run `python run.py` and check logs for binding (e.g., "Uvicorn running on http://0.0.0.0:8000"). Use `netstat -ano | findstr :8000` to confirm LISTENING on 0.0.0.0.
   - Test internal: `curl http://localhost:8000` (should work if bound).
   - Test external: `curl http://0.0.0.0:8000` or browser (fails now).

2. **Post-Fix Implementation**:
   - Apply run.py changes; restart server.
   - Verify logs show explicit binding to 0.0.0.0:8000.
   - Add firewall rule if needed; retest curl.

3. **Comprehensive Tests**:
   - Port conflict sim: Run another app on 8000; verify error logging and exit.
   - Firewall test: Disable rule temporarily; confirm refusal, then re-enable.
   - Full MCP test: Once accessible, run curl on health endpoint; verify response.
   - Cross-OS: Note for Linux/Mac (e.g., `lsof -i :8000` for conflicts).
   - Load test: 10 concurrent curls; ensure no binding drops.

4. **Rollback Test**: Revert changes; confirm original behavior.

This plan achieves perfect server operation for MCP testing with minimal risk.