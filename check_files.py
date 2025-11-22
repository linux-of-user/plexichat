"""
Script to check which files need standardization.
"""
import os

src_dir = "src/plexichat"
files_needing_work = []

# Files I've already rewritten/standardized in this session
standardized_files = {
    "core/database/manager.py",
    "core/coordinator.py",
    "core/config.py",
    "core/logging.py",
    "core/auth/services/authentication.py",
    "core/auth/services/session_service.py",
    "core/auth/permissions.py",
    "core/auth/exceptions_auth.py",
    "core/cache/manager.py",
    "core/performance/message_queue.py",
    "core/performance/microsecond_optimizer.py",
    "core/performance/scalability_manager.py",
    "core/performance/latency_optimizer.py",
    "core/database/models.py",
    "core/websocket/websocket_manager.py",
    "core/security/security_manager.py",
    "core/services/rate_limiter.py",
    "core/services/user_service.py",
    "core/plugins/plugin_manager.py",
    "features/ai/ai_coordinator.py",
    "features/messaging/messaging_service.py",
    "features/channels/channel_service.py",
    "interfaces/api/routers/status_router.py",
    "interfaces/api/routers/performance_router.py",
    "interfaces/api/routers/file_sharing_router.py",
    "interfaces/cli/commands/settings.py",
    "interfaces/web/components/thread_component.py",
    "interfaces/web/routers/help.py",
    "infrastructure/scalability/coordinator.py",
    "infrastructure/deployment/deployment_manager.py",
    "infrastructure/monitoring/monitoring_service.py",
    "main.py",
}

for root, dirs, files in os.walk(src_dir):
    for file in files:
        if file.endswith(".py"):
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, src_dir)
            
            if rel_path not in standardized_files and not rel_path.startswith("__pycache__"):
                files_needing_work.append(rel_path)

print(f"Total files: {len(files_needing_work) + len(standardized_files)}")
print(f"Already standardized: {len(standardized_files)}")
print(f"Need standardization: {len(files_needing_work)}")
print(f"\nFirst 20 files needing work:")
for f in files_needing_work[:20]:
    print(f"  - {f}")
