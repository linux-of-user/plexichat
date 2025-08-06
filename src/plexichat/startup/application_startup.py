#!/usr/bin/env python3
"""
Application Startup System for PlexiChat

Manages the complete startup process with proper service loading,
error handling, and comprehensive logging.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional

# Add src to path if needed
if str(Path(__file__).parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import core systems
try:
    from plexichat.core.logging.unified_logger import setup_logging, get_logger, LogCategory
    from plexichat.core.config.simple_config import init_config, get_config
    from plexichat.core.services.service_loader import get_service_loader, ServiceDefinition, ServicePriority
except ImportError as e:
    print(f"Import error: {e}")
    print("Trying alternative import paths...")

    # Try alternative paths
    import sys
    from pathlib import Path

    # Add the src directory to path
    src_path = Path(__file__).parent.parent.parent
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    from plexichat.core.logging.unified_logger import setup_logging, get_logger, LogCategory
    from plexichat.core.config.simple_config import init_config, get_config
    from plexichat.core.services.service_loader import get_service_loader, ServiceDefinition, ServicePriority

class ApplicationStartup:
    """Manages application startup process."""
    
    def __init__(self):
        self.logger = None
        self.config = None
        self.service_loader = None
        self.startup_time = time.time()
        self.startup_stats = {
            "start_time": self.startup_time,
            "phases_completed": 0,
            "services_loaded": 0,
            "services_started": 0,
            "errors": []
        }
    
    async def startup(self) -> bool:
        """Complete application startup process."""
        try:
            print("[STARTUP] PlexiChat Application Starting...")
            print("=" * 60)
            
            # Phase 1: Initialize logging
            if not await self._phase_1_logging():
                return False
            
            # Phase 2: Load configuration
            if not await self._phase_2_config():
                return False
            
            # Phase 3: Initialize service loader
            if not await self._phase_3_service_loader():
                return False
            
            # Phase 4: Load core services
            if not await self._phase_4_load_services():
                return False
            
            # Phase 5: Start services
            if not await self._phase_5_start_services():
                return False
            
            # Phase 6: Final validation
            if not await self._phase_6_validation():
                return False
            
            # Startup complete
            total_time = time.time() - self.startup_time
            self.logger.info(f"Application startup completed in {total_time:.3f}s", LogCategory.STARTUP)
            self._print_startup_summary()
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.critical(f"Application startup failed: {e}", LogCategory.STARTUP)
            else:
                print(f"[CRITICAL] Application startup failed: {e}")
            return False
    
    async def _phase_1_logging(self) -> bool:
        """Phase 1: Initialize logging system."""
        try:
            print("[PHASE 1] Initializing logging system...")
            
            # Setup logging
            self.logger = setup_logging(log_level="INFO")
            
            self.logger.log_startup("LoggingSystem", "SUCCESS", "ASCII-only logging initialized")
            self.startup_stats["phases_completed"] += 1
            
            print("    Logging system initialized")
            return True
            
        except Exception as e:
            print(f"    Logging initialization failed: {e}")
            self.startup_stats["errors"].append(f"Logging: {e}")
            return False
    
    async def _phase_2_config(self) -> bool:
        """Phase 2: Load configuration."""
        try:
            self.logger.info("Initializing configuration system", LogCategory.STARTUP)
            
            # Initialize configuration
            self.config = init_config()
            
            # Validate configuration
            if not self.config.validate():
                self.logger.error("Configuration validation failed", LogCategory.CONFIG)
                return False
            
            self.logger.log_startup("ConfigSystem", "SUCCESS", "Configuration loaded and validated")
            self.startup_stats["phases_completed"] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration initialization failed: {e}", LogCategory.CONFIG)
            self.startup_stats["errors"].append(f"Config: {e}")
            return False
    
    async def _phase_3_service_loader(self) -> bool:
        """Phase 3: Initialize service loader."""
        try:
            self.logger.info("Initializing service loader", LogCategory.STARTUP)
            
            # Get service loader
            self.service_loader = get_service_loader()
            
            # Register additional services
            self._register_application_services()
            
            self.logger.log_startup("ServiceLoader", "SUCCESS", "Service loader initialized")
            self.startup_stats["phases_completed"] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"Service loader initialization failed: {e}", LogCategory.STARTUP)
            self.startup_stats["errors"].append(f"ServiceLoader: {e}")
            return False
    
    def _register_application_services(self):
        """Register application-specific services."""
        additional_services = [
            ServiceDefinition(
                name="database",
                module_path="plexichat.core.database.db_manager",
                class_name="DatabaseManager",
                priority=ServicePriority.HIGH,
                dependencies=["config"],
                config_key="database"
            ),
            ServiceDefinition(
                name="auth_service",
                module_path="plexichat.core.auth.auth",
                class_name="AuthenticationService",
                priority=ServicePriority.HIGH,
                dependencies=["config", "database"]
            ),
            ServiceDefinition(
                name="api_server",
                module_path="plexichat.interfaces.api.server",
                class_name="APIServer",
                priority=ServicePriority.NORMAL,
                dependencies=["config", "integrated_protection", "auth_service"]
            )
        ]
        
        for service_def in additional_services:
            try:
                self.service_loader.register_service(service_def)
                self.logger.debug(f"Registered service: {service_def.name}", LogCategory.STARTUP)
            except Exception as e:
                self.logger.warning(f"Failed to register service {service_def.name}: {e}", LogCategory.STARTUP)
    
    async def _phase_4_load_services(self) -> bool:
        """Phase 4: Load all services."""
        try:
            self.logger.info("Loading services", LogCategory.STARTUP)
            
            # Load all services
            success = await self.service_loader.load_all_services()
            
            if success:
                self.startup_stats["services_loaded"] = len(self.service_loader.services)
                self.logger.log_startup("ServiceLoading", "SUCCESS", 
                                       f"Loaded {self.startup_stats['services_loaded']} services")
                self.startup_stats["phases_completed"] += 1
                return True
            else:
                self.logger.error("Service loading failed", LogCategory.STARTUP)
                return False
            
        except Exception as e:
            self.logger.error(f"Service loading failed: {e}", LogCategory.STARTUP)
            self.startup_stats["errors"].append(f"ServiceLoading: {e}")
            return False
    
    async def _phase_5_start_services(self) -> bool:
        """Phase 5: Start all services."""
        try:
            self.logger.info("Starting services", LogCategory.STARTUP)
            
            # Start all services
            success = await self.service_loader.start_all_services()
            
            if success:
                # Count running services
                running_count = sum(1 for service in self.service_loader.services.values() 
                                  if service.state.value == "running")
                self.startup_stats["services_started"] = running_count
                
                self.logger.log_startup("ServiceStartup", "SUCCESS", 
                                       f"Started {running_count} services")
                self.startup_stats["phases_completed"] += 1
                return True
            else:
                self.logger.error("Service startup failed", LogCategory.STARTUP)
                return False
            
        except Exception as e:
            self.logger.error(f"Service startup failed: {e}", LogCategory.STARTUP)
            self.startup_stats["errors"].append(f"ServiceStartup: {e}")
            return False
    
    async def _phase_6_validation(self) -> bool:
        """Phase 6: Final validation."""
        try:
            self.logger.info("Performing final validation", LogCategory.STARTUP)
            
            # Check critical services
            critical_services = ["config", "rate_limiter", "integrated_protection"]
            missing_services = []
            
            for service_name in critical_services:
                service = self.service_loader.get_service(service_name)
                if not service:
                    missing_services.append(service_name)
            
            if missing_services:
                self.logger.error(f"Critical services not running: {missing_services}", LogCategory.STARTUP)
                return False
            
            # Validate system health
            protection_service = self.service_loader.get_service("integrated_protection")
            if protection_service:
                try:
                    stats = protection_service.get_comprehensive_stats()
                    self.logger.info("Protection system operational", LogCategory.STARTUP, 
                                   {"load_level": stats["system_metrics"]["load_level"]})
                except Exception as e:
                    self.logger.warning(f"Protection system validation failed: {e}", LogCategory.STARTUP)
            
            self.logger.log_startup("FinalValidation", "SUCCESS", "All systems operational")
            self.startup_stats["phases_completed"] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"Final validation failed: {e}", LogCategory.STARTUP)
            self.startup_stats["errors"].append(f"Validation: {e}")
            return False
    
    def _print_startup_summary(self):
        """Print startup summary."""
        print("\n" + "=" * 60)
        print(" PLEXICHAT STARTUP SUMMARY")
        print("=" * 60)
        
        total_time = time.time() - self.startup_time
        print(f"Total startup time: {total_time:.3f}s")
        print(f"Phases completed: {self.startup_stats['phases_completed']}/6")
        print(f"Services loaded: {self.startup_stats['services_loaded']}")
        print(f"Services started: {self.startup_stats['services_started']}")
        
        if self.startup_stats["errors"]:
            print(f"Errors encountered: {len(self.startup_stats['errors'])}")
            for error in self.startup_stats["errors"]:
                print(f"  - {error}")
        else:
            print("No errors encountered")
        
        # Service status
        if self.service_loader:
            print("\nService Status:")
            status = self.service_loader.get_service_status()
            for name, info in status.items():
                state_icon = "" if info["state"] == "running" else "" if info["state"] == "loaded" else ""
                print(f"  {state_icon} {name}: {info['state']}")
        
        print("\n PlexiChat is ready!")
        print("=" * 60)
    
    async def shutdown(self):
        """Shutdown the application."""
        if self.logger:
            self.logger.info("Application shutdown initiated", LogCategory.STARTUP)
        
        if self.service_loader:
            await self.service_loader.stop_all_services()
        
        if self.logger:
            self.logger.info("Application shutdown completed", LogCategory.STARTUP)
            self.logger.flush()

async def main():
    """Main startup function."""
    startup = ApplicationStartup()
    
    try:
        success = await startup.startup()
        if success:
            print("\n[INFO] Application started successfully")
            print("[INFO] Press Ctrl+C to shutdown")
            
            # Keep running
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\n[INFO] Shutdown signal received")
        else:
            print("\n[ERROR] Application startup failed")
            return 1
    
    except KeyboardInterrupt:
        print("\n[INFO] Startup interrupted")
    except Exception as e:
        print(f"\n[ERROR] Startup error: {e}")
        return 1
    finally:
        await startup.shutdown()
    
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
