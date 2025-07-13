import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.logger_config import logger, monitoring_logger, selftest_logger, settings
from app.utils.self_tests.connectivity import run_connectivity_tests
from app.utils.self_tests.database import run_database_tests
from app.utils.self_tests.endpoints import run_endpoint_tests
from app.utils.self_tests.test_executor import test_executor
from app.utils.self_tests.users import run_user_tests
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
from apscheduler.schedulers.background import BackgroundScheduler


                   from plexichat.core.config import settings
                                 from plexichat.core.config import settings

# app/utils/scheduling.py
"""
Enhanced self-test scheduling system with comprehensive error handling,
configurable intervals, and detailed reporting.
"""

_scheduler: Optional[BackgroundScheduler] = None
_failure_count = 0
_last_success_time: Optional[datetime] = None


def run_comprehensive_self_tests() -> Dict[str, Any]:
    """Run comprehensive self-test suite with enhanced reporting."""
    global _failure_count, _last_success_time

    if not from plexichat.core.config import settings
settings.SELFTEST_ENABLED:
        selftest_logger.info("Self-tests are disabled")
        return {"status": "DISABLED", "message": "Self-tests disabled in configuration"}

    start_time = datetime.now(timezone.utc)
    selftest_logger.info("=" * 60)
    selftest_logger.info("STARTING COMPREHENSIVE SELF-TEST SUITE")
    selftest_logger.info("=" * 60)

    try:
        # Validate test environment first
        env_ok, env_issues = test_executor.validate_test_environment()
        if not env_ok:
            selftest_logger.error("Test environment validation failed: %s", env_issues)
            return {
                "status": "ENVIRONMENT_ERROR",
                "issues": env_issues,
                "timestamp": start_time.isoformat() + "Z"
            }

        # Define test suite
        test_suite = {
            "connectivity": run_connectivity_tests,
            "database": run_database_tests,
            "users": run_user_tests,
            "endpoints": run_endpoint_tests
        }

        # Execute test suite using the enhanced executor
        suite_result = test_executor.execute_test_suite("comprehensive_selftest", test_suite)

        # Determine overall success
        success_rate = suite_result.summary["success_rate"]
        overall_success = success_rate >= 80  # 80% success threshold

        if overall_success:
            _failure_count = 0
            _last_success_time = start_time
            selftest_logger.info("Self-test suite PASSED (%.1f%% success rate)", success_rate)
        else:
            _failure_count += 1
            selftest_logger.warning("Self-test suite FAILED (%.1f%% success rate, failure #%d)",
                                  success_rate, _failure_count)

        # Log monitoring metrics
        if from plexichat.core.config import settings
settings.MONITORING_ENABLED and from plexichat.core.config import settings
settings.MONITORING_LOG_PERFORMANCE:
            monitoring_logger.info("SELFTEST_METRICS: duration=%.2fs success_rate=%.1f%% failures=%d",
                                 suite_result.duration_ms / 1000, success_rate, _failure_count)

        return {
            "status": "SUCCESS" if overall_success else "FAILED",
            "suite_result": suite_result,
            "failure_count": _failure_count,
            "last_success": _last_success_time.isoformat() + "Z" if _last_success_time else None
        }

    except Exception as e:
        _failure_count += 1
        error_details = {
            "error": str(e),
            "traceback": traceback.format_exc(),
            "failure_count": _failure_count
        }

        selftest_logger.error("Self-test suite execution failed: %s", e)
        selftest_logger.debug("Self-test error details: %s", error_details["traceback"])

        return {
            "status": "ERROR",
            "error_details": error_details,
            "timestamp": start_time.isoformat() + "Z"
        }


def _job_listener(event):
    """Listen to scheduler job events for monitoring."""
    if event.job_id == 'comprehensive_selftest_job':
        if event.exception:
            selftest_logger.error("Scheduled self-test job failed: %s", event.exception)
            if from plexichat.core.config import settings
settings.MONITORING_ENABLED:
                monitoring_logger.error("SELFTEST_JOB_ERROR: %s", event.exception)
        else:
            selftest_logger.debug("Scheduled self-test job completed successfully")


def start_scheduler():
    """Start the enhanced self-test scheduler."""
    global _scheduler

    if not from plexichat.core.config import settings
settings.SELFTEST_ENABLED:
        logger.info("Self-test scheduler disabled in configuration")
        return

    if _scheduler is not None:
        logger.warning("Self-test scheduler already running")
        return

    try:
        _scheduler = BackgroundScheduler()

        # Add job event listener
        _scheduler.add_listener(_job_listener, EVENT_JOB_ERROR | EVENT_JOB_EXECUTED)

        # Calculate initial delay and interval
        initial_delay = timedelta(seconds=from plexichat.core.config import settings
settings.SELFTEST_INITIAL_DELAY_SECONDS)
        interval_minutes = from plexichat.core.config import settings
settings.SELFTEST_INTERVAL_MINUTES

        # Schedule the comprehensive self-test job
        _scheduler.add_job(
            run_comprehensive_self_tests,
            'interval',
            minutes=interval_minutes,
            next_run_time=datetime.now(timezone.utc) + initial_delay,
            id='comprehensive_selftest_job',
            max_instances=1,  # Prevent overlapping executions
            coalesce=True,    # Combine missed executions
            misfire_grace_time=60  # Allow 60 seconds grace for missed executions
        )

        _scheduler.start()

        logger.info("Self-test scheduler started successfully")
        logger.info("Configuration: initial_delay=%ds, interval=%dm",
settings.SELFTEST_INITIAL_DELAY_SECONDS, interval_minutes)

        if from plexichat.core.config import settings
settings.MONITORING_ENABLED:
            monitoring_logger.info("SELFTEST_SCHEDULER_STARTED: delay=%ds interval=%dm",
settings.SELFTEST_INITIAL_DELAY_SECONDS, interval_minutes)

    except Exception as e:
        logger.error("Failed to start self-test scheduler: %s", e)
        logger.debug("Scheduler error details: %s", traceback.format_exc())
        _scheduler = None

        if from plexichat.core.config import settings
settings.MONITORING_ENABLED:
            monitoring_logger.error("SELFTEST_SCHEDULER_ERROR: %s", e)


def stop_scheduler():
    """Stop the self-test scheduler."""
    global _scheduler

    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=True)
            _scheduler = None
            logger.info("Self-test scheduler stopped")

            if from plexichat.core.config import settings
settings.MONITORING_ENABLED:
                monitoring_logger.info("SELFTEST_SCHEDULER_STOPPED")

        except Exception as e:
            logger.error("Error stopping self-test scheduler: %s", e)


def get_scheduler_status() -> Dict[str, Any]:
    """Get current scheduler status and statistics."""
    global _scheduler, _failure_count, _last_success_time

    if not from plexichat.core.config import settings
settings.SELFTEST_ENABLED:
        return {"status": "DISABLED", "message": "Self-tests disabled in configuration"}

    if _scheduler is None:
        return {"status": "NOT_RUNNING", "message": "Scheduler not started"}

    try:
        jobs = _scheduler.get_jobs()
        next_run = None

        for job in jobs:
            if job.id == 'comprehensive_selftest_job':
                next_run = job.next_run_time.isoformat() + "Z" if job.next_run_time else None
                break

        return {
            "status": "RUNNING",
            "next_run": next_run,
            "failure_count": _failure_count,
            "last_success": _last_success_time.isoformat() + "Z" if _last_success_time else None,
            "interval_minutes": from plexichat.core.config import settings
settings.SELFTEST_INTERVAL_MINUTES,
            "job_count": len(jobs)
        }

    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


# Legacy function for backward compatibility
def run_all():
    """Legacy function - redirects to new comprehensive test runner."""
    result = run_comprehensive_self_tests()
    return result.get("suite_result", {}).get("tests", {})
