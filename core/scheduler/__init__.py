"""Core scheduler module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["TaskScheduler", "ScheduledTask", "TaskStatus", "TaskType", "task_scheduler", "schedule_once"]

class TaskScheduler:
    def __init__(self):
        pass

class ScheduledTask:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class TaskStatus:
    PENDING = 1
    RUNNING = 2
    COMPLETED = 3

class TaskType:
    ONE_TIME = 1
    RECURRING = 2

task_scheduler = None

def schedule_once(*args, **kwargs):
    pass

def schedule_recurring(*args, **kwargs):
    pass