"""
Enhanced CLI Logic Engine
Advanced automation, scripting, and logic processing for CLI commands.
"""

import asyncio
import json
import re
import logging
import os
import random
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
import yaml
try:
    import croniter
except ImportError:
    croniter = None
try:
    from jinja2 import Template
except ImportError:
    Template = None

logger = logging.getLogger(__name__)

class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"

class ConditionType(str, Enum):
    """Condition types for logic engine."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    REGEX_MATCH = "regex_match"
    FILE_EXISTS = "file_exists"
    COMMAND_SUCCESS = "command_success"
    TIME_RANGE = "time_range"
    SYSTEM_METRIC = "system_metric"

@dataclass
class Condition:
    """Logic condition definition."""
    type: ConditionType
    field: str
    value: Any
    operator: str = "and"  # and, or, not
    
@dataclass
class Action:
    """Action definition for automation."""
    type: str  # command, notification, webhook, etc.
    command: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    retry_count: int = 0
    timeout: int = 30
    
@dataclass
class AutomationRule:
    """Automation rule definition."""
    id: str
    name: str
    description: str
    enabled: bool
    conditions: List[Condition]
    actions: List[Action]
    schedule: Optional[str] = None  # Cron expression
    created_at: datetime = None
    last_run: Optional[datetime] = None
    run_count: int = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class TaskExecution:
    """Task execution record."""
    id: str
    rule_id: str
    status: TaskStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    logs: List[str] = None
    
    def __post_init__(self):
        if self.logs is None:
            self.logs = []

class EnhancedLogicEngine:
    """Enhanced logic engine for CLI automation and scripting."""
    
    def __init__(self, config_path: str = "cli_automation.yaml"):
        self.config_path = Path(config_path)
        self.rules: Dict[str, AutomationRule] = {}
        self.executions: Dict[str, TaskExecution] = {}
        self.variables: Dict[str, Any] = {}
        self.functions: Dict[str, Callable] = {}
        
        # Built-in variables
        self.variables.update({
            'current_time': datetime.now(),
            'current_date': datetime.now().date(),
            'system_uptime': 0,  # Would be calculated
            'server_status': 'unknown'
        })
        
        # Register built-in functions
        self._register_builtin_functions()
        
        # Load configuration
        self.load_config()
        
        # Scheduler
        self._scheduler_task = None
        self._running = False
    
    def _register_builtin_functions(self):
        """Register built-in functions for logic engine."""
        self.functions.update({
            'now': lambda: datetime.now(),
            'today': lambda: datetime.now().date(),
            'format_time': lambda dt, fmt='%Y-%m-%d %H:%M:%S': dt.strftime(fmt),
            'days_ago': lambda days: datetime.now() - timedelta(days=days),
            'hours_ago': lambda hours: datetime.now() - timedelta(hours=hours),
            'file_size': lambda path: Path(path).stat().st_size if Path(path).exists() else 0,
            'file_age': lambda path: (datetime.now() - datetime.fromtimestamp(Path(path).stat().st_mtime)).days if Path(path).exists() else -1,
            'env_var': lambda name, default=None: os.environ.get(name, default),
            'random_int': lambda min_val, max_val: random.randint(min_val, max_val),
            'uuid': lambda: str(uuid.uuid4()),
            'hash_string': lambda s: hashlib.md5(s.encode()).hexdigest()
        })
    
    def load_config(self):
        """Load automation configuration."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                
                # Load rules
                for rule_data in config.get('rules', []):
                    rule = AutomationRule(**rule_data)
                    self.rules[rule.id] = rule
                
                # Load variables
                self.variables.update(config.get('variables', {}))
                
                logger.info(f"Loaded {len(self.rules)} automation rules")
                
            except Exception as e:
                logger.error(f"Failed to load automation config: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default automation configuration."""
        default_rules = [
            AutomationRule(
                id="daily_backup",
                name="Daily Database Backup",
                description="Automatically backup database every day at 2 AM",
                enabled=True,
                conditions=[
                    Condition(
                        type=ConditionType.TIME_RANGE,
                        field="hour",
                        value=2
                    )
                ],
                actions=[
                    Action(
                        type="command",
                        command="database backup",
                        parameters={"auto": True}
                    )
                ],
                schedule="0 2 * * *"  # Daily at 2 AM
            ),
            AutomationRule(
                id="system_health_check",
                name="System Health Monitor",
                description="Check system health every 15 minutes",
                enabled=True,
                conditions=[
                    Condition(
                        type=ConditionType.SYSTEM_METRIC,
                        field="cpu_usage",
                        value=80,
                        operator="greater_than"
                    )
                ],
                actions=[
                    Action(
                        type="notification",
                        parameters={"message": "High CPU usage detected: {cpu_usage}%"}
                    ),
                    Action(
                        type="command",
                        command="logs system --tail 50"
                    )
                ],
                schedule="*/15 * * * *"  # Every 15 minutes
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.id] = rule
        
        self.save_config()
    
    def save_config(self):
        """Save automation configuration."""
        try:
            config = {
                'rules': [asdict(rule) for rule in self.rules.values()],
                'variables': self.variables,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, indent=2, default_flow_style=False)
                
        except Exception as e:
            logger.error(f"Failed to save automation config: {e}")
    
    def add_rule(self, rule: AutomationRule) -> bool:
        """Add automation rule."""
        try:
            self.rules[rule.id] = rule
            self.save_config()
            logger.info(f"Added automation rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add rule {rule.id}: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove automation rule."""
        try:
            if rule_id in self.rules:
                rule_name = self.rules[rule_id].name
                del self.rules[rule_id]
                self.save_config()
                logger.info(f"Removed automation rule: {rule_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove rule {rule_id}: {e}")
            return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable automation rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            self.save_config()
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable automation rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            self.save_config()
            return True
        return False
    
    async def evaluate_condition(self, condition: Condition, context: Dict[str, Any] = None) -> bool:
        """Evaluate a single condition."""
        try:
            context = context or {}
            
            # Get field value
            field_value = self._get_field_value(condition.field, context)
            
            # Evaluate based on condition type
            if condition.type == ConditionType.EQUALS:
                return field_value == condition.value
            
            elif condition.type == ConditionType.NOT_EQUALS:
                return field_value != condition.value
            
            elif condition.type == ConditionType.GREATER_THAN:
                return float(field_value) > float(condition.value)
            
            elif condition.type == ConditionType.LESS_THAN:
                return float(field_value) < float(condition.value)
            
            elif condition.type == ConditionType.CONTAINS:
                return str(condition.value) in str(field_value)
            
            elif condition.type == ConditionType.REGEX_MATCH:
                return bool(re.match(condition.value, str(field_value)))
            
            elif condition.type == ConditionType.FILE_EXISTS:
                return Path(condition.value).exists()
            
            elif condition.type == ConditionType.COMMAND_SUCCESS:
                # Execute command and check return code
                result = await self._execute_command(condition.value)
                return result.get('success', False)
            
            elif condition.type == ConditionType.TIME_RANGE:
                current_hour = datetime.now().hour
                return current_hour == condition.value
            
            elif condition.type == ConditionType.SYSTEM_METRIC:
                metric_value = await self._get_system_metric(condition.field)
                return float(metric_value) > float(condition.value)
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False
    
    def _get_field_value(self, field: str, context: Dict[str, Any]) -> Any:
        """Get field value from context or variables."""
        # Check context first
        if field in context:
            return context[field]
        
        # Check variables
        if field in self.variables:
            return self.variables[field]
        
        # Check if it's a function call
        if '(' in field and ')' in field:
            return self._evaluate_function(field)
        
        # Return field name as literal
        return field
    
    def _evaluate_function(self, expression: str) -> Any:
        """Evaluate function expression."""
        try:
            # Simple function parsing (could be enhanced)
            match = re.match(r'(\w+)\((.*)\)', expression)
            if match:
                func_name, args_str = match.groups()
                
                if func_name in self.functions:
                    # Parse arguments (simplified)
                    args = []
                    if args_str.strip():
                        args = [arg.strip().strip('"\'') for arg in args_str.split(',')]
                    
                    return self.functions[func_name](*args)
            
            return expression
            
        except Exception as e:
            logger.error(f"Error evaluating function {expression}: {e}")
            return expression
    
    async def _get_system_metric(self, metric: str) -> float:
        """Get system metric value."""
        # This would integrate with actual system monitoring
        metrics = {
            'cpu_usage': 15.5,
            'memory_usage': 45.2,
            'disk_usage': 23.8,
            'network_io': 1.2
        }
        return metrics.get(metric, 0.0)
    
    async def _execute_command(self, command: str) -> Dict[str, Any]:
        """Execute CLI command."""
        try:
            # This would integrate with the actual CLI system
            logger.info(f"Executing automation command: {command}")
            
            # Simulate command execution
            await asyncio.sleep(0.1)
            
            return {
                'success': True,
                'output': f"Command '{command}' executed successfully",
                'exit_code': 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'exit_code': 1
            }

    async def evaluate_conditions(self, conditions: List[Condition], context: Dict[str, Any] = None) -> bool:
        """Evaluate multiple conditions with logical operators."""
        if not conditions:
            return True

        results = []
        current_operator = "and"

        for condition in conditions:
            result = await self.evaluate_condition(condition, context)

            if condition.operator == "not":
                result = not result

            results.append((result, current_operator))
            current_operator = condition.operator

        # Evaluate results with operators
        final_result = results[0][0] if results else True

        for i in range(1, len(results)):
            result, operator = results[i]

            if operator == "and":
                final_result = final_result and result
            elif operator == "or":
                final_result = final_result or result

        return final_result

    async def execute_rule(self, rule_id: str, context: Dict[str, Any] = None) -> TaskExecution:
        """Execute automation rule."""
        if rule_id not in self.rules:
            raise ValueError(f"Rule not found: {rule_id}")

        rule = self.rules[rule_id]
        execution_id = f"{rule_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        execution = TaskExecution(
            id=execution_id,
            rule_id=rule_id,
            status=TaskStatus.RUNNING,
            started_at=datetime.now()
        )

        self.executions[execution_id] = execution

        try:
            execution.logs.append(f"Starting execution of rule: {rule.name}")

            # Evaluate conditions
            if rule.conditions:
                conditions_met = await self.evaluate_conditions(rule.conditions, context)
                execution.logs.append(f"Conditions evaluation: {conditions_met}")

                if not conditions_met:
                    execution.status = TaskStatus.COMPLETED
                    execution.completed_at = datetime.now()
                    execution.result = {'conditions_met': False, 'actions_executed': 0}
                    execution.logs.append("Conditions not met, skipping actions")
                    return execution

            # Execute actions
            action_results = []
            for i, action in enumerate(rule.actions):
                execution.logs.append(f"Executing action {i+1}/{len(rule.actions)}: {action.type}")

                result = await self.execute_action(action, context)
                action_results.append(result)

                if not result.get('success', False):
                    execution.logs.append(f"Action failed: {result.get('error', 'Unknown error')}")
                    if action.retry_count == 0:  # No retries for now
                        break
                else:
                    execution.logs.append(f"Action completed successfully")

            # Update execution
            execution.status = TaskStatus.COMPLETED
            execution.completed_at = datetime.now()
            execution.result = {
                'conditions_met': True,
                'actions_executed': len(action_results),
                'action_results': action_results
            }

            # Update rule statistics
            rule.last_run = datetime.now()
            rule.run_count += 1
            self.save_config()

            execution.logs.append(f"Rule execution completed successfully")

        except Exception as e:
            execution.status = TaskStatus.FAILED
            execution.completed_at = datetime.now()
            execution.error = str(e)
            execution.logs.append(f"Rule execution failed: {e}")
            logger.error(f"Rule execution failed for {rule_id}: {e}")

        return execution

    async def execute_action(self, action: Action, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a single action."""
        try:
            context = context or {}

            if action.type == "command":
                return await self._execute_command_action(action, context)

            elif action.type == "notification":
                return await self._execute_notification_action(action, context)

            elif action.type == "webhook":
                return await self._execute_webhook_action(action, context)

            elif action.type == "email":
                return await self._execute_email_action(action, context)

            elif action.type == "script":
                return await self._execute_script_action(action, context)

            else:
                return {
                    'success': False,
                    'error': f'Unknown action type: {action.type}'
                }

        except Exception as e:
            logger.error(f"Error executing action {action.type}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def _execute_command_action(self, action: Action, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute command action."""
        command = action.command

        # Template substitution
        if command and context and Template:
            template = Template(command)
            command = template.render(**context, **self.variables)

        return await self._execute_command(command)

    async def _execute_notification_action(self, action: Action, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute notification action."""
        try:
            params = action.parameters or {}
            message = params.get('message', 'Automation notification')

            # Template substitution
            if context:
                template = Template(message)
                message = template.render(**context, **self.variables)

            # This would integrate with notification system
            logger.info(f"NOTIFICATION: {message}")

            return {
                'success': True,
                'message': message
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def start_scheduler(self):
        """Start the automation scheduler."""
        if self._running:
            return

        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Automation scheduler started")

    async def stop_scheduler(self):
        """Stop the automation scheduler."""
        self._running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("Automation scheduler stopped")

    async def _scheduler_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                current_time = datetime.now()

                for rule_id, rule in self.rules.items():
                    if not rule.enabled or not rule.schedule:
                        continue

                    # Check if rule should run based on schedule
                    if self._should_run_rule(rule, current_time):
                        logger.info(f"Triggering scheduled rule: {rule.name}")

                        # Execute rule in background
                        asyncio.create_task(self.execute_rule(rule_id))

                # Sleep for 60 seconds before next check
                await asyncio.sleep(60)

            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)

    def _should_run_rule(self, rule: AutomationRule, current_time: datetime) -> bool:
        """Check if rule should run based on schedule."""
        try:
            if not rule.schedule or not croniter:
                return False

            # Use croniter to check if rule should run
            cron = croniter.croniter(rule.schedule, current_time)
            next_run = cron.get_prev(datetime)

            # Check if rule should have run in the last minute
            if rule.last_run is None:
                return True

            return next_run > rule.last_run

        except Exception as e:
            logger.error(f"Error checking rule schedule for {rule.id}: {e}")
            return False

    def get_rule_status(self, rule_id: str) -> Dict[str, Any]:
        """Get rule status and statistics."""
        if rule_id not in self.rules:
            return {'error': 'Rule not found'}

        rule = self.rules[rule_id]

        # Get recent executions
        recent_executions = [
            exec for exec in self.executions.values()
            if exec.rule_id == rule_id
        ]
        recent_executions.sort(key=lambda x: x.started_at, reverse=True)
        recent_executions = recent_executions[:10]  # Last 10 executions

        return {
            'rule': asdict(rule),
            'recent_executions': [asdict(exec) for exec in recent_executions],
            'total_executions': len([e for e in self.executions.values() if e.rule_id == rule_id]),
            'success_rate': self._calculate_success_rate(rule_id)
        }

    def _calculate_success_rate(self, rule_id: str) -> float:
        """Calculate success rate for a rule."""
        executions = [e for e in self.executions.values() if e.rule_id == rule_id]
        if not executions:
            return 0.0

        successful = len([e for e in executions if e.status == TaskStatus.COMPLETED])
        return (successful / len(executions)) * 100

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all automation rules."""
        return [
            {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'enabled': rule.enabled,
                'schedule': rule.schedule,
                'last_run': rule.last_run.isoformat() if rule.last_run else None,
                'run_count': rule.run_count,
                'success_rate': self._calculate_success_rate(rule.id)
            }
            for rule in self.rules.values()
        ]

    def get_execution_logs(self, execution_id: str) -> Dict[str, Any]:
        """Get execution logs."""
        if execution_id not in self.executions:
            return {'error': 'Execution not found'}

        execution = self.executions[execution_id]
        return asdict(execution)

    def cleanup_old_executions(self, days: int = 30):
        """Clean up old execution records."""
        cutoff_date = datetime.now() - timedelta(days=days)

        old_executions = [
            exec_id for exec_id, execution in self.executions.items()
            if execution.started_at < cutoff_date
        ]

        for exec_id in old_executions:
            del self.executions[exec_id]

        logger.info(f"Cleaned up {len(old_executions)} old execution records")
        return len(old_executions)

    def export_config(self) -> Dict[str, Any]:
        """Export automation configuration."""
        return {
            'rules': [asdict(rule) for rule in self.rules.values()],
            'variables': self.variables,
            'exported_at': datetime.now().isoformat()
        }

    def import_config(self, config: Dict[str, Any]) -> bool:
        """Import automation configuration."""
        try:
            # Import rules
            for rule_data in config.get('rules', []):
                rule = AutomationRule(**rule_data)
                self.rules[rule.id] = rule

            # Import variables
            self.variables.update(config.get('variables', {}))

            # Save configuration
            self.save_config()

            logger.info(f"Imported {len(config.get('rules', []))} rules")
            return True

        except Exception as e:
            logger.error(f"Failed to import config: {e}")
            return False
