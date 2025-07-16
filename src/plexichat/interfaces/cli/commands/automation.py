# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import uuid
from datetime import datetime
from typing import List

import yaml

from .enhanced_logic_engine import (
from datetime import datetime

from datetime import datetime
import logging


    CLI,
    Action,
    Automation,
    AutomationRule,
    Commands,
    Condition,
    ConditionType,
    Enhanced,
    EnhancedLogicEngine,
    TaskStatus,
    """,
    and,
    automation,
    commands,
    engine,
    for,
    logic,
    management.,
    scripting,
, Optional)


logger = logging.getLogger(__name__)
class AutomationCLI:
    """CLI interface for automation and logic engine."""

    def __init__(self, logic_engine: Optional[EnhancedLogicEngine] = None):
        self.logic_engine = logic_engine or EnhancedLogicEngine()
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m',
            'bold': '\033[1m'
        }

    def colorize(self, text: str, color: str) -> str:
        """Colorize text for terminal output."""
        return f"{self.colors.get(color, '')}{text}{self.colors['reset']}"

    async def cmd_automation(self, args: List[str]):
        """Main automation command handler."""
        if not args:
            self.show_automation_help()
            return

        subcommand = args[0].lower()
        subargs = args[1:] if len(args) > 1 else []

        commands = {
            'list': self.cmd_automation_list,
            'show': self.cmd_automation_show,
            'create': self.cmd_automation_create,
            'edit': self.cmd_automation_edit,
            'delete': self.cmd_automation_delete,
            'enable': self.cmd_automation_enable,
            'disable': self.cmd_automation_disable,
            'run': self.cmd_automation_run,
            'logs': self.cmd_automation_logs,
            'status': self.cmd_automation_status,
            'export': self.cmd_automation_export,
            'import': self.cmd_automation_import,
            'scheduler': self.cmd_automation_scheduler,
            'cleanup': self.cmd_automation_cleanup
        }

        if subcommand in commands:
            await commands[subcommand](subargs)
        else:
            logger.info(self.colorize(f"Unknown automation command: {subcommand}", "red"))
            self.show_automation_help()

    def show_automation_help(self):
        """Show automation help."""
        help_text = f"""
{self.colorize(' PlexiChat Automation System', 'cyan')}
{self.colorize('=' * 50, 'cyan')}

{self.colorize('Available Commands:', 'yellow')}
  {self.colorize('list', 'green')}                List all automation rules
  {self.colorize('show <rule_id>', 'green')}      Show detailed rule information
  {self.colorize('create', 'green')}              Create new automation rule (interactive)
  {self.colorize('edit <rule_id>', 'green')}      Edit existing rule
  {self.colorize('delete <rule_id>', 'green')}    Delete automation rule
  {self.colorize('enable <rule_id>', 'green')}    Enable automation rule
  {self.colorize('disable <rule_id>', 'green')}   Disable automation rule
  {self.colorize('run <rule_id>', 'green')}       Manually execute rule
  {self.colorize('logs <execution_id>', 'green')} Show execution logs
  {self.colorize('status', 'green')}              Show automation system status
  {self.colorize('export [file]', 'green')}       Export automation config
  {self.colorize('import <file>', 'green')}       Import automation config
  {self.colorize('scheduler <start|stop>', 'green')} Control automation scheduler
  {self.colorize('cleanup [days]', 'green')}      Clean up old execution logs

{self.colorize('Examples:', 'yellow')}
  automation list
  automation show daily_backup
  automation create
  automation run system_health_check
  automation scheduler start
        """
        logger.info(help_text)

    async def cmd_automation_list(self, args: List[str]):
        """List all automation rules."""
        rules = self.logic_engine.list_rules()

        if not rules:
            logger.info(self.colorize(" No automation rules configured", "yellow"))
            return

        logger.info(self.colorize(" Automation Rules", "cyan"))
        logger.info(self.colorize("=" * 80, "cyan"))

        # Table header
        logger.info(f"{'ID':<20} {'Name':<25} {'Status':<10} {'Schedule':<15} {'Success Rate':<12} {'Runs':<8}")
        logger.info("-" * 80)

        for rule in rules:
            status = self.colorize(" Enabled", "green") if rule['enabled'] else self.colorize(" Disabled", "red")
            schedule = rule['schedule'] or "Manual"
            success_rate = f"{rule['success_rate']:.1f}%"

            logger.info(f"{rule['id']:<20} {rule['name'][:24]:<25} {status:<20} {schedule:<15} {success_rate:<12} {rule['run_count']:<8}")

    async def cmd_automation_show(self, args: List[str]):
        """Show detailed rule information."""
        if not args:
            logger.info(self.colorize(" Please specify rule ID", "red"))
            return

        rule_id = args[0]
        status = self.logic_engine.get_rule_status(rule_id)

        if 'error' in status:
            logger.info(self.colorize(f" {status['error']}", "red"))
            return

        rule = status['rule']

        logger.info(self.colorize(f" Rule: {rule['name']}", "cyan"))
        logger.info(self.colorize("=" * 60, "cyan"))

        logger.info(f"{self.colorize('ID:', 'yellow')} {rule['id']}")
        logger.info(f"{self.colorize('Description:', 'yellow')} {rule['description']}")
        logger.info(f"{self.colorize('Status:', 'yellow')} {' Enabled' if rule['enabled'] else ' Disabled'}")
        logger.info(f"{self.colorize('Schedule:', 'yellow')} {rule['schedule'] or 'Manual'}")
        logger.info(f"{self.colorize('Created:', 'yellow')} {rule['created_at']}")
        logger.info(f"{self.colorize('Last Run:', 'yellow')} {rule['last_run'] or 'Never'}")
        logger.info(f"{self.colorize('Run Count:', 'yellow')} {rule['run_count']}")
        logger.info(f"{self.colorize('Success Rate:', 'yellow')} {status['success_rate']:.1f}%")

        # Show conditions
        if rule['conditions']:
            logger.info(f"\n{self.colorize('Conditions:', 'yellow')}")
            for i, condition in enumerate(rule['conditions'], 1):
                logger.info(f"  {i}. {condition['type']} {condition['field']} {condition['value']}")

        # Show actions
        if rule['actions']:
            logger.info(f"\n{self.colorize('Actions:', 'yellow')}")
            for i, action in enumerate(rule['actions'], 1):
                logger.info(f"  {i}. {action['type']}: {action.get('command', action.get('parameters', {}))}")

        # Show recent executions
        if status['recent_executions']:
            logger.info(f"\n{self.colorize('Recent Executions:', 'yellow')}")
            for exec in status['recent_executions'][:5]:
                status_color = "green" if exec['status'] == 'completed' else "red"
                logger.info(f"   {exec['started_at']} - {self.colorize(exec['status'], status_color)}")

    async def cmd_automation_create(self, args: List[str]):
        """Create new automation rule interactively."""
        logger.info(self.colorize(" Creating New Automation Rule", "cyan"))
        logger.info(self.colorize("=" * 40, "cyan"))

        try:
            # Basic information
            rule_id = input("Rule ID (or press Enter for auto-generated): ").strip()
            if not rule_id:
                rule_id = f"rule_{uuid.uuid4().hex[:8]}"

            name = input("Rule Name: ").strip()
            if not name:
                logger.info(self.colorize(" Rule name is required", "red"))
                return

            description = input("Description: ").strip()

            # Schedule
            schedule = input("Schedule (cron format, or press Enter for manual): ").strip()

            # Create rule
            rule = AutomationRule(
                id=rule_id,
                name=name,
                description=description,
                enabled=True,
                conditions=[],
                actions=[],
                schedule=schedule if schedule else None
            )

            # Add conditions
            logger.info(f"\n{self.colorize('Adding Conditions (press Enter to skip):', 'yellow')}")
            while True:
                condition_type = input("Condition type (equals/greater_than/file_exists/etc): ").strip()
                if not condition_type:
                    break

                try:
                    condition_type_enum = ConditionType(condition_type)
                except ValueError:
                    logger.info(self.colorize(f" Invalid condition type: {condition_type}", "red"))
                    continue

                field = input("Field/Variable: ").strip()
                value = input("Value: ").strip()

                condition = Condition(
                    type=condition_type_enum,
                    field=field,
                    value=value
                )
                rule.conditions.append(condition)
                logger.info(self.colorize(f" Added condition: {condition_type} {field} {value}", "green"))

            # Add actions
            logger.info(f"\n{self.colorize('Adding Actions (at least one required):', 'yellow')}")
            while True:
                action_type = input("Action type (command/notification/webhook/email): ").strip()
                if not action_type:
                    if not rule.actions:
                        logger.info(self.colorize(" At least one action is required", "red"))
                        continue
                    break

                if action_type == "command":
                    command = input("Command to execute: ").strip()
                    action = Action(type="command", command=command)

                elif action_type == "notification":
                    message = input("Notification message: ").strip()
                    action = Action(type="notification", parameters={"message": message})

                elif action_type == "webhook":
                    url = input("Webhook URL: ").strip()
                    method = input("HTTP method (POST): ").strip() or "POST"
                    action = Action(type="webhook", parameters={"url": url, "method": method})

                elif action_type == "email":
                    to_email = input("Recipient email: ").strip()
                    subject = input("Email subject: ").strip()
                    body = input("Email body: ").strip()
                    action = Action(type="email", parameters={"to": to_email, "subject": subject, "body": body})

                else:
                    logger.info(self.colorize(f" Unknown action type: {action_type}", "red"))
                    continue

                rule.actions.append(action)
                logger.info(self.colorize(f" Added action: {action_type}", "green"))

            # Save rule
            if self.logic_engine.add_rule(rule):
                logger.info(self.colorize(f" Created automation rule: {rule.name}", "green"))
                logger.info(f"Rule ID: {rule.id}")
            else:
                logger.info(self.colorize(" Failed to create rule", "red"))

        except KeyboardInterrupt:
            logger.info(self.colorize("\n Rule creation cancelled", "yellow"))
        except Exception as e:
            logger.info(self.colorize(f" Error creating rule: {e}", "red"))

    async def cmd_automation_run(self, args: List[str]):
        """Manually execute automation rule."""
        if not args:
            logger.info(self.colorize(" Please specify rule ID", "red"))
            return

        rule_id = args[0]

        logger.info(self.colorize(f" Executing rule: {rule_id}", "blue"))

        try:
            execution = await self.logic_engine.execute_rule(rule_id)

            if execution.status == TaskStatus.COMPLETED:
                logger.info(self.colorize(" Rule executed successfully", "green"))
            elif execution.status == TaskStatus.FAILED:
                logger.info(self.colorize(f" Rule execution failed: {execution.error}", "red"))

            logger.info(f"Execution ID: {execution.id}")
            logger.info(f"Duration: {(execution.completed_at - execution.started_at).total_seconds():.2f}s")

            if execution.result:
                logger.info(f"Actions executed: {execution.result.get('actions_executed', 0)}")

        except Exception as e:
            logger.info(self.colorize(f" Error executing rule: {e}", "red"))

    async def cmd_automation_enable(self, args: List[str]):
        """Enable automation rule."""
        if not args:
            logger.info(self.colorize(" Please specify rule ID", "red"))
            return

        rule_id = args[0]
        if self.logic_engine.enable_rule(rule_id):
            logger.info(self.colorize(f" Enabled rule: {rule_id}", "green"))
        else:
            logger.info(self.colorize(f" Rule not found: {rule_id}", "red"))

    async def cmd_automation_disable(self, args: List[str]):
        """Disable automation rule."""
        if not args:
            logger.info(self.colorize(" Please specify rule ID", "red"))
            return

        rule_id = args[0]
        if self.logic_engine.disable_rule(rule_id):
            logger.info(self.colorize(f" Disabled rule: {rule_id}", "green"))
        else:
            logger.info(self.colorize(f" Rule not found: {rule_id}", "red"))

    async def cmd_automation_delete(self, args: List[str]):
        """Delete automation rule."""
        if not args:
            logger.info(self.colorize(" Please specify rule ID", "red"))
            return

        rule_id = args[0]

        # Confirm deletion
        confirm = input(f"Are you sure you want to delete rule '{rule_id}'? (y/N): ").strip().lower()
        if confirm != 'y':
            logger.info(self.colorize(" Deletion cancelled", "yellow"))
            return

        if self.logic_engine.remove_rule(rule_id):
            logger.info(self.colorize(f" Deleted rule: {rule_id}", "green"))
        else:
            logger.info(self.colorize(f" Rule not found: {rule_id}", "red"))

    async def cmd_automation_status(self, args: List[str]):
        """Show automation system status."""
        rules = self.logic_engine.list_rules()

        logger.info(self.colorize(" Automation System Status", "cyan"))
        logger.info(self.colorize("=" * 40, "cyan"))

        total_rules = len(rules)
        enabled_rules = len([r for r in rules if r['enabled']])
        scheduled_rules = len([r for r in rules if r['schedule']])

        logger.info(f"Total Rules: {total_rules}")
        logger.info(f"Enabled Rules: {enabled_rules}")
        logger.info(f"Scheduled Rules: {scheduled_rules}")
        logger.info(f"Manual Rules: {total_rules - scheduled_rules}")

        if rules:
            total_runs = sum(r['run_count'] for r in rules)
            avg_success_rate = sum(r['success_rate'] for r in rules) / len(rules)

            logger.info(f"Total Executions: {total_runs}")
            logger.info(f"Average Success Rate: {avg_success_rate:.1f}%")

        # Scheduler status
        scheduler_status = "Running" if self.logic_engine._running else "Stopped"
        status_color = "green" if self.logic_engine._running else "red"
        logger.info(f"Scheduler: {self.colorize(scheduler_status, status_color)}")

    async def cmd_automation_scheduler(self, args: List[str]):
        """Control automation scheduler."""
        if not args:
            logger.info(self.colorize(" Please specify action: start or stop", "red"))
            return

        action = args[0].lower()

        if action == "start":
            await self.logic_engine.start_scheduler()
            logger.info(self.colorize(" Automation scheduler started", "green"))

        elif action == "stop":
            await self.logic_engine.stop_scheduler()
            logger.info(self.colorize(" Automation scheduler stopped", "green"))

        else:
            logger.info(self.colorize(f" Unknown scheduler action: {action}", "red"))

    async def cmd_automation_logs(self, args: List[str]):
        """Show execution logs."""
        if not args:
            logger.info(self.colorize(" Please specify execution ID", "red"))
            return

        execution_id = args[0]
        logs = self.logic_engine.get_execution_logs(execution_id)

        if 'error' in logs:
            logger.info(self.colorize(f" {logs['error']}", "red"))
            return

        logger.info(self.colorize(f" Execution Logs: {execution_id}", "cyan"))
        logger.info(self.colorize("=" * 60, "cyan"))

        logger.info(f"Rule ID: {logs['rule_id']}")
        logger.info(f"Status: {logs['status']}")
        logger.info(f"Started: {logs['started_at']}")
        logger.info(f"Completed: {logs['completed_at'] or 'N/A'}")

        if logs['error']:
            logger.info(f"Error: {self.colorize(logs['error'], 'red')}")

        if logs['logs']:
            logger.info(f"\n{self.colorize('Log Entries:', 'yellow')}")
            for i, log_entry in enumerate(logs['logs'], 1):
                logger.info(f"  {i}. {log_entry}")

    async def cmd_automation_export(self, args: List[str]):
        """Export automation configuration."""
        filename = args[0] if args else f"automation_export_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"

        try:
            config = self.logic_engine.export_config()

            with open(filename, 'w') as f:
                yaml.dump(config, f, indent=2, default_flow_style=False)

            logger.info(self.colorize(f" Configuration exported to: {filename}", "green"))

        except Exception as e:
            logger.info(self.colorize(f" Export failed: {e}", "red"))

    async def cmd_automation_import(self, args: List[str]):
        """Import automation configuration."""
        if not args:
            logger.info(self.colorize(" Please specify config file", "red"))
            return

        filename = args[0]

        try:
            with open(filename, 'r') as f:
                config = yaml.safe_load(f)

            if self.logic_engine.import_config(config):
                logger.info(self.colorize(f" Configuration imported from: {filename}", "green"))
            else:
                logger.info(self.colorize(" Import failed", "red"))

        except Exception as e:
            logger.info(self.colorize(f" Import failed: {e}", "red"))

    async def cmd_automation_cleanup(self, args: List[str]):
        """Clean up old execution logs."""
        days = int(args[0]) if args and args[0].isdigit() else 30

        cleaned = self.logic_engine.cleanup_old_executions(days)
        logger.info(self.colorize(f" Cleaned up {cleaned} old execution records (older than {days} days)", "green"))
