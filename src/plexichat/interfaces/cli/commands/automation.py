import logging
from typing import List, Optional

# Mock for standalone execution
class MockLogicEngine:
    def list_rules(self): return []
    def get_rule_status(self, rule_id): return {"error": "Not found"}
    def add_rule(self, rule): return True
    def enable_rule(self, rule_id): return True
    def disable_rule(self, rule_id): return True
    def remove_rule(self, rule_id): return True
    async def execute_rule(self, rule_id): return type("obj", (), {"status": "completed", "error": None})()
    def get_execution_logs(self, execution_id): return {"logs": []}

logger = logging.getLogger(__name__)

class AutomationCLI:
    """CLI interface for automation and logic engine."""
    def __init__(self, logic_engine: Optional[MockLogicEngine] = None):
        self.logic_engine = logic_engine or MockLogicEngine()

    async def cmd_automation(self, args: List[str]):
        """Main automation command handler."""
        if not args:
            self.show_automation_help()
            return

        subcommand, *subargs = args
        commands = {
            'list': self.cmd_automation_list,
            'show': self.cmd_automation_show,
            'run': self.cmd_automation_run,
        }
        handler = commands.get(subcommand.lower())
        if handler:
            await handler(subargs)
        else:
            logger.error(f"Unknown automation command: {subcommand}")
            self.show_automation_help()

    def show_automation_help(self):
        """Shows help for automation commands."""
        logger.info("Available automation commands: list, show, run")

    async def cmd_automation_list(self, args: List[str]):
        """Lists all automation rules."""
        rules = self.logic_engine.list_rules()
        if not rules:
            logger.info("No automation rules configured.")
            return
        for rule in rules:
            logger.info(f"- {rule.get('name')} ({'enabled' if rule.get('enabled') else 'disabled'})")

    async def cmd_automation_show(self, args: List[str]):
        """Shows detailed information for a rule."""
        if not args:
            logger.error("Usage: automation show <rule_id>")
            return
        rule_id = args[0]
        status = self.logic_engine.get_rule_status(rule_id)
        if "error" in status:
            logger.error(status["error"])
        else:
            logger.info(f"Details for rule {rule_id}: {status}")

    async def cmd_automation_run(self, args: List[str]):
        """Manually executes an automation rule."""
        if not args:
            logger.error("Usage: automation run <rule_id>")
            return
        rule_id = args[0]
        result = await self.logic_engine.execute_rule(rule_id)
        if result.status == "completed":
            logger.info(f"Rule '{rule_id}' executed successfully.")
        else:
            logger.error(f"Rule '{rule_id}' failed: {result.error}")

async def handle_automation_command(args: List[str]):
    """Handle automation CLI commands."""
    cli = AutomationCLI()
    await cli.cmd_automation(args)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        asyncio.run(handle_automation_command(sys.argv[1:]))
    else:
        print("Usage: python -m automation <command> [args...]")
