"""
CLI Integration Module
Provides unified access to all CLI components and systems.
"""

import asyncio
import sys
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import all CLI components
try:
    from .main_cli import NetLinkCLI
    from .advanced_cli import AdvancedCLI
    from .automation_commands import AutomationCLI
    from .enhanced_logic_engine import EnhancedLogicEngine
except ImportError as e:
    print(f"Warning: Could not import CLI components: {e}")

# Import AI CLI if available
try:
    from netlink.ai.cli.ai_cli import AICommandLineInterface
    AI_CLI_AVAILABLE = True
except ImportError:
    AI_CLI_AVAILABLE = False

class UnifiedCLI:
    """Unified CLI interface that combines all CLI systems."""
    
    def __init__(self):
        self.main_cli = NetLinkCLI()
        self.advanced_cli = AdvancedCLI()
        self.automation_cli = AutomationCLI()
        self.logic_engine = EnhancedLogicEngine()
        
        if AI_CLI_AVAILABLE:
            self.ai_cli = AICommandLineInterface()
        else:
            self.ai_cli = None
        
        self.available_interfaces = {
            'main': 'Standard NetLink CLI',
            'advanced': 'Advanced interactive CLI with enhanced features',
            'automation': 'Automation and logic engine CLI',
            'ai': 'AI system management CLI' if AI_CLI_AVAILABLE else None
        }
    
    def show_welcome(self):
        """Show welcome message with available interfaces."""
        print("🚀 NetLink Unified CLI v3.0.0")
        print("=" * 50)
        print("Available CLI Interfaces:")
        
        for interface, description in self.available_interfaces.items():
            if description:
                status = "✅" if self._check_interface_available(interface) else "❌"
                print(f"  {status} {interface:<12} - {description}")
        
        print("\nUsage:")
        print("  --interface <name>  - Select specific interface")
        print("  --interactive       - Start interactive mode")
        print("  --help             - Show this help")
        print()
    
    def _check_interface_available(self, interface: str) -> bool:
        """Check if interface is available."""
        if interface == 'main':
            return self.main_cli is not None
        elif interface == 'advanced':
            return self.advanced_cli is not None
        elif interface == 'automation':
            return self.automation_cli is not None
        elif interface == 'ai':
            return self.ai_cli is not None
        return False
    
    async def run_interface(self, interface: str, interactive: bool = False):
        """Run specific CLI interface."""
        if interface == 'main':
            if interactive:
                print("Main CLI does not support interactive mode. Use 'advanced' interface.")
                return
            self.main_cli.run()
            
        elif interface == 'advanced':
            if interactive:
                await self.advanced_cli.run_interactive()
            else:
                print("Advanced CLI requires interactive mode.")
                
        elif interface == 'automation':
            if interactive:
                # Start automation CLI in interactive mode
                print("🤖 Automation CLI - Interactive Mode")
                while True:
                    try:
                        command = input("automation> ").strip()
                        if command.lower() in ['exit', 'quit']:
                            break
                        if command:
                            args = command.split()
                            await self.automation_cli.cmd_automation(args)
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"Error: {e}")
            else:
                print("Automation CLI requires interactive mode or specific commands.")
                
        elif interface == 'ai':
            if not self.ai_cli:
                print("❌ AI CLI not available")
                return
                
            if interactive:
                # Start AI CLI in interactive mode
                print("🤖 AI CLI - Interactive Mode")
                while True:
                    try:
                        command = input("ai> ").strip()
                        if command.lower() in ['exit', 'quit']:
                            break
                        if command:
                            # Parse and execute AI command
                            await self._execute_ai_command(command)
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print(f"Error: {e}")
            else:
                print("AI CLI requires interactive mode or specific commands.")
        else:
            print(f"Unknown interface: {interface}")
    
    async def _execute_ai_command(self, command: str):
        """Execute AI CLI command."""
        args = command.split()
        if not args:
            return
        
        cmd = args[0].lower()
        cmd_args = args[1:]
        
        if cmd == 'status':
            await self.ai_cli.get_system_status()
        elif cmd == 'models':
            if not cmd_args:
                await self.ai_cli.list_models()
            elif cmd_args[0] == 'add':
                if len(cmd_args) > 1:
                    await self.ai_cli.add_model(cmd_args[1])
                else:
                    print("Usage: models add <model_config>")
        elif cmd == 'providers':
            if not cmd_args:
                await self.ai_cli.list_providers()
            elif cmd_args[0] == 'configure' and len(cmd_args) >= 3:
                await self.ai_cli.configure_provider(cmd_args[1], cmd_args[2])
        elif cmd == 'test' and len(cmd_args) >= 2:
            await self.ai_cli.test_model(cmd_args[0], " ".join(cmd_args[1:]))
        elif cmd == 'health':
            await self.ai_cli.health_check()
        elif cmd == 'help':
            print("Available AI commands:")
            print("  status              - Show AI system status")
            print("  models [add <cfg>]  - List or add models")
            print("  providers [cfg]     - List or configure providers")
            print("  test <model> <text> - Test model with text")
            print("  health              - Check system health")
            print("  help                - Show this help")
        else:
            print(f"Unknown AI command: {cmd}")
    
    async def auto_detect_mode(self, args: List[str]):
        """Auto-detect the best CLI mode based on arguments."""
        if not args:
            # No arguments, show welcome and start advanced interactive
            self.show_welcome()
            print("Starting advanced interactive CLI...")
            await self.run_interface('advanced', interactive=True)
            return
        
        # Check for specific interface requests
        if '--interface' in args:
            idx = args.index('--interface')
            if idx + 1 < len(args):
                interface = args[idx + 1]
                interactive = '--interactive' in args
                await self.run_interface(interface, interactive)
                return
        
        # Check for AI-related commands
        ai_commands = ['ai', 'models', 'providers']
        if any(cmd in args for cmd in ai_commands):
            await self.run_interface('ai', interactive=True)
            return
        
        # Check for automation commands
        automation_commands = ['automation', 'logic', 'script', 'scheduler']
        if any(cmd in args for cmd in automation_commands):
            await self.run_interface('automation', interactive=True)
            return
        
        # Default to main CLI for standard commands
        self.main_cli.run()

async def main():
    """Main entry point for unified CLI."""
    unified_cli = UnifiedCLI()
    
    # Parse basic arguments
    args = sys.argv[1:]
    
    if '--help' in args or '-h' in args:
        unified_cli.show_welcome()
        return
    
    try:
        await unified_cli.auto_detect_mode(args)
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ CLI Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
