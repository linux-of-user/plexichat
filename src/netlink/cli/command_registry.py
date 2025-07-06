"""
CLI Command Registry
Comprehensive registry of all available CLI commands across all systems.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class CommandCategory(str, Enum):
    """Command categories for organization."""
    SERVER = "server"
    DATABASE = "database"
    USER = "user"
    SECURITY = "security"
    AI = "ai"
    BACKUP = "backup"
    CLUSTERING = "clustering"
    PLUGIN = "plugin"
    AUTOMATION = "automation"
    MONITORING = "monitoring"
    NETWORK = "network"
    DEVELOPMENT = "development"
    UTILITY = "utility"

@dataclass
class CommandInfo:
    """Information about a CLI command."""
    name: str
    category: CommandCategory
    description: str
    usage: str
    examples: List[str]
    aliases: List[str] = None
    requires_auth: bool = False
    requires_admin: bool = False
    available_in: List[str] = None  # Which CLI interfaces support this
    
    def __post_init__(self):
        if self.aliases is None:
            self.aliases = []
        if self.available_in is None:
            self.available_in = ["advanced"]

class CommandRegistry:
    """Registry of all CLI commands."""
    
    def __init__(self):
        self.commands: Dict[str, CommandInfo] = {}
        self._register_all_commands()
    
    def _register_all_commands(self):
        """Register all available commands."""
        
        # NetLink Node Management Commands
        self.register_command(CommandInfo(
            name="node",
            category=CommandCategory.SERVER,
            description="NetLink node management operations",
            usage="node <start|stop|restart|status>",
            examples=["node start", "node status", "node restart"],
            available_in=["main", "advanced"]
        ))

        self.register_command(CommandInfo(
            name="status",
            category=CommandCategory.SERVER,
            description="Show NetLink core status",
            usage="status [component]",
            examples=["status", "status node", "status database"],
            available_in=["main", "advanced"]
        ))
        
        # Database Commands
        self.register_command(CommandInfo(
            name="database",
            category=CommandCategory.DATABASE,
            description="Database operations",
            usage="database <backup|restore|migrate|vacuum>",
            examples=["database backup", "database migrate", "database vacuum"],
            requires_admin=True,
            available_in=["main", "advanced"]
        ))
        
        # User Management Commands
        self.register_command(CommandInfo(
            name="user",
            category=CommandCategory.USER,
            description="User management operations",
            usage="user <list|create|delete|modify> [options]",
            examples=["user list", "user create john", "user delete john"],
            requires_admin=True,
            available_in=["main", "advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="permissions",
            category=CommandCategory.USER,
            description="Permission management",
            usage="permissions <list|grant|revoke> [user] [permission]",
            examples=["permissions list", "permissions grant john admin"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        # AI System Commands
        self.register_command(CommandInfo(
            name="ai",
            category=CommandCategory.AI,
            description="AI system management",
            usage="ai <status|health|models|providers|test|cache|usage>",
            examples=["ai status", "ai models", "ai test gpt-4 'Hello world'"],
            available_in=["advanced", "ai"]
        ))
        
        self.register_command(CommandInfo(
            name="models",
            category=CommandCategory.AI,
            description="AI model management",
            usage="models [add <config>|remove <id>|list]",
            examples=["models list", "models add model.json", "models remove gpt-4"],
            available_in=["advanced", "ai"]
        ))
        
        self.register_command(CommandInfo(
            name="providers",
            category=CommandCategory.AI,
            description="AI provider configuration",
            usage="providers [configure <provider> <key> [url]|list]",
            examples=["providers list", "providers configure openai sk-..."],
            requires_admin=True,
            available_in=["advanced", "ai"]
        ))
        
        # Backup & Clustering Commands
        self.register_command(CommandInfo(
            name="backup",
            category=CommandCategory.BACKUP,
            description="Backup operations",
            usage="backup <create|restore|list|status>",
            examples=["backup create", "backup list", "backup restore backup.db"],
            requires_admin=True,
            available_in=["main", "advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="shards",
            category=CommandCategory.BACKUP,
            description="Shard management",
            usage="shards <list|status|create|delete|verify|distribute>",
            examples=["shards list", "shards status", "shards verify"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="cluster",
            category=CommandCategory.CLUSTERING,
            description="Cluster management",
            usage="cluster <status|nodes|sync|health>",
            examples=["cluster status", "cluster nodes", "cluster health"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="nodes",
            category=CommandCategory.CLUSTERING,
            description="Node management",
            usage="nodes <list|add|remove|health|sync>",
            examples=["nodes list", "nodes health", "nodes sync"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        # Plugin System Commands
        self.register_command(CommandInfo(
            name="plugins",
            category=CommandCategory.PLUGIN,
            description="Plugin management",
            usage="plugins <list|install|uninstall|enable|disable|update|info>",
            examples=["plugins list", "plugins install plugin.zip", "plugins enable antivirus"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="antivirus",
            category=CommandCategory.SECURITY,
            description="Antivirus management",
            usage="antivirus <scan|update|status|config>",
            examples=["antivirus scan", "antivirus update", "antivirus status"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        # Automation Commands
        self.register_command(CommandInfo(
            name="automation",
            category=CommandCategory.AUTOMATION,
            description="Automation and logic engine",
            usage="automation <list|show|create|edit|delete|enable|disable|run>",
            examples=["automation list", "automation create", "automation run daily_backup"],
            requires_admin=True,
            available_in=["advanced", "automation"]
        ))
        
        self.register_command(CommandInfo(
            name="logic",
            category=CommandCategory.AUTOMATION,
            description="Logic engine operations",
            usage="logic <variables|functions|evaluate|test>",
            examples=["logic variables", "logic evaluate 'cpu_usage > 80'"],
            available_in=["advanced", "automation"]
        ))
        
        self.register_command(CommandInfo(
            name="script",
            category=CommandCategory.AUTOMATION,
            description="Script execution and management",
            usage="script <run|list|create|edit|delete>",
            examples=["script list", "script run backup.script", "script create maintenance"],
            available_in=["advanced", "automation"]
        ))
        
        # Monitoring Commands
        self.register_command(CommandInfo(
            name="health",
            category=CommandCategory.MONITORING,
            description="System health checks",
            usage="health [component]",
            examples=["health", "health database", "health ai"],
            available_in=["advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="metrics",
            category=CommandCategory.MONITORING,
            description="System metrics and analytics",
            usage="metrics [type]",
            examples=["metrics", "metrics cpu", "metrics memory"],
            available_in=["advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="logs",
            category=CommandCategory.MONITORING,
            description="Log management and viewing",
            usage="logs <view|search|filter|tail> [options]",
            examples=["logs view netlink.log", "logs search error", "logs tail -f"],
            available_in=["main", "advanced"]
        ))
        
        # Security Commands
        self.register_command(CommandInfo(
            name="security",
            category=CommandCategory.SECURITY,
            description="Security operations",
            usage="security <scan|audit|test|config>",
            examples=["security scan", "security audit", "security test"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="ssl",
            category=CommandCategory.SECURITY,
            description="SSL certificate management",
            usage="ssl <status|renew|install|config>",
            examples=["ssl status", "ssl renew", "ssl install cert.pem"],
            requires_admin=True,
            available_in=["advanced"]
        ))
        
        # Utility Commands
        self.register_command(CommandInfo(
            name="help",
            category=CommandCategory.UTILITY,
            description="Show help information",
            usage="help [command]",
            examples=["help", "help server", "help automation"],
            available_in=["main", "advanced", "automation", "ai"]
        ))
        
        self.register_command(CommandInfo(
            name="version",
            category=CommandCategory.UTILITY,
            description="Show version information",
            usage="version",
            examples=["version"],
            available_in=["main", "advanced"]
        ))
        
        self.register_command(CommandInfo(
            name="info",
            category=CommandCategory.UTILITY,
            description="Show system information",
            usage="info",
            examples=["info"],
            available_in=["advanced"]
        ))
    
    def register_command(self, command: CommandInfo):
        """Register a command."""
        self.commands[command.name] = command
        
        # Register aliases
        for alias in command.aliases:
            self.commands[alias] = command
    
    def get_command(self, name: str) -> Optional[CommandInfo]:
        """Get command information."""
        return self.commands.get(name)
    
    def list_commands(self, category: CommandCategory = None, interface: str = None) -> List[CommandInfo]:
        """List commands by category or interface."""
        commands = []
        for cmd in self.commands.values():
            if category and cmd.category != category:
                continue
            if interface and interface not in cmd.available_in:
                continue
            if cmd not in commands:  # Avoid duplicates from aliases
                commands.append(cmd)
        return sorted(commands, key=lambda x: x.name)
    
    def get_categories(self) -> List[CommandCategory]:
        """Get all command categories."""
        return list(CommandCategory)
    
    def search_commands(self, query: str) -> List[CommandInfo]:
        """Search commands by name or description."""
        query = query.lower()
        results = []
        for cmd in self.commands.values():
            if (query in cmd.name.lower() or 
                query in cmd.description.lower() or
                any(query in example.lower() for example in cmd.examples)):
                if cmd not in results:
                    results.append(cmd)
        return sorted(results, key=lambda x: x.name)

# Global command registry instance
command_registry = CommandRegistry()
