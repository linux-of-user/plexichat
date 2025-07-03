"""
CLI Script Manager
Advanced script execution, scheduling, and management system.
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import shlex
import subprocess

logger = logging.getLogger(__name__)

@dataclass
class ScriptInfo:
    """Script information."""
    name: str
    path: str
    description: str
    created_at: datetime
    modified_at: datetime
    size: int
    executable: bool = True
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class ScriptExecution:
    """Script execution record."""
    id: str
    script_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    exit_code: Optional[int] = None
    output: str = ""
    error: str = ""
    success: bool = False

class ScriptManager:
    """Advanced script management system."""
    
    def __init__(self, scripts_dir: str = "scripts"):
        self.scripts_dir = Path(scripts_dir)
        self.scripts_dir.mkdir(exist_ok=True)
        
        self.executions: Dict[str, ScriptExecution] = {}
        self.script_cache: Dict[str, ScriptInfo] = {}
        
        # Built-in script templates
        self.templates = {
            'basic': self._get_basic_template(),
            'automation': self._get_automation_template(),
            'monitoring': self._get_monitoring_template(),
            'backup': self._get_backup_template(),
            'maintenance': self._get_maintenance_template()
        }
        
        self._refresh_script_cache()
    
    def _get_basic_template(self) -> str:
        """Get basic script template."""
        return """#!/usr/bin/env netlink-cli
# NetLink CLI Script
# Created: {timestamp}
# Description: {description}

# Basic commands
status
logs system --tail 10
"""
    
    def _get_automation_template(self) -> str:
        """Get automation script template."""
        return """#!/usr/bin/env netlink-cli
# NetLink Automation Script
# Created: {timestamp}
# Description: {description}

# Automation commands
automation list
automation status
automation scheduler start

# Check system health
monitor
performance
"""
    
    def _get_monitoring_template(self) -> str:
        """Get monitoring script template."""
        return """#!/usr/bin/env netlink-cli
# NetLink Monitoring Script
# Created: {timestamp}
# Description: {description}

# System monitoring
monitor
performance
logs system --tail 20
database info

# Check automation status
automation status
"""
    
    def _get_backup_template(self) -> str:
        """Get backup script template."""
        return """#!/usr/bin/env netlink-cli
# NetLink Backup Script
# Created: {timestamp}
# Description: {description}

# Create backup
database backup
backup create --auto

# Verify backup integrity
backup verify
backup list

# Clean old backups
backup cleanup --days 30
"""
    
    def _get_maintenance_template(self) -> str:
        """Get maintenance script template."""
        return """#!/usr/bin/env netlink-cli
# NetLink Maintenance Script
# Created: {timestamp}
# Description: {description}

# System maintenance
database optimize
logs cleanup --days 7
automation cleanup --days 30

# Performance optimization
performance optimize
cache clear

# Security updates
security scan
security update
"""
    
    def _refresh_script_cache(self):
        """Refresh script cache."""
        self.script_cache.clear()
        
        for script_file in self.scripts_dir.glob("*.script"):
            try:
                stat = script_file.stat()
                
                # Read description from script header
                description = "No description"
                try:
                    with open(script_file, 'r') as f:
                        for line in f:
                            if line.startswith('# Description:'):
                                description = line.replace('# Description:', '').strip()
                                break
                except:
                    pass
                
                script_info = ScriptInfo(
                    name=script_file.stem,
                    path=str(script_file),
                    description=description,
                    created_at=datetime.fromtimestamp(stat.st_ctime),
                    modified_at=datetime.fromtimestamp(stat.st_mtime),
                    size=stat.st_size
                )
                
                self.script_cache[script_info.name] = script_info
                
            except Exception as e:
                logger.error(f"Error reading script {script_file}: {e}")
    
    def list_scripts(self) -> List[ScriptInfo]:
        """List all available scripts."""
        self._refresh_script_cache()
        return list(self.script_cache.values())
    
    def get_script(self, name: str) -> Optional[ScriptInfo]:
        """Get script information."""
        return self.script_cache.get(name)
    
    def create_script(self, name: str, template: str = 'basic', description: str = "", content: str = None) -> bool:
        """Create new script."""
        try:
            if not name.endswith('.script'):
                name += '.script'
            
            script_path = self.scripts_dir / name
            
            if script_path.exists():
                return False  # Script already exists
            
            if content is None:
                # Use template
                template_content = self.templates.get(template, self.templates['basic'])
                content = template_content.format(
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    description=description or "Auto-generated script"
                )
            
            with open(script_path, 'w') as f:
                f.write(content)
            
            # Make executable on Unix systems
            if os.name != 'nt':
                os.chmod(script_path, 0o755)
            
            self._refresh_script_cache()
            logger.info(f"Created script: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating script {name}: {e}")
            return False
    
    def delete_script(self, name: str) -> bool:
        """Delete script."""
        try:
            if not name.endswith('.script'):
                name += '.script'
            
            script_path = self.scripts_dir / name
            
            if not script_path.exists():
                return False
            
            script_path.unlink()
            self._refresh_script_cache()
            logger.info(f"Deleted script: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting script {name}: {e}")
            return False
    
    def read_script(self, name: str) -> Optional[str]:
        """Read script content."""
        try:
            script_info = self.get_script(name)
            if not script_info:
                return None
            
            with open(script_info.path, 'r') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Error reading script {name}: {e}")
            return None
    
    def write_script(self, name: str, content: str) -> bool:
        """Write script content."""
        try:
            if not name.endswith('.script'):
                name += '.script'
            
            script_path = self.scripts_dir / name
            
            with open(script_path, 'w') as f:
                f.write(content)
            
            self._refresh_script_cache()
            logger.info(f"Updated script: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Error writing script {name}: {e}")
            return False
    
    async def execute_script(self, name: str, cli_executor: Callable = None) -> ScriptExecution:
        """Execute script."""
        execution_id = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        execution = ScriptExecution(
            id=execution_id,
            script_name=name,
            started_at=datetime.now()
        )
        
        self.executions[execution_id] = execution
        
        try:
            script_content = self.read_script(name)
            if not script_content:
                execution.error = f"Script not found: {name}"
                execution.completed_at = datetime.now()
                return execution
            
            # Parse and execute commands
            commands = []
            for line in script_content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('#!/'):
                    continue
                commands.append(line)
            
            output_lines = []
            
            for command in commands:
                try:
                    if cli_executor:
                        # Use provided CLI executor
                        result = await cli_executor(command)
                        if isinstance(result, str):
                            output_lines.append(f"[{command}] {result}")
                        else:
                            output_lines.append(f"[{command}] Command executed")
                    else:
                        # Fallback to subprocess
                        result = subprocess.run(
                            shlex.split(command),
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        if result.stdout:
                            output_lines.append(f"[{command}] {result.stdout.strip()}")
                        if result.stderr:
                            output_lines.append(f"[{command}] ERROR: {result.stderr.strip()}")
                        
                        if result.returncode != 0:
                            execution.exit_code = result.returncode
                            break
                
                except Exception as e:
                    output_lines.append(f"[{command}] ERROR: {e}")
                    execution.error = str(e)
                    break
            
            execution.output = '\n'.join(output_lines)
            execution.success = execution.exit_code == 0 if execution.exit_code is not None else not execution.error
            execution.completed_at = datetime.now()
            
            logger.info(f"Script execution completed: {name} (success: {execution.success})")
            
        except Exception as e:
            execution.error = str(e)
            execution.completed_at = datetime.now()
            logger.error(f"Script execution failed: {name} - {e}")
        
        return execution
    
    def get_execution(self, execution_id: str) -> Optional[ScriptExecution]:
        """Get script execution record."""
        return self.executions.get(execution_id)
    
    def list_executions(self, script_name: str = None, limit: int = 50) -> List[ScriptExecution]:
        """List script executions."""
        executions = list(self.executions.values())
        
        if script_name:
            executions = [e for e in executions if e.script_name == script_name]
        
        # Sort by start time, most recent first
        executions.sort(key=lambda x: x.started_at, reverse=True)
        
        return executions[:limit]
    
    def cleanup_executions(self, days: int = 30) -> int:
        """Clean up old execution records."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        old_executions = [
            exec_id for exec_id, execution in self.executions.items()
            if execution.started_at < cutoff_date
        ]
        
        for exec_id in old_executions:
            del self.executions[exec_id]
        
        logger.info(f"Cleaned up {len(old_executions)} old script execution records")
        return len(old_executions)
    
    def get_script_stats(self, name: str) -> Dict[str, Any]:
        """Get script execution statistics."""
        executions = self.list_executions(script_name=name)
        
        if not executions:
            return {
                'total_executions': 0,
                'success_rate': 0.0,
                'last_execution': None,
                'average_duration': 0.0
            }
        
        successful = len([e for e in executions if e.success])
        
        # Calculate average duration
        durations = []
        for execution in executions:
            if execution.completed_at:
                duration = (execution.completed_at - execution.started_at).total_seconds()
                durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0.0
        
        return {
            'total_executions': len(executions),
            'success_rate': (successful / len(executions)) * 100,
            'last_execution': executions[0].started_at.isoformat() if executions else None,
            'average_duration': avg_duration
        }
    
    def export_scripts(self, export_path: str) -> bool:
        """Export all scripts to a directory."""
        try:
            export_dir = Path(export_path)
            export_dir.mkdir(exist_ok=True)
            
            exported_count = 0
            
            for script_info in self.list_scripts():
                source_path = Path(script_info.path)
                dest_path = export_dir / source_path.name
                
                with open(source_path, 'r') as src, open(dest_path, 'w') as dst:
                    dst.write(src.read())
                
                exported_count += 1
            
            # Export metadata
            metadata = {
                'exported_at': datetime.now().isoformat(),
                'script_count': exported_count,
                'scripts': [asdict(script) for script in self.list_scripts()]
            }
            
            with open(export_dir / 'metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            logger.info(f"Exported {exported_count} scripts to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting scripts: {e}")
            return False
    
    def import_scripts(self, import_path: str, overwrite: bool = False) -> int:
        """Import scripts from a directory."""
        try:
            import_dir = Path(import_path)
            
            if not import_dir.exists():
                return 0
            
            imported_count = 0
            
            for script_file in import_dir.glob("*.script"):
                dest_path = self.scripts_dir / script_file.name
                
                if dest_path.exists() and not overwrite:
                    continue
                
                with open(script_file, 'r') as src, open(dest_path, 'w') as dst:
                    dst.write(src.read())
                
                imported_count += 1
            
            self._refresh_script_cache()
            logger.info(f"Imported {imported_count} scripts from {import_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Error importing scripts: {e}")
            return 0
