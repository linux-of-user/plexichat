#!/usr/bin/env python3
"""
PlexiChat Debug CLI

Command-line interface for debugging PlexiChat components and plugins.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from plexichat.infrastructure.debugging.debug_manager import get_debug_manager, DebugLevel
from plexichat.infrastructure.debugging.debug_utils import (
    create_debug_dump, analyze_performance_bottlenecks
)
from plexichat.infrastructure.debugging.plugin_debug_integration import get_plugin_debugger
from plexichat.infrastructure.modules.plugin_manager import get_plugin_manager


class DebugCLI:
    """Command-line interface for debugging."""
    
    def __init__(self):
        self.debug_manager = get_debug_manager()
        self.plugin_manager = None
    
    async def initialize(self):
        """Initialize the debug CLI."""
        try:
            self.plugin_manager = get_plugin_manager()
            await self.plugin_manager.initialize()
            print("✅ Debug CLI initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize Debug CLI: {e}")
            return False
        return True
    
    def show_events(self, level: str = None, source: str = None, limit: int = 50):
        """Show recent debug events."""
        try:
            debug_level = None
            if level:
                debug_level = DebugLevel(level.lower())
            
            events = self.debug_manager.get_debug_events(debug_level, source, limit)
            
            print(f"\n📋 Recent Debug Events (showing {len(events)} events)")
            print("=" * 80)
            
            for event in events[-20:]:  # Show last 20
                level_color = {
                    'trace': '\033[90m',     # Gray
                    'debug': '\033[96m',     # Cyan
                    'info': '\033[94m',      # Blue
                    'warning': '\033[93m',   # Yellow
                    'error': '\033[91m',     # Red
                    'critical': '\033[95m'   # Magenta
                }.get(event.level.value, '\033[0m')
                
                reset_color = '\033[0m'
                
                print(f"{level_color}[{event.level.value.upper()}]{reset_color} "
                      f"{event.timestamp} - {event.source}")
                print(f"  {event.message}")
                
                if event.context:
                    print(f"  Context: {json.dumps(event.context, indent=2)}")
                print()
            
        except Exception as e:
            print(f"❌ Error showing events: {e}")
    
    def show_errors(self):
        """Show error summary."""
        try:
            error_summary = self.debug_manager.get_error_summary()
            
            print(f"\n🚨 Error Summary")
            print("=" * 50)
            print(f"Total Errors: {error_summary.get('total_errors', 0)}")
            print(f"Unique Errors: {error_summary.get('unique_errors', 0)}")
            print(f"Error Rate: {error_summary.get('error_rate', 0):.2%}")
            
            print(f"\nTop Errors:")
            for error_type, count in error_summary.get('top_errors', [])[:10]:
                print(f"  {error_type}: {count}")
            
        except Exception as e:
            print(f"❌ Error showing error summary: {e}")
    
    def show_performance(self):
        """Show performance summary."""
        try:
            performance_summary = self.debug_manager.get_performance_summary()
            bottlenecks = analyze_performance_bottlenecks()
            
            print(f"\n⚡ Performance Summary")
            print("=" * 60)
            print(f"Total Functions Tracked: {len(performance_summary)}")
            
            print(f"\n🐌 Slowest Functions:")
            for func_data in bottlenecks.get('slow_functions', [])[:10]:
                print(f"  {func_data['function']}")
                print(f"    Avg: {func_data['avg_duration']:.4f}s, "
                      f"Max: {func_data['max_duration']:.4f}s, "
                      f"Calls: {func_data['call_count']}")
            
            print(f"\n🔄 Most Frequent Functions:")
            for func_data in bottlenecks.get('frequent_functions', [])[:10]:
                print(f"  {func_data['function']}")
                print(f"    Calls: {func_data['call_count']}, "
                      f"Avg: {func_data['avg_duration']:.4f}s, "
                      f"Total: {func_data['total_time']:.4f}s")
            
        except Exception as e:
            print(f"❌ Error showing performance summary: {e}")
    
    def show_memory(self):
        """Show memory usage information."""
        try:
            snapshots = self.debug_manager.memory_snapshots[-10:]  # Last 10 snapshots
            
            print(f"\n🧠 Memory Usage")
            print("=" * 50)
            print(f"Total Snapshots: {len(self.debug_manager.memory_snapshots)}")
            
            if snapshots:
                print(f"\nRecent Snapshots:")
                for snapshot in snapshots:
                    print(f"  {snapshot['timestamp']} - {snapshot['memory_usage']:.2f} MB")
                    if snapshot['label']:
                        print(f"    Label: {snapshot['label']}")
                
                # Calculate trend
                if len(snapshots) > 1:
                    first_memory = snapshots[0]['memory_usage']
                    last_memory = snapshots[-1]['memory_usage']
                    change = last_memory - first_memory
                    
                    trend_symbol = "📈" if change > 0 else "📉" if change < 0 else "➡️"
                    print(f"\nMemory Trend: {trend_symbol} {change:+.2f} MB")
            else:
                print("No memory snapshots available")
            
        except Exception as e:
            print(f"❌ Error showing memory information: {e}")
    
    def show_sessions(self):
        """Show debug sessions."""
        try:
            sessions = self.debug_manager.debug_sessions
            
            print(f"\n🔍 Debug Sessions")
            print("=" * 60)
            print(f"Total Sessions: {len(sessions)}")
            
            for session_id, session in sessions.items():
                status = "🟢 Active" if session.active else "🔴 Ended"
                print(f"\n{status} {session.name}")
                print(f"  ID: {session_id}")
                print(f"  Start: {time.ctime(session.start_time)}")
                print(f"  Events: {len(session.events)}")
                print(f"  Profiling Data: {len(session.profiling_data)}")
                
                if hasattr(session, 'duration') and session.duration:
                    print(f"  Duration: {session.duration:.2f}s")
            
        except Exception as e:
            print(f"❌ Error showing sessions: {e}")
    
    async def test_plugin(self, plugin_name: str):
        """Test a specific plugin with debugging."""
        try:
            if not self.plugin_manager:
                print("❌ Plugin manager not initialized")
                return
            
            print(f"\n🧪 Testing Plugin: {plugin_name}")
            print("=" * 50)
            
            # Create debug session for testing
            debugger = get_plugin_debugger(plugin_name)
            session_id = debugger.start_debug_session({"operation": "cli_test"})
            
            try:
                # Run plugin tests
                test_results = await self.plugin_manager.run_plugin_tests(plugin_name)
                
                if test_results.get("success", False):
                    print(f"✅ Plugin tests completed successfully")
                    
                    for result in test_results.get("results", []):
                        status_symbol = "✅" if result["status"] == "passed" else "❌"
                        print(f"  {status_symbol} {result['test_name']}: {result['message']} "
                              f"({result['duration']:.4f}s)")
                else:
                    print(f"❌ Plugin tests failed: {test_results.get('error', 'Unknown error')}")
                
            finally:
                debugger.end_debug_session()
            
        except Exception as e:
            print(f"❌ Error testing plugin: {e}")
    
    def export_data(self, filename: str = None):
        """Export debug data to file."""
        try:
            if filename:
                # Custom filename
                dump_path = create_debug_dump(filename)
            else:
                # Auto-generated filename
                dump_path = create_debug_dump()
            
            if dump_path:
                print(f"✅ Debug data exported to: {dump_path}")
            else:
                print("❌ Failed to export debug data")
            
        except Exception as e:
            print(f"❌ Error exporting data: {e}")
    
    def clear_data(self, confirm: bool = False):
        """Clear debug data."""
        try:
            if not confirm:
                response = input("⚠️  Clear all debug data? This cannot be undone. (y/N): ")
                if response.lower() != 'y':
                    print("Operation cancelled")
                    return
            
            self.debug_manager.clear_debug_data()
            print("✅ Debug data cleared successfully")
            
        except Exception as e:
            print(f"❌ Error clearing data: {e}")
    
    def take_snapshot(self, label: str = ""):
        """Take a memory snapshot."""
        try:
            snapshot_label = f"CLI: {label}" if label else "CLI snapshot"
            self.debug_manager.take_memory_snapshot(snapshot_label)
            print(f"✅ Memory snapshot taken: {snapshot_label}")
            
        except Exception as e:
            print(f"❌ Error taking snapshot: {e}")
    
    def monitor_live(self, duration: int = 60):
        """Monitor debug events in real-time."""
        try:
            print(f"\n👁️  Live Monitoring (for {duration} seconds)")
            print("=" * 50)
            print("Press Ctrl+C to stop early")
            
            start_time = time.time()
            last_event_count = len(self.debug_manager.debug_events)
            
            while time.time() - start_time < duration:
                try:
                    current_event_count = len(self.debug_manager.debug_events)
                    
                    if current_event_count > last_event_count:
                        # New events
                        new_events = self.debug_manager.debug_events[last_event_count:]
                        
                        for event in new_events:
                            level_symbol = {
                                'trace': '🔍',
                                'debug': '🐛',
                                'info': 'ℹ️',
                                'warning': '⚠️',
                                'error': '❌',
                                'critical': '🚨'
                            }.get(event.level.value, '📝')
                            
                            print(f"{level_symbol} [{event.level.value.upper()}] "
                                  f"{event.source}: {event.message}")
                        
                        last_event_count = current_event_count
                    
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    break
            
            print(f"\n✅ Monitoring completed")
            
        except Exception as e:
            print(f"❌ Error during monitoring: {e}")


async def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="PlexiChat Debug CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Events command
    events_parser = subparsers.add_parser("events", help="Show debug events")
    events_parser.add_argument("--level", choices=["trace", "debug", "info", "warning", "error", "critical"])
    events_parser.add_argument("--source", help="Filter by source")
    events_parser.add_argument("--limit", type=int, default=50, help="Number of events to show")
    
    # Errors command
    subparsers.add_parser("errors", help="Show error summary")
    
    # Performance command
    subparsers.add_parser("performance", help="Show performance summary")
    
    # Memory command
    subparsers.add_parser("memory", help="Show memory usage")
    
    # Sessions command
    subparsers.add_parser("sessions", help="Show debug sessions")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Test a plugin")
    test_parser.add_argument("plugin", help="Plugin name to test")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export debug data")
    export_parser.add_argument("--filename", help="Output filename")
    
    # Clear command
    clear_parser = subparsers.add_parser("clear", help="Clear debug data")
    clear_parser.add_argument("--yes", action="store_true", help="Skip confirmation")
    
    # Snapshot command
    snapshot_parser = subparsers.add_parser("snapshot", help="Take memory snapshot")
    snapshot_parser.add_argument("--label", default="", help="Snapshot label")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Monitor events live")
    monitor_parser.add_argument("--duration", type=int, default=60, help="Monitoring duration in seconds")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = DebugCLI()
    await cli.initialize()
    
    # Execute command
    try:
        if args.command == "events":
            cli.show_events(args.level, args.source, args.limit)
        elif args.command == "errors":
            cli.show_errors()
        elif args.command == "performance":
            cli.show_performance()
        elif args.command == "memory":
            cli.show_memory()
        elif args.command == "sessions":
            cli.show_sessions()
        elif args.command == "test":
            await cli.test_plugin(args.plugin)
        elif args.command == "export":
            cli.export_data(args.filename)
        elif args.command == "clear":
            cli.clear_data(args.yes)
        elif args.command == "snapshot":
            cli.take_snapshot(args.label)
        elif args.command == "monitor":
            cli.monitor_live(args.duration)
        
    except KeyboardInterrupt:
        print("\n👋 Debug CLI interrupted by user")
    except Exception as e:
        print(f"❌ Command failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
