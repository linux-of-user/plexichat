import argparse
import json
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import List

from services.log_management import LogEntry, log_manager

from pathlib import Path

from pathlib import Path
import logging


"""
Advanced CLI log management commands.
Provides comprehensive log viewing, filtering, and management from command line.
"""

# Add parent directory to path for imports
sys.path.append(str(from pathlib import Path
Path(__file__).parent.parent))

logger = logging.getLogger(__name__)
class LogCLI:
    """Advanced CLI for log management."""

    def __init__(self):
        self.log_manager = log_manager
        self.colors = {
            'ERROR': '\033[91m',    # Red
            'WARNING': '\033[93m',  # Yellow
            'INFO': '\033[94m',     # Blue
            'DEBUG': '\033[90m',    # Gray
            'RESET': '\033[0m',     # Reset
            'BOLD': '\033[1m',      # Bold
            'GREEN': '\033[92m',    # Green
            'CYAN': '\033[96m',     # Cyan
            'MAGENTA': '\033[95m'   # Magenta
        }

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for log commands."""
        parser = argparse.ArgumentParser(
            description="PlexiChat Advanced Log Management CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  plexichat logs list                           # List all log files
  plexichat logs view plexichat.log               # View log file
  plexichat logs view plexichat.log -l ERROR      # View only ERROR entries
  plexichat logs search "database error"        # Search across all logs
  plexichat logs tail plexichat.log               # Follow log file
  plexichat logs stats plexichat.log              # Show log statistics
  plexichat logs archive --days 7               # Archive logs older than 7 days
  plexichat logs export plexichat.log -f json     # Export logs as JSON
  plexichat logs clean --days 30                # Clean old archives
            """
        )

        subparsers = parser.add_subparsers(dest='command', help='Log management commands')

        # List command
        list_parser = subparsers.add_parser('list', help='List all log files')
        list_parser.add_argument('--archived', action='store_true', help='Include archived files')
        list_parser.add_argument('--sort', choices=['name', 'size', 'date'], default='date', help='Sort by')

        # View command
        view_parser = subparsers.add_parser('view', help='View log file contents')
        view_parser.add_argument('filename', help='Log file to view')
        view_parser.add_argument('-l', '--level', choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'], help='Filter by log level')
        view_parser.add_argument('-n', '--lines', type=int, default=100, help='Number of lines to show')
        view_parser.add_argument('-s', '--search', help='Search term to filter')
        view_parser.add_argument('--start', help='Start time (YYYY-MM-DD HH:MM:SS)')
        view_parser.add_argument('--end', help='End time (YYYY-MM-DD HH:MM:SS)')
        view_parser.add_argument('--no-color', action='store_true', help='Disable colored output')
        view_parser.add_argument('--raw', action='store_true', help='Show raw log lines')

        # Search command
        search_parser = subparsers.add_parser('search', help='Search across log files')
        search_parser.add_argument('term', help='Search term')
        search_parser.add_argument('-l', '--level', choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'], help='Filter by log level')
        search_parser.add_argument('-f', '--files', nargs='+', help='Specific files to search')
        search_parser.add_argument('-n', '--max-results', type=int, default=100, help='Maximum results')
        search_parser.add_argument('--no-color', action='store_true', help='Disable colored output')

        # Tail command
        tail_parser = subparsers.add_parser('tail', help='Follow log file in real-time')
        tail_parser.add_argument('filename', help='Log file to follow')
        tail_parser.add_argument('-n', '--lines', type=int, default=10, help='Number of initial lines')
        tail_parser.add_argument('-l', '--level', choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'], help='Filter by log level')
        tail_parser.add_argument('--no-color', action='store_true', help='Disable colored output')

        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Show log file statistics')
        stats_parser.add_argument('filename', help='Log file to analyze')
        stats_parser.add_argument('--json', action='store_true', help='Output as JSON')

        # Archive command
        archive_parser = subparsers.add_parser('archive', help='Archive old log files')
        archive_parser.add_argument('--days', type=int, default=7, help='Archive files older than N days')
        archive_parser.add_argument('--dry-run', action='store_true', help='Show what would be archived')

        # Export command
        export_parser = subparsers.add_parser('export', help='Export log entries')
        export_parser.add_argument('filename', help='Log file to export')
        export_parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json', help='Export format')
        export_parser.add_argument('-o', '--output', help='Output file (default: stdout)')
        export_parser.add_argument('-l', '--level', choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'], help='Filter by log level')
        export_parser.add_argument('-s', '--search', help='Search term to filter')
        export_parser.add_argument('--start', help='Start time (YYYY-MM-DD HH:MM:SS)')
        export_parser.add_argument('--end', help='End time (YYYY-MM-DD HH:MM:SS)')

        # Clean command
        clean_parser = subparsers.add_parser('clean', help='Clean old archived files')
        clean_parser.add_argument('--days', type=int, default=30, help='Delete archives older than N days')
        clean_parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted')

        # WebUI command
        webui_parser = subparsers.add_parser('webui', help='Open log viewer in web browser')
        webui_parser.add_argument('--port', type=int, default=8000, help='Server port')

        return parser

    def run(self, args: List[str]):
        """Run CLI command."""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)

        if not parsed_args.command:
            parser.print_help()
            return

        try:
            if parsed_args.command == 'list':
                self.cmd_list(parsed_args)
            elif parsed_args.command == 'view':
                self.cmd_view(parsed_args)
            elif parsed_args.command == 'search':
                self.cmd_search(parsed_args)
            elif parsed_args.command == 'tail':
                self.cmd_tail(parsed_args)
            elif parsed_args.command == 'stats':
                self.cmd_stats(parsed_args)
            elif parsed_args.command == 'archive':
                self.cmd_archive(parsed_args)
            elif parsed_args.command == 'export':
                self.cmd_export(parsed_args)
            elif parsed_args.command == 'clean':
                self.cmd_clean(parsed_args)
            elif parsed_args.command == 'webui':
                self.cmd_webui(parsed_args)

        except Exception as e:
            self.print_error(f"Command failed: {e}")
            sys.exit(1)

    def cmd_list(self, args):
        """List log files command."""
        log_files = self.log_manager.get_log_files()

        if not args.archived:
            log_files = [lf for lf in log_files if not lf.is_archived]

        # Sort files
        if args.sort == 'name':
            log_files.sort(key=lambda x: x.filename)
        elif args.sort == 'size':
            log_files.sort(key=lambda x: x.size_bytes, reverse=True)
        else:  # date
            log_files.sort(key=lambda x: x.modified_at, reverse=True)

        if not log_files:
            self.print_info("No log files found")
            return

        # Print header
        self.print_header("Log Files")
        logger.info(f"{'Filename':<30} {'Size':<10} {'Entries':<8} {'Modified':<20} {'Type':<8}")
        logger.info("-" * 80)

        # Print files
        for log_file in log_files:
            size_str = self.format_size(log_file.size_bytes)
            modified_str = log_file.modified_at.strftime('%Y-%m-%d %H:%M:%S')
            type_str = "Archive" if log_file.is_archived else "Active"

            color = self.colors['CYAN'] if log_file.is_archived else self.colors['GREEN']
            logger.info(f"{color}{log_file.filename:<30}{self.colors['RESET']} "
                  f"{size_str:<10} {log_file.entry_count:<8} {modified_str:<20} {type_str:<8}")

        logger.info(f"\nTotal: {len(log_files)} files")

    def cmd_view(self, args):
        """View log file command."""
        try:
            start_time = self.parse_datetime(args.start) if args.start else None
            end_time = self.parse_datetime(args.end) if args.end else None

            entries, total_lines = self.log_manager.read_log_entries(
                filename=args.filename,
                max_lines=args.lines,
                level_filter=args.level,
                search_term=args.search,
                start_time=start_time,
                end_time=end_time
            )

            if not entries:
                self.print_info("No log entries found matching criteria")
                return

            # Print header
            filters = []
            if args.level:
                filters.append(f"level={args.level}")
            if args.search:
                filters.append(f"search='{args.search}'")
            if start_time:
                filters.append(f"start={args.start}")
            if end_time:
                filters.append(f"end={args.end}")

            filter_str = f" ({', '.join(filters)})" if filters else ""
            self.print_header(f"Log Entries: {args.filename}{filter_str}")
            logger.info(f"Showing {len(entries)} of {total_lines} total lines\n")

            # Print entries
            for entry in entries:
                if args.raw:
                    logger.info(entry.raw_line)
                else:
                    self.print_log_entry(entry, not args.no_color)

        except FileNotFoundError:
            self.print_error(f"Log file '{args.filename}' not found")
        except Exception as e:
            self.print_error(f"Failed to read log file: {e}")

    def cmd_search(self, args):
        """Search logs command."""
        try:
            results = self.log_manager.search_logs(
                search_term=args.term,
                filenames=args.files,
                level_filter=args.level,
                max_results=args.max_results
            )

            if not results:
                self.print_info(f"No results found for '{args.term}'")
                return

            self.print_header(f"Search Results: '{args.term}'")
            logger.info(f"Found {len(results)} matches\n")

            current_file = None
            for filename, entry in results:
                if filename != current_file:
                    if current_file is not None:
                        print()
                    logger.info(f"{self.colors['BOLD']}{self.colors['CYAN']}=== {filename} ==={self.colors['RESET']}")
                    current_file = filename

                self.print_log_entry(entry, not args.no_color, highlight_term=args.term)

        except Exception as e:
            self.print_error(f"Search failed: {e}")

    def cmd_tail(self, args):
        """Tail log file command."""
        try:
            # Show initial lines
            entries, _ = self.log_manager.read_log_entries(
                filename=args.filename,
                max_lines=args.lines,
                level_filter=args.level
            )

            self.print_header(f"Tailing: {args.filename}")

            for entry in entries[-args.lines:]:
                self.print_log_entry(entry, not args.no_color)

            logger.info(f"\n{self.colors['YELLOW']}Following log file... (Press Ctrl+C to stop){self.colors['RESET']}")

            # In a real implementation, this would use file watching
            # For demo, we'll just show a message
            logger.info("(Real-time following would be implemented here)")

        except FileNotFoundError:
            self.print_error(f"Log file '{args.filename}' not found")
        except KeyboardInterrupt:
            logger.info(f"\n{self.colors['YELLOW']}Stopped following log file{self.colors['RESET']}")
        except Exception as e:
            self.print_error(f"Failed to tail log file: {e}")

    def cmd_stats(self, args):
        """Show log statistics command."""
        try:
            stats = self.log_manager.get_log_statistics(args.filename)

            if args.json:
                logger.info(json.dumps(stats, indent=2))
                return

            self.print_header(f"Log Statistics: {args.filename}")

            logger.info(f"Total Entries: {stats.get('total_entries', 0)}")
            logger.info(f"Total Lines: {stats.get('total_lines', 0)}")

            if 'time_range' in stats and stats['time_range']['start']:
                logger.info(f"Time Range: {stats['time_range']['start']} to {stats['time_range']['end']}")

            # Level distribution
            if 'level_distribution' in stats:
                logger.info(f"\n{self.colors['BOLD']}Level Distribution:{self.colors['RESET']}")
                for level, count in stats['level_distribution'].items():
                    color = self.colors.get(level, self.colors['RESET'])
                    logger.info(f"  {color}{level:<8}{self.colors['RESET']}: {count}")

            # Module distribution
            if 'module_distribution' in stats:
                logger.info(f"\n{self.colors['BOLD']}Top Modules:{self.colors['RESET']}")
                sorted_modules = sorted(
                    stats['module_distribution'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]

                for module, count in sorted_modules:
                    logger.info(f"  {module:<30}: {count}")

        except FileNotFoundError:
            self.print_error(f"Log file '{args.filename}' not found")
        except Exception as e:
            self.print_error(f"Failed to get statistics: {e}")

    def cmd_archive(self, args):
        """Archive old logs command."""
        try:
            if args.dry_run:
                self.print_info(f"Dry run: Would archive files older than {args.days} days")
                # In real implementation, show what would be archived
                return

            archived_files = self.log_manager.archive_old_logs(args.days)

            if archived_files:
                self.print_success(f"Archived {len(archived_files)} files:")
                for filename in archived_files:
                    logger.info(f"   {filename}")
            else:
                self.print_info("No files to archive")

        except Exception as e:
            self.print_error(f"Archive failed: {e}")

    def cmd_export(self, args):
        """Export logs command."""
        try:
            filters = {
                'level_filter': args.level,
                'search_term': args.search,
                'start_time': self.parse_datetime(args.start) if args.start else None,
                'end_time': self.parse_datetime(args.end) if args.end else None
            }

            exported_data = self.log_manager.export_logs(
                filenames=[args.filename],
                export_format=args.format,
                filters=filters
            )

            if args.output:
                with open(args.output, 'w') as f:
                    f.write(exported_data)
                self.print_success(f"Exported to {args.output}")
            else:
                logger.info(exported_data)

        except FileNotFoundError:
            self.print_error(f"Log file '{args.filename}' not found")
        except Exception as e:
            self.print_error(f"Export failed: {e}")

    def cmd_clean(self, args):
        """Clean old archives command."""
        try:
            if args.dry_run:
                self.print_info(f"Dry run: Would delete archives older than {args.days} days")
                return

            cleaned_files = self.log_manager.cleanup_old_archives(args.days)

            if cleaned_files:
                self.print_success(f"Cleaned {len(cleaned_files)} old archives:")
                for filename in cleaned_files:
                    logger.info(f"   {filename}")
            else:
                self.print_info("No old archives to clean")

        except Exception as e:
            self.print_error(f"Cleanup failed: {e}")

    def cmd_webui(self, args):
        """Open web UI command."""
        try:
            url = f"http://localhost:{args.port}/logs"
            self.print_info(f"Opening log viewer at {url}")

            # Try to open in browser
            webbrowser.open(url)

        except Exception as e:
            self.print_error(f"Failed to open web UI: {e}")

    def print_log_entry(self, entry: LogEntry, use_color: bool = True, highlight_term: str = None):
        """Print a formatted log entry."""
        timestamp = entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')

        if use_color:
            level_color = self.colors.get(entry.level, self.colors['RESET'])
            timestamp_color = self.colors['CYAN']
            module_color = self.colors['MAGENTA']
            reset = self.colors['RESET']
        else:
            level_color = timestamp_color = module_color = reset = ''

        message = entry.message
        if highlight_term and use_color:
            message = message.replace(
                highlight_term,
                f"{self.colors['BOLD']}{self.colors['YELLOW']}{highlight_term}{reset}"
            )

        logger.info(f"{timestamp_color}{timestamp}{reset} "
              f"{level_color}[{entry.level:<7}]{reset} "
              f"{module_color}{entry.module:<20}{reset} "
              f"{message}")

    def print_header(self, text: str):
        """Print a formatted header."""
        logger.info(f"\n{self.colors['BOLD']}{self.colors['GREEN']}{'=' * 60}{self.colors['RESET']}")
        logger.info(f"{self.colors['BOLD']}{self.colors['GREEN']}{text}{self.colors['RESET']}")
        logger.info(f"{self.colors['BOLD']}{self.colors['GREEN']}{'=' * 60}{self.colors['RESET']}\n")

    def print_success(self, text: str):
        """Print success message."""
        logger.info(f"{self.colors['GREEN']} {text}{self.colors['RESET']}")

    def print_info(self, text: str):
        """Print info message."""
        logger.info(f"{self.colors['CYAN']}  {text}{self.colors['RESET']}")

    def print_error(self, text: str):
        """Print error message."""
        logger.info(f"{self.colors['ERROR']} {text}{self.colors['RESET']}", file=sys.stderr)

    def format_size(self, bytes_size: int) -> str:
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024:
                return f"{bytes_size:.1f}{unit}"
            bytes_size /= 1024
        return f"{bytes_size:.1f}TB"

    def parse_datetime(self, date_str: str) -> datetime:
        """Parse datetime string."""
        try:
            return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                return datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                raise ValueError(f"Invalid date format: {date_str}. Use 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD'")


def main():
    """Main CLI entry point."""
    cli = LogCLI()
    cli.run(sys.argv[1:])


if __name__ == "__main__":
    main()
