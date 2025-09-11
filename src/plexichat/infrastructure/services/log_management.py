# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import re
from typing import Any
import zipfile

logger = logging.getLogger(__name__)

@dataclass
class LogEntry:
    """Individual log entry structure."""
    timestamp: datetime
    level: str
    message: str
    module: str
    line_number: int | None = None
    function: str | None = None
    thread: str | None = None
    raw_line: str = ""


@dataclass
class LogFile:
    """Log file information."""
    filename: str
    filepath: str
    size_bytes: int
    created_at: datetime
    modified_at: datetime
    entry_count: int
    is_compressed: bool = False
    is_archived: bool = False


class LogParser:
    """Parses different log formats."""
    def __init__(self):
        # Common log patterns
        self.patterns = {
            'standard': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - '
                r'(?P<level>\w+) - '
                r'(?P<module>[\w\.]+) - '
                r'(?P<message>.*)'
            ),
            'detailed': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - '
                r'(?P<level>\w+) - '
                r'(?P<module>[\w\.]+):(?P<line>\d+) - '
                r'(?P<function>\w+) - '
                r'(?P<message>.*)'
            ),
            'simple': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
                r'(?P<level>\w+): '
                r'(?P<message>.*)'
            )
        }

    def parse_log_line(self, line: str) -> LogEntry | None:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None

        for pattern_name, pattern in self.patterns.items():
            match = pattern.match(line)
            if match:
                groups = match.groupdict()

                try:
                    # Parse timestamp
                    timestamp_str = groups['timestamp']
                    if ',' in timestamp_str:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                    else:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

                    return LogEntry(
                        timestamp=timestamp,
                        level=groups['level'],
                        message=groups['message'],
                        module=groups.get('module', 'unknown'),
                        line_number=int(groups['line']) if groups.get('line') else None,
                        function=groups.get('function'),
                        raw_line=line
                    )

                except (ValueError, KeyError) as e:
                    logger.debug(f"Failed to parse log line: {e}")
                    continue

        # If no pattern matches, create a simple entry
        return LogEntry(
            timestamp=datetime.now(),
            level='UNKNOWN',
            message=line,
            module='unknown',
            raw_line=line
        )


class LogManager:
    """Advanced log management with filtering and archiving."""
    def __init__(self, log_directory: str = "logs"):
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(exist_ok=True)

        self.archive_directory = self.log_directory / "archive"
        self.archive_directory.mkdir(exist_ok=True)

        self.parser = LogParser()
        self.max_log_size_mb = 100
        self.max_archive_days = 30

    def get_log_files(self) -> list[LogFile]:
        """Get list of all log files."""
        log_files = []

        # Get current log files
        for log_path in self.log_directory.glob("*.log"):
            if log_path.is_file():
                stat_info = log_path.stat()

                # Count entries (approximate)
                entry_count = self._count_log_entries(log_path)

                log_files.append(LogFile(
                    filename=log_path.name,
                    filepath=str(log_path),
                    size_bytes=stat_info.st_size,
                    created_at=datetime.fromtimestamp(stat_info.st_ctime),
                    modified_at=datetime.fromtimestamp(stat_info.st_mtime),
                    entry_count=entry_count,
                    is_compressed=False,
                    is_archived=False
                ))

        # Get archived log files
        for archive_path in self.archive_directory.glob("*.zip"):
            if archive_path.is_file():
                stat_info = archive_path.stat()

                log_files.append(LogFile(
                    filename=archive_path.name,
                    filepath=str(archive_path),
                    size_bytes=stat_info.st_size,
                    created_at=datetime.fromtimestamp(stat_info.st_ctime),
                    modified_at=datetime.fromtimestamp(stat_info.st_mtime),
                    entry_count=0,  # Would need to extract to count
                    is_compressed=True,
                    is_archived=True
                ))

        return sorted(log_files, key=lambda x: x.modified_at, reverse=True)

    def read_log_entries(
        self,
        filename: str,
        start_line: int = 0,
        max_lines: int = 1000,
        level_filter: str | None = None,
        search_term: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None
    ) -> tuple[list[LogEntry], int]:
        """Read log entries with filtering."""

        log_path = self.log_directory / filename
        if not log_path.exists():
            # Check archive
            archive_path = self.archive_directory / filename.replace('.log', '.zip')
            if archive_path.exists() and filename.endswith('.log'):
                return self._read_archived_log(
                    archive_path, start_line, max_lines,
                    level_filter, search_term, start_time, end_time
                )
            raise FileNotFoundError(f"Log file {filename} not found")

        entries = []
        total_lines = 0
        current_line = 0

        try:
            with open(log_path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines += 1

                    if current_line < start_line:
                        current_line += 1
                        continue

                    if len(entries) >= max_lines:
                        break

                    entry = self.parser.parse_log_line(line)
                    if not entry:
                        continue

                    # Apply filters
                    if level_filter and entry.level.upper() != level_filter.upper():
                        continue

                    if search_term and search_term.lower() not in entry.message.lower():
                        continue

                    if start_time and entry.timestamp < start_time:
                        continue

                    if end_time and entry.timestamp > end_time:
                        continue

                    entries.append(entry)
                    current_line += 1

        except Exception as e:
            logger.error(f"Failed to read log file {filename}: {e}")
            raise

        return entries, total_lines

    def search_logs(
        self,
        search_term: str,
        filenames: list[str] | None = None,
        level_filter: str | None = None,
        max_results: int = 500
    ) -> list[tuple[str, LogEntry]]:
        """Search across multiple log files."""

        results = []

        if not filenames:
            log_files = self.get_log_files()
            filenames = [lf.filename for lf in log_files if not lf.is_archived]

        for filename in filenames:
            try:
                entries, _ = self.read_log_entries(
                    filename=filename,
                    max_lines=max_results,
                    level_filter=level_filter,
                    search_term=search_term
                )

                for entry in entries:
                    results.append((filename, entry))

                    if len(results) >= max_results:
                        break

                if len(results) >= max_results:
                    break

            except Exception as e:
                logger.error(f"Failed to search in {filename}: {e}")
                continue

        return results

    def get_log_statistics(self, filename: str) -> dict[str, Any]:
        """Get statistics for a log file."""

        try:
            entries, total_lines = self.read_log_entries(filename, max_lines=10000)

            level_counts = {}
            module_counts = {}
            hourly_counts = {}

            for entry in entries:
                # Count by level
                level_counts[entry.level] = level_counts.get(entry.level, 0) + 1

                # Count by module
                module_counts[entry.module] = module_counts.get(entry.module, 0) + 1

                # Count by hour
                hour_key = entry.timestamp.strftime('%Y-%m-%d %H:00')
                hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1

            return {
                'total_entries': len(entries),
                'total_lines': total_lines,
                'level_distribution': level_counts,
                'module_distribution': module_counts,
                'hourly_distribution': hourly_counts,
                'time_range': {
                    'start': entries[0].timestamp.isoformat() if entries else None,
                    'end': entries[-1].timestamp.isoformat() if entries else None
                }
            }

        except Exception as e:
            logger.error(f"Failed to get statistics for {filename}: {e}")
            return {}

    def archive_old_logs(self, days_old: int = 7) -> list[str]:
        """Archive log files older than specified days."""

        archived_files = []

        cutoff_date = datetime.now() - timedelta(days=days_old)

        for log_path in self.log_directory.glob("*.log"):
            if log_path.is_file():
                stat_info = log_path.stat()
                modified_date = datetime.fromtimestamp(stat_info.st_mtime)

                if modified_date < cutoff_date:
                    try:
                        # Create archive
                        archive_name = f"{log_path.stem}_{modified_date.strftime('%Y%m%d')}.zip"
                        archive_path = self.archive_directory / archive_name

                        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                            zf.write(log_path, log_path.name)

                        # Remove original
                        log_path.unlink()

                        archived_files.append(archive_name)
                        logger.info(f" Archived log file: {log_path.name}")

                    except Exception as e:
                        logger.error(f"Failed to archive {log_path.name}: {e}")

        return archived_files

    def cleanup_old_archives(self, days_old: int = 30) -> list[str]:
        """Clean up archive files older than specified days."""

        cleaned_files = []

        cutoff_date = datetime.now() - timedelta(days=days_old)

        for archive_path in self.archive_directory.glob("*.zip"):
            if archive_path.is_file():
                stat_info = archive_path.stat()
                modified_date = datetime.fromtimestamp(stat_info.st_mtime)

                if modified_date < cutoff_date:
                    try:
                        archive_path.unlink()
                        cleaned_files.append(archive_path.name)
                        logger.info(f" Cleaned up old archive: {archive_path.name}")

                    except Exception as e:
                        logger.error(f"Failed to cleanup {archive_path.name}: {e}")

        return cleaned_files

    def export_logs(
        self,
        filenames: list[str],
        export_format: str = "json",
        filters: dict[str, Any] | None = None
    ) -> str:
        """Export logs in specified format."""

        filters = filters or {}
        export_data = []

        for filename in filenames:
            try:
                entries, _ = self.read_log_entries(
                    filename=filename,
                    max_lines=filters.get('max_lines', 10000),
                    level_filter=filters.get('level_filter'),
                    search_term=filters.get('search_term'),
                    start_time=filters.get('start_time'),
                    end_time=filters.get('end_time')
                )

                for entry in entries:
                    export_data.append({
                        'filename': filename,
                        'timestamp': entry.timestamp.isoformat(),
                        'level': entry.level,
                        'module': entry.module,
                        'message': entry.message,
                        'line_number': entry.line_number,
                        'function': entry.function
                    })

            except Exception as e:
                logger.error(f"Failed to export {filename}: {e}")
                continue

        if export_format.lower() == "json":
            return json.dumps(export_data, indent=2)
        elif export_format.lower() == "csv":
            # Simple CSV export
            lines = ["timestamp,level,module,message"]
            for item in export_data:
                lines.append(f"{item['timestamp']},{item['level']},{item['module']},\"{item['message']}\"")
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

    def _count_log_entries(self, log_path: Path) -> int:
        """Count entries in a log file (approximate)."""
        try:
            with open(log_path, encoding='utf-8', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    def _read_archived_log(
        self,
        archive_path: Path,
        start_line: int,
        max_lines: int,
        level_filter: str | None,
        search_term: str | None,
        start_time: datetime | None,
        end_time: datetime | None
    ) -> tuple[list[LogEntry], int]:
        """Read entries from archived log file."""

        entries = []
        total_lines = 0

        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for filename in zf.namelist():
                    if filename.endswith('.log'):
                        with zf.open(filename) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            lines = content.split('\n')

                            current_line = 0
                            for line in lines:
                                total_lines += 1

                                if current_line < start_line:
                                    current_line += 1
                                    continue

                                if len(entries) >= max_lines:
                                    break

                                entry = self.parser.parse_log_line(line)
                                if not entry:
                                    continue

                                # Apply filters (same as regular read)
                                if level_filter and entry.level.upper() != level_filter.upper():
                                    continue

                                if search_term and search_term.lower() not in entry.message.lower():
                                    continue

                                if start_time and entry.timestamp < start_time:
                                    continue

                                if end_time and entry.timestamp > end_time:
                                    continue

                                entries.append(entry)
                                current_line += 1

        except Exception as e:
            logger.error(f"Failed to read archived log {archive_path}: {e}")
            raise

        return entries, total_lines


# Global log manager instance
log_manager = LogManager()
