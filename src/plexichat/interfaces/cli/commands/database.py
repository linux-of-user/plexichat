import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import click
import yaml
from tabulate import tabulate

from plexichat.core.config.config_manager import ConfigManager
from plexichat.core.database.enhanced_abstraction import enhanced_db_manager
from plexichat.core.database.indexing_strategy import index_manager
from plexichat.core.database.performance_integration import performance_optimizer
from plexichat.core.database.query_optimizer import performance_monitor

"""
PlexiChat Database Performance CLI Commands

Comprehensive command-line interface for database performance optimization,
monitoring, and management. Provides tools for analyzing, optimizing, and
monitoring database performance across all supported database types.
"""

# Add src to path for imports
sys.path.insert(0, str(from pathlib import Path
Path(__file__).parent.parent.parent))

logger = logging.getLogger(__name__)


@click.group(name="db-perf")
@click.pass_context
def database_performance_cli(ctx):
    """Database Performance Optimization Commands."""
    ctx.ensure_object(dict)
    ctx.obj['config'] = ConfigManager()


@database_performance_cli.command()
@click.option('--database', '-d', help='Database name to analyze')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml']), default='table', help='Output format')
@click.option('--detailed', is_flag=True, help='Show detailed analysis')
@click.pass_context
def analyze(ctx, database: str, format: str, detailed: bool):
    """Analyze database performance and generate recommendations."""
    click.echo(" Analyzing database performance...")
    
    async def run_analysis():
        try:
            # Get available databases
            if not database:
                databases = list(enhanced_db_manager.clients.keys())
                if not databases:
                    click.echo(" No databases configured")
                    return
                database_name = databases[0]  # Use first available
                click.echo(f" Using database: {database_name}")
            else:
                database_name = database
            
            # Run performance analysis
            report = await performance_optimizer.analyze_database_performance(database_name)
            
            if format == 'json':
                click.echo(json.dumps({
                    "database": report.database_name,
                    "performance_score": report.performance_score,
                    "optimization_priority": report.optimization_priority,
                    "total_queries": report.total_queries,
                    "slow_queries": report.slow_queries_count,
                    "avg_query_time_ms": report.avg_query_time_ms,
                    "recommended_indexes": len(report.recommended_indexes),
                    "schema_recommendations": len(report.schema_recommendations),
                    "top_recommendations": report.top_recommendations
                }, indent=2))
            
            elif format == 'yaml':
                click.echo(yaml.dump({
                    "database_performance_report": {
                        "database": report.database_name,
                        "analysis_timestamp": report.analysis_timestamp.isoformat(),
                        "performance_score": report.performance_score,
                        "optimization_priority": report.optimization_priority,
                        "metrics": {
                            "total_queries": report.total_queries,
                            "slow_queries": report.slow_queries_count,
                            "avg_query_time_ms": report.avg_query_time_ms
                        },
                        "recommendations": {
                            "indexes": len(report.recommended_indexes),
                            "schema": len(report.schema_recommendations),
                            "procedures": len(report.procedure_recommendations)
                        },
                        "top_recommendations": report.top_recommendations
                    }
                }, default_flow_style=False))
            
            else:  # table format
                click.echo(f"\n Database Performance Report: {report.database_name}")
                click.echo("=" * 60)
                
                # Performance summary
                score_color = "green" if report.performance_score >= 80 else "yellow" if report.performance_score >= 60 else "red"
                click.echo(f"Performance Score: {click.style(f'{report.performance_score:.1f}/100', fg=score_color)}")
                click.echo(f"Optimization Priority: {click.style(report.optimization_priority.upper(), fg='red' if report.optimization_priority == 'critical' else 'yellow' if report.optimization_priority == 'high' else 'green')}")
                click.echo(f"Analysis Time: {report.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Metrics table
                metrics_data = [
                    ["Total Queries", report.total_queries],
                    ["Slow Queries", report.slow_queries_count],
                    ["Avg Query Time", f"{report.avg_query_time_ms:.2f}ms"],
                    ["Recommended Indexes", len(report.recommended_indexes)],
                    ["Schema Optimizations", len(report.schema_recommendations)],
                    ["Procedure Recommendations", len(report.procedure_recommendations)]
                ]
                
                click.echo("\n Performance Metrics:")
                click.echo(tabulate(metrics_data, headers=["Metric", "Value"], tablefmt="grid"))
                
                # Top recommendations
                if report.top_recommendations:
                    click.echo("\n Top Recommendations:")
                    for i, rec in enumerate(report.top_recommendations, 1):
                        click.echo(f"  {i}. {rec}")
                
                # Detailed analysis
                if detailed:
                    if report.recommended_indexes:
                        click.echo("\n Index Recommendations:")
                        index_data = []
                        for idx in report.recommended_indexes[:5]:  # Show top 5
                            index_data.append([
                                idx.index_definition.table,
                                ", ".join(idx.index_definition.columns),
                                f"{idx.estimated_improvement:.1f}%",
                                idx.reason
                            ])
                        click.echo(tabulate(index_data, headers=["Table", "Columns", "Improvement", "Reason"], tablefmt="grid"))
                    
                    if report.schema_recommendations:
                        click.echo("\n Schema Recommendations:")
                        schema_data = []
                        for rec in report.schema_recommendations[:5]:  # Show top 5
                            schema_data.append([
                                f"{rec.table_name}.{rec.column_name}",
                                rec.current_type,
                                rec.recommended_type,
                                f"{rec.estimated_space_savings:.1f}%"
                            ])
                        click.echo(tabulate(schema_data, headers=["Column", "Current Type", "Recommended", "Savings"], tablefmt="grid"))
        
        except Exception as e:
            click.echo(f" Analysis failed: {e}")
            logger.error(f"Performance analysis failed: {e}", exc_info=True)
    
    asyncio.run(run_analysis())


@database_performance_cli.command()
@click.option('--database', '-d', help='Database name to optimize')
@click.option('--auto-apply', is_flag=True, help='Automatically apply safe optimizations')
@click.option('--max-tasks', type=int, default=5, help='Maximum optimization tasks to create')
@click.option('--dry-run', is_flag=True, help='Show what would be optimized without applying changes')
@click.pass_context
def optimize(ctx, database: str, auto_apply: bool, max_tasks: int, dry_run: bool):
    """Optimize database performance with recommended improvements."""
    click.echo(" Starting database optimization...")
    
    async def run_optimization():
        try:
            # Get database
            if not database:
                databases = list(enhanced_db_manager.clients.keys())
                if not databases:
                    click.echo(" No databases configured")
                    return
                database_name = databases[0]
            else:
                database_name = database
            
            if dry_run:
                click.echo(" Dry run mode - analyzing optimizations without applying changes")
                auto_apply = False
            
            # Run optimization
            tasks = await performance_optimizer.optimize_database_performance(
                database_name, auto_apply=auto_apply
            )
            
            if not tasks:
                click.echo(" No optimizations needed - database performance is already optimal")
                return
            
            click.echo(f"\n Created {len(tasks)} optimization tasks:")
            
            task_data = []
            for task in tasks:
                status_color = "green" if task.success else "red" if task.status.value == "failed" else "yellow"
                task_data.append([
                    task.optimization_type.replace("_", " ").title(),
                    task.description,
                    click.style(task.status.value.title(), fg=status_color),
                    f"Priority {task.priority}"
                ])
            
            click.echo(tabulate(task_data, headers=["Type", "Description", "Status", "Priority"], tablefmt="grid"))
            
            if auto_apply:
                successful_tasks = [t for t in tasks if t.success]
                click.echo(f"\n Successfully applied {len(successful_tasks)} optimizations")
                
                if len(successful_tasks) < len(tasks):
                    failed_tasks = len(tasks) - len(successful_tasks)
                    click.echo(f" {failed_tasks} optimizations failed or require manual intervention")
            else:
                click.echo("\n Use --auto-apply to automatically apply safe optimizations")
                click.echo(" Use 'plexichat db-perf apply-task <task_id>' to apply specific optimizations")
        
        except Exception as e:
            click.echo(f" Optimization failed: {e}")
            logger.error(f"Database optimization failed: {e}", exc_info=True)
    
    asyncio.run(run_optimization())


@database_performance_cli.command()
@click.option('--database', '-d', help='Database name to monitor')
@click.option('--interval', type=int, default=60, help='Monitoring interval in seconds')
@click.option('--duration', type=int, default=300, help='Monitoring duration in seconds')
@click.option('--threshold', type=float, default=1000, help='Slow query threshold in milliseconds')
@click.pass_context
def monitor(ctx, database: str, interval: int, duration: int, threshold: float):
    """Monitor database performance in real-time."""
    click.echo(" Starting real-time performance monitoring...")
    click.echo(f" Interval: {interval}s, Duration: {duration}s, Threshold: {threshold}ms")
    
    async def run_monitoring():
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                # Get performance metrics
                report = performance_monitor.get_performance_report()
                
                # Display current metrics
                click.clear()
                click.echo(" PlexiChat Database Performance Monitor")
                click.echo("=" * 50)
                click.echo(f"Time: {from datetime import datetime
datetime.now().strftime('%H:%M:%S')}")
                click.echo(f"Total Queries: {report.get('total_queries', 0)}")
                click.echo(f"Average Response Time: {report.get('average_response_time_ms', 0):.2f}ms")
                click.echo(f"Slow Queries: {report.get('slow_queries_count', 0)}")
                
                # Show recent slow queries
                slow_queries = [q for q in performance_monitor.slow_queries 
                              if q["execution_time_ms"] > threshold]
                
                if slow_queries:
                    click.echo(f"\n Recent Slow Queries (>{threshold}ms):")
                    for query in slow_queries[-5:]:  # Show last 5
                        click.echo(f"   {query['execution_time_ms']:.1f}ms - {query['query'][:60]}...")
                
                click.echo("\nPress Ctrl+C to stop monitoring...")
                
                await asyncio.sleep(interval)
        
        except KeyboardInterrupt:
            click.echo("\n Monitoring stopped by user")
        except Exception as e:
            click.echo(f" Monitoring failed: {e}")
    
    asyncio.run(run_monitoring())


@database_performance_cli.command()
@click.option('--database', '-d', help='Database name')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'yaml']), default='table', help='Output format')
@click.pass_context
def indexes(ctx, database: str, format: str):
    """Show database indexes and recommendations."""
    click.echo(" Analyzing database indexes...")
    
    async def show_indexes():
        try:
            if not database:
                databases = list(enhanced_db_manager.clients.keys())
                if not databases:
                    click.echo(" No databases configured")
                    return
                database_name = databases[0]
            else:
                database_name = database
            
            # Get index report
            report = index_manager.get_index_report(database_name)
            
            if format == 'json':
                click.echo(json.dumps(report, indent=2))
            elif format == 'yaml':
                click.echo(yaml.dump(report, default_flow_style=False))
            else:
                click.echo(f"\n Index Report: {database_name}")
                click.echo("=" * 50)
                
                # Summary
                click.echo(f"Total Indexes: {report.get('total_indexes', 0)}")
                click.echo(f"Active Indexes: {report.get('active_indexes', 0)}")
                click.echo(f"Unused Indexes: {report.get('unused_indexes', 0)}")
                click.echo(f"Recommendations: {report.get('recommendations_count', 0)}")
                
                # Top recommendations
                recommendations = report.get('top_recommendations', [])
                if recommendations:
                    click.echo("\n Top Index Recommendations:")
                    rec_data = []
                    for rec in recommendations:
                        rec_data.append([
                            rec['table'],
                            ", ".join(rec['columns']),
                            f"Priority {rec['priority']}",
                            f"{rec['estimated_improvement']:.1f}%"
                        ])
                    click.echo(tabulate(rec_data, headers=["Table", "Columns", "Priority", "Improvement"], tablefmt="grid"))
        
        except Exception as e:
            click.echo(f" Index analysis failed: {e}")
    
    asyncio.run(show_indexes())


@database_performance_cli.command()
@click.option('--enable/--disable', default=None, help='Enable or disable auto-optimization')
@click.option('--interval', type=int, help='Set optimization interval in hours')
@click.option('--threshold', type=float, help='Set slow query threshold in milliseconds')
@click.pass_context
def config(ctx, enable: bool, interval: int, threshold: float):
    """Configure database performance optimization from plexichat.core.config import settings
settings."""
    config_manager = ctx.obj['config']
    
    try:
        # Load current database performance config
        db_perf_config = config_manager.load_database_performance_config()
        
        # Apply changes
        changes_made = False
        
        if enable is not None:
            db_perf_config['database_performance']['auto_optimization'] = enable
            changes_made = True
            status = "enabled" if enable else "disabled"
            click.echo(f" Auto-optimization {status}")
        
        if interval is not None:
            db_perf_config['database_performance']['optimization_interval_hours'] = interval
            changes_made = True
            click.echo(f" Optimization interval set to {interval} hours")
        
        if threshold is not None:
            db_perf_config['database_performance']['thresholds']['slow_query_ms'] = threshold
            changes_made = True
            click.echo(f" Slow query threshold set to {threshold}ms")
        
        if changes_made:
            # Save updated configuration
            config_file = config_manager.config_dir / "database_performance.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(db_perf_config, f, default_flow_style=False, indent=2)
            click.echo(f" Configuration saved to {config_file}")
        else:
            # Show current configuration
            click.echo(" Current Database Performance Configuration:")
            perf_config = db_perf_config.get('database_performance', {})
            
            config_data = [
                ["Auto-optimization", perf_config.get('auto_optimization', False)],
                ["Optimization Interval", f"{perf_config.get('optimization_interval_hours', 24)} hours"],
                ["Slow Query Threshold", f"{perf_config.get('thresholds', {}).get('slow_query_ms', 1000)}ms"],
                ["Monitoring Enabled", perf_config.get('monitoring', {}).get('enabled', True)],
                ["Query Cache Enabled", perf_config.get('query_optimization', {}).get('cache_enabled', True)]
            ]
            
            click.echo(tabulate(config_data, headers=["Setting", "Value"], tablefmt="grid"))
    
    except Exception as e:
        click.echo(f" Configuration failed: {e}")


@database_performance_cli.command()
@click.pass_context
def status(ctx):
    """Show database performance optimization system status."""
    click.echo(" Database Performance System Status")
    click.echo("=" * 40)
    
    try:
        # Get optimization summary
        summary = performance_optimizer.get_optimization_summary()
        
        status_data = [
            ["Databases Analyzed", summary.get('total_databases_analyzed', 0)],
            ["Optimization Tasks", summary.get('total_optimization_tasks', 0)],
            ["Completed Tasks", summary.get('completed_tasks', 0)],
            ["Failed Tasks", summary.get('failed_tasks', 0)],
            ["Success Rate", f"{summary.get('success_rate', 0):.1f}%"]
        ]
        
        click.echo(tabulate(status_data, headers=["Metric", "Value"], tablefmt="grid"))
        
        # Show database performance scores
        reports = summary.get('performance_reports', {})
        if reports:
            click.echo("\n Database Performance Scores:")
            score_data = []
            for db_name, report in reports.items():
                score = report.get('performance_score', 0)
                priority = report.get('optimization_priority', 'unknown')
                score_data.append([
                    db_name,
                    f"{score:.1f}/100",
                    priority.title(),
                    len(report.get('top_recommendations', []))
                ])
            
            click.echo(tabulate(score_data, headers=["Database", "Score", "Priority", "Recommendations"], tablefmt="grid"))
    
    except Exception as e:
        click.echo(f" Status check failed: {e}")


if __name__ == "__main__":
    database_performance_cli()
