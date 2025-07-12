"""
Testing CLI Interface
Command-line interface for running comprehensive tests.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from plexichat.tests.comprehensive_test_suite import test_framework, TestResult

console = Console()
app = typer.Typer(help="Enhanced Chat API Testing Framework")

@app.command()
def list_suites():
    """List all available test suites."""
    console.print("\n[bold cyan]Available Test Suites[/bold cyan]")
    console.print("=" * 50)
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Suite Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Tests", justify="center", style="yellow")
    table.add_column("Timeout", justify="center", style="green")
    
    for suite_name, suite in test_framework.test_suites.items():
        table.add_row(
            suite_name,
            suite.description,
            str(len(suite.tests)),
            f"{suite.timeout}s"
        )
    
    console.print(table)
    console.print()

@app.command()
def run(
    suite: Optional[str] = typer.Argument(None, help="Specific test suite to run"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, html"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    parallel: bool = typer.Option(False, "--parallel", "-p", help="Run tests in parallel"),
    timeout: Optional[int] = typer.Option(None, "--timeout", "-t", help="Override test timeout"),
    filter: Optional[str] = typer.Option(None, "--filter", help="Filter tests by name pattern"),
    fail_fast: bool = typer.Option(False, "--fail-fast", help="Stop on first failure"),
    repeat: int = typer.Option(1, "--repeat", "-r", help="Number of times to repeat tests"),
    base_url: Optional[str] = typer.Option(None, "--base-url", help="Override base URL for tests")
):
    """Run test suites."""
    
    if base_url:
        test_framework.base_url = base_url
        test_framework.websocket_url = base_url.replace("http", "ws")
    
    console.print(f"\n[bold green]🚀 Enhanced Chat API Test Runner[/bold green]")
    console.print(f"Base URL: [cyan]{test_framework.base_url}[/cyan]")
    console.print()
    
    # Run tests
    if suite:
        if suite not in test_framework.test_suites:
            console.print(f"[red]Error: Unknown test suite '{suite}'[/red]")
            console.print("Use 'list-suites' to see available suites.")
            raise typer.Exit(1)
        
        asyncio.run(_run_single_suite(suite, verbose, timeout, repeat))
    else:
        asyncio.run(_run_all_suites(verbose, timeout, repeat))
    
    # Generate and display results
    results = test_framework.generate_report()
    
    if format == "table":
        _display_results_table(results, verbose)
    elif format == "json":
        _display_results_json(results)
    elif format == "html":
        _display_results_html(results)
    
    # Save to file if specified
    if output:
        _save_results(results, output, format)
    
    # Exit with appropriate code
    if results["summary"]["failed"] > 0:
        raise typer.Exit(1)

@app.command()
def health():
    """Quick health check of the API."""
    console.print("\n[bold yellow]🏥 API Health Check[/bold yellow]")
    
    async def check_health():
        await test_framework.setup_session()
        try:
            await test_framework.test_api_health()
            console.print("[green]✅ API is healthy[/green]")
            
            await test_framework.test_api_ready()
            console.print("[green]✅ API is ready[/green]")
            
            await test_framework.test_api_version()
            console.print("[green]✅ API version endpoint working[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Health check failed: {e}[/red]")
            raise typer.Exit(1)
        finally:
            await test_framework.teardown_session()
    
    asyncio.run(check_health())

@app.command()
def performance(
    duration: int = typer.Option(60, "--duration", "-d", help="Test duration in seconds"),
    concurrent: int = typer.Option(10, "--concurrent", "-c", help="Number of concurrent users"),
    ramp_up: int = typer.Option(10, "--ramp-up", help="Ramp-up time in seconds")
):
    """Run performance tests."""
    console.print(f"\n[bold magenta]⚡ Performance Testing[/bold magenta]")
    console.print(f"Duration: {duration}s, Concurrent Users: {concurrent}, Ramp-up: {ramp_up}s")
    console.print()
    
    asyncio.run(_run_performance_test(duration, concurrent, ramp_up))

@app.command()
def security():
    """Run security tests."""
    console.print("\n[bold red]🔒 Security Testing[/bold red]")
    
    asyncio.run(_run_single_suite("security", verbose=True))

@app.command()
def monitor(
    interval: int = typer.Option(30, "--interval", "-i", help="Check interval in seconds"),
    duration: int = typer.Option(300, "--duration", "-d", help="Total monitoring duration in seconds")
):
    """Continuous monitoring mode."""
    console.print(f"\n[bold blue]📊 Continuous Monitoring[/bold blue]")
    console.print(f"Interval: {interval}s, Duration: {duration}s")
    console.print()
    
    asyncio.run(_continuous_monitoring(interval, duration))

@app.command()
def report(
    input_file: str = typer.Argument(..., help="Input test results file"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: html, pdf"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file")
):
    """Generate detailed test report."""
    try:
        with open(input_file, 'r') as f:
            results = json.load(f)
        
        if format == "html":
            _generate_html_report(results, output)
        elif format == "pdf":
            _generate_pdf_report(results, output)
        
        console.print(f"[green]Report generated: {output or 'report.' + format}[/green]")
        
    except FileNotFoundError:
        console.print(f"[red]Error: File '{input_file}' not found[/red]")
        raise typer.Exit(1)
    except json.JSONDecodeError:
        console.print(f"[red]Error: Invalid JSON in '{input_file}'[/red]")
        raise typer.Exit(1)

async def _run_single_suite(suite_name: str, verbose: bool = False, timeout: Optional[int] = None, repeat: int = 1):
    """Run a single test suite."""
    if timeout:
        test_framework.test_suites[suite_name].timeout = timeout
    
    total_results = []
    
    for run in range(repeat):
        if repeat > 1:
            console.print(f"\n[bold]Run {run + 1}/{repeat}[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(f"Running {suite_name} tests...", total=None)
            
            results = await test_framework.run_suite(suite_name)
            total_results.extend(results)
            
            progress.update(task, completed=True)
        
        if verbose:
            _display_suite_results(suite_name, results)
    
    return total_results

async def _run_all_suites(verbose: bool = False, timeout: Optional[int] = None, repeat: int = 1):
    """Run all test suites."""
    all_results = {}
    
    for run in range(repeat):
        if repeat > 1:
            console.print(f"\n[bold]Run {run + 1}/{repeat}[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            for suite_name in test_framework.test_suites.keys():
                if timeout:
                    test_framework.test_suites[suite_name].timeout = timeout
                
                task = progress.add_task(f"Running {suite_name}...", total=None)
                
                results = await test_framework.run_suite(suite_name)
                
                if suite_name not in all_results:
                    all_results[suite_name] = []
                all_results[suite_name].extend(results)
                
                progress.update(task, completed=True)
                
                if verbose:
                    _display_suite_results(suite_name, results)
    
    return all_results

async def _run_performance_test(duration: int, concurrent: int, ramp_up: int):
    """Run performance tests."""
    # This would implement actual performance testing
    console.print("[yellow]Performance testing not yet implemented[/yellow]")

async def _continuous_monitoring(interval: int, duration: int):
    """Continuous monitoring."""
    start_time = asyncio.get_event_loop().time()
    end_time = start_time + duration
    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    
    with Live(layout, refresh_per_second=1, screen=True):
        while asyncio.get_event_loop().time() < end_time:
            # Update header
            elapsed = int(asyncio.get_event_loop().time() - start_time)
            remaining = duration - elapsed
            layout["header"].update(Panel(f"Monitoring - Elapsed: {elapsed}s, Remaining: {remaining}s"))
            
            # Run health check
            try:
                await test_framework.setup_session()
                await test_framework.test_api_health()
                status = "[green]Healthy[/green]"
            except Exception as e:
                status = f"[red]Unhealthy: {e}[/red]"
            finally:
                await test_framework.teardown_session()
            
            # Update body
            layout["body"].update(Panel(f"API Status: {status}"))
            
            # Update footer
            layout["footer"].update(Panel("Press Ctrl+C to stop"))
            
            await asyncio.sleep(interval)

def _display_suite_results(suite_name: str, results: List[TestResult]):
    """Display results for a single suite."""
    table = Table(title=f"Results for {suite_name}")
    table.add_column("Test", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Duration", justify="right", style="yellow")
    table.add_column("Message", style="white")
    
    for result in results:
        status_style = "green" if result.passed else "red"
        status_text = f"[{status_style}]{result.status.upper()}[/{status_style}]"
        
        table.add_row(
            result.test_name,
            status_text,
            f"{result.duration:.2f}s",
            result.message[:50] + "..." if len(result.message) > 50 else result.message
        )
    
    console.print(table)
    console.print()

def _display_results_table(results: Dict, verbose: bool = False):
    """Display results in table format."""
    summary = results["summary"]
    
    # Summary panel
    summary_text = f"""
Total Tests: {summary['total_tests']}
Passed: [green]{summary['passed']}[/green]
Failed: [red]{summary['failed']}[/red]
Success Rate: {summary['success_rate']:.1f}%
Duration: {summary['total_duration']:.2f}s
    """
    
    console.print(Panel(summary_text.strip(), title="Test Summary", border_style="blue"))
    
    # Suite results table
    table = Table(title="Suite Results")
    table.add_column("Suite", style="cyan")
    table.add_column("Total", justify="center", style="white")
    table.add_column("Passed", justify="center", style="green")
    table.add_column("Failed", justify="center", style="red")
    table.add_column("Success Rate", justify="center", style="yellow")
    table.add_column("Duration", justify="right", style="magenta")
    
    for suite_name, suite_data in results["suites"].items():
        table.add_row(
            suite_name,
            str(suite_data["total"]),
            str(suite_data["passed"]),
            str(suite_data["failed"]),
            f"{suite_data['success_rate']:.1f}%",
            f"{suite_data['duration']:.2f}s"
        )
    
    console.print(table)
    
    # Detailed results if verbose
    if verbose:
        for suite_name, suite_data in results["suites"].items():
            if suite_data["failed"] > 0:
                console.print(f"\n[bold red]Failed tests in {suite_name}:[/bold red]")
                for test in suite_data["tests"]:
                    if test["status"] == "failed":
                        console.print(f"  ❌ {test['name']}: {test['message']}")

def _display_results_json(results: Dict):
    """Display results in JSON format."""
    console.print(json.dumps(results, indent=2))

def _display_results_html(results: Dict):
    """Display results in HTML format."""
    console.print("[yellow]HTML format display not implemented[/yellow]")

def _save_results(results: Dict, output: str, format: str):
    """Save results to file."""
    output_path = Path(output)
    
    if format == "json":
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
    elif format == "html":
        _generate_html_report(results, str(output_path))
    
    console.print(f"[green]Results saved to: {output_path}[/green]")

def _generate_html_report(results: Dict, output: Optional[str] = None):
    """Generate HTML report."""
    if not output:
        output = "test_report.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .passed {{ color: green; }}
            .failed {{ color: red; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Enhanced Chat API Test Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>Total Tests: {results['summary']['total_tests']}</p>
            <p>Passed: <span class="passed">{results['summary']['passed']}</span></p>
            <p>Failed: <span class="failed">{results['summary']['failed']}</span></p>
            <p>Success Rate: {results['summary']['success_rate']:.1f}%</p>
            <p>Duration: {results['summary']['total_duration']:.2f}s</p>
        </div>
        
        <h2>Suite Results</h2>
        <table>
            <tr>
                <th>Suite</th>
                <th>Total</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Success Rate</th>
                <th>Duration</th>
            </tr>
    """
    
    for suite_name, suite_data in results["suites"].items():
        html_content += f"""
            <tr>
                <td>{suite_name}</td>
                <td>{suite_data['total']}</td>
                <td class="passed">{suite_data['passed']}</td>
                <td class="failed">{suite_data['failed']}</td>
                <td>{suite_data['success_rate']:.1f}%</td>
                <td>{suite_data['duration']:.2f}s</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(output, 'w') as f:
        f.write(html_content)

def _generate_pdf_report(results: Dict, output: Optional[str] = None):
    """Generate PDF report."""
    console.print("[yellow]PDF report generation not implemented[/yellow]")

if __name__ == "__main__":
    app()
