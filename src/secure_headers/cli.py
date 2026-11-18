import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

try:  # works when run as a package: python -m secure_headers.cli
    from .scanner import fetch_headers
    from .analyzer import analyze_headers
    from .scoring import calculate_score
    from .generator import generate_nginx_config, generate_apache_config
    from .report import save_reports
except ImportError:  # works when run directly: python src/secure_headers/cli.py
    from scanner import fetch_headers
    from analyzer import analyze_headers
    from scoring import calculate_score
    from generator import generate_nginx_config, generate_apache_config
    from report import save_reports

app = typer.Typer()
console = Console()


@app.command()
def main(url: str):
    """Scan a website for security headers"""
    console.print(f"\n[cyan]Scanning:[/cyan] {escape(url)}\n")

    result = fetch_headers(url)

    if not result.get("success"):
        console.print(f"[red]Error:[/red] {escape(str(result.get('error')))}")
        raise typer.Exit(code=1)  # non-zero exit code so scripts/CI can detect failure

    # Analyze + Score
    analysis = analyze_headers(result["headers"])
    score_data = calculate_score(analysis)

    grade = score_data["grade"]
    score = score_data["score"]

    if grade in ["A+", "A"]:
        color = "green"
    elif grade in ["B", "C"]:
        color = "yellow"
    else:
        color = "red"

    # Show Grade
    console.print(Panel(
        f"[bold {color}]Grade: {grade}    Score: {score}/100[/bold {color}]",
        title="Final Result"
    ))

    # Show Analysis Table
    table = Table(title="Security Headers Analysis")
    table.add_column("Header", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Details")

    for key, data in analysis.items():
        status = data["status"]

        if status in ["Good", "Present"]:
            status_text = f"[green]{status}[/green]"
        elif status == "Weak":
            status_text = f"[yellow]{status}[/yellow]"
        else:
            status_text = f"[red]{status}[/red]"

        # Messages can contain text from the scanned site, so escape rich markup
        table.add_row(
            key.replace("_", "-").title(),
            status_text,
            escape(data["message"])
        )

    console.print(table)
    console.print(f"\n[green]Final URL:[/green] {escape(result['url'])}\n")

    # Generate Configs
    nginx_config = generate_nginx_config(analysis)
    apache_config = generate_apache_config(analysis)

    console.print(Panel("[bold]Nginx Configuration[/bold]", subtitle="Copy and paste into your server block"))
    console.print(Syntax(nginx_config, "nginx", theme="monokai", line_numbers=False))
    console.print()

    console.print(Panel("[bold]Apache Configuration[/bold]", subtitle="Copy and paste into .htaccess or VirtualHost"))
    console.print(Syntax(apache_config, "apache", theme="monokai", line_numbers=False))
    console.print()

    # Save reports (HTML + TXT)
    html_path, txt_path = save_reports(
        url=url,
        analysis=analysis,
        score_data=score_data,
        final_url=result["url"],
        nginx_config=nginx_config,
        apache_config=apache_config
    )

    console.print(f"[bold green]✓ HTML report saved:[/bold green] {escape(html_path)}")
    console.print(f"[bold green]✓ Text report saved:[/bold green] {escape(txt_path)}")


if __name__ == "__main__":
    app()
