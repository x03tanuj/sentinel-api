"""Command line interface for SentinelAPI scanner tools."""

import argparse
import asyncio
import sys

from rich.console import Console

from app.parser.describe import describe_surface, summarize
from app.parser.openapi_loader import SpecLoadError, SpecValidationError, load_spec, resolve_and_validate
from app.parser.risk_prioritizer import prioritize
from app.parser.surface_mapper import build_attack_surface


async def execute_surface(spec_source: str) -> int:
    """Load, parse, prioritize, and display attack surface for a target spec."""
    console = Console()
    try:
        raw_spec = await load_spec(spec_source)
        resolved_spec = resolve_and_validate(raw_spec)
        endpoints = build_attack_surface(resolved_spec)
        prioritized = prioritize(endpoints)

        # Render rich table
        table_output = describe_surface(prioritized)
        console.print(table_output)

        # Render summary metrics
        counts = summarize(prioritized)
        console.print(
            f"[bold cyan]Surface Summary:[/bold cyan] "
            f"Total: [bold white]{counts['total']}[/bold white] | "
            f"Auth Required: [bold green]{counts['auth_required']}[/bold green] | "
            f"Object Level: [bold yellow]{counts['object_level']}[/bold yellow] | "
            f"Privileged: [bold red]{counts['privileged']}[/bold red] | "
            f"Public: [bold blue]{counts['public']}[/bold blue]\n"
        )
        return 0
    except (SpecLoadError, SpecValidationError) as exc:
        console.print(f"[bold red]Specification Error:[/bold red] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        console.print(f"[bold red]Unexpected Error:[/bold red] {exc}", file=sys.stderr)
        return 2


def main() -> None:
    """Entry point for CLI commands."""
    parser = argparse.ArgumentParser(
        prog="sentinelapi",
        description="SentinelAPI Security Scanner CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: surface
    surface_parser = subparsers.add_parser(
        "surface",
        help="Analyze OpenAPI specification and map prioritized attack surface",
    )
    surface_parser.add_argument(
        "--spec",
        required=True,
        help="Local file path or allow-listed URL to OpenAPI specification",
    )

    args = parser.parse_args()

    if args.command == "surface":
        exit_code = asyncio.run(execute_surface(args.spec))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
