"""Command line interface for SentinelAPI scanner tools."""

import argparse
import asyncio
import sys

from pydantic import SecretStr
from rich.console import Console
from rich.table import Table

from app.engine.http_executor import Executor
from app.engine.identity import IdentityConfig, IdentityManager
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


async def execute_whoami(base_url: str, identity_specs: list[str], me_path: str = "/users/me") -> int:
    """Authenticate configured identities, verify permissions via profile endpoint, and display identity status.

    Note:
        Passing plaintext passwords via CLI arguments is strictly intended for sandboxed
        demo and testing environments. In production, load credentials via secure environment
        variables or a secret management store.
    """
    console = Console()
    try:
        async with Executor() as executor:
            mgr = IdentityManager(base_url=base_url, executor=executor)
            configs: list[IdentityConfig] = []
            for spec in identity_specs:
                parts = [p.strip() for p in spec.split(",")]
                if len(parts) < 4:
                    console.print(
                        f"[bold red]Invalid identity format:[/bold red] '{spec}'. Expected: name,role,username,password",
                        file=sys.stderr,
                    )
                    return 1
                configs.append(
                    IdentityConfig(
                        name=parts[0],
                        role=parts[1],
                        username=parts[2],
                        password=SecretStr(parts[3]),
                    )
                )

            # Authenticate all requested identities
            logged_in = await mgr.login_all(configs)

            # Query profile path with each authenticated identity
            results = []
            user_ids: list[str] = []
            for ident in logged_in:
                clean_base = base_url.rstrip("/")
                clean_path = "/" + me_path.lstrip("/")
                url = f"{clean_base}{clean_path}"
                _, resp_rec = await executor.execute("GET", url, identity=ident)
                results.append((ident, resp_rec.status))
                if ident.user_id is not None:
                    user_ids.append(str(ident.user_id))

            # Determine whether multiple identities resolved to distinct user accounts
            distinct_users = len(set(user_ids)) > 1 if len(logged_in) > 1 else True

            table = Table(
                title="SentinelAPI Whoami Identity Verification",
                show_lines=True,
                header_style="bold cyan",
            )
            table.add_column("IDENTITY", style="white", justify="left")
            table.add_column("ROLE IN TOKEN", style="yellow", justify="center")
            table.add_column("USER_ID", style="green", justify="center")
            table.add_column("STATUS", style="white", justify="center")
            table.add_column("DIFFERENT USERS", style="magenta", justify="center")

            for i, (ident, status) in enumerate(results):
                status_color = "green" if status == 200 else "red"
                diff_label = "YES" if distinct_users else "NO"
                table.add_row(
                    ident.name,
                    ident.role,
                    str(ident.user_id) if ident.user_id is not None else "-",
                    f"[{status_color}]{status}[/{status_color}]",
                    diff_label if i == 0 else "",
                )

            console.print(table)
            if not distinct_users and len(logged_in) > 1:
                console.print(
                    "[bold yellow]Warning:[/bold yellow] All authenticated personas resolved to the same user_id."
                )
            return 0
    except Exception as exc:
        console.print(f"[bold red]Whoami Execution Error:[/bold red] {exc}", file=sys.stderr)
        return 1


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

    # Subcommand: whoami
    whoami_parser = subparsers.add_parser(
        "whoami",
        help="Authenticate identities and verify permission separation",
    )
    whoami_parser.add_argument(
        "--base-url",
        required=True,
        help="Target base URL (e.g. http://localhost:9000)",
    )
    whoami_parser.add_argument(
        "--identity",
        action="append",
        required=True,
        help="Identity in format: name,role,username,password (repeatable)",
    )
    whoami_parser.add_argument(
        "--me-path",
        default="/users/me",
        help="Endpoint path to probe identity profile (default: /users/me)",
    )

    args = parser.parse_args()

    if args.command == "surface":
        exit_code = asyncio.run(execute_surface(args.spec))
        sys.exit(exit_code)
    elif args.command == "whoami":
        exit_code = asyncio.run(execute_whoami(args.base_url, args.identity, args.me_path))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
