"""Visual presentation and statistical summary utilities for attack surfaces."""

import io
from typing import Any

from rich.console import Console
from rich.table import Table

from app.models import Endpoint
from app.parser.risk_prioritizer import score_endpoint


def describe_surface(endpoints: list[Endpoint]) -> str:
    """Render a clean text table of discovered endpoints formatted with rich.

    Columns: METHOD, PATH, AUTH, OBJECT, PRIV, RESOURCE, SCORE.
    """
    table = Table(
        title="SentinelAPI Attack Surface Mapping",
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )

    table.add_column("METHOD", style="bold", width=8)
    table.add_column("PATH", style="white", min_width=25)
    table.add_column("AUTH", justify="center", width=6)
    table.add_column("OBJECT", justify="center", width=8)
    table.add_column("PRIV", justify="center", width=6)
    table.add_column("RESOURCE", style="magenta", width=12)
    table.add_column("SCORE", justify="right", style="green", width=7)

    for ep in endpoints:
        score = score_endpoint(ep)
        score_str = f"+{score}" if score > 0 else str(score)

        method_style = {
            "GET": "[cyan]GET[/cyan]",
            "POST": "[green]POST[/green]",
            "PUT": "[yellow]PUT[/yellow]",
            "PATCH": "[yellow]PATCH[/yellow]",
            "DELETE": "[red]DELETE[/red]",
        }.get(ep.method, ep.method)

        auth_str = "[green]YES[/green]" if ep.requires_auth else "[dim]NO[/dim]"
        obj_str = "[yellow]YES[/yellow]" if ep.is_object_level else "[dim]NO[/dim]"
        priv_str = "[red]YES[/red]" if ep.is_privileged else "[dim]NO[/dim]"
        res_str = ep.resource or "[dim]-[/dim]"

        table.add_row(
            method_style,
            ep.path,
            auth_str,
            obj_str,
            priv_str,
            res_str,
            score_str,
        )

    output = io.StringIO()
    console = Console(file=output, force_terminal=True, width=110)
    console.print(table)
    return output.getvalue()


def summarize(endpoints: list[Endpoint]) -> dict[str, int]:
    """Calculate summary metric counts for discovered endpoints."""
    return {
        "total": len(endpoints),
        "auth_required": sum(1 for e in endpoints if e.requires_auth),
        "object_level": sum(1 for e in endpoints if e.is_object_level),
        "privileged": sum(1 for e in endpoints if e.is_privileged),
        "public": sum(1 for e in endpoints if not e.requires_auth),
    }
