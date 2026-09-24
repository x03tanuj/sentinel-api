"""Command line interface for SentinelAPI scanner tools."""

import argparse
import asyncio
import json
from pathlib import Path
import sys
import time
from typing import Any

from pydantic import SecretStr
from rich.console import Console
from rich.table import Table

from app.config import get_settings
from app.engine.auth_matrix import build_matrix, render_matrix
from app.engine.checks import CHECKS, run_checks_with_reproduction
from app.engine.context import ScanContext
from app.engine.discovery import discover_ownership
from app.engine.http_executor import Executor
from app.engine.identity import IdentityConfig, IdentityManager
from app.engine.test_generator import TestCategory, generate_all
from app.models import Finding, Severity
from app.parser.describe import describe_surface, summarize
from app.parser.openapi_loader import SpecLoadError, SpecValidationError, load_spec, resolve_and_validate
from app.parser.risk_prioritizer import prioritize
from app.parser.surface_mapper import build_attack_surface

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim white",
}


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
    """Authenticate configured identities, verify permissions via profile endpoint, and display identity status."""
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


async def execute_plan(
    spec_source: str,
    base_url: str,
    identity_specs: list[str],
    budget: int = 150,
) -> int:
    """Execute complete test planning pipeline: spec load -> discovery -> matrix -> test case generation."""
    console = Console()
    try:
        raw_spec = await load_spec(spec_source)
        resolved_spec = resolve_and_validate(raw_spec)
        endpoints = build_attack_surface(resolved_spec)

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

            identities = await mgr.login_all(configs)
            owned = await discover_ownership(endpoints, identities, executor, base_url=base_url)
            matrix_cells = build_matrix(owned, identities)
            res = generate_all(endpoints, identities, owned, matrix_cells, budget=budget)
            cases, stats = res.cases, res.stats

            matrix_table_str = render_matrix(matrix_cells, identities)
            console.print(matrix_table_str)

            summary_table = Table(
                title="SentinelAPI Test Generation Plan",
                show_lines=True,
                header_style="bold cyan",
            )
            summary_table.add_column("CATEGORY", style="bold white", justify="left")
            summary_table.add_column("GENERATED", style="yellow", justify="center")
            summary_table.add_column("KEPT (BUDGETED)", style="green", justify="center")

            for cat in TestCategory:
                gen_cnt = stats["generated"].get(cat.value, 0)
                kept_cnt = stats["kept"].get(cat.value, 0)
                summary_table.add_row(cat.value, str(gen_cnt), str(kept_cnt))

            summary_table.add_row(
                "[bold]TOTAL[/bold]",
                f"[bold yellow]{stats['total_generated']}[/bold yellow]",
                f"[bold green]{stats['total_kept']}[/bold green]",
            )
            console.print(summary_table)

            console.print(
                f"[bold cyan]Plan Budget Allocation:[/bold cyan] "
                f"Generated: [bold yellow]{stats['total_generated']}[/bold yellow] | "
                f"Capped to Budget: [bold green]{stats['total_kept']}[/bold green] / {budget}\n"
            )
            return 0
    except Exception as exc:
        console.print(f"[bold red]Plan Execution Error:[/bold red] {exc}", file=sys.stderr)
        return 1


async def execute_scan(
    spec_source: str,
    base_url: str,
    identity_specs: list[str],
    budget: int = 150,
    sample_body_specs: list[str] | None = None,
    checks_filter: str | None = None,
    json_out: str | None = None,
) -> int:
    """Execute complete security scan pipeline with differential analysis and modular checks."""
    console = Console()
    err_console = Console(stderr=True)
    settings = get_settings()

    # 1. Parse sample bodies
    sample_bodies: dict[str, dict[str, Any]] = {}
    if sample_body_specs:
        for item in sample_body_specs:
            if "=" in item:
                resource_name, raw_json = item.split("=", 1)
                try:
                    sample_bodies[resource_name.strip()] = json.loads(raw_json)
                except Exception as exc:
                    console.print(
                        f"[bold red]Invalid sample body JSON for '{resource_name}':[/bold red] {exc}",
                        file=sys.stderr,
                    )
                    return 1

    # 2. Parse enabled checks
    enabled_checks: list[str] | None = None
    if checks_filter:
        enabled_checks = [c.strip() for c in checks_filter.split(",") if c.strip()]

    try:
        # 3. Load specification and compute attack surface
        raw_spec = await load_spec(spec_source)
        resolved_spec = resolve_and_validate(raw_spec)
        endpoints = build_attack_surface(resolved_spec)

        # 4. Initialize executor and authenticate personas
        async with Executor(settings=settings) as executor:
            mgr = IdentityManager(base_url=base_url, executor=executor)
            configs: list[IdentityConfig] = []
            for spec in identity_specs:
                parts = [p.strip() for p in spec.split(",")]
                if len(parts) < 4:
                    err_console.print(
                        f"[bold red]Invalid identity format:[/bold red] '{spec}'. Expected: name,role,username,password"
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

            identities = await mgr.login_all(configs)

            # 5. Discover ownership, construct matrix, and generate test cases
            owned = await discover_ownership(endpoints, identities, executor, base_url=base_url)
            matrix_cells = build_matrix(owned, identities)
            test_gen_res = generate_all(endpoints, identities, owned, matrix_cells, budget=budget)
            cases = test_gen_res.cases

            # 6. Build execution context
            ctx = ScanContext(
                base_url=base_url,
                endpoints=endpoints,
                identity_manager=mgr,
                owned=owned,
                matrix_cells=matrix_cells,
                cases=cases,
                executor=executor,
                settings=settings,
                sample_bodies=sample_bodies,
            )

            # 7. Execute security check modules with empirical reproduction
            start_time = time.monotonic()
            findings = await run_checks_with_reproduction(ctx, enabled=enabled_checks)
            elapsed_secs = time.monotonic() - start_time

            # 8. Sort findings by severity and confidence
            findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence))

            # 9. Render findings table
            table = Table(
                title="SentinelAPI Security Vulnerability Findings",
                show_lines=True,
                header_style="bold cyan",
            )
            table.add_column("SEVERITY", style="bold", justify="center")
            table.add_column("CONFIDENCE", justify="center")
            table.add_column("CHECK", justify="left")
            table.add_column("METHOD + PATH", justify="left")
            table.add_column("ATTACKER IDENTITY", justify="center")
            table.add_column("TITLE", justify="left")

            for f in findings:
                sev_style = SEVERITY_COLORS.get(f.severity, "white")
                attacker = f.evidence.identity if (f.evidence and f.evidence.identity) else "-"
                conf_str = f"{f.confidence:.2f}"
                table.add_row(
                    f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                    conf_str,
                    f.check,
                    f"{f.method} {f.endpoint}",
                    attacker,
                    f.title,
                )
            console.print(table)

            # 10. Render per-check count summary
            summary_table = Table(
                title="Security Checks Summary",
                show_lines=True,
                header_style="bold cyan",
            )
            summary_table.add_column("CHECK", style="bold white", justify="left")
            summary_table.add_column("FINDINGS COUNT", justify="center")

            check_counts: dict[str, int] = {}
            for f in findings:
                check_counts[f.check] = check_counts.get(f.check, 0) + 1

            for chk_name in sorted(CHECKS.keys()):
                if enabled_checks is None or chk_name in enabled_checks:
                    cnt = check_counts.get(chk_name, 0)
                    cnt_style = "bold red" if cnt > 0 else "green"
                    summary_table.add_row(chk_name, f"[{cnt_style}]{cnt}[/{cnt_style}]")

            console.print(summary_table)

            # 11. Render reproduction summary
            reproduced_count = sum(
                1 for f in findings
                if f.evidence and f.evidence.response_diff.get("reproduction", {}).get("reproduced", 0) > 0
            )
            downgraded_count = sum(
                1 for f in findings
                if f.evidence and f.evidence.response_diff.get("downgraded") is True
            )
            attempted_count = sum(
                1 for f in findings
                if f.evidence and "reproduction" in f.evidence.response_diff
            )
            skipped_count = len(findings) - attempted_count

            console.print("\n[bold cyan]Vulnerability Reproduction Summary:[/bold cyan]")
            console.print(
                f" • Verified & Reproduced: [bold green]{reproduced_count}[/bold green]\n"
                f" • Failed / Downgraded: [bold red]{downgraded_count}[/bold red]\n"
                f" • Skipped (top_n cap): [bold yellow]{skipped_count}[/bold yellow]"
            )

            # 12. Render context notes (skipped tests & errors)
            if ctx.notes:
                console.print("\n[bold yellow]Scan Execution Notes:[/bold yellow]")
                for note in ctx.notes:
                    console.print(f" • [dim yellow]{note}[/dim yellow]")

            # 13. Execution metrics
            console.print(
                f"\n[bold cyan]Scan Execution Metrics:[/bold cyan] "
                f"Requests Sent: [bold white]{executor.requests_sent}[/bold white] / Budget: [bold white]{budget}[/bold white] | "
                f"Elapsed: [bold white]{elapsed_secs:.2f}s[/bold white]"
            )

            # Clear FINDINGS count line
            console.print(f"\n[bold white]FINDINGS: {len(findings)}[/bold white]\n")

            # 14. Write JSON output if requested
            if json_out:
                data = [f.to_dict() for f in findings]
                with open(json_out, "w", encoding="utf-8") as fp:
                    json.dump(data, fp, indent=2)
                console.print(f"[bold green]Exported {len(findings)} findings to:[/bold green] {json_out}\n")

            return 0

    except Exception as exc:
        err_console.print(f"[bold red]Scan Execution Error:[/bold red] {exc}")
        return 0


def execute_report(json_in: str) -> int:
    """Load findings JSON and render rich findings table plus explainable risk breakdown."""
    console = Console()
    err_console = Console(stderr=True)
    in_path = Path(json_in)
    if not in_path.exists():
        err_console.print(f"[bold red]File not found:[/bold red] {json_in}")
        return 1

    try:
        with open(in_path, encoding="utf-8") as fp:
            data = json.load(fp)
    except Exception as exc:
        err_console.print(f"[bold red]Failed to read JSON file:[/bold red] {exc}")
        return 1

    if not isinstance(data, list):
        err_console.print("[bold red]Expected a list of findings in JSON file[/bold red]")
        return 1

    # Sort data by severity and confidence
    def _sort_key(item: dict[str, Any]) -> tuple[int, float]:
        sev_str = item.get("severity", "INFO")
        try:
            sev = Severity(sev_str)
            order = SEVERITY_ORDER.get(sev, 99)
        except Exception:
            order = 99
        conf = float(item.get("confidence", 0.0))
        return (order, -conf)

    data.sort(key=_sort_key)

    # 1. Findings table
    table = Table(
        title="SentinelAPI Security Vulnerability Findings",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("SEVERITY", style="bold", justify="center")
    table.add_column("CONFIDENCE", justify="center")
    table.add_column("CHECK", justify="left")
    table.add_column("METHOD + PATH", justify="left")
    table.add_column("ATTACKER IDENTITY", justify="center")
    table.add_column("TITLE", justify="left")

    for f in data:
        sev_str = f.get("severity", "INFO")
        try:
            sev = Severity(sev_str)
            sev_style = SEVERITY_COLORS.get(sev, "white")
        except Exception:
            sev_style = "white"

        conf = float(f.get("confidence", 0.0))
        evidence = f.get("evidence") or {}
        attacker = evidence.get("identity") or "-"

        table.add_row(
            f"[{sev_style}]{sev_str}[/{sev_style}]",
            f"{conf:.2f}",
            str(f.get("check", "-")),
            f"{f.get('method', '')} {f.get('endpoint', '')}",
            attacker,
            str(f.get("title", "")),
        )
    console.print(table)

    # 2. Risk breakdown table (Explainable severity)
    breakdown_table = Table(
        title="Explainable Risk Score Breakdown (Why This Severity)",
        show_lines=True,
        header_style="bold magenta",
    )
    breakdown_table.add_column("SEVERITY", style="bold", justify="center")
    breakdown_table.add_column("TITLE / ENDPOINT", justify="left")
    breakdown_table.add_column("RISK SCORE", justify="center", style="bold white")
    breakdown_table.add_column("IMPACT (0-40)", justify="center")
    breakdown_table.add_column("EXPLOIT (0-25)", justify="center")
    breakdown_table.add_column("SENSITIVITY (0-30)", justify="center")
    breakdown_table.add_column("EVIDENCE (0-15)", justify="center")
    breakdown_table.add_column("REPRODUCED?", justify="center")

    for f in data:
        sev_str = f.get("severity", "INFO")
        try:
            sev = Severity(sev_str)
            sev_style = SEVERITY_COLORS.get(sev, "white")
        except Exception:
            sev_style = "white"

        evidence = f.get("evidence") or {}
        resp_diff = evidence.get("response_diff") or {}
        total_score = resp_diff.get("risk_score", "-")
        breakdown = resp_diff.get("risk_breakdown") or {}
        impact = breakdown.get("impact", "-")
        exploit = breakdown.get("exploitability", "-")
        sens = breakdown.get("sensitivity", "-")
        evid = breakdown.get("evidence_strength", "-")

        repro_info = resp_diff.get("reproduction")
        if repro_info:
            repro_str = f"[green]Yes ({repro_info.get('reproduced', 0)}/{repro_info.get('attempts', 0)})[/green]"
            if resp_diff.get("downgraded"):
                repro_str = "[red]Failed (Downgraded)[/red]"
        else:
            repro_str = "[dim]Skipped[/dim]"

        breakdown_table.add_row(
            f"[{sev_style}]{sev_str}[/{sev_style}]",
            f"[bold]{f.get('title', '')}[/bold]\n[dim]{f.get('method', '')} {f.get('endpoint', '')}[/dim]",
            f"[{sev_style}]{total_score}[/{sev_style}]",
            str(impact),
            str(exploit),
            str(sens),
            str(evid),
            repro_str,
        )

    console.print(breakdown_table)
    console.print(f"\n[bold white]TOTAL FINDINGS REPORTED: {len(data)}[/bold white]\n")
    return 0


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

    # Subcommand: plan
    plan_parser = subparsers.add_parser(
        "plan",
        help="Execute discovery, build authorization matrix, and generate budgeted test plan",
    )
    plan_parser.add_argument(
        "--spec",
        required=True,
        help="Local file path or allow-listed URL to OpenAPI specification",
    )
    plan_parser.add_argument(
        "--base-url",
        required=True,
        help="Target base URL (e.g. http://localhost:9000)",
    )
    plan_parser.add_argument(
        "--identity",
        action="append",
        required=True,
        help="Identity in format: name,role,username,password (repeatable)",
    )
    plan_parser.add_argument(
        "--budget",
        type=int,
        default=150,
        help="Maximum test case execution budget (default: 150)",
    )

    # Subcommand: scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Execute automated authorization and security vulnerability scan",
    )
    scan_parser.add_argument(
        "--spec",
        required=True,
        help="Local file path or allow-listed URL to OpenAPI specification",
    )
    scan_parser.add_argument(
        "--base-url",
        required=True,
        help="Target API base URL (e.g. http://localhost:9000)",
    )
    scan_parser.add_argument(
        "--identity",
        action="append",
        required=True,
        help="Identity in format: name,role,username,password (repeatable)",
    )
    scan_parser.add_argument(
        "--budget",
        type=int,
        default=150,
        help="Maximum test case execution budget (default: 150)",
    )
    scan_parser.add_argument(
        "--sample-body",
        action="append",
        default=[],
        help="Sample JSON body for resource creation: resource=JSON (repeatable)",
    )
    scan_parser.add_argument(
        "--checks",
        default=None,
        help="Comma-separated list of check modules to run (e.g. bola,bfla,data_exposure)",
    )
    scan_parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to export redacted findings JSON",
    )

    # Subcommand: report
    report_parser = subparsers.add_parser(
        "report",
        help="Display vulnerability findings and explainable risk breakdown from JSON",
    )
    report_parser.add_argument(
        "--json-in",
        required=True,
        help="Path to exported findings JSON file",
    )

    args = parser.parse_args()

    if args.command == "surface":
        exit_code = asyncio.run(execute_surface(args.spec))
        sys.exit(exit_code)
    elif args.command == "whoami":
        exit_code = asyncio.run(execute_whoami(args.base_url, args.identity, args.me_path))
        sys.exit(exit_code)
    elif args.command == "plan":
        exit_code = asyncio.run(execute_plan(args.spec, args.base_url, args.identity, args.budget))
        sys.exit(exit_code)
    elif args.command == "scan":
        exit_code = asyncio.run(
            execute_scan(
                spec_source=args.spec,
                base_url=args.base_url,
                identity_specs=args.identity,
                budget=args.budget,
                sample_body_specs=args.sample_body,
                checks_filter=args.checks,
                json_out=args.json_out,
            )
        )
        sys.exit(exit_code)
    elif args.command == "report":
        exit_code = execute_report(args.json_in)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
