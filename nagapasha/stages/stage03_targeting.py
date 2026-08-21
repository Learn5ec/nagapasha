"""Stage 3 — Targeting (human checkpoint).

Presents the parameter list to the user and lets them include/exclude
parameters as fuzz targets. Returns an updated RequestModel with
``parameters[].is_fuzz_target`` set by the user.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from nagapasha.models.request_model import ParameterModel, RequestModel


console = Console()


def run_targeting(
    request_model: RequestModel,
    auto: bool = False,
) -> RequestModel:
    """Run the targeting checkpoint.

    Args:
        request_model: RequestModel from Stage 2 recon.
        auto: If True, fuzz all non-auth, non-flaky parameters automatically.

    Returns:
        Updated RequestModel with is_fuzz_target set.
    """
    parameters = request_model.parameters

    if not parameters:
        console.print("[yellow]No parameters detected — nothing to target.[/yellow]")
        return request_model

    if auto:
        return _auto_target(request_model)

    console.print("\n[bold]Stage 3: Targeting[/bold]")
    console.print("Select which parameters to fuzz:\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Name", style="bold")
    table.add_column("Location")
    table.add_column("Type")
    table.add_column("Value", max_width=40)
    table.add_column("Auth?", style="yellow")
    table.add_column("Default", style="dim")
    table.add_column("Fuzz?", style="green")

    for idx, param in enumerate(parameters):
        auth = "[red]yes[/red]" if param.do_not_fuzz else "[dim]no[/dim]"
        default_fuzz = "[yellow]auto[/yellow]" if param.do_not_fuzz else "[green]yes[/green]"
        table.add_row(
            str(idx + 1),
            param.name,
            param.location,
            param.inferred_type,
            param.raw_value[:37] + ("..." if len(param.raw_value) > 37 else ""),
            auth,
            default_fuzz,
            "[dim]—[/dim]",
        )

    console.print(table)

    # Ask user which to fuzz
    console.print(
        "\nType indices to fuzz (e.g. '1 3 5'), 'all', or 'none':"
    )
    try:
        answer = Prompt.ask("Target", default="all")
    except (EOFError, KeyboardInterrupt):
        console.print("[yellow]No input received — fuzzing all eligible parameters.[/yellow]")
        return _auto_target(request_model)

    if answer.strip().lower() in ("all", "a", "yes", "y"):
        return _auto_target(request_model)
    elif answer.strip().lower() in ("none", "n", "no"):
        return request_model

    # Parse indices
    try:
        indices = [int(x) - 1 for x in answer.split()]
        for i in indices:
            if 0 <= i < len(parameters):
                parameters[i].is_fuzz_target = True
                parameters[i].do_not_fuzz = False
    except ValueError:
        console.print("[yellow]Invalid input — fuzzing all eligible parameters.[/yellow]")
        return _auto_target(request_model)

    return request_model


def _auto_target(request_model: RequestModel) -> RequestModel:
    """Auto-select: fuzz all non-auth, non-flaky parameters."""
    for param in request_model.parameters:
        if param.do_not_fuzz:
            continue
        param.is_fuzz_target = True
        param.do_not_fuzz = False

    count = sum(1 for p in request_model.parameters if p.is_fuzz_target)
    console.print(f"\n[green]Auto-targeted {count} parameter(s):[/green]")
    for p in request_model.parameters:
        if p.is_fuzz_target:
            console.print(f"  [green]+[/green] {p.name} ({p.location})")
        else:
            console.print(f"  [dim]-[/dim] {p.name} ({p.location}) [dim]excluded[/dim]")

    return request_model
