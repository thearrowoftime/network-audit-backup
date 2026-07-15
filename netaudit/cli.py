"""CLI for Network Audit and Config Backup."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from netaudit import __version__
from netaudit.audit import (
    audit_config,
    infer_platform_from_config,
    load_rules,
    summarize_findings,
)
from netaudit.diff import diff_backups, format_diff_markdown
from netaudit.export import (
    export_diff_csv,
    export_diff_markdown,
    export_findings_csv,
    export_findings_markdown,
)
from netaudit.inventory import load_inventory, platform_for_device, save_inventory_template
from netaudit.ssh_backup import SSHBackupError, backup_device
from netaudit.store import ConfigStore
from netaudit.wazuh_integration import (
    export_wazuh_ndjson,
    send_wazuh_api,
    send_wazuh_syslog,
)

# Force UTF-8 friendly output on Windows consoles (cp1252 breaks on arrows etc.)
console = Console(force_terminal=True, legacy_windows=False)
SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _store(ctx: click.Context) -> ConfigStore:
    return ConfigStore(ctx.obj["backups"])


@click.group()
@click.version_option(__version__, prog_name="netaudit")
@click.option(
    "--backups",
    default="backups",
    show_default=True,
    type=click.Path(),
    help="Directory for config snapshots",
)
@click.option(
    "--inventory",
    default="inventory.yaml",
    show_default=True,
    type=click.Path(),
    help="Device inventory YAML",
)
@click.pass_context
def main(ctx: click.Context, backups: str, inventory: str) -> None:
    """Network Audit and Config Backup — SSH backup, diff, security audit."""
    ctx.ensure_object(dict)
    ctx.obj["backups"] = backups
    ctx.obj["inventory"] = inventory


@main.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing inventory.yaml")
@click.pass_context
def init_cmd(ctx: click.Context, force: bool) -> None:
    """Create example inventory.yaml and folders."""
    inv = Path(ctx.obj["inventory"])
    if inv.exists() and not force:
        console.print(f"[yellow]Inventory already exists:[/] {inv} (use --force)")
    else:
        save_inventory_template(inv)
        console.print(f"[green]Wrote[/] {inv}")
    Path(ctx.obj["backups"]).mkdir(parents=True, exist_ok=True)
    Path("reports").mkdir(parents=True, exist_ok=True)
    console.print("[green]Ready.[/] Edit inventory.yaml, then run: netaudit backup")


@main.command("backup")
@click.option("--device", "device_filter", default=None, help="Backup only this device name")
@click.option("--demo", is_flag=True, help="Import sample configs instead of SSH")
@click.option(
    "--samples",
    default="samples",
    type=click.Path(),
    show_default=True,
    help="Sample configs dir (with --demo)",
)
@click.pass_context
def backup_cmd(
    ctx: click.Context,
    device_filter: str | None,
    demo: bool,
    samples: str,
) -> None:
    """Backup running configs over SSH (or import demo samples)."""
    store = _store(ctx)

    if demo:
        sample_dir = Path(samples)
        files = sorted(sample_dir.glob("*.cfg")) + sorted(sample_dir.glob("*.txt"))
        # Skip *-v2.cfg — those are for import-config / diff demos
        files = [f for f in files if not f.stem.endswith("-v2")]
        if not files:
            console.print(f"[red]No sample configs in {sample_dir}[/]")
            sys.exit(1)
        for f in files:
            name = f.stem
            if device_filter and name != device_filter:
                continue
            meta = store.import_file(name, f, source="demo")
            console.print(
                f"[green]OK[/] {name} -> {meta.path} ({meta.size_bytes} B, {meta.sha256[:12]}...)"
            )
        return

    try:
        devices = load_inventory(ctx.obj["inventory"])
    except FileNotFoundError:
        console.print(
            f"[red]Inventory not found:[/] {ctx.obj['inventory']}\n"
            "Run [bold]netaudit init[/] first."
        )
        sys.exit(1)

    if device_filter:
        devices = [d for d in devices if d.name == device_filter]
        if not devices:
            console.print(f"[red]Device not in inventory:[/] {device_filter}")
            sys.exit(1)

    ok, fail = 0, 0
    for device in devices:
        try:
            config = backup_device(device, progress=lambda m: console.print(f"  [dim]{m}[/]"))
            meta = store.save(device.name, config, source="ssh")
            console.print(
                f"[green]OK[/] {device.name} -> {meta.path} ({meta.size_bytes} B)"
            )
            ok += 1
        except SSHBackupError as exc:
            console.print(f"[red]FAIL[/] {device.name}: {exc}")
            fail += 1

    console.print(Panel(f"Backed up [green]{ok}[/] | failed [red]{fail}[/]"))
    if fail:
        sys.exit(1)


@main.command("list")
@click.option("--device", "device_filter", default=None)
@click.pass_context
def list_cmd(ctx: click.Context, device_filter: str | None) -> None:
    """List stored config backups."""
    store = _store(ctx)
    backups = store.list_backups(device_filter)
    if not backups:
        console.print("[yellow]No backups yet.[/]")
        return
    table = Table(title="Config backups")
    table.add_column("Device")
    table.add_column("Timestamp")
    table.add_column("Size")
    table.add_column("Source")
    table.add_column("SHA256")
    for b in backups:
        table.add_row(b.device, b.timestamp, str(b.size_bytes), b.source, b.sha256[:12] + "...")
    console.print(table)


@main.command("diff")
@click.argument("device")
@click.option("--older", default=None, help="Older timestamp (default: previous)")
@click.option("--newer", default=None, help="Newer timestamp (default: latest)")
@click.option("--export", "export_path", default=None, type=click.Path(), help="Write Markdown diff")
@click.option("--csv", "csv_path", default=None, type=click.Path(), help="Write CSV of added/removed")
@click.pass_context
def diff_cmd(
    ctx: click.Context,
    device: str,
    older: str | None,
    newer: str | None,
    export_path: str | None,
    csv_path: str | None,
) -> None:
    """Show unified diff between two backups (default: last two)."""
    store = _store(ctx)
    try:
        result = diff_backups(store, device, older_ts=older, newer_ts=newer)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)

    if not result.has_changes:
        console.print(f"[green]No changes[/] for {device} ({result.older} -> {result.newer})")
    else:
        console.print(
            f"[bold]{device}[/] {result.older} -> {result.newer} "
            f"(+{len(result.added)} / -{len(result.removed)})"
        )
        console.print(Syntax("\n".join(result.changed_hunks), "diff", theme="monokai"))

    if export_path:
        export_diff_markdown(result, export_path)
        console.print(f"[green]Wrote[/] {export_path}")
    if csv_path:
        export_diff_csv(result, csv_path)
        console.print(f"[green]Wrote[/] {csv_path}")


@main.command("audit")
@click.option("--device", "device_filter", default=None, help="Audit one device (latest backup)")
@click.option("--file", "config_file", default=None, type=click.Path(exists=True), help="Audit a local .cfg")
@click.option("--platform", "platform_override", default=None, help="Force platform (fortigate|scalance_xc|cisco_ios|...)")
@click.option("--rules", "rules_path", default=None, type=click.Path(exists=True))
@click.option(
    "--export",
    "export_md",
    default=None,
    type=click.Path(),
    help="Write Markdown report",
)
@click.option("--csv", "export_csv", default=None, type=click.Path(), help="Write CSV report")
@click.option(
    "--wazuh-file",
    default=None,
    type=click.Path(),
    help="Append findings as NDJSON for Wazuh agent localfile",
)
@click.option("--wazuh-syslog", default=None, help="Send findings via syslog to HOST")
@click.option("--wazuh-syslog-port", default=514, show_default=True, type=int)
@click.option("--wazuh-syslog-proto", default="udp", type=click.Choice(["udp", "tcp"]))
@click.option("--wazuh-api", default=None, help="Wazuh API base URL (e.g. https://manager:55000)")
@click.option("--wazuh-user", default="wazuh", show_default=True)
@click.option("--wazuh-pass", default=None, help="Wazuh API password")
@click.pass_context
def audit_cmd(
    ctx: click.Context,
    device_filter: str | None,
    config_file: str | None,
    platform_override: str | None,
    rules_path: str | None,
    export_md: str | None,
    export_csv: str | None,
    wazuh_file: str | None,
    wazuh_syslog: str | None,
    wazuh_syslog_port: int,
    wazuh_syslog_proto: str,
    wazuh_api: str | None,
    wazuh_user: str,
    wazuh_pass: str | None,
) -> None:
    """Audit configs for dangerous settings and missing standards."""
    store = _store(ctx)
    findings = []

    if config_file:
        name = Path(config_file).stem
        text = Path(config_file).read_text(encoding="utf-8")
        platform = (
            platform_override
            or infer_platform_from_config(text)
            or platform_for_device(ctx.obj["inventory"], name)
        )
        rules = load_rules(rules_path, platform=platform)
        findings.extend(audit_config(name, text, rules, platform=platform))
        console.print(f"[dim]platform={platform or 'all'}[/]")
    else:
        devices: list[str]
        if device_filter:
            devices = [device_filter]
        else:
            seen = {b.device for b in store.list_backups()}
            devices = sorted(seen)
        if not devices:
            console.print("[yellow]No backups to audit. Run backup --demo or backup first.[/]")
            sys.exit(1)
        for name in devices:
            try:
                _meta, text = store.get(name)
            except FileNotFoundError as exc:
                console.print(f"[red]{exc}[/]")
                continue
            platform = (
                platform_override
                or platform_for_device(ctx.obj["inventory"], name)
                or infer_platform_from_config(text)
            )
            rules = load_rules(rules_path, platform=platform)
            findings.extend(audit_config(name, text, rules, platform=platform))

    summary = summarize_findings(findings)
    table = Table(title="Audit findings")
    table.add_column("Sev")
    table.add_column("Device")
    table.add_column("Rule")
    table.add_column("Evidence / detail")
    for f in findings:
        style = SEVERITY_STYLE.get(f.severity.value, "")
        evidence = f.evidence or f.detail
        if len(evidence) > 80:
            evidence = evidence[:77] + "..."
        table.add_row(
            f"[{style}]{f.severity.value}[/]",
            f.device,
            f.rule_id,
            evidence,
        )
    console.print(table)
    console.print(
        Panel(
            f"total={summary['total']}  "
            f"critical={summary['critical']}  high={summary['high']}  "
            f"medium={summary['medium']}  low={summary['low']}"
        )
    )

    if export_md:
        export_findings_markdown(findings, export_md)
        console.print(f"[green]Wrote[/] {export_md}")
    if export_csv:
        export_findings_csv(findings, export_csv)
        console.print(f"[green]Wrote[/] {export_csv}")

    if wazuh_file:
        export_wazuh_ndjson(findings, wazuh_file)
        console.print(f"[green]Wazuh NDJSON[/] {wazuh_file} ({len(findings)} events)")
    if wazuh_syslog:
        n = send_wazuh_syslog(
            findings, wazuh_syslog, port=wazuh_syslog_port, protocol=wazuh_syslog_proto
        )
        console.print(f"[green]Wazuh syslog[/] {n} events -> {wazuh_syslog}:{wazuh_syslog_port}/{wazuh_syslog_proto}")
    if wazuh_api:
        if not wazuh_pass:
            console.print("[red]--wazuh-api requires --wazuh-pass[/]")
            sys.exit(1)
        try:
            result = send_wazuh_api(findings, wazuh_api, wazuh_user, wazuh_pass)
            if result.get("ok"):
                console.print(f"[green]Wazuh API[/] posted {result.get('count')} events")
            else:
                console.print(f"[yellow]Wazuh API[/] {result.get('message')}")
        except RuntimeError as exc:
            console.print(f"[red]Wazuh API[/] {exc}")
            sys.exit(1)

    # Non-zero exit if critical/high — useful in CI / scheduled jobs
    if summary["critical"] or summary["high"]:
        sys.exit(2)


@main.command("show")
@click.argument("device")
@click.option("--timestamp", default=None)
@click.pass_context
def show_cmd(ctx: click.Context, device: str, timestamp: str | None) -> None:
    """Print a stored config."""
    store = _store(ctx)
    try:
        meta, text = store.get(device, timestamp)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)
    console.print(f"[dim]{meta.path} | {meta.timestamp} | {meta.sha256[:12]}...[/]")
    console.print(text)


@main.command("import-config")
@click.argument("device")
@click.argument("path", type=click.Path(exists=True))
@click.pass_context
def import_cmd(ctx: click.Context, device: str, path: str) -> None:
    """Import a local config file as a backup snapshot."""
    store = _store(ctx)
    meta = store.import_file(device, path, source="file")
    console.print(f"[green]Imported[/] {device} -> {meta.path}")


if __name__ == "__main__":
    main()
