import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from ..models import RiskReport, Severity

console = Console(force_terminal=True, legacy_windows=False)


class TerminalReporter:
    """Renders risk reports in rich interactive CLI tables and panels."""

    def render(self, report: RiskReport):
        console.print()
        # Title Banner
        console.print(Panel.fit(
            "[bold white on blue] 🛡️ Software Dependency Security Analyzer [/bold white on blue]\n"
            f"[dim]Target: {report.target_path} | Timestamp: {report.scan_timestamp}[/dim]",
            border_style="blue"
        ))

        # Risk Summary Panel
        level_colors = {
            "CRITICAL": "bold red",
            "HIGH": "bold bright_red",
            "MEDIUM": "bold yellow",
            "LOW": "bold green",
        }
        color = level_colors.get(report.risk_level, "white")

        gate_status = "[bold green]PASSED[/bold green]" if report.quality_gate_passed else "[bold red]FAILED (QUALITY GATE BREACHED)[/bold red]"

        summary_text = (
            f"[bold]1. Overall Security Risk Score:[/bold] [{color}]{report.overall_risk_score} / 100.0 ({report.risk_level})[/{color}]\n"
            f"[bold]2. Total Dependencies Scanned:[/bold] {report.total_dependencies}\n"
            f"[bold]3. Vulnerable Dependencies:[/bold] {report.vulnerable_dependencies_count}\n"
            f"[bold]4. Critical Vulnerabilities:[/bold] [bold red]{report.critical_count}[/bold red] | "
            f"[bold]5. High Vulnerabilities:[/bold] [bold bright_red]{report.high_count}[/bold bright_red]\n"
            f"[bold]6. Outdated Dependencies:[/bold] {report.outdated_dependencies_count}\n"
            f"[bold]7. License Compliance Issues:[/bold] {report.license_compliance_issues_count}\n"
            f"[bold]8. Transitive Dependencies:[/bold] {report.transitive_dependencies_count}\n"
            f"[bold]9. Security Issues Fixed/Fixable:[/bold] [bold green]{report.security_issues_fixed_count}[/bold green]\n"
            f"[bold]10. Dependency Health Score:[/bold] [bold cyan]{report.dependency_health_score} / 100.0[/bold cyan]\n\n"
            f"[bold]Quality Gate Outcome:[/bold] {gate_status}\n"
            f"[bold red]Critical:[/bold red] {report.severity_counts.get('CRITICAL', 0)} | "
            f"[bold bright_red]High:[/bold bright_red] {report.severity_counts.get('HIGH', 0)} | "
            f"[bold yellow]Medium:[/bold yellow] {report.severity_counts.get('MEDIUM', 0)} | "
            f"[bold green]Low:[/bold green] {report.severity_counts.get('LOW', 0)}"
        )
        console.print(Panel(summary_text, title="🛡️ Security Metrics Overview", border_style="cyan"))

        # Vulnerabilities Table
        if report.vulnerable_dependencies_count > 0:
            table = Table(title="🚨 Detected Dependency Vulnerabilities", show_header=True, header_style="bold magenta")
            table.add_column("Ecosystem", style="dim", width=10)
            table.add_column("Package", style="bold cyan")
            table.add_column("Version", width=10)
            table.add_column("CVE / Vuln ID", style="bold yellow", width=18)
            table.add_column("Severity", width=10)
            table.add_column("CVSS", width=6)
            table.add_column("Fixed Version", style="bold green", width=14)
            table.add_column("Summary")

            for dep_analysis in report.dependencies:
                dep = dep_analysis.dependency
                for vuln in dep_analysis.vulnerabilities:
                    sev_style = {
                        Severity.CRITICAL: "bold red",
                        Severity.HIGH: "bold bright_red",
                        Severity.MEDIUM: "bold yellow",
                        Severity.LOW: "bold green",
                    }.get(vuln.severity, "white")

                    table.add_row(
                        dep.ecosystem,
                        dep.name,
                        dep.version,
                        vuln.vuln_id,
                        Text(vuln.severity.value, style=sev_style),
                        f"{vuln.cvss_score:.1f}",
                        vuln.fixed_version or "[dim]N/A[/dim]",
                        vuln.summary[:60] + "..." if len(vuln.summary) > 60 else vuln.summary
                    )
            console.print(table)

        # Remediation Panel
        if report.remediation_recommendations:
            rem_table = Table(title="🛠️ Automated Remediation Guidance", show_header=True, header_style="bold green")
            rem_table.add_column("Package", style="bold cyan")
            rem_table.add_column("Installed", width=10)
            rem_table.add_column("Recommended", style="bold green", width=14)
            rem_table.add_column("CVEs Resolved")
            rem_table.add_column("Upgrade Command", style="bold yellow")

            for rec in report.remediation_recommendations[:8]:
                rem_table.add_row(
                    rec.get("package", ""),
                    rec.get("installed_version", ""),
                    rec.get("recommended_version", ""),
                    ", ".join(rec.get("resolved_cves", [])[:3]),
                    rec.get("upgrade_command", "")
                )
            console.print(rem_table)

        console.print()
