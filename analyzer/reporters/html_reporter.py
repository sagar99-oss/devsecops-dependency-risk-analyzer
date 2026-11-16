from pathlib import Path
from jinja2 import Template
from ..models import RiskReport

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software Dependency Security Analyzer Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-color: #090d16;
            --card-bg: #111827;
            --border-color: #1f2937;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --accent-blue: #38bdf8;
            --accent-indigo: #6366f1;
            --critical-red: #f43f5e;
            --high-orange: #fb923c;
            --medium-yellow: #facc15;
            --low-green: #4ade80;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2.5rem 1.5rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1350px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .brand-title {
            margin: 0;
            font-size: 1.85rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-indigo));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .meta { color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }

        .badge {
            display: inline-block;
            padding: 0.35rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .gate-passed { background: rgba(74, 222, 128, 0.15); color: var(--low-green); border: 1px solid var(--low-green); }
        .gate-failed { background: rgba(244, 63, 94, 0.15); color: var(--critical-red); border: 1px solid var(--critical-red); }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }

        .stat-title {
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 800;
        }

        .charts-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        @media (max-width: 900px) {
            .charts-row { grid-template-columns: 1fr; }
        }

        .chart-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin: 2.5rem 0 1rem 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-main);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }

        th, td {
            padding: 0.85rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }

        th {
            background-color: #0f172a;
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
        }

        tr:hover { background-color: rgba(255, 255, 255, 0.02); }

        .badge-CRITICAL { background: rgba(244, 63, 94, 0.15); color: var(--critical-red); border: 1px solid var(--critical-red); }
        .badge-HIGH { background: rgba(251, 146, 60, 0.15); color: var(--high-orange); border: 1px solid var(--high-orange); }
        .badge-MEDIUM { background: rgba(250, 204, 21, 0.15); color: var(--medium-yellow); border: 1px solid var(--medium-yellow); }
        .badge-LOW { background: rgba(74, 222, 128, 0.15); color: var(--low-green); border: 1px solid var(--low-green); }

        .callout-box {
            background: rgba(56, 189, 248, 0.05);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-left: 4px solid var(--accent-blue);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }

        a { color: var(--accent-blue); text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background: rgba(255, 255, 255, 0.08); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 class="brand-title">🛡️ Software Dependency Security Analyzer</h1>
                <div class="meta">Target: <strong>{{ report.target_path }}</strong> | Scanned on: <strong>{{ report.scan_timestamp }}</strong></div>
            </div>
            <div>
                <span class="badge {% if report.quality_gate_passed %}gate-passed{% else %}gate-failed{% endif %}">
                    Quality Gate: {% if report.quality_gate_passed %}PASSED{% else %}FAILED (SECURITY GATE BREACHED){% endif %}
                </span>
            </div>
        </header>

        <!-- 10 Core Security KPI Metrics Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">1. Overall Risk Score</div>
                <div class="stat-value" style="color: {% if report.overall_risk_score >= 70 %}var(--critical-red){% elif report.overall_risk_score >= 40 %}var(--high-orange){% else %}var(--low-green){% endif %};">
                    {{ report.overall_risk_score }} <span style="font-size:1rem; color:var(--text-muted)">/ 100</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-title">2. Total Dependencies</div>
                <div class="stat-value">{{ report.total_dependencies }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">3. Vulnerable Dependencies</div>
                <div class="stat-value" style="color: var(--high-orange)">{{ report.vulnerable_dependencies_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">4. Critical Vulnerabilities</div>
                <div class="stat-value" style="color: var(--critical-red)">{{ report.critical_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">5. High Vulnerabilities</div>
                <div class="stat-value" style="color: var(--high-orange)">{{ report.high_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">6. Outdated Dependencies</div>
                <div class="stat-value" style="color: var(--medium-yellow)">{{ report.outdated_dependencies_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">7. License Compliance Issues</div>
                <div class="stat-value" style="color: {% if report.license_compliance_issues_count > 0 %}var(--critical-red){% else %}var(--low-green){% endif %}">
                    {{ report.license_compliance_issues_count }}
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-title">8. Transitive Dependencies</div>
                <div class="stat-value" style="color: var(--accent-blue)">{{ report.transitive_dependencies_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">9. Security Issues Fixable</div>
                <div class="stat-value" style="color: var(--low-green)">{{ report.security_issues_fixed_count }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">10. Dependency Health Score</div>
                <div class="stat-value" style="color: {% if report.dependency_health_score >= 80 %}var(--low-green){% elif report.dependency_health_score >= 50 %}var(--medium-yellow){% else %}var(--critical-red){% endif %};">
                    {{ report.dependency_health_score }} <span style="font-size:1rem; color:var(--text-muted)">/ 100</span>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="charts-row">
            <div class="chart-card">
                <div class="stat-title">📊 Vulnerability Severity Breakdown</div>
                <canvas id="severityChart" height="200"></canvas>
            </div>
            <div class="chart-card">
                <div class="stat-title">⚖️ License Compliance Breakdown</div>
                <canvas id="licenseChart" height="200"></canvas>
            </div>
        </div>

        <!-- Section 1: Dependency Inventory -->
        <h2 class="section-title">📦 Dependency Inventory ({{ report.total_dependencies }} Packages Detected)</h2>
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Current Version</th>
                    <th>Latest Version</th>
                    <th>Ecosystem</th>
                    <th>Dependency Type</th>
                    <th>Status</th>
                    <th>License</th>
                    <th>Compliance</th>
                </tr>
            </thead>
            <tbody>
                {% for item in report.dependencies %}
                <tr>
                    <td><strong>{{ item.dependency.name }}</strong></td>
                    <td>{{ item.dependency.version }}</td>
                    <td>{{ item.dependency.latest_version or item.dependency.version }}</td>
                    <td>{{ item.dependency.ecosystem }}</td>
                    <td>
                        {% if item.dependency.is_direct %}
                        <span class="badge" style="background:rgba(56,189,248,0.15); color:var(--accent-blue)">Direct</span>
                        {% else %}
                        <span class="badge" style="background:rgba(156,163,175,0.15); color:var(--text-muted)">Transitive (Depth {{ item.dependency.depth }})</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if item.dependency.is_malicious %}
                        <span class="badge badge-CRITICAL">🚨 MALWARE</span>
                        {% elif item.dependency.is_deprecated %}
                        <span class="badge badge-HIGH">⚠️ Deprecated</span>
                        {% elif item.dependency.is_outdated %}
                        <span class="badge badge-MEDIUM">Outdated</span>
                        {% else %}
                        <span class="badge" style="background:rgba(74,222,128,0.15); color:var(--low-green)">Up-to-date</span>
                        {% endif %}
                    </td>
                    <td><code>{{ item.dependency.license }}</code></td>
                    <td>
                        {% if item.dependency.is_license_risk %}
                        <span class="badge badge-HIGH">{{ item.dependency.license_category }}</span>
                        {% else %}
                        <span class="badge" style="background:rgba(74,222,128,0.15); color:var(--low-green)">{{ item.dependency.license_category }}</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <!-- Section 2: Vulnerability Management -->
        <h2 class="section-title">🚨 Detected Security Vulnerabilities ({{ report.vulnerable_dependencies_count }} Affected Packages)</h2>
        {% if report.vulnerable_dependencies_count == 0 %}
        <div class="callout-box" style="border-left-color: var(--low-green)">
            ✨ <strong>No known security vulnerabilities</strong> detected in the scanned dependency manifests.
        </div>
        {% else %}
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Vulnerability ID</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Fixed Version</th>
                    <th>Summary</th>
                    <th>References</th>
                </tr>
            </thead>
            <tbody>
                {% for item in report.dependencies %}
                    {% for vuln in item.vulnerabilities %}
                    <tr>
                        <td><strong>{{ item.dependency.name }}</strong></td>
                        <td>{{ item.dependency.version }}</td>
                        <td><code>{{ vuln.vuln_id }}</code></td>
                        <td><span class="badge badge-{{ vuln.severity.value }}">{{ vuln.severity.value }}</span></td>
                        <td>{{ "%.1f"|format(vuln.cvss_score) }}</td>
                        <td>
                            {% if vuln.fixed_version %}
                            <strong style="color:var(--low-green)">{{ vuln.fixed_version }}</strong>
                            {% else %}
                            <span style="color:var(--text-muted)">None reported</span>
                            {% endif %}
                        </td>
                        <td>{{ vuln.summary }}</td>
                        <td>
                            {% for ref in vuln.references[:2] %}
                            <div><a href="{{ ref }}" target="_blank" rel="noopener">Link</a></div>
                            {% endfor %}
                        </td>
                    </tr>
                    {% endfor %}
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <!-- Section 3: Automated Remediation Recommendations -->
        <h2 class="section-title">🛠️ Automated Remediation Recommendations</h2>
        <div class="callout-box">
            <strong>Notice:</strong> Review changelogs and run tests before updating dependencies in production. Dependencies are never modified automatically without user approval.
        </div>
        {% if report.remediation_recommendations|length == 0 %}
        <p style="color: var(--text-muted)">No automated upgrade actions currently required.</p>
        {% else %}
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Installed</th>
                    <th>Recommended</th>
                    <th>Resolved Vulnerabilities</th>
                    <th>Severity</th>
                    <th>Upgrade Command</th>
                </tr>
            </thead>
            <tbody>
                {% for rec in report.remediation_recommendations %}
                <tr>
                    <td><strong>{{ rec.package }}</strong></td>
                    <td>{{ rec.installed_version }}</td>
                    <td><strong style="color:var(--low-green)">{{ rec.recommended_version }}</strong></td>
                    <td>
                        {% for cve in rec.resolved_cves %}
                        <code>{{ cve }}</code> 
                        {% endfor %}
                    </td>
                    <td><span class="badge badge-{{ rec.highest_severity }}">{{ rec.highest_severity }}</span></td>
                    <td><code>{{ rec.upgrade_command }}</code></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <footer style="margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); color: var(--text-muted); font-size: 0.85rem; text-align: center;">
            Generated by <strong>Software Dependency Security Analyzer</strong>. All metrics computed from real manifest & vulnerability intelligence.
        </footer>
    </div>

    <script>
        const sevData = {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    {{ report.critical_count }},
                    {{ report.high_count }},
                    {{ report.medium_count }},
                    {{ report.low_count }}
                ],
                backgroundColor: ['#f43f5e', '#fb923c', '#facc15', '#4ade80'],
                borderWidth: 0
            }]
        };

        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: sevData,
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#9ca3af' } }
                }
            }
        });

        const licLabels = [];
        const licCounts = [];
        {% for cat, count in report.license_summary.items() %}
        {% if count > 0 %}
        licLabels.push('{{ cat }}');
        licCounts.push({{ count }});
        {% endif %}
        {% endfor %}

        new Chart(document.getElementById('licenseChart'), {
            type: 'doughnut',
            data: {
                labels: licLabels.length ? licLabels : ['No Data'],
                datasets: [{
                    data: licCounts.length ? licCounts : [1],
                    backgroundColor: ['#4ade80', '#38bdf8', '#f43f5e', '#facc15', '#a855f7', '#9ca3af'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#9ca3af' } }
                }
            }
        });
    </script>
</body>
</html>
"""


class HTMLReporter:
    """Generates rich, standalone, executive-level interactive HTML reports."""

    def export(self, report: RiskReport, output_path: str) -> str:
        template = Template(HTML_TEMPLATE)
        rendered_html = template.render(report=report)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return str(path)
