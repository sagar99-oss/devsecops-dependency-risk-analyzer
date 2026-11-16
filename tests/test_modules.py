import json
from pathlib import Path
from analyzer.models import Dependency, Vulnerability, DependencyAnalysis, Severity
from analyzer.scoring import RiskEngine
from analyzer.reporters import HTMLReporter, JSONReporter, SARIFReporter
import db


def test_ten_security_metrics_calculation():
    # Setup test dependencies
    dep_safe = Dependency(
        name="flask",
        version="3.1.0",
        ecosystem="PyPI",
        is_direct=True,
        license="BSD-3-Clause",
        license_category="Permissive",
        is_outdated=False
    )
    dep_vuln = Dependency(
        name="urllib3",
        version="1.26.4",
        ecosystem="PyPI",
        is_direct=False,
        depth=2,
        license="MIT",
        license_category="Permissive",
        is_outdated=True,
        latest_version="2.2.3"
    )
    dep_gpl = Dependency(
        name="pygpl-example",
        version="1.0.0",
        ecosystem="PyPI",
        is_direct=True,
        license="GPL-3.0",
        license_category="Strong Copyleft (Restrictive)",
        is_license_risk=True,
        is_deprecated=True
    )

    vuln_crit = Vulnerability(
        vuln_id="CVE-2023-1111",
        summary="Critical RCE",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="1.26.5"
    )
    vuln_high = Vulnerability(
        vuln_id="CVE-2023-2222",
        summary="High ReDoS",
        severity=Severity.HIGH,
        cvss_score=7.5,
        fixed_version="1.26.6"
    )

    a1 = DependencyAnalysis(dependency=dep_safe, vulnerabilities=[])
    a2 = DependencyAnalysis(dependency=dep_vuln, vulnerabilities=[vuln_crit, vuln_high])
    a3 = DependencyAnalysis(dependency=dep_gpl, vulnerabilities=[])

    engine = RiskEngine(risk_threshold=70.0)
    report = engine.evaluate("test-project", [a1, a2, a3])

    # Check the 10 Core Security Metrics
    assert 0.0 <= report.overall_risk_score <= 100.0  # Metric 1
    assert report.total_dependencies == 3              # Metric 2
    assert report.vulnerable_dependencies_count == 1   # Metric 3
    assert report.critical_count == 1                  # Metric 4
    assert report.high_count == 1                      # Metric 5
    assert report.outdated_dependencies_count == 1     # Metric 6
    assert report.license_compliance_issues_count == 1 # Metric 7
    assert report.transitive_dependencies_count == 1   # Metric 8
    assert report.security_issues_fixed_count == 2     # Metric 9
    assert 0.0 <= report.dependency_health_score <= 100.0 # Metric 10

    # Check Dependency Graph Structure
    assert "nodes" in report.dependency_graph
    assert len(report.dependency_graph["nodes"]) == 3

    # Check Remediation Recommendations
    assert len(report.remediation_recommendations) >= 1
    rec = report.remediation_recommendations[0]
    assert rec["package"] == "urllib3"
    assert "upgrade_command" in rec
    assert "pip install" in rec["upgrade_command"]


def test_reports_generation(tmp_path):
    dep = Dependency(name="requests", version="2.25.1", ecosystem="PyPI", is_direct=True, license="Apache-2.0")
    vuln = Vulnerability(vuln_id="CVE-2023-0001", summary="Test Vuln", severity=Severity.HIGH, cvss_score=7.8)
    analysis = DependencyAnalysis(dependency=dep, vulnerabilities=[vuln])

    engine = RiskEngine()
    report = engine.evaluate("sample-project", [analysis])

    # Test HTML Report
    html_out = tmp_path / "report.html"
    HTMLReporter().export(report, str(html_out))
    assert html_out.exists()
    html_content = html_out.read_text(encoding="utf-8")
    assert "Software Dependency Security Analyzer" in html_content
    assert "CVE-2023-0001" in html_content

    # Test JSON Report
    json_out = tmp_path / "report.json"
    JSONReporter().export(report, str(json_out))
    assert json_out.exists()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["total_dependencies"] == 1
    assert data["vulnerable_dependencies_count"] == 1

    # Test SARIF Report
    sarif_out = tmp_path / "report.sarif"
    SARIFReporter().export(report, str(sarif_out))
    assert sarif_out.exists()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "Software Dependency Security Analyzer"


def test_scan_comparison():
    # Create Report A (baseline)
    dep_a = Dependency(name="lodash", version="4.17.15", ecosystem="npm")
    vuln_a = Vulnerability(vuln_id="CVE-2020-8203", summary="Prototype Pollution", severity=Severity.HIGH, cvss_score=7.4)
    analysis_a = DependencyAnalysis(dependency=dep_a, vulnerabilities=[vuln_a])
    rep_a = RiskEngine().evaluate("project-v1", [analysis_a])
    id_a = db.save_scan_record(rep_a)

    # Create Report B (fixed lodash, but introduced axios vuln)
    dep_b1 = Dependency(name="lodash", version="4.17.21", ecosystem="npm")  # fixed
    dep_b2 = Dependency(name="axios", version="0.21.1", ecosystem="npm")
    vuln_b2 = Vulnerability(vuln_id="CVE-2021-3749", summary="ReDoS", severity=Severity.MEDIUM, cvss_score=5.3)
    analysis_b1 = DependencyAnalysis(dependency=dep_b1, vulnerabilities=[])
    analysis_b2 = DependencyAnalysis(dependency=dep_b2, vulnerabilities=[vuln_b2])
    rep_b = RiskEngine().evaluate("project-v2", [analysis_b1, analysis_b2])
    id_b = db.save_scan_record(rep_b)

    # Perform comparison
    cmp_res = db.compare_scans(id_a, id_b)
    assert cmp_res is not None
    assert "deltas" in cmp_res

    # Check resolved: lodash CVE-2020-8203 was in A, absent in B
    resolved_ids = [v["vuln_id"] for v in cmp_res["resolved_vulnerabilities"]]
    assert "CVE-2020-8203" in resolved_ids

    # Check introduced: axios CVE-2021-3749 was absent in A, present in B
    new_ids = [v["vuln_id"] for v in cmp_res["newly_introduced_vulnerabilities"]]
    assert "CVE-2021-3749" in new_ids

    # Check updated dependencies
    updated_pkgs = [u["package"] for u in cmp_res["dependency_changes"]["updated"]]
    assert "lodash" in updated_pkgs
