from pathlib import Path
from typing import List, Dict, Any, Set
from ..models import DependencyAnalysis, RiskReport, Severity, ResearchMetrics, ReachabilityStatus
from ..research import (
    ASTReachabilityAnalyzer,
    DependencyGraphEngine,
    MLZeroDayPredictor,
    ASTDiffBreakingChangeAnalyzer
)


class RiskEngine:
    """
    Software Dependency Security Analyzer Composite Risk & Health Scoring Engine.
    Computes 10 core security metrics:
    1. Overall Security Risk Score (0-100)
    2. Total Dependencies Scanned
    3. Vulnerable Dependencies
    4. Critical Vulnerabilities
    5. High-Severity Vulnerabilities
    6. Outdated Dependencies
    7. License Compliance Issues
    8. Transitive Dependencies
    9. Security Issues Fixed / Fixable
    10. Dependency Health Score (0-100)
    
    Includes AST Call-Graph Reachability, DAG Supply-Chain Graphing,
    Zero-Day ML Prediction, and AST Differential Breaking-Change Analysis.
    """

    def __init__(self, risk_threshold: float = 70.0, fail_on_critical: bool = True, fail_on_high: bool = False):
        self.risk_threshold = risk_threshold
        self.fail_on_critical = fail_on_critical
        self.fail_on_high = fail_on_high

        self.reachability_analyzer = ASTReachabilityAnalyzer()
        self.graph_engine = DependencyGraphEngine()
        self.ml_predictor = MLZeroDayPredictor()
        self.ast_diff_analyzer = ASTDiffBreakingChangeAnalyzer()

    def evaluate(self, target_path: str, analyses: List[DependencyAnalysis]) -> RiskReport:
        target_path_obj = Path(target_path).resolve()

        # Step 1: Run Academic Research Engines
        reachability_res = self.reachability_analyzer.analyze_workspace(target_path_obj, analyses)
        graph_res = self.graph_engine.compute_blast_radius(analyses)
        predicted_zero_days = self.ml_predictor.predict_zero_day_risks(analyses)
        breaking_changes = self.ast_diff_analyzer.analyze_breaking_changes(analyses)

        research_metrics = ResearchMetrics(
            total_packages_analyzed=len(analyses),
            false_positives_eliminated=reachability_res.get("false_positives_eliminated", 0),
            graph_node_count=graph_res.get("graph_nodes", 0),
            graph_edge_count=graph_res.get("graph_edges", 0),
            average_blast_radius=graph_res.get("avg_blast_radius", 0.0),
            predicted_zero_day_threats=predicted_zero_days,
            breaking_changes_prevented=breaking_changes
        )

        total_deps = len(analyses)
        vulnerable_deps = [a for a in analyses if a.has_vulnerabilities]
        vulnerable_deps_count = len(vulnerable_deps)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        outdated_count = 0
        license_issues_count = 0
        transitive_count = 0
        fixed_issues_count = 0
        deprecated_count = 0
        malicious_count = 0

        license_summary: Dict[str, int] = {
            "Permissive": 0,
            "Weak Copyleft": 0,
            "Strong Copyleft (Restrictive)": 0,
            "Unknown": 0,
            "Proprietary": 0,
            "Other / Custom": 0,
        }

        remediations_map: Dict[str, Dict[str, Any]] = {}
        accumulated_dep_score = 0.0

        for analysis in analyses:
            dep = analysis.dependency

            # Track Outdated & License Metrics
            if dep.is_outdated:
                outdated_count += 1
            if not dep.is_direct:
                transitive_count += 1
            if dep.is_license_risk:
                license_issues_count += 1
            if dep.is_deprecated:
                deprecated_count += 1
            if dep.is_malicious:
                malicious_count += 1

            cat = dep.license_category or "Unknown"
            license_summary[cat] = license_summary.get(cat, 0) + 1

            dep_weight = 0.05 if dep.is_dev_dependency else (1.0 if dep.is_direct else 0.50)
            max_dep_cvss = 0.0

            for vuln in analysis.vulnerabilities:
                # Discount unreachable false positives in risk scoring
                if vuln.reachability == ReachabilityStatus.UNREACHABLE:
                    continue

                sev_key = vuln.severity.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

                # Base CVSS rating + EPSS weight
                cvss = vuln.cvss_score or vuln.severity.score_weight
                epss = getattr(vuln, "epss_score", 0.05)
                weighted_cvss = cvss * (1.0 + epss * 0.5)

                if weighted_cvss > max_dep_cvss:
                    max_dep_cvss = weighted_cvss

                # Remediation collection
                target_ver = vuln.fixed_version or dep.latest_version
                if vuln.fixed_version:
                    fixed_issues_count += 1

                if target_ver and target_ver != dep.version:
                    pkg_key = dep.name
                    if pkg_key not in remediations_map:
                        eco = dep.ecosystem.lower()
                        if eco == "npm":
                            cmd = f"npm install {dep.name}@{target_ver}"
                        elif eco == "maven":
                            cmd = f"<version>{target_ver}</version>"
                        elif eco == "go":
                            cmd = f"go get {dep.name}@v{target_ver}"
                        else:
                            cmd = f"pip install --upgrade {dep.name}=={target_ver}"

                        remediations_map[pkg_key] = {
                            "package": dep.name,
                            "installed_version": dep.version,
                            "recommended_version": target_ver,
                            "resolved_cves": [vuln.vuln_id],
                            "highest_severity": vuln.severity.value,
                            "ecosystem": dep.ecosystem,
                            "is_direct": dep.is_direct,
                            "breaking_change_risk": f"{analysis.breaking_change_risk:.2f}",
                            "upgrade_command": cmd,
                            "instructions": f"Update {dep.name} from {dep.version} to {target_ver} to remediate security exposure.",
                            "safety_notice": "Review package changelog and test in staging before production deployment. Automated updates are never applied without approval."
                        }
                    else:
                        if vuln.vuln_id not in remediations_map[pkg_key]["resolved_cves"]:
                            remediations_map[pkg_key]["resolved_cves"].append(vuln.vuln_id)

            accumulated_dep_score += max_dep_cvss * dep_weight

        # 1. Overall Security Risk Score (0.0 - 100.0)
        crit_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)
        med_count = severity_counts.get("MEDIUM", 0)
        low_count = severity_counts.get("LOW", 0)

        if total_deps == 0 or vulnerable_deps_count == 0:
            overall_score = 0.0
        else:
            avg_risk = accumulated_dep_score / max(total_deps, 1)
            base_score = min(55.0, avg_risk * 5.5)
            crit_bonus = min(25.0, crit_count * 10.0)
            high_bonus = min(15.0, high_count * 3.5)
            med_bonus = min(8.0, med_count * 1.5)
            malware_bonus = 15.0 if malicious_count > 0 else 0.0

            overall_score = min(100.0, round(base_score + crit_bonus + high_bonus + med_bonus + malware_bonus, 1))

        # 10. Dependency Health Score (0.0 - 100.0)
        # Pristine score is 100, reduced by security vulnerabilities, outdated packages, unmaintained status, and license issues
        if total_deps == 0:
            health_score = 100.0
        else:
            health_deductions = (
                (crit_count * 20.0) +
                (high_count * 10.0) +
                (med_count * 4.0) +
                (low_count * 1.0) +
                (outdated_count * 2.5) +
                (license_issues_count * 3.0) +
                (deprecated_count * 5.0) +
                (malicious_count * 25.0)
            )
            health_score = max(0.0, round(100.0 - (health_deductions / max(total_deps * 0.4, 1.0)), 1))

        # Risk Categorization
        if overall_score >= 75.0 or crit_count > 0 or malicious_count > 0:
            risk_level = "CRITICAL"
        elif overall_score >= 50.0 or high_count > 1:
            risk_level = "HIGH"
        elif overall_score >= 25.0 or med_count > 1:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Quality Gate evaluation
        gate_passed = True
        if self.fail_on_critical and crit_count > 0:
            gate_passed = False
        elif self.fail_on_high and high_count > 0:
            gate_passed = False
        elif overall_score >= self.risk_threshold:
            gate_passed = False

        # Build Interactive Dependency Graph (Nodes & Edges)
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        existing_nodes: Set[str] = set()

        for a in analyses:
            d = a.dependency
            if d.name not in existing_nodes:
                existing_nodes.add(d.name)
                nodes.append({
                    "id": d.name,
                    "name": d.name,
                    "version": d.version,
                    "latest_version": d.latest_version or d.version,
                    "ecosystem": d.ecosystem,
                    "is_direct": d.is_direct,
                    "depth": d.depth,
                    "has_vulns": a.has_vulnerabilities,
                    "vuln_count": len(a.vulnerabilities),
                    "highest_severity": a.highest_severity.value if a.has_vulnerabilities else "NONE",
                    "license": d.license,
                    "license_category": d.license_category,
                    "is_outdated": d.is_outdated,
                    "is_license_risk": d.is_license_risk,
                    "is_deprecated": d.is_deprecated,
                    "is_malicious": d.is_malicious,
                    "blast_radius": d.blast_radius_score
                })

            # Add edges for sub-dependencies or direct dependents
            for child_name in d.dependencies:
                edges.append({
                    "source": d.name,
                    "target": child_name,
                    "type": "depends_on"
                })
            for parent_name in d.direct_dependents:
                edges.append({
                    "source": parent_name,
                    "target": d.name,
                    "type": "transitive"
                })

        # Deduplicate edges
        unique_edges = []
        seen_edges = set()
        for e in edges:
            edge_key = (e["source"], e["target"])
            if edge_key not in seen_edges and e["source"] in existing_nodes and e["target"] in existing_nodes:
                seen_edges.add(edge_key)
                unique_edges.append(e)

        return RiskReport(
            target_path=str(target_path),
            dependencies=analyses,
            # 10 Dashboard Security Metrics
            overall_risk_score=overall_score,
            total_dependencies=total_deps,
            vulnerable_dependencies_count=vulnerable_deps_count,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            outdated_dependencies_count=outdated_count,
            license_compliance_issues_count=license_issues_count,
            transitive_dependencies_count=transitive_count,
            security_issues_fixed_count=fixed_issues_count,
            dependency_health_score=health_score,
            # Additional metadata
            deprecated_count=deprecated_count,
            malicious_count=malicious_count,
            risk_level=risk_level,
            severity_counts=severity_counts,
            quality_gate_passed=gate_passed,
            remediation_recommendations=list(remediations_map.values()),
            research_metrics=research_metrics,
            license_summary=license_summary,
            dependency_graph={"nodes": nodes, "edges": unique_edges}
        )
