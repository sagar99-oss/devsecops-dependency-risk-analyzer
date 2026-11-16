import json
from pathlib import Path
from ..models import RiskReport


class SARIFReporter:
    """Exports scan results to SARIF (Static Analysis Results Interchange Format) for GitHub Code Scanning."""

    def export(self, report: RiskReport, output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        rules = []
        results = []
        seen_rules = set()

        for dep_analysis in report.dependencies:
            dep = dep_analysis.dependency
            for vuln in dep_analysis.vulnerabilities:
                rule_id = vuln.vuln_id
                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    rules.append({
                        "id": rule_id,
                        "shortDescription": {"text": f"Vulnerability in {dep.name}: {rule_id}"},
                        "fullDescription": {"text": vuln.summary},
                        "help": {"text": vuln.description or vuln.summary},
                        "helpUri": vuln.references[0] if vuln.references else f"https://osv.dev/vulnerability/{rule_id}",
                        "properties": {
                            "cvss": vuln.cvss_score,
                            "severity": vuln.severity.value,
                            "package": dep.name,
                            "fixed_version": vuln.fixed_version or "None"
                        },
                        "defaultConfiguration": {
                            "level": "error" if vuln.severity.value in ["CRITICAL", "HIGH"] else "warning"
                        }
                    })

                results.append({
                    "ruleId": rule_id,
                    "message": {"text": f"Package {dep.name}@{dep.version} is vulnerable to {rule_id}. {vuln.summary}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": dep.file_origin or "dependency-manifest"},
                        }
                    }]
                })

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Software Dependency Security Analyzer",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/DevSecOps/software-dependency-security-analyzer",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

        return str(path)
