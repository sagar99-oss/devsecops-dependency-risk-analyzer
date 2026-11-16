import json
from pathlib import Path
from typing import Dict, Any
from ..models import RiskReport


class CycloneDXReporter:
    """Generates standard CycloneDX v1.4 SBOM (Software Bill of Materials) JSON format."""

    def export(self, report: RiskReport, output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        components = []
        vulnerabilities = []

        for dep_analysis in report.dependencies:
            dep = dep_analysis.dependency
            purl = f"pkg:{dep.ecosystem.lower()}/{dep.name}@{dep.version}"

            licenses = []
            if dep.license and dep.license != "Unknown":
                licenses.append({"license": {"id": dep.license, "name": dep.license}})

            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": purl,
                "bom-ref": purl,
                "licenses": licenses,
                "properties": [
                    {"name": "security:is_direct", "value": str(dep.is_direct).lower()},
                    {"name": "security:is_outdated", "value": str(dep.is_outdated).lower()},
                    {"name": "security:latest_version", "value": dep.latest_version or dep.version},
                    {"name": "security:license_category", "value": dep.license_category},
                ]
            }
            components.append(component)

            for v in dep_analysis.vulnerabilities:
                vuln_item = {
                    "id": v.vuln_id,
                    "source": {
                        "name": v.source,
                        "url": v.references[0] if v.references else "https://osv.dev"
                    },
                    "ratings": [{
                        "score": v.cvss_score,
                        "severity": v.severity.value.lower(),
                        "method": "CVSSv3"
                    }],
                    "description": v.summary,
                    "affects": [{
                        "ref": purl
                    }]
                }
                vulnerabilities.append(vuln_item)

        cyclonedx_data: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": report.scan_timestamp,
                "tools": [{
                    "vendor": "Software Dependency Security Analyzer",
                    "name": "Software Dependency Security Analyzer",
                    "version": "2.0.0"
                }],
                "component": {
                    "type": "application",
                    "name": report.target_path,
                    "version": "latest"
                }
            },
            "components": components,
            "vulnerabilities": vulnerabilities
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(cyclonedx_data, f, indent=2)

        return str(path)
