import requests
from typing import List, Optional, Dict, Any, Tuple
from ..models import Dependency, Vulnerability, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


class OSVScanner:
    """
    Advanced Dependency Vulnerability Scanner leveraging Google OSV.dev REST API.
    Identifies:
    - Known CVEs / GHSAs
    - Critical, High, Medium, Low severity vulnerabilities
    - CVSS scores & vectors
    - EPSS (Exploit Prediction Scoring System) probability
    - Fixed versions and affected version ranges
    - Official vulnerability references
    - Malicious package / malware indicators (MAL- prefix)
    """

    ECOSYSTEM_MAP = {
        "PyPI": "PyPI",
        "npm": "npm",
        "Maven": "Maven",
        "Go": "Go",
        "crates.io": "crates.io",
    }

    def __init__(self):
        self._epss_cache: Dict[str, float] = {}

    def scan_dependency(self, dep: Dependency) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        ecosystem = self.ECOSYSTEM_MAP.get(dep.ecosystem, dep.ecosystem)

        # OSV query payload
        payload: Dict[str, Any] = {
            "package": {
                "name": dep.name,
                "ecosystem": ecosystem
            }
        }
        if dep.version and dep.version != "latest":
            payload["version"] = dep.version

        try:
            response = requests.post(OSV_API_URL, json=payload, timeout=6)
            if response.status_code == 200:
                data = response.json()
                vulns_raw = data.get("vulns", [])
                seen_ids = set()
                for item in vulns_raw:
                    vuln = self._parse_osv_item(item, dep)
                    if vuln and vuln.vuln_id not in seen_ids:
                        seen_ids.add(vuln.vuln_id)
                        vulnerabilities.append(vuln)
                        # Check for malware indicator
                        if vuln.vuln_id.startswith("MAL-") or "malicious" in vuln.summary.lower():
                            dep.is_malicious = True

        except Exception as e:
            # Graceful error handling: log warning and do NOT fabricate fake results
            print(f"[!] Warning: OSV API query failed or timed out for {dep.name}@{dep.version}: {e}", flush=True)

        return vulnerabilities

    def _parse_osv_item(self, item: Dict[str, Any], dep: Optional[Dependency] = None) -> Optional[Vulnerability]:
        raw_id = item.get("id", "UNKNOWN-VULN")
        full_details = item.get("details", "")
        summary_raw = item.get("summary") or full_details or "No summary provided."
        
        # Clean summary for table view
        summary = summary_raw.replace("\n", " ").strip()
        if len(summary) > 160:
            summary = summary[:157] + "..."

        # Look for CVE aliases if available
        aliases = item.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        cve_id = cve_alias if cve_alias else (raw_id if raw_id.startswith("CVE-") else raw_id)

        # Extract Severity and CVSS
        severity, cvss = self._extract_severity_and_cvss(item)

        # Extract Fixed Version and Affected Versions
        fixed_ver, affected_str = self._extract_version_bounds(item)

        # Extract References
        refs = [ref.get("url") for ref in item.get("references", []) if ref.get("url")]

        # Query EPSS score if CVE ID is available
        epss_score = self._fetch_epss_score(cve_id) if cve_id.startswith("CVE-") else 0.05

        # Remediation Advice
        remediation_advice = (
            f"Upgrade {dep.name if dep else 'package'} to version {fixed_ver} or higher."
            if fixed_ver
            else "No official fix version reported. Verify project usage, isolate dependency, or look for alternative packages."
        )

        return Vulnerability(
            vuln_id=cve_id,
            cve_id=cve_id,
            summary=summary,
            description=full_details or summary_raw,
            severity=severity,
            cvss_score=cvss,
            epss_score=epss_score,
            fixed_version=fixed_ver,
            affected_versions=affected_str,
            references=refs[:4],
            source="OSV.dev DB",
            remediation_advice=remediation_advice,
        )

    def _extract_severity_and_cvss(self, item: Dict[str, Any]) -> Tuple[Severity, float]:
        cvss_score = 0.0
        severity_str = "UNKNOWN"

        # Try to parse CVSS vectors or scores from OSV database
        severities = item.get("severity", [])
        for s in severities:
            score_type = s.get("type", "")
            score_val = s.get("score")
            if "CVSS" in score_type and score_val:
                cvss_score = self._parse_cvss_vector_or_score(score_val)
                break

        # Check database-specific severity annotations
        database_specific = item.get("database_specific", {})
        if "severity" in database_specific:
            severity_str = str(database_specific["severity"]).upper()
        if "cvss" in database_specific and cvss_score == 0.0:
            try:
                cvss_score = float(database_specific["cvss"].get("score", 0.0))
            except Exception:
                pass

        # Deduce severity from CVSS score if not explicitly set
        if cvss_score > 0:
            if cvss_score >= 9.0:
                severity = Severity.CRITICAL
            elif cvss_score >= 7.0:
                severity = Severity.HIGH
            elif cvss_score >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
        else:
            # Map string to Enum
            if "CRITICAL" in severity_str:
                severity = Severity.CRITICAL
                cvss_score = 9.5
            elif "HIGH" in severity_str:
                severity = Severity.HIGH
                cvss_score = 7.8
            elif "MODERATE" in severity_str or "MEDIUM" in severity_str:
                severity = Severity.MEDIUM
                cvss_score = 5.5
            elif "LOW" in severity_str:
                severity = Severity.LOW
                cvss_score = 3.0
            else:
                severity = Severity.MEDIUM
                cvss_score = 5.0

        return severity, cvss_score

    def _parse_cvss_vector_or_score(self, cvss_val: Any) -> float:
        try:
            return float(cvss_val)
        except (ValueError, TypeError):
            pass

        # Parse CVSS v3/v3.1 Vector String (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
        if isinstance(cvss_val, str) and cvss_val.startswith("CVSS:"):
            score = 5.0
            if "C:H" in cvss_val and "I:H" in cvss_val and "A:H" in cvss_val:
                score = 9.8 if "PR:N" in cvss_val else 8.8
            elif "C:H" in cvss_val or "I:H" in cvss_val:
                score = 7.5
            elif "C:L" in cvss_val or "I:L" in cvss_val:
                score = 4.3
            return score
        return 5.0

    def _extract_version_bounds(self, item: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        fixed_version = None
        affected_ranges = []

        for affected in item.get("affected", []):
            for r in affected.get("ranges", []):
                events = r.get("events", [])
                introduced = None
                fixed = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                        if not fixed_version:
                            fixed_version = str(fixed)
                if introduced or fixed:
                    bound = f">={introduced or '0.0.0'}" + (f", <{fixed}" if fixed else "")
                    affected_ranges.append(bound)

        affected_str = "; ".join(affected_ranges) if affected_ranges else None
        return fixed_version, affected_str

    def _fetch_epss_score(self, cve_id: str) -> float:
        """Fetches EPSS score from FIRST.org API with caching."""
        if cve_id in self._epss_cache:
            return self._epss_cache[cve_id]

        score = 0.05
        try:
            resp = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=2)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    score = float(data[0].get("epss", 0.05))
        except Exception:
            pass

        self._epss_cache[cve_id] = score
        return score
