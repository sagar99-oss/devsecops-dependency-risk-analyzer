import os
import shutil
import tempfile
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from analyzer.parsers import find_and_parse
from analyzer.scanners import ScanManager
from analyzer.scoring import RiskEngine
from analyzer.reporters import HTMLReporter, JSONReporter, SARIFReporter, CycloneDXReporter
from analyzer.github import GitHubFetcher
from analyzer.models import RiskReport, DependencyAnalysis, Dependency, Vulnerability, Severity, ReachabilityStatus
import db

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("security_analyzer")

app = FastAPI(
    title="Software Dependency Security Analyzer API",
    description="REST API & Dashboard Server for Software Dependency Vulnerability Scanning, License Compliance & Risk Scoring",
    version="2.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database
db.init_db()

# Mount Web Dashboard Frontend Assets
WEB_DIR = Path(__file__).parent / "web"
WEB_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


class GitHubScanRequest(BaseModel):
    url: str
    branch: Optional[str] = "main"
    token: Optional[str] = None
    threshold: Optional[float] = 70.0
    fail_on_critical: Optional[bool] = True


@app.get("/", response_class=HTMLResponse)
def read_root():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Software Dependency Security Analyzer API is running.</h1><p>Frontend template initializing...</p>")


@app.get("/api/health")
def health_check():
    """Health check and service status."""
    return {
        "status": "healthy",
        "service": "Software Dependency Security Analyzer",
        "version": "2.0.0",
        "database": "sqlite_connected",
        "engines": {
            "osv_scanner": "active",
            "epss_service": "active",
            "license_analyzer": "active",
            "ast_reachability": "active",
            "dag_blast_radius": "active",
            "zero_day_predictor": "active",
            "ast_diff_analyzer": "active"
        }
    }


ALLOWED_EXTENSIONS = {".txt", ".req", ".json", ".xml", ".toml", ".lock", ".mod"}
ALLOWED_FILENAMES = {"requirements.txt", "package.json", "pom.xml", "pyproject.toml", "cargo.lock", "go.mod"}


@app.post("/api/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    threshold: float = Form(70.0),
    fail_on_critical: bool = Form(True)
):
    """Scan an uploaded dependency manifest file (requirements.txt, package.json, pom.xml, pyproject.toml)."""
    filename = file.filename or "manifest.txt"
    suffix = Path(filename).suffix.lower()
    lower_name = Path(filename).name.lower()

    if suffix not in ALLOWED_EXTENSIONS and lower_name not in ALLOWED_FILENAMES and "requirement" not in lower_name:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{filename}'. Supported formats: requirements.txt, package.json, pom.xml, pyproject.toml."
        )

    temp_dir = Path(tempfile.mkdtemp(prefix="sec_upload_"))
    try:
        file_path = temp_dir / filename
        content = await file.read()
        if not content or len(content.strip()) == 0:
            raise HTTPException(status_code=400, detail=f"File '{filename}' is empty.")
        if len(content) > 25 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Uploaded manifest exceeds maximum size of 25MB.")

        with open(file_path, "wb") as buffer:
            buffer.write(content)

        logger.info(f"Parsing uploaded manifest: {filename}")
        dependencies = find_and_parse(file_path)
        if not dependencies:
            raise HTTPException(status_code=400, detail=f"No parseable dependencies found in file '{filename}'.")

        logger.info(f"Scanning {len(dependencies)} dependencies from {filename}")
        scanner = ScanManager()
        analyses = scanner.scan_dependencies(dependencies)

        risk_engine = RiskEngine(risk_threshold=threshold, fail_on_critical=fail_on_critical)
        report = risk_engine.evaluate(filename, analyses)

        scan_id = db.save_scan_record(report)
        result = report.to_dict()
        result["scan_id"] = scan_id

        logger.info(f"Scan completed for {filename} (ID: {scan_id}, Risk: {report.overall_risk_score})")
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning file {filename}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/scan/github")
def scan_github(req: GitHubScanRequest):
    """Scan a remote public or private GitHub repository."""
    url = req.url.strip()
    if not url or "github.com" not in url.lower():
        raise HTTPException(status_code=400, detail="Please provide a valid GitHub repository URL.")

    fetcher = GitHubFetcher()
    try:
        logger.info(f"Fetching manifests from GitHub: {url} (branch: {req.branch})")
        temp_dir = fetcher.fetch_repo_manifests(url, branch=req.branch, token=req.token)
        dependencies = find_and_parse(temp_dir)
        if not dependencies:
            raise HTTPException(status_code=400, detail=f"No supported dependency manifests found in repository '{url}'.")

        logger.info(f"Found {len(dependencies)} dependencies in GitHub repo. Commencing scan...")
        scanner = ScanManager()
        analyses = scanner.scan_dependencies(dependencies)

        fail_on_critical = req.fail_on_critical if req.fail_on_critical is not None else True
        risk_engine = RiskEngine(risk_threshold=req.threshold or 70.0, fail_on_critical=fail_on_critical)
        report = risk_engine.evaluate(url, analyses)

        scan_id = db.save_scan_record(report)
        result = report.to_dict()
        result["scan_id"] = scan_id

        logger.info(f"GitHub scan completed for {url} (ID: {scan_id}, Risk: {report.overall_risk_score})")
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitHub scan error for {url}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
def list_scans(limit: int = 50):
    """Get list of past scans."""
    return db.get_all_scans(limit=limit)


@app.get("/api/scans/compare")
def compare_scans(
    scan_a: int = Query(..., description="Baseline Scan ID"),
    scan_b: int = Query(..., description="Target Scan ID to compare")
):
    """Compare two scans: calculate score deltas, newly introduced and resolved vulnerabilities."""
    comparison = db.compare_scans(scan_a, scan_b)
    if not comparison:
        raise HTTPException(status_code=404, detail="One or both scan records not found for comparison.")
    return comparison


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    """Get full scan details by ID."""
    record = db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return record


@app.get("/api/scans/{scan_id}/export/{export_format}")
def export_scan_report(scan_id: int, export_format: str):
    """Export scan report in HTML, JSON, or SARIF format."""
    record = db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    report_dict = record["report"]
    temp_dir = Path(tempfile.mkdtemp(prefix="sec_export_"))

    export_format = export_format.lower()
    if export_format == "json":
        json_file = temp_dir / f"scan_{scan_id}_report.json"
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(record["report_json"])
        return FileResponse(json_file, media_type="application/json", filename=f"scan_{scan_id}_security_report.json")

    elif export_format == "html":
        report_obj = _dict_to_risk_report(report_dict)
        html_file = temp_dir / f"scan_{scan_id}_report.html"
        HTMLReporter().export(report_obj, str(html_file))
        return FileResponse(html_file, media_type="text/html", filename=f"scan_{scan_id}_security_report.html")

    elif export_format == "sarif":
        report_obj = _dict_to_risk_report(report_dict)
        sarif_file = temp_dir / f"scan_{scan_id}_report.sarif"
        SARIFReporter().export(report_obj, str(sarif_file))
        return FileResponse(sarif_file, media_type="application/json", filename=f"scan_{scan_id}_security_report.sarif")

    elif export_format in ["cyclonedx", "sbom"]:
        report_obj = _dict_to_risk_report(report_dict)
        cyclonedx_file = temp_dir / f"scan_{scan_id}_cyclonedx.json"
        CycloneDXReporter().export(report_obj, str(cyclonedx_file))
        return FileResponse(cyclonedx_file, media_type="application/json", filename=f"scan_{scan_id}_cyclonedx.json")

    else:
        raise HTTPException(status_code=400, detail="Invalid export format. Choose html, json, sarif, or cyclonedx.")


@app.post("/api/scans/{scan_id}/push-dependency-track")
def push_to_dependency_track(scan_id: int, server_url: str = Form(...), api_key: str = Form(...), project_id: str = Form(...)):
    """Pushes CycloneDX SBOM directly to OWASP Dependency-Track instance."""
    record = db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    import requests
    report_obj = _dict_to_risk_report(record["report"])
    temp_dir = Path(tempfile.mkdtemp(prefix="sec_dtrack_"))
    sbom_file = temp_dir / "sbom.json"
    CycloneDXReporter().export(report_obj, str(sbom_file))

    try:
        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom_json = f.read()

        import base64
        b64_bom = base64.b64encode(sbom_json.encode("utf-8")).decode("utf-8")

        payload = {"project": project_id, "bom": b64_bom}
        headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}

        target_endpoint = f"{server_url.rstrip('/')}/api/v1/bom"
        resp = requests.put(target_endpoint, json=payload, headers=headers, timeout=10)

        if resp.status_code in [200, 201, 202]:
            return {"status": "success", "message": "Successfully uploaded SBOM to OWASP Dependency-Track"}
        else:
            raise HTTPException(status_code=resp.status_code, detail=f"OWASP Dependency-Track response: {resp.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/api/analytics")
def get_analytics():
    """Get aggregate security analytics for dashboard charts."""
    return db.get_analytics_summary()


def _dict_to_risk_report(d: dict) -> RiskReport:
    deps = []
    for item in d.get("dependencies", []):
        dep_data = item.get("dependency", {})
        dep = Dependency(
            name=dep_data.get("name", ""),
            version=dep_data.get("version", ""),
            ecosystem=dep_data.get("ecosystem", ""),
            is_direct=dep_data.get("is_direct", True),
            is_dev_dependency=dep_data.get("is_dev_dependency", False),
            file_origin=dep_data.get("file_origin", ""),
            depth=dep_data.get("depth", 1),
            blast_radius_score=dep_data.get("blast_radius_score", 0.0),
            zero_day_risk_score=dep_data.get("zero_day_risk_score", 0.0),
            latest_version=dep_data.get("latest_version"),
            is_outdated=dep_data.get("is_outdated", False),
            license=dep_data.get("license", "Unknown"),
            license_category=dep_data.get("license_category", "Unknown"),
            is_license_risk=dep_data.get("is_license_risk", False),
            is_deprecated=dep_data.get("is_deprecated", False),
            is_malicious=dep_data.get("is_malicious", False),
            unmaintained=dep_data.get("unmaintained", False),
            dependencies=dep_data.get("dependencies", []),
            direct_dependents=dep_data.get("direct_dependents", [])
        )
        vulns = []
        for v in item.get("vulnerabilities", []):
            sev_str = v.get("severity", "UNKNOWN")
            sev_enum = getattr(Severity, sev_str, Severity.MEDIUM)
            vulns.append(Vulnerability(
                vuln_id=v.get("vuln_id", ""),
                summary=v.get("summary", ""),
                severity=sev_enum,
                cvss_score=v.get("cvss_score", 0.0),
                epss_score=v.get("epss_score", 0.0),
                fixed_version=v.get("fixed_version"),
                affected_versions=v.get("affected_versions"),
                references=v.get("references", []),
                source=v.get("source", "OSV DB"),
                cve_id=v.get("cve_id"),
                description=v.get("description"),
                remediation_advice=v.get("remediation_advice")
            ))
        deps.append(DependencyAnalysis(
            dependency=dep,
            vulnerabilities=vulns,
            breaking_change_risk=item.get("breaking_change_risk", 0.0),
            is_reachable=item.get("is_reachable", True)
        ))

    sev_counts = d.get("severity_counts", {})
    return RiskReport(
        target_path=d.get("target_path", ""),
        scan_timestamp=d.get("scan_timestamp", ""),
        dependencies=deps,
        overall_risk_score=d.get("overall_risk_score", 0.0),
        risk_level=d.get("risk_level", "LOW"),
        total_dependencies=d.get("total_dependencies", len(deps)),
        vulnerable_dependencies_count=d.get("vulnerable_dependencies_count", sum(1 for a in deps if a.has_vulnerabilities)),
        critical_count=d.get("critical_count", sev_counts.get("CRITICAL", 0)),
        high_count=d.get("high_count", sev_counts.get("HIGH", 0)),
        medium_count=d.get("medium_count", sev_counts.get("MEDIUM", 0)),
        low_count=d.get("low_count", sev_counts.get("LOW", 0)),
        outdated_dependencies_count=d.get("outdated_dependencies_count", 0),
        license_compliance_issues_count=d.get("license_compliance_issues_count", 0),
        transitive_dependencies_count=d.get("transitive_dependencies_count", 0),
        security_issues_fixed_count=d.get("security_issues_fixed_count", 0),
        dependency_health_score=d.get("dependency_health_score", 100.0),
        deprecated_count=d.get("deprecated_count", 0),
        malicious_count=d.get("malicious_count", 0),
        severity_counts=sev_counts,
        quality_gate_passed=d.get("quality_gate_passed", True),
        remediation_recommendations=d.get("remediation_recommendations", []),
        license_summary=d.get("license_summary", {}),
        dependency_graph=d.get("dependency_graph", {"nodes": [], "edges": []})
    )
