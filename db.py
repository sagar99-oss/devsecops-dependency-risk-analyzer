import os
import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from analyzer.models import RiskReport

DB_PATH = Path(os.environ.get("DB_PATH", Path(__file__).parent / "devsecops.db"))


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_name TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL,
                overall_risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                total_dependencies INTEGER NOT NULL,
                vulnerable_dependencies_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                outdated_count INTEGER DEFAULT 0,
                license_issues_count INTEGER DEFAULT 0,
                transitive_count INTEGER DEFAULT 0,
                fixed_issues_count INTEGER DEFAULT 0,
                health_score REAL DEFAULT 100.0,
                quality_gate_passed INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        # Backward-compatible migrations for existing SQLite databases
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(scans)")
        columns = [row["name"] for row in cursor.fetchall()]

        new_columns = [
            ("outdated_count", "INTEGER DEFAULT 0"),
            ("license_issues_count", "INTEGER DEFAULT 0"),
            ("transitive_count", "INTEGER DEFAULT 0"),
            ("fixed_issues_count", "INTEGER DEFAULT 0"),
            ("health_score", "REAL DEFAULT 100.0"),
        ]
        for col_name, col_type in new_columns:
            if col_name not in columns:
                try:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass
        conn.commit()


def save_scan_record(report: RiskReport) -> int:
    init_db()
    report_dict = report.to_dict()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                target_name, scan_timestamp, overall_risk_score, risk_level,
                total_dependencies, vulnerable_dependencies_count,
                critical_count, high_count, medium_count, low_count,
                outdated_count, license_issues_count, transitive_count,
                fixed_issues_count, health_score,
                quality_gate_passed, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.target_path,
            report.scan_timestamp,
            report.overall_risk_score,
            report.risk_level,
            report.total_dependencies,
            report.vulnerable_dependencies_count,
            report.critical_count if hasattr(report, "critical_count") else report.severity_counts.get("CRITICAL", 0),
            report.high_count if hasattr(report, "high_count") else report.severity_counts.get("HIGH", 0),
            report.medium_count if hasattr(report, "medium_count") else report.severity_counts.get("MEDIUM", 0),
            report.low_count if hasattr(report, "low_count") else report.severity_counts.get("LOW", 0),
            getattr(report, "outdated_dependencies_count", 0),
            getattr(report, "license_compliance_issues_count", 0),
            getattr(report, "transitive_dependencies_count", 0),
            getattr(report, "security_issues_fixed_count", 0),
            getattr(report, "dependency_health_score", 100.0),
            1 if report.quality_gate_passed else 0,
            json.dumps(report_dict)
        ))
        conn.commit()
        return cursor.lastrowid


def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target_name, scan_timestamp, overall_risk_score, risk_level,
                   total_dependencies, vulnerable_dependencies_count,
                   critical_count, high_count, medium_count, low_count,
                   outdated_count, license_issues_count, transitive_count,
                   fixed_issues_count, health_score, quality_gate_passed
            FROM scans ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row:
            res = dict(row)
            try:
                res["report"] = json.loads(res["report_json"])
            except Exception:
                res["report"] = {}
            return res
        return None


def compare_scans(scan_id_a: int, scan_id_b: int) -> Optional[Dict[str, Any]]:
    """
    Compares two scans (Scan A as baseline, Scan B as current/comparison).
    Returns score deltas, newly introduced vulnerabilities, resolved vulnerabilities,
    persisting vulnerabilities, and dependency changes.
    """
    scan_a = get_scan_by_id(scan_id_a)
    scan_b = get_scan_by_id(scan_id_b)

    if not scan_a or not scan_b:
        return None

    rep_a = scan_a.get("report", {})
    rep_b = scan_b.get("report", {})

    score_a = rep_a.get("overall_risk_score", scan_a.get("overall_risk_score", 0.0))
    score_b = rep_b.get("overall_risk_score", scan_b.get("overall_risk_score", 0.0))
    risk_delta = round(score_b - score_a, 1)

    health_a = rep_a.get("dependency_health_score", 100.0)
    health_b = rep_b.get("dependency_health_score", 100.0)
    health_delta = round(health_b - health_a, 1)

    # Extract all vulnerabilities from Scan A
    vulns_a = {}
    deps_a = {}
    for item in rep_a.get("dependencies", []):
        dep = item.get("dependency", {})
        deps_a[dep.get("name", "").lower()] = dep.get("version", "")
        for v in item.get("vulnerabilities", []):
            vid = v.get("vuln_id") or v.get("cve_id", "")
            key = f"{dep.get('name')}::{vid}"
            vulns_a[key] = {
                "package": dep.get("name"),
                "version": dep.get("version"),
                "vuln_id": vid,
                "severity": v.get("severity", "MEDIUM"),
                "cvss_score": v.get("cvss_score", 0.0),
                "summary": v.get("summary", "")
            }

    # Extract all vulnerabilities from Scan B
    vulns_b = {}
    deps_b = {}
    for item in rep_b.get("dependencies", []):
        dep = item.get("dependency", {})
        deps_b[dep.get("name", "").lower()] = dep.get("version", "")
        for v in item.get("vulnerabilities", []):
            vid = v.get("vuln_id") or v.get("cve_id", "")
            key = f"{dep.get('name')}::{vid}"
            vulns_b[key] = {
                "package": dep.get("name"),
                "version": dep.get("version"),
                "vuln_id": vid,
                "severity": v.get("severity", "MEDIUM"),
                "cvss_score": v.get("cvss_score", 0.0),
                "summary": v.get("summary", "")
            }

    # Compare vulnerabilities
    newly_introduced = [vulns_b[k] for k in vulns_b if k not in vulns_a]
    resolved = [vulns_a[k] for k in vulns_a if k not in vulns_b]
    persisting = [vulns_b[k] for k in vulns_b if k in vulns_a]

    # Compare dependency versions
    added_deps = [name for name in deps_b if name not in deps_a]
    removed_deps = [name for name in deps_a if name not in deps_b]
    updated_deps = []
    for name in deps_b:
        if name in deps_a and deps_a[name] != deps_b[name]:
            updated_deps.append({
                "package": name,
                "old_version": deps_a[name],
                "new_version": deps_b[name]
            })

    return {
        "scan_a": {
            "id": scan_a["id"],
            "target": scan_a["target_name"],
            "timestamp": scan_a["scan_timestamp"],
            "risk_score": score_a,
            "health_score": health_a,
            "total_dependencies": rep_a.get("total_dependencies", scan_a["total_dependencies"]),
            "vulnerable_dependencies": rep_a.get("vulnerable_dependencies_count", scan_a["vulnerable_dependencies_count"]),
            "quality_gate_passed": bool(scan_a["quality_gate_passed"])
        },
        "scan_b": {
            "id": scan_b["id"],
            "target": scan_b["target_name"],
            "timestamp": scan_b["scan_timestamp"],
            "risk_score": score_b,
            "health_score": health_b,
            "total_dependencies": rep_b.get("total_dependencies", scan_b["total_dependencies"]),
            "vulnerable_dependencies": rep_b.get("vulnerable_dependencies_count", scan_b["vulnerable_dependencies_count"]),
            "quality_gate_passed": bool(scan_b["quality_gate_passed"])
        },
        "deltas": {
            "risk_score_delta": risk_delta,
            "health_score_delta": health_delta,
            "is_improved": risk_delta < 0,
            "total_new_vulnerabilities": len(newly_introduced),
            "total_resolved_vulnerabilities": len(resolved),
            "total_persisting_vulnerabilities": len(persisting),
        },
        "newly_introduced_vulnerabilities": newly_introduced,
        "resolved_vulnerabilities": resolved,
        "persisting_vulnerabilities": persisting,
        "dependency_changes": {
            "added": added_deps,
            "removed": removed_deps,
            "updated": updated_deps
        }
    }


def get_analytics_summary() -> Dict[str, Any]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                AVG(overall_risk_score) as avg_risk_score,
                SUM(critical_count) as total_critical,
                SUM(high_count) as total_high,
                SUM(medium_count) as total_medium,
                SUM(low_count) as total_low,
                SUM(CASE WHEN quality_gate_passed = 1 THEN 1 ELSE 0 END) as passed_scans,
                SUM(CASE WHEN quality_gate_passed = 0 THEN 1 ELSE 0 END) as failed_scans
            FROM scans
        """)
        row = cursor.fetchone()
        stats = dict(row) if row else {}

        # Fetch recent 15 risk scores for trend chart
        cursor.execute("SELECT id, scan_timestamp, overall_risk_score, target_name FROM scans ORDER BY id ASC LIMIT 15")
        trend_rows = cursor.fetchall()
        trend = [dict(r) for r in trend_rows]

        return {
            "total_scans": stats.get("total_scans") or 0,
            "avg_risk_score": round(stats.get("avg_risk_score") or 0.0, 1),
            "total_critical": stats.get("total_critical") or 0,
            "total_high": stats.get("total_high") or 0,
            "total_medium": stats.get("total_medium") or 0,
            "total_low": stats.get("total_low") or 0,
            "passed_scans": stats.get("passed_scans") or 0,
            "failed_scans": stats.get("failed_scans") or 0,
            "trend": trend,
        }
