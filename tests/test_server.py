from fastapi.testclient import TestClient
from server import app

client = TestClient(app)


def test_api_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "Software Dependency Security Analyzer" in data["service"]


def test_api_analytics_endpoint():
    response = client.get("/api/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "avg_risk_score" in data
    assert "trend" in data


def test_api_scans_list_endpoint():
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_api_file_upload_scan(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\n", encoding="utf-8")

    with open(req_file, "rb") as f:
        response = client.post(
            "/api/scan/file",
            files={"file": ("requirements.txt", f, "text/plain")}
        )

    assert response.status_code == 200
    data = response.json()
    assert "overall_risk_score" in data
    assert "scan_id" in data
    assert data["total_dependencies"] >= 1
    assert "dependency_health_score" in data

    # Test export endpoints
    scan_id = data["scan_id"]
    res_html = client.get(f"/api/scans/{scan_id}/export/html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers.get("content-type", "")

    res_json = client.get(f"/api/scans/{scan_id}/export/json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers.get("content-type", "")

    res_sarif = client.get(f"/api/scans/{scan_id}/export/sarif")
    assert res_sarif.status_code == 200


def test_api_compare_endpoint(tmp_path):
    # Upload scan 1
    f1 = tmp_path / "req1.txt"
    f1.write_text("requests==2.25.1\n", encoding="utf-8")
    with open(f1, "rb") as f:
        res1 = client.post("/api/scan/file", files={"file": ("requirements.txt", f, "text/plain")})
    id1 = res1.json()["scan_id"]

    # Upload scan 2
    f2 = tmp_path / "req2.txt"
    f2.write_text("requests==2.31.0\n", encoding="utf-8")
    with open(f2, "rb") as f:
        res2 = client.post("/api/scan/file", files={"file": ("requirements.txt", f, "text/plain")})
    id2 = res2.json()["scan_id"]

    # Compare
    res_cmp = client.get(f"/api/scans/compare?scan_a={id1}&scan_b={id2}")
    assert res_cmp.status_code == 200
    cmp_data = res_cmp.json()
    assert "deltas" in cmp_data
    assert "newly_introduced_vulnerabilities" in cmp_data
    assert "resolved_vulnerabilities" in cmp_data
