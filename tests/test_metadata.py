from analyzer.metadata import PackageMetadataService
from analyzer.models import Dependency


def test_license_categorization():
    service = PackageMetadataService()

    # Permissive licenses
    name, cat, is_risk = service.categorize_license("MIT")
    assert cat == "Permissive"
    assert is_risk is False

    name, cat, is_risk = service.categorize_license("Apache-2.0")
    assert cat == "Permissive"
    assert is_risk is False

    # Strong Copyleft
    name, cat, is_risk = service.categorize_license("GPL-3.0")
    assert "Copyleft" in cat
    assert is_risk is True

    name, cat, is_risk = service.categorize_license("AGPL-3.0")
    assert "Copyleft" in cat
    assert is_risk is True

    # Unknown
    name, cat, is_risk = service.categorize_license(None)
    assert cat == "Unknown"
    assert is_risk is True


def test_outdated_version_comparison():
    service = PackageMetadataService()

    # 1.0.0 < 2.0.0 -> True
    assert service.is_version_outdated("1.0.0", "2.0.0") is True

    # 2.32.0 < 2.32.3 -> True
    assert service.is_version_outdated("2.32.0", "2.32.3") is True

    # 3.0.0 is not < 2.5.0 -> False
    assert service.is_version_outdated("3.0.0", "2.5.0") is False

    # same version -> False
    assert service.is_version_outdated("1.2.3", "1.2.3") is False


def test_enrich_dependency():
    service = PackageMetadataService()
    dep = Dependency(name="requests", version="2.25.1", ecosystem="PyPI")

    service.enrich_dependency(dep)

    assert dep.license == "Apache-2.0"
    assert dep.license_category == "Permissive"
    assert dep.is_license_risk is False
    assert dep.is_outdated is True
    assert len(dep.dependencies) > 0  # has sub-dependencies like urllib3
