from pathlib import Path
from typing import List, Set, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from .osv_scanner import OSVScanner
from .trivy_scanner import TrivyScanner
from ..metadata import PackageMetadataService
from ..models import Dependency, DependencyAnalysis


class ScanManager:
    """Coordinates dependency parsing, metadata enrichment, and vulnerability scanning."""

    def __init__(self, max_workers: int = 10):
        self.osv_scanner = OSVScanner()
        self.trivy_scanner = TrivyScanner()
        self.metadata_service = PackageMetadataService()
        self.max_workers = max_workers

    def scan_dependencies(self, dependencies: List[Dependency]) -> List[DependencyAnalysis]:
        # Step 1: Enrich direct dependencies with metadata (license, latest version, outdated, sub-dependencies)
        for dep in dependencies:
            self.metadata_service.enrich_dependency(dep)

        # Step 2: Build complete dependency list including detected transitive dependencies
        expanded_dependencies = self._resolve_transitive_hierarchy(dependencies)

        # Step 3: Scan all dependencies across OSV database concurrently
        analyses: List[DependencyAnalysis] = []

        def _scan_dep(dep: Dependency) -> DependencyAnalysis:
            vulns = self.osv_scanner.scan_dependency(dep)
            return DependencyAnalysis(dependency=dep, vulnerabilities=vulns)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dep = {executor.submit(_scan_dep, dep): dep for dep in expanded_dependencies}
            for future in as_completed(future_to_dep):
                try:
                    analysis = future.result()
                    analyses.append(analysis)
                except Exception as e:
                    dep = future_to_dep[future]
                    print(f"[!] Warning scanning {dep.name}: {e}", flush=True)

        return analyses

    def _resolve_transitive_hierarchy(self, dependencies: List[Dependency]) -> List[Dependency]:
        """
        Builds direct and transitive relationship hierarchy and DAG graph edges.
        If a package has sub-dependencies, creates/links transitive Dependency objects.
        """
        dep_map: Dict[str, Dependency] = {d.name.lower(): d for d in dependencies}
        transitive_deps: List[Dependency] = []
        seen_keys: Set[str] = {d.key for d in dependencies}

        for direct_dep in list(dependencies):
            for sub_name in direct_dep.dependencies:
                sub_clean = sub_name.strip()
                if not sub_clean:
                    continue

                # If child already in scanned list, link direct_dependents
                if sub_clean.lower() in dep_map:
                    child_dep = dep_map[sub_clean.lower()]
                    if direct_dep.name not in child_dep.direct_dependents:
                        child_dep.direct_dependents.append(direct_dep.name)
                else:
                    # Create transitive dependency node
                    t_dep = Dependency(
                        name=sub_clean,
                        version="latest",
                        ecosystem=direct_dep.ecosystem,
                        is_direct=False,
                        depth=direct_dep.depth + 1,
                        file_origin=direct_dep.file_origin,
                        direct_dependents=[direct_dep.name]
                    )
                    if t_dep.key not in seen_keys:
                        seen_keys.add(t_dep.key)
                        self.metadata_service.enrich_dependency(t_dep)
                        transitive_deps.append(t_dep)
                        dep_map[sub_clean.lower()] = t_dep

        # Return full set of direct + transitive dependencies
        return dependencies + transitive_deps
