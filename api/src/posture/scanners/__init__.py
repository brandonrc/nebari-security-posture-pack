"""Scanner adapters (trivy, grype, clair)."""

from .base import Finding, ScanResult, Scanner
from .clair import ClairScanner
from .grype import GrypeScanner
from .trivy import TrivyScanner

SCANNER_NAMES = ("trivy", "grype", "clair")

__all__ = ["Finding", "ScanResult", "Scanner", "TrivyScanner", "GrypeScanner", "ClairScanner", "SCANNER_NAMES"]
