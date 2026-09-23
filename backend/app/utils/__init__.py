"""Utility package for OSINT Platform."""
from backend.app.utils.domain import (
    normalize_domain,
    is_valid_domain,
    is_subdomain_of,
)

__all__ = [
    "normalize_domain",
    "is_valid_domain",
    "is_subdomain_of",
]
