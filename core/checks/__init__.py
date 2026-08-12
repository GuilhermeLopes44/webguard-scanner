from __future__ import annotations

from core.checks.base import BaseCheck
from core.checks.cookie_flags import CookieFlagsCheck
from core.checks.cors_misconfig import CorsMisconfigCheck
from core.checks.csrf_heuristic import CsrfHeuristicCheck
from core.checks.open_redirect import OpenRedirectCheck
from core.checks.security_headers import SecurityHeadersCheck
from core.checks.sensitive_paths import SensitivePathsCheck
from core.checks.sqli_error import SqliErrorCheck
from core.checks.tech_detect import TechDetectCheck
from core.checks.xss_reflected import XssReflectedCheck

ALL_CHECKS: list[type[BaseCheck]] = [
    SecurityHeadersCheck,
    CookieFlagsCheck,
    TechDetectCheck,
    XssReflectedCheck,
    SqliErrorCheck,
    OpenRedirectCheck,
    CorsMisconfigCheck,
    SensitivePathsCheck,
    CsrfHeuristicCheck,
]


def get_enabled_checks(enabled_ids: list[str]) -> list[BaseCheck]:
    enabled = set(enabled_ids)
    return [cls() for cls in ALL_CHECKS if cls.check_id in enabled]
