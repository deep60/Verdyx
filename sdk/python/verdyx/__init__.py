"""Verdyx malware and URL scanning.

    from verdyx import Verdyx

    client = Verdyx()                      # reads VERDYX_API_KEY
    result = client.scan("suspicious.exe")
    print(result.verdict, result.report_url)
"""

__version__ = "0.1.0"

from .client import (  # noqa: E402
    DEFAULT_API_URL,
    DEFAULT_WEB_URL,
    EngineResult,
    ScanResult,
    ScanTimeoutError,
    Submission,
    Verdyx,
    VerdyxError,
    meets_threshold,
)

__all__ = [
    "DEFAULT_API_URL",
    "DEFAULT_WEB_URL",
    "EngineResult",
    "ScanResult",
    "ScanTimeoutError",
    "Submission",
    "Verdyx",
    "VerdyxError",
    "meets_threshold",
    "__version__",
]
