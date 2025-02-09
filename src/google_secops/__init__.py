"""Google SecOps SDK for Python."""

__version__ = "0.1.0"

from google_secops.client import SecOpsClient
from google_secops.auth import SecOpsAuth

__all__ = ["SecOpsClient", "SecOpsAuth"] 