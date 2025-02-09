"""Google SecOps SDK for Python."""

__version__ = "0.1.1"

from secops.client import SecOpsClient
from secops.auth import SecOpsAuth

__all__ = ["SecOpsClient", "SecOpsAuth"] 