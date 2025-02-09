"""Authentication handling for Google SecOps SDK."""
from typing import Optional, Dict, Any, List
from google.auth.credentials import Credentials
from google.oauth2 import service_account
import google.auth
from google_secops.exceptions import AuthenticationError

# Define default scopes needed for Chronicle API
CHRONICLE_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform"
]

class SecOpsAuth:
    """Handles authentication for the Google SecOps SDK."""

    def __init__(
        self,
        credentials: Optional[Credentials] = None,
        service_account_path: Optional[str] = None,
        service_account_info: Optional[Dict[str, Any]] = None,
        scopes: Optional[List[str]] = None
    ):
        """Initialize authentication for SecOps.
        
        Args:
            credentials: Optional pre-existing Google Auth credentials
            service_account_path: Optional path to service account JSON key file
            service_account_info: Optional service account JSON key data as dict
            scopes: Optional list of OAuth scopes to request
        """
        self.scopes = scopes or CHRONICLE_SCOPES
        self.credentials = self._get_credentials(
            credentials, 
            service_account_path,
            service_account_info
        )

    def _get_credentials(
        self,
        credentials: Optional[Credentials],
        service_account_path: Optional[str],
        service_account_info: Optional[Dict[str, Any]]
    ) -> Credentials:
        """Get credentials from various sources."""
        try:
            if credentials:
                return credentials.with_scopes(self.scopes)
            
            if service_account_info:
                return service_account.Credentials.from_service_account_info(
                    service_account_info,
                    scopes=self.scopes
                )
            
            if service_account_path:
                return service_account.Credentials.from_service_account_file(
                    service_account_path,
                    scopes=self.scopes
                )
            
            # Try to get default credentials
            credentials, project = google.auth.default(scopes=self.scopes)
            return credentials
        except Exception as e:
            raise AuthenticationError(f"Failed to get credentials: {str(e)}") 