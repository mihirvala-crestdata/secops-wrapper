"""Pytest configuration and fixtures."""
import os
import sys
import pytest
from google_secops import SecOpsClient

# Add tests directory to Python path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)

@pytest.fixture
def client():
    """Create a SecOps client for testing."""
    return SecOpsClient() 