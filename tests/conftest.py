"""
pytest/unittest configuration and fixtures for pyos tests
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the parent directory is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestBase(unittest.TestCase):
    """Base test class with common setup and teardown"""
    
    def setUp(self):
        """Common setup for all tests"""
        self.mock_cherrypy_request = MagicMock()
        self.mock_cherrypy_response = MagicMock()
        
    def tearDown(self):
        """Common teardown for all tests"""
        pass


# Mock fixtures for CherryPy components if needed
def create_mock_cherrypy_context():
    """Create a mock CherryPy context for testing"""
    mock_request = MagicMock()
    mock_response = MagicMock()
    mock_request.json = {}
    mock_response.headers = {}
    mock_response.status = 200
    return mock_request, mock_response
