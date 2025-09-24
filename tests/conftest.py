"""
Pytest configuration and fixtures for the GitHub Advisory Database Scraper tests.
"""
import pytest
import tempfile
import shutil
import os
import json
import logging
from unittest.mock import Mock, patch
import sys
from pathlib import Path

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from helpers import setup_logging, create_csv, zip_files, create_dir
from advisory_scraper import AdvisoryScraper, CISAAdvisoryScraper


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_advisory():
    """Sample advisory data for testing."""
    return {
        'ghsa_id': 'GHSA-test-123',
        'cve_id': 'CVE-2023-12345',
        'summary': 'Test vulnerability',
        'severity': 'high',
        'source_code_location': 'https://github.com/test/repo',
        'nvd_published_at': '2023-01-01T00:00:00Z',
        'references': ['https://github.com/test/repo/security/advisories/1'],
        'cvss': {'score': 7.5, 'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
        'epss': 0.123,
        'kev': '0'
    }


@pytest.fixture
def sample_advisories_list(sample_advisory):
    """List of sample advisories for testing."""
    return [
        sample_advisory,
        {
            'ghsa_id': 'GHSA-test-456',
            'cve_id': 'CVE-2023-67890',
            'summary': 'Another test vulnerability',
            'severity': 'critical',
            'source_code_location': 'https://github.com/test/repo2',
            'nvd_published_at': '2023-01-02T00:00:00Z',
            'references': ['https://github.com/test/repo2/security/advisories/2'],
            'cvss': {'score': 9.0, 'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
            'epss': 0.456,
            'kev': '1'
        }
    ]


@pytest.fixture
def sample_cisa_data():
    """Sample CISA data for testing."""
    return {
        'vulnerabilities': [
            {
                'cveID': 'CVE-2023-12345',
                'vendorProject': 'Test Project',
                'product': 'Test Product',
                'vulnerabilityName': 'Test Vulnerability',
                'dateAdded': '2023-01-01',
                'shortDescription': 'Test description',
                'requiredAction': 'Test action',
                'dueDate': '2023-02-01',
                'notes': 'Test notes'
            },
            {
                'cveID': 'CVE-2023-67890',
                'vendorProject': 'Another Project',
                'product': 'Another Product',
                'vulnerabilityName': 'Another Vulnerability',
                'dateAdded': '2023-01-02',
                'shortDescription': 'Another description',
                'requiredAction': 'Another action',
                'dueDate': '2023-02-02',
                'notes': 'Another notes'
            }
        ]
    }


@pytest.fixture
def mock_github_response():
    """Mock GitHub API response."""
    return [
        {
            'ghsa_id': 'GHSA-test-123',
            'cve_id': 'CVE-2023-12345',
            'summary': 'Test vulnerability',
            'severity': 'high',
            'source_code_location': 'https://github.com/test/repo',
            'nvd_published_at': '2023-01-01T00:00:00Z',
            'references': ['https://github.com/test/repo/security/advisories/1'],
            'cvss': {'score': 7.5, 'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
            'epss': 0.123,
            'kev': '0'
        }
    ]


@pytest.fixture
def mock_requests_get():
    """Mock requests.get for API calls."""
    with patch('requests.get') as mock_get:
        yield mock_get


@pytest.fixture
def mock_requests_post():
    """Mock requests.post for API calls."""
    with patch('requests.post') as mock_post:
        yield mock_post


@pytest.fixture(autouse=True)
def setup_test_logging():
    """Setup logging for tests."""
    # Clear any existing handlers
    for handler in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(handler)
    
    # Setup basic logging for tests
    logging.basicConfig(level=logging.DEBUG)
    
    yield
    
    # Cleanup after test
    for handler in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(handler)
