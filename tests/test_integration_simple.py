"""
Simplified integration tests for the GitHub Advisory Database Scraper.
"""
import pytest
import os
import tempfile
import shutil
import json
from unittest.mock import patch, Mock
import requests

from helpers import setup_logging, create_csv, zip_files, create_dir
from advisory_scraper import AdvisoryScraper, CISAAdvisoryScraper


class TestSimpleIntegration:
    """Simplified integration tests that don't call the real main function."""
    
    def test_workflow_components(self, temp_dir, sample_advisories_list, sample_cisa_data):
        """Test the workflow components individually."""
        # Change to temp directory
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Test directory creation
            advisories_dir = create_dir("advisories")
            assert os.path.exists(advisories_dir)
            
            # Test CSV creation
            csv_file = os.path.join(advisories_dir, "test.csv")
            create_csv(sample_advisories_list, csv_file)
            assert os.path.exists(csv_file)
            
            # Test ZIP creation
            zip_file = os.path.join(advisories_dir, "test.zip")
            zip_files([csv_file], zip_file)
            assert os.path.exists(zip_file)
            
            # Verify ZIP contents
            import zipfile
            with zipfile.ZipFile(zip_file, 'r') as zipf:
                file_list = zipf.namelist()
                csv_found = any("test.csv" in f for f in file_list)
                assert csv_found
            
        finally:
            os.chdir(original_cwd)
    
    def test_advisory_scraper_with_mocks(self, mock_requests_get, sample_advisories_list):
        """Test AdvisoryScraper with mocked requests."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_advisories_list
        mock_response.headers = {'Link': ''}
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        advisories = scraper.fetch_all_advisories(max_pages=1)
        
        assert advisories == sample_advisories_list
        mock_requests_get.assert_called_once()
    
    def test_cisa_scraper_with_mocks(self, mock_requests_get, sample_cisa_data):
        """Test CISAAdvisoryScraper with mocked requests."""
        mock_response = Mock()
        mock_response.json.return_value = sample_cisa_data
        mock_requests_get.return_value = mock_response
        
        scraper = CISAAdvisoryScraper()
        data = scraper.fetch_all_cisa_advisories()
        
        assert data == sample_cisa_data
        mock_requests_get.assert_called_once()
    
    def test_kev_checking(self, sample_cisa_data):
        """Test KEV checking functionality."""
        scraper = CISAAdvisoryScraper()
        
        # Test with CVE that exists
        result = scraper.check_if_known_exploited_vulnerabilities(
            sample_cisa_data, 'CVE-2023-12345'
        )
        assert result is True
        
        # Test with CVE that doesn't exist
        result = scraper.check_if_known_exploited_vulnerabilities(
            sample_cisa_data, 'CVE-2023-99999'
        )
        assert result is False
    
    def test_severity_filtering(self, temp_dir):
        """Test advisory filtering by severity."""
        # Create advisories with different severities
        advisories = [
            {'cve_id': 'CVE-2023-1', 'severity': 'low', 'summary': 'Low severity'},
            {'cve_id': 'CVE-2023-2', 'severity': 'medium', 'summary': 'Medium severity'},
            {'cve_id': 'CVE-2023-3', 'severity': 'high', 'summary': 'High severity'},
            {'cve_id': 'CVE-2023-4', 'severity': 'critical', 'summary': 'Critical severity'},
        ]
        
        # Filter by severity
        low_advisories = [a for a in advisories if a['severity'] == 'low']
        medium_advisories = [a for a in advisories if a['severity'] == 'medium']
        high_advisories = [a for a in advisories if a['severity'] == 'high']
        critical_advisories = [a for a in advisories if a['severity'] == 'critical']
        
        assert len(low_advisories) == 1
        assert len(medium_advisories) == 1
        assert len(high_advisories) == 1
        assert len(critical_advisories) == 1
        
        # Test CSV creation for each severity
        create_dir("test_advisories")
        
        if low_advisories:
            create_csv(low_advisories, "test_advisories/low.csv")
            assert os.path.exists("test_advisories/low.csv")
        
        if medium_advisories:
            create_csv(medium_advisories, "test_advisories/medium.csv")
            assert os.path.exists("test_advisories/medium.csv")
        
        if high_advisories:
            create_csv(high_advisories, "test_advisories/high.csv")
            assert os.path.exists("test_advisories/high.csv")
        
        if critical_advisories:
            create_csv(critical_advisories, "test_advisories/critical.csv")
            assert os.path.exists("test_advisories/critical.csv")
    
    def test_error_handling(self, temp_dir):
        """Test error handling in various components."""
        # Test directory creation with invalid path
        with pytest.raises(OSError):
            create_dir("/invalid/path/that/does/not/exist")
        
        # Test CSV creation with invalid data
        invalid_advisories = [{'invalid': 'data'}]  # Missing required fields
        csv_file = os.path.join(temp_dir, "invalid.csv")
        
        # Should handle missing fields gracefully
        create_csv(invalid_advisories, csv_file)
        assert os.path.exists(csv_file)
        
        # Test ZIP creation with nonexistent file
        zip_file = os.path.join(temp_dir, "test.zip")
        with pytest.raises(FileNotFoundError):
            zip_files(["nonexistent.csv"], zip_file)
    
    def test_large_dataset_handling(self, temp_dir):
        """Test handling of large datasets."""
        # Create a large dataset
        large_advisories = []
        for i in range(100):
            large_advisories.append({
                'cve_id': f'CVE-2023-{i:05d}',
                'severity': ['low', 'medium', 'high', 'critical'][i % 4],
                'summary': f'Test vulnerability {i}',
                'source_code_location': f'https://github.com/test/repo{i}',
                'nvd_published_at': '2023-01-01T00:00:00Z',
                'references': [f'https://github.com/test/repo{i}/security/advisories/1'],
                'cvss': {'score': 5.0 + (i % 5), 'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'},
                'epss': 0.1 + (i % 10) * 0.01,
                'kev': '0'
            })
        
        # Test CSV creation with large dataset
        csv_file = os.path.join(temp_dir, "large.csv")
        create_csv(large_advisories, csv_file)
        
        assert os.path.exists(csv_file)
        file_size = os.path.getsize(csv_file)
        assert file_size > 0
        
        # Test ZIP creation with large file
        zip_file = os.path.join(temp_dir, "large.zip")
        zip_files([csv_file], zip_file)
        
        assert os.path.exists(zip_file)
        
        # Verify ZIP contents
        import zipfile
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            file_list = zipf.namelist()
            csv_found = any("large.csv" in f for f in file_list)
            assert csv_found
