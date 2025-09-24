"""
Integration tests for the GitHub Advisory Database Scraper.
"""
import pytest
import os
import tempfile
import shutil
import json
from unittest.mock import patch, Mock
import requests

from main import main
from helpers import setup_logging, create_csv, zip_files, create_dir
from advisory_scraper import AdvisoryScraper, CISAAdvisoryScraper


class TestIntegration:
    """Integration tests for the complete application workflow."""
    
    def test_full_workflow_success(self, temp_dir, sample_advisories_list, sample_cisa_data):
        """Test the complete workflow from start to finish."""
        # Change to temp directory
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                    with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                        with patch('requests.get') as mock_get:
                            # Mock GitHub API response
                            github_response = Mock()
                            github_response.status_code = 200
                            github_response.json.return_value = sample_advisories_list
                            github_response.headers = {'Link': ''}
                            
                            # Mock CISA API response
                            cisa_response = Mock()
                            cisa_response.json.return_value = sample_cisa_data
                            
                            mock_get.side_effect = [github_response, cisa_response]
                            
                            # Run the main function
                            main()
                            
                            # Verify directory was created
                            assert os.path.exists('advisories')
                            
                            # Verify CSV files were created
                            expected_files = [
                                'advisories/low_advisories.csv',
                                'advisories/critical_advisories.csv'
                            ]
                            
                            for file_path in expected_files:
                                assert os.path.exists(file_path)
                                
                                # Verify CSV content
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    assert 'CVE' in content  # Header
                                    assert 'CVE-2023-12345' in content  # Data
                            
                            # Verify ZIP files were created
                            expected_zip_files = [
                                'advisories/low_advisories.zip',
                                'advisories/critical_advisories.zip'
                            ]
                            
                            for zip_path in expected_zip_files:
                                assert os.path.exists(zip_path)
                                
                                # Verify ZIP contains CSV
                                import zipfile
                                with zipfile.ZipFile(zip_path, 'r') as zipf:
                                    file_list = zipf.namelist()
                                    csv_filename = os.path.basename(zip_path.replace('.zip', '.csv'))
                                    assert csv_filename in file_list
                            
                            # Verify log file was created
                            assert os.path.exists('app.log')
                            
        finally:
            os.chdir(original_cwd)
    
    def test_workflow_with_kev_checking(self, temp_dir, sample_advisories_list, sample_cisa_data):
        """Test workflow with KEV (Known Exploited Vulnerabilities) checking."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                    with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                        with patch('requests.get') as mock_get:
                            # Mock GitHub API response
                            github_response = Mock()
                            github_response.status_code = 200
                            github_response.json.return_value = sample_advisories_list
                            github_response.headers = {'Link': ''}
                            
                            # Mock CISA API response
                            cisa_response = Mock()
                            cisa_response.json.return_value = sample_cisa_data
                            
                            mock_get.side_effect = [github_response, cisa_response]
                            
                            # Run the main function
                            main()
                            
                            # Verify CSV files contain KEV information
                            csv_files = [
                                'advisories/low_advisories.csv',
                                'advisories/critical_advisories.csv'
                            ]
                            
                            for csv_file in csv_files:
                                if os.path.exists(csv_file):
                                    with open(csv_file, 'r') as f:
                                        content = f.read()
                                        assert 'KEV' in content  # Header should contain KEV
                                        
                                        # Check that KEV values are present (0 or 1)
                                        lines = content.split('\n')
                                        for line in lines[1:]:  # Skip header
                                            if line.strip():
                                                parts = line.split(',')
                                                if len(parts) > 8:  # KEV is the last column
                                                    kev_value = parts[8].strip()
                                                    assert kev_value in ['0', '1']
                            
        finally:
            os.chdir(original_cwd)
    
    def test_workflow_with_different_severities(self, temp_dir, sample_cisa_data):
        """Test workflow with different severity levels."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        # Create advisories with different severities
        mixed_advisories = [
            {'cve_id': 'CVE-2023-1', 'severity': 'low', 'summary': 'Low severity'},
            {'cve_id': 'CVE-2023-2', 'severity': 'medium', 'summary': 'Medium severity'},
            {'cve_id': 'CVE-2023-3', 'severity': 'high', 'summary': 'High severity'},
            {'cve_id': 'CVE-2023-4', 'severity': 'critical', 'summary': 'Critical severity'},
        ]
        
        try:
            with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                    with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                        with patch('requests.get') as mock_get:
                            # Mock GitHub API response
                            github_response = Mock()
                            github_response.status_code = 200
                            github_response.json.return_value = mixed_advisories
                            github_response.headers = {'Link': ''}
                            
                            # Mock CISA API response
                            cisa_response = Mock()
                            cisa_response.json.return_value = sample_cisa_data
                            
                            mock_get.side_effect = [github_response, cisa_response]
                            
                            # Run the main function
                            main()
                            
                            # Verify all severity files were created
                            expected_files = [
                                'advisories/low_advisories.csv',
                                'advisories/moderate_advisories.csv',
                                'advisories/high_advisories.csv',
                                'advisories/critical_advisories.csv'
                            ]
                            
                            for file_path in expected_files:
                                assert os.path.exists(file_path)
                                
                                # Verify CSV content
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    assert 'CVE' in content  # Header
                                    
                                    # Check severity-specific content
                                    if 'low' in file_path:
                                        assert 'CVE-2023-1' in content
                                    elif 'moderate' in file_path:
                                        assert 'CVE-2023-2' in content
                                    elif 'high' in file_path:
                                        assert 'CVE-2023-3' in content
                                    elif 'critical' in file_path:
                                        assert 'CVE-2023-4' in content
                            
                            # Verify ZIP files were created
                            expected_zip_files = [f.replace('.csv', '.zip') for f in expected_files]
                            
                            for zip_path in expected_zip_files:
                                assert os.path.exists(zip_path)
                            
        finally:
            os.chdir(original_cwd)
    
    def test_workflow_with_api_errors(self, temp_dir):
        """Test workflow with API errors."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                    with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                        with patch('requests.get') as mock_get:
                            # Mock API error
                            mock_get.side_effect = requests.RequestException("API Error")
                            
                            # Run the main function - should handle error gracefully
                            with pytest.raises(requests.RequestException):
                                main()
                            
        finally:
            os.chdir(original_cwd)
    
    def test_workflow_with_empty_responses(self, temp_dir):
        """Test workflow with empty API responses."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                    with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                        with patch('requests.get') as mock_get:
                            # Mock empty responses
                            github_response = Mock()
                            github_response.status_code = 200
                            github_response.json.return_value = []
                            github_response.headers = {'Link': ''}
                            
                            cisa_response = Mock()
                            cisa_response.json.return_value = {'vulnerabilities': []}
                            
                            mock_get.side_effect = [github_response, cisa_response]
                            
                            # Run the main function
                            main()
                            
                            # Verify directory was created but no CSV files
                            assert os.path.exists('advisories')
                            
                            # Verify no CSV files were created
                            csv_files = [f for f in os.listdir('advisories') if f.endswith('.csv')]
                            assert len(csv_files) == 0
                            
        finally:
            os.chdir(original_cwd)
    
    def test_workflow_with_file_permissions(self, temp_dir):
        """Test workflow with file permission issues."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Create a read-only directory to test permission issues
            readonly_dir = os.path.join(temp_dir, 'readonly')
            os.makedirs(readonly_dir)
            os.chmod(readonly_dir, 0o444)  # Read-only
            
            with patch('main.create_dir', return_value=readonly_dir):
                with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                    with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                        with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                            with patch('requests.get') as mock_get:
                                # Mock successful API responses
                                github_response = Mock()
                                github_response.status_code = 200
                                github_response.json.return_value = [{'cve_id': 'CVE-2023-1', 'severity': 'high', 'summary': 'Test'}]
                                github_response.headers = {'Link': ''}
                                
                                cisa_response = Mock()
                                cisa_response.json.return_value = {'vulnerabilities': []}
                                
                                mock_get.side_effect = [github_response, cisa_response]
                                
                                # Run the main function - should handle permission error
                                with pytest.raises((PermissionError, IOError)):
                                    main()
                            
        finally:
            os.chdir(original_cwd)
    
    def test_workflow_with_large_dataset(self, temp_dir, sample_cisa_data):
        """Test workflow with a large dataset."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
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
        
        try:
            with patch('_constants.BASE_URL', 'https://api.github.com/advisories'):
                with patch('_constants.HEADERS', {'Authorization': 'Bearer test_token'}):
                    with patch('_constants.CISA_URL', 'https://cisa.gov/test.json'):
                        with patch('requests.get') as mock_get:
                            # Mock GitHub API response
                            github_response = Mock()
                            github_response.status_code = 200
                            github_response.json.return_value = large_advisories
                            github_response.headers = {'Link': ''}
                            
                            # Mock CISA API response
                            cisa_response = Mock()
                            cisa_response.json.return_value = sample_cisa_data
                            
                            mock_get.side_effect = [github_response, cisa_response]
                            
                            # Run the main function
                            main()
                            
                            # Verify all severity files were created
                            expected_files = [
                                'advisories/low_advisories.csv',
                                'advisories/moderate_advisories.csv',
                                'advisories/high_advisories.csv',
                                'advisories/critical_advisories.csv'
                            ]
                            
                            for file_path in expected_files:
                                assert os.path.exists(file_path)
                                
                                # Verify file size is reasonable
                                file_size = os.path.getsize(file_path)
                                assert file_size > 0
                                
                                # Verify CSV content
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    lines = content.split('\n')
                                    # Should have header + data rows
                                    assert len(lines) > 1
                                    
                                    # Count advisories by severity
                                    if 'low' in file_path:
                                        expected_count = 25  # 100/4
                                        assert len(lines) - 1 == expected_count  # -1 for header
                                    elif 'moderate' in file_path:
                                        expected_count = 25
                                        assert len(lines) - 1 == expected_count
                                    elif 'high' in file_path:
                                        expected_count = 25
                                        assert len(lines) - 1 == expected_count
                                    elif 'critical' in file_path:
                                        expected_count = 25
                                        assert len(lines) - 1 == expected_count
                            
        finally:
            os.chdir(original_cwd)
