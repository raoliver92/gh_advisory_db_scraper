"""
Tests for main.py functionality.
"""
import pytest
import os
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock

# Import the main function
from main import main


class TestMain:
    """Test the main function."""
    
    def test_main_success(self, temp_dir, sample_advisories_list, sample_cisa_data):
        """Test successful main function execution."""
        with patch('main.setup_logging') as mock_setup_logging:
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = sample_advisories_list
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper.check_if_known_exploited_vulnerabilities.return_value = True
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function
                                main()
                                
                                # Verify calls
                                mock_setup_logging.assert_called_once_with(console=True)
                                mock_advisory_scraper.fetch_all_advisories.assert_called_once_with(
                                    delay=0.1, ecosystem="pip"
                                )
                                mock_cisa_scraper.fetch_all_cisa_advisories.assert_called_once()
                                mock_create_dir.assert_called_once_with("advisories")
                                
                                # Verify CSV and ZIP creation calls
                                assert mock_create_csv.call_count == 2  # low and critical
                                assert mock_zip_files.call_count == 2
    
    def test_main_no_advisories(self, temp_dir, sample_cisa_data):
        """Test main function with no advisories."""
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks - no advisories
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = []
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function
                                main()
                                
                                # Verify no CSV/ZIP creation calls
                                mock_create_csv.assert_not_called()
                                mock_zip_files.assert_not_called()
    
    def test_main_different_severities(self, temp_dir, sample_cisa_data):
        """Test main function with different severity levels."""
        advisories_by_severity = [
            {'cve_id': 'CVE-2023-1', 'severity': 'low', 'summary': 'Low severity'},
            {'cve_id': 'CVE-2023-2', 'severity': 'medium', 'summary': 'Medium severity'},
            {'cve_id': 'CVE-2023-3', 'severity': 'high', 'summary': 'High severity'},
            {'cve_id': 'CVE-2023-4', 'severity': 'critical', 'summary': 'Critical severity'},
        ]
        
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = advisories_by_severity
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper.check_if_known_exploited_vulnerabilities.return_value = False
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function
                                main()
                                
                                # Verify CSV creation for all severities
                                assert mock_create_csv.call_count == 4
                                assert mock_zip_files.call_count == 4
                                
                                # Verify specific file names
                                csv_calls = [call[0][1] for call in mock_create_csv.call_args_list]
                                assert 'advisories/low_advisories.csv' in csv_calls
                                assert 'advisories/moderate_advisories.csv' in csv_calls
                                assert 'advisories/high_advisories.csv' in csv_calls
                                assert 'advisories/critical_advisories.csv' in csv_calls
    
    def test_main_kev_checking(self, temp_dir, sample_cisa_data):
        """Test main function KEV (Known Exploited Vulnerabilities) checking."""
        advisories_with_cve = [
            {'cve_id': 'CVE-2023-12345', 'severity': 'high', 'summary': 'Test vulnerability'},
            {'cve_id': 'CVE-2023-67890', 'severity': 'critical', 'summary': 'Another vulnerability'},
        ]
        
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = advisories_with_cve
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                # First CVE is in KEV, second is not
                                mock_cisa_scraper.check_if_known_exploited_vulnerabilities.side_effect = [True, False]
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function
                                main()
                                
                                # Verify KEV checking was called for each advisory
                                assert mock_cisa_scraper.check_if_known_exploited_vulnerabilities.call_count == 2
                                
                                # Verify CSV creation calls
                                assert mock_create_csv.call_count == 2  # high and critical
                                
                                # Check that advisories were modified with KEV status
                                csv_calls = mock_create_csv.call_args_list
                                for call in csv_calls:
                                    advisories = call[0][0]  # First argument is advisories list
                                    for advisory in advisories:
                                        assert 'kev' in advisory
                                        assert advisory['kev'] in ['0', '1']
    
    def test_main_cisa_scraper_error(self, temp_dir, sample_advisories_list):
        """Test main function with CISA scraper error."""
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = sample_advisories_list
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.side_effect = Exception("CISA API error")
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function - should handle CISA error gracefully
                                with pytest.raises(Exception, match="CISA API error"):
                                    main()
    
    def test_main_advisory_scraper_error(self, temp_dir, sample_cisa_data):
        """Test main function with advisory scraper error."""
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.side_effect = Exception("GitHub API error")
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function - should handle advisory scraper error
                                with pytest.raises(Exception, match="GitHub API error"):
                                    main()
    
    def test_main_file_creation_error(self, temp_dir, sample_advisories_list, sample_cisa_data):
        """Test main function with file creation error."""
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = sample_advisories_list
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper.check_if_known_exploited_vulnerabilities.return_value = False
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                mock_create_csv.side_effect = IOError("File creation error")
                                
                                # Run main function - should handle file creation error
                                with pytest.raises(IOError, match="File creation error"):
                                    main()
    
    def test_main_empty_advisories_list(self, temp_dir, sample_cisa_data):
        """Test main function with empty advisories list."""
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks - empty advisories
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = []
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function
                                main()
                                
                                # Verify no file operations
                                mock_create_csv.assert_not_called()
                                mock_zip_files.assert_not_called()
    
    def test_main_mixed_severities(self, temp_dir, sample_cisa_data):
        """Test main function with mixed severity levels."""
        mixed_advisories = [
            {'cve_id': 'CVE-2023-1', 'severity': 'low', 'summary': 'Low severity'},
            {'cve_id': 'CVE-2023-2', 'severity': 'low', 'summary': 'Another low severity'},
            {'cve_id': 'CVE-2023-3', 'severity': 'critical', 'summary': 'Critical severity'},
        ]
        
        with patch('main.setup_logging'):
            with patch('main.AdvisoryScraper') as mock_advisory_scraper_class:
                with patch('main.CISAAdvisoryScraper') as mock_cisa_scraper_class:
                    with patch('main.create_dir') as mock_create_dir:
                        with patch('main.create_csv') as mock_create_csv:
                            with patch('main.zip_files') as mock_zip_files:
                                
                                # Setup mocks
                                mock_advisory_scraper = Mock()
                                mock_advisory_scraper.fetch_all_advisories.return_value = mixed_advisories
                                mock_advisory_scraper_class.return_value = mock_advisory_scraper
                                
                                mock_cisa_scraper = Mock()
                                mock_cisa_scraper.fetch_all_cisa_advisories.return_value = sample_cisa_data
                                mock_cisa_scraper.check_if_known_exploited_vulnerabilities.return_value = False
                                mock_cisa_scraper_class.return_value = mock_cisa_scraper
                                
                                mock_create_dir.return_value = temp_dir
                                
                                # Run main function
                                main()
                                
                                # Verify CSV creation for low and critical severities
                                assert mock_create_csv.call_count == 2
                                assert mock_zip_files.call_count == 2
                                
                                # Verify specific file names
                                csv_calls = [call[0][1] for call in mock_create_csv.call_args_list]
                                assert 'advisories/low_advisories.csv' in csv_calls
                                assert 'advisories/critical_advisories.csv' in csv_calls
                                
                                # Verify advisory counts
                                for call in mock_create_csv.call_args_list:
                                    advisories = call[0][0]
                                    if 'low_advisories.csv' in call[0][1]:
                                        assert len(advisories) == 2
                                    elif 'critical_advisories.csv' in call[0][1]:
                                        assert len(advisories) == 1
