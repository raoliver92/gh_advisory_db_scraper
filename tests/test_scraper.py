"""
Tests for AdvisoryScraper and CISAAdvisoryScraper classes.
"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
import requests

from advisory_scraper import AdvisoryScraper, CISAAdvisoryScraper


class TestAdvisoryScraper:
    """Test the AdvisoryScraper class."""
    
    def test_init(self):
        """Test AdvisoryScraper initialization."""
        with patch('advisory_scraper.BASE_URL', 'https://api.github.com/advisories'):
            with patch('advisory_scraper.HEADERS', {'Authorization': 'Bearer token'}):
                scraper = AdvisoryScraper()
                
                assert scraper.base_url == 'https://api.github.com/advisories'
                assert scraper.headers == {'Authorization': 'Bearer token'}
    
    def test_list_global_advisories_success(self, mock_requests_get, mock_github_response):
        """Test successful list_global_advisories call."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {'Link': ''}
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        data, next_url = scraper.list_global_advisories()
        
        assert data == mock_github_response
        assert next_url is None
        mock_requests_get.assert_called_once()
    
    def test_list_global_advisories_with_params(self, mock_requests_get, mock_github_response):
        """Test list_global_advisories with custom parameters."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {'Link': ''}
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        params = {'severity': 'high', 'per_page': 50}
        data, next_url = scraper.list_global_advisories(params)
        
        # Check that default params were added
        expected_params = {
            'type': 'reviewed',
            'ecosystem': 'pip',
            'per_page': 50,
            'severity': 'high'
        }
        mock_requests_get.assert_called_once()
        call_args = mock_requests_get.call_args
        assert call_args[1]['params'] == expected_params
    
    def test_list_global_advisories_no_content(self, mock_requests_get):
        """Test list_global_advisories with 204 No Content response."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        
        with pytest.raises(Exception, match="No advisories found"):
            scraper.list_global_advisories()
    
    def test_list_global_advisories_rate_limit(self, mock_requests_get):
        """Test list_global_advisories with 403 Rate Limit response."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        
        with pytest.raises(Exception, match="Rate limit exceeded"):
            scraper.list_global_advisories()
    
    def test_list_global_advisories_json_error(self, mock_requests_get):
        """Test list_global_advisories with JSON parsing error."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.text = "Invalid JSON response"
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        
        with pytest.raises(json.JSONDecodeError):
            scraper.list_global_advisories()
    
    def test_list_global_advisories_with_next_page(self, mock_requests_get, mock_github_response):
        """Test list_global_advisories with next page link."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {
            'Link': '<https://api.github.com/advisories?page=2>; rel="next"'
        }
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        data, next_url = scraper.list_global_advisories()
        
        assert data == mock_github_response
        assert next_url == 'https://api.github.com/advisories?page=2'
    
    def test_fetch_all_advisories_single_page(self, mock_requests_get, mock_github_response):
        """Test fetch_all_advisories with single page."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {'Link': ''}
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        advisories = scraper.fetch_all_advisories()
        
        assert advisories == mock_github_response
        assert mock_requests_get.call_count == 1
    
    def test_fetch_all_advisories_multiple_pages(self, mock_requests_get, mock_github_response):
        """Test fetch_all_advisories with multiple pages."""
        # First page response
        first_response = Mock()
        first_response.status_code = 200
        first_response.json.return_value = mock_github_response
        first_response.headers = {
            'Link': '<https://api.github.com/advisories?page=2>; rel="next"'
        }
        
        # Second page response
        second_response = Mock()
        second_response.status_code = 200
        second_response.json.return_value = mock_github_response
        second_response.headers = {'Link': ''}
        second_response.raise_for_status.return_value = None
        
        mock_requests_get.side_effect = [first_response, second_response]
        
        scraper = AdvisoryScraper()
        advisories = scraper.fetch_all_advisories()
        
        # Should have data from both pages
        assert len(advisories) == len(mock_github_response) * 2
        assert mock_requests_get.call_count == 2
    
    def test_fetch_all_advisories_with_max_pages(self, mock_requests_get, mock_github_response):
        """Test fetch_all_advisories with max_pages limit."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {
            'Link': '<https://api.github.com/advisories?page=2>; rel="next"'
        }
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        advisories = scraper.fetch_all_advisories(max_pages=1)
        
        assert advisories == mock_github_response
        assert mock_requests_get.call_count == 1
    
    def test_fetch_all_advisories_with_severity_filter(self, mock_requests_get, mock_github_response):
        """Test fetch_all_advisories with severity filter."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {'Link': ''}
        mock_requests_get.return_value = mock_response
        
        scraper = AdvisoryScraper()
        advisories = scraper.fetch_all_advisories(severity='high')
        
        # Check that severity parameter was passed
        call_args = mock_requests_get.call_args
        assert 'params' in call_args[1]
        assert call_args[1]['params']['severity'] == 'high'
    
    def test_fetch_all_advisories_with_delay(self, mock_requests_get, mock_github_response):
        """Test fetch_all_advisories with delay between requests."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_response
        mock_response.headers = {'Link': ''}
        mock_requests_get.return_value = mock_response
        
        with patch('time.sleep') as mock_sleep:
            scraper = AdvisoryScraper()
            advisories = scraper.fetch_all_advisories(delay=1.0)
            
            # Should not sleep for single page
            mock_sleep.assert_not_called()
    
    def test_fetch_all_advisories_request_error(self, mock_requests_get):
        """Test fetch_all_advisories with request error."""
        mock_requests_get.side_effect = requests.RequestException("Network error")
        
        scraper = AdvisoryScraper()
        
        with pytest.raises(requests.RequestException):
            scraper.fetch_all_advisories()


class TestCISAAdvisoryScraper:
    """Test the CISAAdvisoryScraper class."""
    
    def test_init(self):
        """Test CISAAdvisoryScraper initialization."""
        with patch('advisory_scraper.CISA_URL', 'https://cisa.gov/test.json'):
            scraper = CISAAdvisoryScraper()
            
            assert scraper.base_url == 'https://cisa.gov/test.json'
    
    def test_fetch_all_cisa_advisories_success(self, mock_requests_get, sample_cisa_data):
        """Test successful fetch_all_cisa_advisories call."""
        mock_response = Mock()
        mock_response.json.return_value = sample_cisa_data
        mock_requests_get.return_value = mock_response
        
        scraper = CISAAdvisoryScraper()
        data = scraper.fetch_all_cisa_advisories()
        
        assert data == sample_cisa_data
        mock_requests_get.assert_called_once_with('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    
    def test_fetch_all_cisa_advisories_request_error(self, mock_requests_get):
        """Test fetch_all_cisa_advisories with request error."""
        mock_requests_get.side_effect = requests.RequestException("Network error")
        
        scraper = CISAAdvisoryScraper()
        
        with pytest.raises(requests.RequestException):
            scraper.fetch_all_cisa_advisories()
    
    def test_check_if_known_exploited_vulnerabilities_found(self, sample_cisa_data):
        """Test check_if_known_exploited_vulnerabilities when CVE is found."""
        scraper = CISAAdvisoryScraper()
        
        result = scraper.check_if_known_exploited_vulnerabilities(
            sample_cisa_data, 'CVE-2023-12345'
        )
        
        assert result is True
    
    def test_check_if_known_exploited_vulnerabilities_not_found(self, sample_cisa_data):
        """Test check_if_known_exploited_vulnerabilities when CVE is not found."""
        scraper = CISAAdvisoryScraper()
        
        result = scraper.check_if_known_exploited_vulnerabilities(
            sample_cisa_data, 'CVE-2023-99999'
        )
        
        assert result is False
    
    def test_check_if_known_exploited_vulnerabilities_none_cve(self, sample_cisa_data):
        """Test check_if_known_exploited_vulnerabilities with None CVE ID."""
        scraper = CISAAdvisoryScraper()
        
        result = scraper.check_if_known_exploited_vulnerabilities(
            sample_cisa_data, None
        )
        
        assert result is False
    
    def test_check_if_known_exploited_vulnerabilities_empty_cisa_data(self):
        """Test check_if_known_exploited_vulnerabilities with empty CISA data."""
        empty_cisa_data = {'vulnerabilities': []}
        scraper = CISAAdvisoryScraper()
        
        result = scraper.check_if_known_exploited_vulnerabilities(
            empty_cisa_data, 'CVE-2023-12345'
        )
        
        assert result is False
    
    def test_check_if_known_exploited_vulnerabilities_missing_vulnerabilities_key(self):
        """Test check_if_known_exploited_vulnerabilities with missing vulnerabilities key."""
        malformed_cisa_data = {}
        scraper = CISAAdvisoryScraper()
        
        with pytest.raises(KeyError):
            scraper.check_if_known_exploited_vulnerabilities(
                malformed_cisa_data, 'CVE-2023-12345'
            )
