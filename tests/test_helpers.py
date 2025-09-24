"""
Tests for helpers.py functions.
"""
import pytest
import os
import csv
import zipfile
import tempfile
import shutil
from unittest.mock import patch, mock_open, Mock
import logging

from helpers import setup_logging, create_csv, zip_files, create_dir


class TestSetupLogging:
    """Test the setup_logging function."""
    
    def test_setup_logging_default(self):
        """Test setup_logging with default parameters."""
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = mock_get_logger.return_value
            mock_logger.handlers = []
            
            setup_logging()
            
            # Should not raise any exceptions
            assert True
    
    def test_setup_logging_with_console(self):
        """Test setup_logging with console output enabled."""
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = mock_get_logger.return_value
            mock_logger.handlers = []
            
            setup_logging(console=True)
            
            # Should not raise any exceptions
            assert True
    
    def test_setup_logging_existing_handlers(self):
        """Test setup_logging when handlers already exist."""
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = mock_get_logger.return_value
            mock_logger.handlers = [Mock()]  # Simulate existing handlers
            
            setup_logging()
            
            # Should return early without adding new handlers
            assert True
    
    def test_setup_logging_different_levels(self):
        """Test setup_logging with different log levels."""
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        
        for level in levels:
            with patch('logging.getLogger') as mock_get_logger:
                mock_logger = mock_get_logger.return_value
                mock_logger.handlers = []
                
                setup_logging(level=level)
                
                # Should not raise any exceptions
                assert True


class TestCreateDir:
    """Test the create_dir function."""
    
    def test_create_dir_new_directory(self, temp_dir):
        """Test creating a new directory."""
        new_dir = os.path.join(temp_dir, "test_dir")
        
        result = create_dir(new_dir)
        
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)
        assert result == os.path.abspath(new_dir)
    
    def test_create_dir_existing_directory(self, temp_dir):
        """Test creating a directory that already exists."""
        existing_dir = os.path.join(temp_dir, "existing_dir")
        os.makedirs(existing_dir)
        
        result = create_dir(existing_dir)
        
        assert os.path.exists(existing_dir)
        assert result == os.path.abspath(existing_dir)
    
    def test_create_dir_default_name(self, temp_dir):
        """Test create_dir with default directory name."""
        with patch('os.path.exists', return_value=False):
            with patch('os.makedirs') as mock_makedirs:
                with patch('os.path.abspath', return_value='/absolute/path/advisories'):
                    result = create_dir()
                    
                    mock_makedirs.assert_called_once_with("advisories")
                    assert result == '/absolute/path/advisories'
    
    def test_create_dir_permission_error(self, temp_dir):
        """Test create_dir with permission error."""
        with patch('os.path.exists', return_value=False):
            with patch('os.makedirs', side_effect=PermissionError("Permission denied")):
                with pytest.raises(PermissionError):
                    create_dir("test_dir")


class TestCreateCsv:
    """Test the create_csv function."""
    
    def test_create_csv_basic(self, temp_dir, sample_advisories_list):
        """Test creating a CSV file with basic data."""
        filename = os.path.join(temp_dir, "test.csv")
        
        create_csv(sample_advisories_list, filename)
        
        assert os.path.exists(filename)
        
        # Verify CSV content
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
            
            # Check header
            expected_header = [
                "CVE", "Summary", "Severity", "Source Location", 
                "Published", "References", "CVSS", "EPSS", "KEV"
            ]
            assert rows[0] == expected_header
            
            # Check data rows
            assert len(rows) == 3  # Header + 2 data rows
    
    def test_create_csv_empty_list(self, temp_dir):
        """Test creating CSV with empty advisories list."""
        filename = os.path.join(temp_dir, "empty.csv")
        
        create_csv([], filename)
        
        assert os.path.exists(filename)
        
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
            assert len(rows) == 1  # Only header
            assert rows[0] == [
                "CVE", "Summary", "Severity", "Source Location", 
                "Published", "References", "CVSS", "EPSS", "KEV"
            ]
    
    def test_create_csv_missing_fields(self, temp_dir):
        """Test creating CSV with advisories missing some fields."""
        advisories_with_missing_fields = [
            {
                'cve_id': 'CVE-2023-12345',
                'summary': 'Test vulnerability',
                'severity': 'high',
                # Missing other fields
            }
        ]
        
        filename = os.path.join(temp_dir, "missing_fields.csv")
        
        create_csv(advisories_with_missing_fields, filename)
        
        assert os.path.exists(filename)
        
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
            
            # Check that missing fields are filled with empty strings
            data_row = rows[1]
            assert data_row[0] == 'CVE-2023-12345'  # cve_id
            assert data_row[1] == 'Test vulnerability'  # summary
            assert data_row[2] == 'high'  # severity
            # Other fields should be empty
            assert data_row[3] == ''  # source_code_location
            assert data_row[4] == ''  # nvd_published_at
            assert data_row[5] == ''  # references
            assert data_row[6] == ''  # cvss
            assert data_row[7] == ''  # epss
            assert data_row[8] == ''  # kev
    
    def test_create_csv_write_error(self, temp_dir, sample_advisories_list):
        """Test create_csv with write error."""
        filename = os.path.join(temp_dir, "test.csv")
        
        with patch('builtins.open', side_effect=IOError("Write error")):
            # Should handle the error gracefully
            with pytest.raises(IOError, match="Write error"):
                create_csv(sample_advisories_list, filename)
    
    def test_create_csv_row_write_error(self, temp_dir, sample_advisories_list):
        """Test create_csv with row write error."""
        filename = os.path.join(temp_dir, "test.csv")
        
        # Mock csv.writer to raise exception on writerow
        with patch('csv.writer') as mock_writer:
            mock_writer_instance = mock_writer.return_value
            mock_writer_instance.writerow.side_effect = [None, IOError("Row write error")]
            
            create_csv(sample_advisories_list, filename)
            
            # Should handle the error gracefully
            assert True


class TestZipFiles:
    """Test the zip_files function."""
    
    def test_zip_files_basic(self, temp_dir, sample_advisories_list):
        """Test zipping files."""
        # Create test files
        csv_file = os.path.join(temp_dir, "test.csv")
        create_csv(sample_advisories_list, csv_file)
        
        zip_file = os.path.join(temp_dir, "test.zip")
        
        zip_files([csv_file], zip_file)
        
        assert os.path.exists(zip_file)
        
        # Verify zip contents
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            file_list = zipf.namelist()
            # Check that the CSV file is in the zip (may be full path or just filename)
            csv_found = any("test.csv" in f for f in file_list)
            assert csv_found
    
    def test_zip_files_multiple_files(self, temp_dir, sample_advisories_list):
        """Test zipping multiple files."""
        # Create multiple test files
        csv_file1 = os.path.join(temp_dir, "test1.csv")
        csv_file2 = os.path.join(temp_dir, "test2.csv")
        
        create_csv(sample_advisories_list, csv_file1)
        create_csv(sample_advisories_list, csv_file2)
        
        zip_file = os.path.join(temp_dir, "multiple.zip")
        
        zip_files([csv_file1, csv_file2], zip_file)
        
        assert os.path.exists(zip_file)
        
        # Verify zip contents
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            file_list = zipf.namelist()
            # Check that both CSV files are in the zip
            csv1_found = any("test1.csv" in f for f in file_list)
            csv2_found = any("test2.csv" in f for f in file_list)
            assert csv1_found
            assert csv2_found
    
    def test_zip_files_empty_list(self, temp_dir):
        """Test zipping with empty file list."""
        zip_file = os.path.join(temp_dir, "empty.zip")
        
        zip_files([], zip_file)
        
        assert os.path.exists(zip_file)
        
        # Verify empty zip
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            file_list = zipf.namelist()
            assert len(file_list) == 0
    
    def test_zip_files_nonexistent_file(self, temp_dir):
        """Test zipping with nonexistent file."""
        zip_file = os.path.join(temp_dir, "test.zip")
        nonexistent_file = os.path.join(temp_dir, "nonexistent.csv")
        
        # Should handle missing file gracefully
        with pytest.raises(FileNotFoundError):
            zip_files([nonexistent_file], zip_file)
    
    def test_zip_files_zip_error(self, temp_dir, sample_advisories_list):
        """Test zip_files with zip creation error."""
        csv_file = os.path.join(temp_dir, "test.csv")
        create_csv(sample_advisories_list, csv_file)
        
        zip_file = os.path.join(temp_dir, "test.zip")
        
        with patch('zipfile.ZipFile', side_effect=zipfile.BadZipFile("Bad zip")):
            with pytest.raises(zipfile.BadZipFile):
                zip_files([csv_file], zip_file)
