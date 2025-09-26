import csv
import zipfile
import logging
import sys
import time
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

logger = logging.getLogger(__name__)


def setup_logging(level: str = "INFO", log_file: str = "app.log", console: bool = False) -> None:
    """
    Configure application-wide logging.

    level(str): Logging level name (e.g., "DEBUG", "INFO", "WARNING", "ERROR").
    log_file(str): Path to a log file. Defaults to "app.log".
    console(bool): If True, also write logs to console. Defaults to False.
    """
    if logging.getLogger().handlers:
        return

    level_value = getattr(logging, level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level_value)

    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setLevel(level_value)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    if console:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level_value)
        stream_handler.setFormatter(formatter)
        root_logger.addHandler(stream_handler)


def create_dir(directory_name: str = "advisories") -> str:
    """
    Create a directory for storing advisory CSV and ZIP files.
    
    Args:
        directory_name (str): Name of the directory to create. Defaults to "advisories".
        
    Returns:
        str: The path to the created directory.
    """
    try:
        if not os.path.exists(directory_name):
            os.makedirs(directory_name)
            logger.info(f"Created directory: {directory_name}")
        else:
            logger.debug(f"Directory already exists: {directory_name}")
        return os.path.abspath(directory_name)
    except Exception as e:
        logger.error(f"Error creating directory {directory_name}: {e}")
        raise


def create_csv(advisories, filename):
    """Creates csv file from advisories list

    Args:
        advisories (list): list of advisories
        filename (str): filename to save the csv file
    """
    header = [
        "CVE", # cve_id
        "Summary", # summary
        "Severity", # severity
        "Source Location", # source_code_location
        "Published", # nvd_published_at
        "References", # references
        "CVSS", #cvss
        "EPSS", # epss
        "KEV", # kev
    ]
    fieldnames = [
        "cve_id",
        "summary",
        "severity",
        "source_code_location",
        "nvd_published_at",
        "references",
        "cvss",
        "epss",
        "kev",
    ]

    logger.info(f"Creating CSV {filename} with {len(advisories)} advisories")
    with open(filename, 'w') as f:
        writer = csv.writer(f)
        try:
            writer.writerow(header)
        except Exception as e:
            logger.error(f"Error writing fieldnames to CSV: {e}")
            return
        
        for advisory in advisories:
            try:
                writer.writerow([advisory.get(field, '') for field in fieldnames])
            except Exception as e:
                logger.error(f"Error writing advisory {advisory} to CSV: {e}")
                continue
            
def zip_files(files, filename):
    """Zip files into a single file

    Args:
        files (list): list of files to zip
        filename (str): filename to save the zip file
    """
    logger.info(f"Zipping {len(files)} files into {filename}")
    with zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            zipf.write(file)