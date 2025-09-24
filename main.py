import os
from advisory_scraper import AdvisoryScraper, CISAAdvisoryScraper
from helpers import setup_logging, create_csv, zip_files, create_dir
import logging

logger = logging.getLogger(__name__)

def main():
    """
    Main function to run the application.
    """
    setup_logging(console=True)
    scraper = AdvisoryScraper()
    cisa_scraper = CISAAdvisoryScraper()
    cisa_advisories = cisa_scraper.fetch_all_cisa_advisories()
    
    advisories = scraper.fetch_all_advisories(delay=0.1, ecosystem="pip")
    
    logger.info(f"Checking if {len(advisories)} advisories are in the CISA known exploited vulnerabilities")
    for advisory in advisories:
        if cisa_scraper.check_if_known_exploited_vulnerabilities(cisa_advisories, advisory['cve_id']):
            advisory['kev'] = '1'
        else:
            advisory['kev'] = '0'
    
    severities = ['low', 'medium', 'high', 'critical']
    low = []
    moderate = []
    high = []
    critical = []


    for advisory in advisories:
        if advisory['severity'] == 'low':
            low.append(advisory)
        elif advisory['severity'] == 'medium':
            moderate.append(advisory)
        elif advisory['severity'] == 'high':
            high.append(advisory)
        elif advisory['severity'] == 'critical':
            critical.append(advisory)
            
            
    advisories_dir = "advisories"
    create_dir(advisories_dir)
    if low:
        create_csv(low, f"{advisories_dir}/low_advisories.csv")
        zip_files([f"{advisories_dir}/low_advisories.csv"], f"{advisories_dir}/low_advisories.zip")
    if moderate:
        create_csv(moderate, f"{advisories_dir}/moderate_advisories.csv")
        zip_files([f"{advisories_dir}/moderate_advisories.csv"], f"{advisories_dir}/moderate_advisories.zip")
    if high:
        create_csv(high, f"{advisories_dir}/high_advisories.csv")
        zip_files([f"{advisories_dir}/high_advisories.csv"], f"{advisories_dir}/high_advisories.zip")
    if critical:
        create_csv(critical, f"{advisories_dir}/critical_advisories.csv")
        zip_files([f"{advisories_dir}/critical_advisories.csv"], f"{advisories_dir}/critical_advisories.zip")
    
if __name__ == "__main__":
    main()