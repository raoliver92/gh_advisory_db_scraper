import requests
import json
import time
import logging
from _constants import *
from helpers import setup_logging

logger = logging.getLogger(__name__)


class AdvisoryScraper:
    def __init__(self):
        self.base_url = BASE_URL
        self.headers = HEADERS

    def list_global_advisories(self, params=None):
        """
        List global security advisories via the REST API.

        params: dict of query parameters. E.g. {'type': 'reviewed', 'per_page': 100, 'severity': 'high'}
        Returns: a tuple (list of advisories, next_page_url or None)
        """
        if params is None:
            params = {}
        params.setdefault('type', 'reviewed')
        params.setdefault('ecosystem', 'pip')
        params.setdefault('per_page', 100)

        logger.debug(f"Requesting advisories | url={BASE_URL} params={params}")
        resp = requests.get(BASE_URL, headers=HEADERS, params=params)
        if resp.status_code == 204:
            logger.warning("No advisories found (204)")
            raise Exception("No advisories found")
        if resp.status_code == 403:
            logger.error("Rate limit exceeded (403)")
            raise Exception("Rate limit exceeded")
        try:
            data = resp.json()
        except Exception:
            logger.exception("Error parsing JSON response")
            logger.debug(f"Raw response text: {resp.text}")
            raise

        link = resp.headers.get('Link', '')
        next_url = None
        if link:
            for part in link.split(','):
                section = part.split(';')
                if len(section) < 2:
                    continue
                url_part = section[0].strip()
                rel_part = section[1].strip()
                if rel_part == 'rel="next"':
                    next_url = url_part.strip()[1:-1]  # remove < >
                    break

        return data, next_url

    def fetch_all_advisories(self, delay=0.5, max_pages=None, severity=None, ecosystem=None, reviewed=True):
        """
        Fetch all reviewed global security advisories, paginated.
        delay: seconds between requests
        max_pages: limit pages fetched (None = until done)
        severity: optional severity filter ('low', 'medium', 'high', 'critical')
        Returns: list of advisory dicts
        """
        all_advs = []
        params = {}
        if severity:
            params['severity'] = severity
        page_count = 0
        next_url = None

        while True:
            page_count += 1
            if max_pages and page_count > max_pages:
                logger.info(f"Reached max_pages={max_pages}, stopping")
                break

            if next_url:
                logger.debug(f"Fetching next page: {next_url}")
                resp = requests.get(next_url, headers=HEADERS)
                resp.raise_for_status()
                data = resp.json()
                all_advs.extend(data)

                link = resp.headers.get('Link', '')
                next_url = None
                if link:
                    for part in link.split(','):
                        section = part.split(';')
                        if len(section) < 2:
                            continue
                        url_part = section[0].strip()
                        rel_part = section[1].strip()
                        if rel_part == 'rel="next"':
                            next_url = url_part.strip()[1:-1]
                            break
            else:
                data, next_url = self.list_global_advisories(params)
                all_advs.extend(data)

            if not next_url:
                logger.info(f"No next page. Fetched {page_count} pages.")
                break
            time.sleep(delay)
        logger.info(f"Total advisories fetched: {len(all_advs)}")
        return all_advs


class CISAAdvisoryScraper:
    def __init__(self):
        self.base_url = CISA_URL

    def fetch_all_cisa_advisories(self):
        resp = requests.get(CISA_URL)
        logger.info(f"Fetched {len(resp.json()['vulnerabilities'])} CISA advisories")
        return resp.json()
    
    def check_if_known_exploited_vulnerabilities(self, cisa_advisories, cve_id):
        logger.debug(f"Checking if {cve_id} is a known exploited vulnerability")
        for vulnerability in cisa_advisories['vulnerabilities']:
            if vulnerability['cveID'] == cve_id:
                return True
        return False