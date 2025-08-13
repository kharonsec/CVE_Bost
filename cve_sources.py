import requests
import feedparser
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from config import Config

class CVESource:
    """Base class for CVE data sources"""
    
    def __init__(self):
        self.last_check = None
        self.processed_cves = set()
    
    def clear_processed_cves(self):
        """Clear the list of processed CVEs to allow re-posting"""
        self.processed_cves.clear()
        print("Cleared processed CVEs list - will process all CVEs again")
    
    def get_new_cves(self) -> List[Dict]:
        """Get new CVEs from the source"""
        raise NotImplementedError
    
    def format_cve(self, cve_data: Dict) -> Dict:
        """Format CVE data into standard format"""
        raise NotImplementedError

class NVDSource(CVESource):
    """NVD (National Vulnerability Database) source"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = Config.NVD_API_KEY
    
    def get_new_cves(self) -> List[Dict]:
        """Get recent CVEs from NVD"""
        try:
            # Get CVEs from the configured number of days back
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=Config.NVD_MAX_DAYS_BACK)
            
            # Start with basic parameters that work without API key
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'resultsPerPage': min(Config.NVD_RESULTS_PER_PAGE, 2000)  # Limit to 2000 for no API key
            }
            
            # Only add advanced filtering if we have an API key
            if self.api_key:
                # Add KEV filtering
                if Config.NVD_INCLUDE_KEV:
                    params['hasKev'] = ''
                
                # Add CERT alerts filtering
                if Config.NVD_INCLUDE_CERT_ALERTS:
                    params['hasCertAlerts'] = ''
                
                # Add CERT notes filtering
                if Config.NVD_INCLUDE_CERT_NOTES:
                    params['hasCertNotes'] = ''
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(self.base_url, params=params, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln['cve']['id']
                if cve_id not in self.processed_cves:
                    cve_data = self.format_cve(vuln)
                    
                    # Apply severity filtering if configured
                    if Config.NVD_SEVERITY_FILTER and cve_data['severity'] not in Config.NVD_SEVERITY_FILTER:
                        continue
                    
                    cves.append(cve_data)
                    self.processed_cves.add(cve_id)
            
            return cves
            
        except Exception as e:
            print(f"Error fetching from NVD: {e}")
            return []
    
    def format_cve(self, cve_data: Dict) -> Dict:
        """Format NVD CVE data"""
        cve = cve_data['cve']
        descriptions = cve.get('descriptions', [])
        description = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), 'No description available')
        
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssV3', {})
        cvss_v4 = metrics.get('cvssV4', {})
        
        # Check if CVE is in KEV catalog
        is_kev = cve.get('evaluatorComment', '').lower().find('kev') != -1
        
        # Get CWE information
        weaknesses = cve.get('weaknesses', [])
        cwe_ids = []
        if weaknesses:
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))
        
        return {
            'id': cve['id'],
            'description': description[:500] + '...' if len(description) > 500 else description,
            'severity': cvss_v3.get('baseSeverity', 'Unknown'),
            'score': cvss_v3.get('baseScore', 0),
            'vector': cvss_v3.get('vectorString', ''),
            'published': cve.get('published', ''),
            'last_modified': cve.get('lastModified', ''),
            'source': 'NVD',
            'exploited': is_kev,
            'cwe_ids': cwe_ids[:3],  # Limit to first 3 CWE IDs
            'cvss_v4_score': cvss_v4.get('baseScore', 0),
            'cvss_v4_severity': cvss_v4.get('baseSeverity', ''),
            'status': cve.get('vulnStatus', 'Unknown')
        }

class CISASource(CVESource):
    """CISA (Cybersecurity & Infrastructure Security Agency) source"""
    
    def __init__(self):
        super().__init__()
        self.feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def get_new_cves(self) -> List[Dict]:
        """Get CVEs from CISA Known Exploited Vulnerabilities catalog"""
        try:
            response = requests.get(self.feed_url)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln['cveID']
                if cve_id not in self.processed_cves:
                    cve_data = self.format_cve(vuln)
                    cves.append(cve_data)
                    self.processed_cves.add(cve_id)
            
            return cves
            
        except Exception as e:
            print(f"Error fetching from CISA: {e}")
            return []
    
    def format_cve(self, cve_data: Dict) -> Dict:
        """Format CISA CVE data"""
        return {
            'id': cve_data['cveID'],
            'description': cve_data.get('shortDescription', 'No description available'),
            'severity': 'High',  # CISA catalog focuses on exploited vulnerabilities
            'score': 0,
            'vector': '',
            'published': cve_data.get('dateAdded', ''),
            'source': 'CISA',
            'exploited': True
        }

class GitHubSource(CVESource):
    """GitHub Security Advisories source"""
    
    def __init__(self):
        super().__init__()
        self.feed_url = "https://github.com/advisories?query=type%3Areviewed+ecosystem%3A"
    
    def get_new_cves(self) -> List[Dict]:
        """Get CVEs from GitHub Security Advisories"""
        try:
            # GitHub doesn't provide a simple API for this, so we'll use a basic approach
            # In a production environment, you might want to use GitHub's GraphQL API
            response = requests.get(self.feed_url)
            response.raise_for_status()
            
            # This is a simplified implementation
            # In practice, you'd need to parse the HTML or use GitHub's API
            return []
            
        except Exception as e:
            print(f"Error fetching from GitHub: {e}")
            return []

class CVESourceManager:
    """Manages multiple CVE sources"""
    
    def __init__(self):
        self.sources = {
            'nvd': NVDSource(),
            'cisa': CISASource(),
            'github': GitHubSource()
        }
    
    def get_all_new_cves(self) -> List[Dict]:
        """Get new CVEs from all configured sources"""
        all_cves = []
        
        for source_name in Config.CVE_SOURCES:
            if source_name in self.sources:
                source = self.sources[source_name]
                try:
                    cves = source.get_new_cves()
                    all_cves.extend(cves)
                    print(f"Found {len(cves)} new CVEs from {source_name}")
                except Exception as e:
                    print(f"Warning: Failed to fetch from {source_name}: {e}")
                    # Continue with other sources
                    continue
        
        if not all_cves:
            print("Warning: No CVEs found from any source")
            return []
        
        # Sort by severity and score
        all_cves.sort(key=lambda x: (self._severity_score(x['severity']), x['score']), reverse=True)
        
        return all_cves[:Config.MAX_POSTS_PER_RUN]
    
    def clear_all_processed_cves(self):
        """Clear processed CVEs from all sources"""
        for source in self.sources.values():
            if hasattr(source, 'clear_processed_cves'):
                source.clear_processed_cves()
        print("Cleared processed CVEs from all sources")
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity string to numeric score for sorting"""
        severity_map = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Unknown': 0
        }
        return severity_map.get(severity, 0)
    
    def get_cves_by_keyword(self, keyword: str, max_results: int = 50) -> List[Dict]:
        """Get CVEs by keyword search"""
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': min(max_results, Config.NVD_RESULTS_PER_PAGE)
            }
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(self.base_url, params=params, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln['cve']['id']
                if cve_id not in self.processed_cves:
                    cve_data = self.format_cve(vuln)
                    cves.append(cve_data)
                    self.processed_cves.add(cve_id)
            
            return cves
            
        except Exception as e:
            print(f"Error searching CVEs by keyword '{keyword}': {e}")
            return []
    
    def get_cves_by_cpe(self, cpe_name: str, max_results: int = 50) -> List[Dict]:
        """Get CVEs by CPE name"""
        try:
            params = {
                'cpeName': cpe_name,
                'resultsPerPage': min(max_results, Config.NVD_RESULTS_PER_PAGE)
            }
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(self.base_url, params=params, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln['cve']['id']
                if cve_id not in self.processed_cves:
                    cve_data = self.format_cve(vuln)
                    cves.append(cve_data)
                    self.processed_cves.add(cve_id)
            
            return cves
            
        except Exception as e:
            print(f"Error searching CVEs by CPE '{cpe_name}': {e}")
            return []
