import os
from dotenv import load_dotenv
from typing import List

# Load environment variables
load_dotenv()

class Config:
    """Configuration class for the CVE Bot"""
    
    # Bluesky Configuration
    BLUESKY_IDENTIFIER = os.getenv('BLUESKY_IDENTIFIER', '')
    BLUESKY_PASSWORD = os.getenv('BLUESKY_PASSWORD', '')
    
    # CVE Sources
    NVD_API_KEY = os.getenv('NVD_API_KEY', '')
    CVE_SOURCES = os.getenv('CVE_SOURCES', 'nvd,cisa,github').split(',')
    
    # NVD API Configuration
    NVD_RESULTS_PER_PAGE = int(os.getenv('NVD_RESULTS_PER_PAGE', '2000'))
    NVD_MAX_DAYS_BACK = int(os.getenv('NVD_MAX_DAYS_BACK', '7'))
    
    # NVD Filtering Options
    NVD_SEVERITY_FILTER = os.getenv('NVD_SEVERITY_FILTER', 'CRITICAL,HIGH').split(',')
    NVD_INCLUDE_KEV = os.getenv('NVD_INCLUDE_KEV', 'true').lower() == 'true'
    NVD_INCLUDE_CERT_ALERTS = os.getenv('NVD_INCLUDE_CERT_ALERTS', 'false').lower() == 'true'
    NVD_INCLUDE_CERT_NOTES = os.getenv('NVD_INCLUDE_CERT_NOTES', 'false').lower() == 'true'
    
    # Posting Configuration
    POST_INTERVAL_MINUTES = int(os.getenv('POST_INTERVAL_MINUTES', '30'))
    MAX_POSTS_PER_RUN = int(os.getenv('MAX_POSTS_PER_RUN', '5'))
    POST_TEMPLATE = os.getenv('POST_TEMPLATE', 'default')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'cve_bot.log')
    
    @classmethod
    def validate(cls) -> bool:
        """Validate that required configuration is present"""
        if not cls.BLUESKY_IDENTIFIER:
            print("ERROR: BLUESKY_IDENTIFIER is required")
            return False
        if not cls.BLUESKY_PASSWORD:
            print("ERROR: BLUESKY_PASSWORD is required")
            return False
        return True
    
    @classmethod
    def print_config(cls):
        """Print current configuration (without sensitive data)"""
        print("CVE Bot Configuration:")
        print(f"  Bluesky Account: {cls.BLUESKY_IDENTIFIER}")
        print(f"  CVE Sources: {', '.join(cls.CVE_SOURCES)}")
        print(f"  NVD Results per Page: {cls.NVD_RESULTS_PER_PAGE}")
        print(f"  NVD Max Days Back: {cls.NVD_MAX_DAYS_BACK}")
        print(f"  NVD Severity Filter: {', '.join(cls.NVD_SEVERITY_FILTER)}")
        print(f"  NVD Include KEV: {cls.NVD_INCLUDE_KEV}")
        print(f"  NVD Include CERT Alerts: {cls.NVD_INCLUDE_CERT_ALERTS}")
        print(f"  NVD Include CERT Notes: {cls.NVD_INCLUDE_CERT_NOTES}")
        print(f"  Post Interval: {cls.POST_INTERVAL_MINUTES} minutes")
        print(f"  Max Posts per Run: {cls.MAX_POSTS_PER_RUN}")
        print(f"  Log Level: {cls.LOG_LEVEL}")
