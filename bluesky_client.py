import atproto
from atproto import Client
from typing import Dict, Optional
import logging
from config import Config

class BlueskyClient:
    """Client for interacting with Bluesky"""
    
    def __init__(self):
        self.client = None
        self.authenticated = False
        self.logger = logging.getLogger(__name__)
    
    def authenticate(self) -> bool:
        """Authenticate with Bluesky"""
        try:
            if not Config.BLUESKY_IDENTIFIER or not Config.BLUESKY_PASSWORD:
                self.logger.error("Bluesky credentials not configured")
                return False
            
            self.client = Client()
            self.client.login(Config.BLUESKY_IDENTIFIER, Config.BLUESKY_PASSWORD)
            self.authenticated = True
            self.logger.info(f"Successfully authenticated as {Config.BLUESKY_IDENTIFIER}")
            return True
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            return False
    
    def post_cve(self, cve_data: Dict) -> bool:
        """Post a CVE to Bluesky"""
        if not self.authenticated:
            if not self.authenticate():
                return False
        
        try:
            # Format the post content
            content = self._format_cve_post(cve_data)
            
            # Post to Bluesky
            response = self.client.send_post(text=content)
            
            if response:
                self.logger.info(f"Successfully posted CVE {cve_data['id']}")
                return True
            else:
                self.logger.error(f"Failed to post CVE {cve_data['id']}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error posting CVE {cve_data['id']}: {e}")
            # Try to re-authenticate on error
            self.authenticated = False
            return False
    
    def _format_cve_post(self, cve_data: Dict) -> str:
        """Format CVE data into a Bluesky post (Bluesky limit: 300 characters)"""
        cve_id = cve_data['id']
        severity = cve_data['severity']
        description = cve_data['description']
        source = cve_data['source']
        
        # Create severity emoji
        severity_emoji = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢',
            'Unknown': '⚪'
        }.get(severity, '⚪')
        
        # Smart description truncation - find complete sentences or logical breaks
        def smart_truncate(text, max_length):
            if len(text) <= max_length:
                return text
            
            # Try to find sentence endings first
            sentence_endings = ['. ', '! ', '? ', '; ']
            for ending in sentence_endings:
                pos = text.rfind(ending, 0, max_length)
                if pos > max_length * 0.7:  # Only if we get at least 70% of the text
                    return text[:pos + 1].strip()
            
            # Try to find word boundaries
            pos = text.rfind(' ', 0, max_length)
            if pos > max_length * 0.8:  # Only if we get at least 80% of the text
                return text[:pos].strip() + "..."
            
            # If all else fails, truncate at word boundary
            return text[:max_length].rsplit(' ', 1)[0] + "..."
        
        # Calculate available space for description
        base_post = f"{severity_emoji} {cve_id} - {severity}\n\n"
        base_post += "DESCRIPTION_PLACEHOLDER\n\n"
        
        # Essential info
        if cve_data.get('score'):
            base_post += f"CVSS: {cve_data['score']}\n"
        if cve_data.get('exploited'):
            base_post += "🚨 Exploited\n"
        base_post += f"Source: {source}\n\n#CVE #Security"
        if severity.lower() in ['critical', 'high']:
            base_post += " #HighPriority"
        if cve_data.get('exploited'):
            base_post += " #Exploited"
        
        # Calculate how much space we have for description
        available_space = 300 - len(base_post.replace("DESCRIPTION_PLACEHOLDER", ""))
        
        # Smart truncate the description
        truncated_desc = smart_truncate(description, available_space)
        
        # Build the final post
        post = base_post.replace("DESCRIPTION_PLACEHOLDER", truncated_desc)
        
        # Final safety check
        if len(post) > 300:
            # Emergency truncation - keep only essential info
            post = f"{severity_emoji} {cve_id} - {severity}\n\n"
            post += smart_truncate(description, 100) + "\n\n"
            post += f"Source: {source}\n#CVE #Security"
            if severity.lower() in ['critical', 'high']:
                post += " #HighPriority"
        
        return post
    
    def test_connection(self) -> bool:
        """Test the Bluesky connection"""
        try:
            if not self.authenticated:
                return self.authenticate()
            
            # Try to get profile info
            profile = self.client.get_profile({})
            if profile:
                self.logger.info("Bluesky connection test successful")
                return True
            else:
                self.logger.error("Bluesky connection test failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Bluesky connection test failed: {e}")
            return False
    
    def logout(self):
        """Logout from Bluesky"""
        if self.client and self.authenticated:
            try:
                self.client.logout()
                self.authenticated = False
                self.logger.info("Logged out from Bluesky")
            except Exception as e:
                self.logger.error(f"Error during logout: {e}")
