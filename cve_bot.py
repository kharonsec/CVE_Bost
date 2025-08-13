import logging
import time
import schedule
from datetime import datetime
from typing import List, Dict
from config import Config
from cve_sources import CVESourceManager
from bluesky_client import BlueskyClient

class CVEBot:
    """Main CVE Bot class"""
    
    def __init__(self):
        self.setup_logging()
        self.source_manager = CVESourceManager()
        self.bluesky_client = BlueskyClient()
        self.logger = logging.getLogger(__name__)
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=getattr(logging, Config.LOG_LEVEL),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(Config.LOG_FILE),
                logging.StreamHandler()
            ]
        )
    
    def run_once(self) -> bool:
        """Run the bot once to fetch and post CVEs"""
        try:
            self.logger.info("Starting CVE bot run...")
            
            # Get new CVEs from all sources
            new_cves = self.source_manager.get_all_new_cves()
            
            if not new_cves:
                self.logger.info("No new CVEs found")
                return True
            
            self.logger.info(f"Found {len(new_cves)} new CVEs to post")
            
            # Post each CVE to Bluesky
            success_count = 0
            for cve in new_cves:
                try:
                    if self.bluesky_client.post_cve(cve):
                        success_count += 1
                        self.logger.info(f"Successfully posted {cve['id']}")
                    else:
                        self.logger.error(f"Failed to post {cve['id']}")
                    
                    # Add delay between posts to avoid rate limiting
                    time.sleep(2)
                    
                except Exception as e:
                    self.logger.error(f"Error posting {cve['id']}: {e}")
            
            self.logger.info(f"CVE bot run completed. Posted {success_count}/{len(new_cves)} CVEs")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during CVE bot run: {e}")
            return False
    
    def run_scheduled(self):
        """Run the bot on schedule"""
        self.logger.info("Starting scheduled CVE bot...")
        
        # Schedule the bot to run every X minutes
        schedule.every(Config.POST_INTERVAL_MINUTES).minutes.do(self.run_once)
        
        # Run once immediately
        self.run_once()
        
        # Keep running
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                self.logger.info("CVE bot stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in scheduled run: {e}")
                time.sleep(300)  # Wait 5 minutes on error
    
    def test_connection(self) -> bool:
        """Test all connections"""
        self.logger.info("Testing connections...")
        
        # Test Bluesky connection
        if not self.bluesky_client.test_connection():
            self.logger.error("Bluesky connection test failed")
            return False
        
        # Test CVE sources
        try:
            test_cves = self.source_manager.get_all_new_cves()
            self.logger.info(f"Successfully fetched {len(test_cves)} CVEs from sources")
        except Exception as e:
            self.logger.error(f"CVE source test failed: {e}")
            return False
        
        self.logger.info("All connection tests passed")
        return True
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            self.bluesky_client.logout()
            self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

def main():
    """Main entry point"""
    print("CVE Bot - Automatic CVE Posting to Bluesky")
    print("=" * 50)
    
    # Validate configuration
    if not Config.validate():
        print("Configuration validation failed. Please check your .env file.")
        return
    
    # Print configuration
    Config.print_config()
    print()
    
    # Create and run bot
    bot = CVEBot()
    
    try:
        # Test connections first
        if not bot.test_connection():
            print("Connection test failed. Please check your configuration.")
            return
        
        print("Connection test successful!")
        print()
        
        # Ask user for mode
        print("Choose mode:")
        print("1. Run once")
        print("2. Run scheduled")
        print("3. Clear processed CVEs and run once")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            print("Running CVE bot once...")
            bot.run_once()
        elif choice == "2":
            print(f"Starting scheduled CVE bot (every {Config.POST_INTERVAL_MINUTES} minutes)...")
            print("Press Ctrl+C to stop")
            bot.run_scheduled()
        elif choice == "3":
            print("Clearing processed CVEs and running once...")
            bot.source_manager.clear_all_processed_cves()
            bot.run_once()
        elif choice == "4":
            print("Exiting...")
        else:
            print("Invalid choice. Exiting...")
    
    except KeyboardInterrupt:
        print("\nBot stopped by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        bot.cleanup()

if __name__ == "__main__":
    main()
