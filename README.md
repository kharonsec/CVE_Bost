# CVE Bot - Automatic CVE Posting to Bluesky

A minimal, production-ready Python bot that automatically monitors for new CVEs (Common Vulnerabilities and Exposures) from multiple sources and posts them to Bluesky social media platform.

## Features

- **Multiple CVE Sources**: Monitors NVD, CISA, and GitHub Security Advisories
- **Automatic Posting**: Posts new CVEs to Bluesky with formatted content
- **Severity-based Sorting**: Prioritizes high and critical vulnerabilities
- **Scheduled Operation**: Can run continuously or on-demand
- **Rate Limiting**: Respects API limits and adds delays between posts
- **Comprehensive Logging**: Detailed logs for monitoring and debugging
- **Minimal Footprint**: Clean, production-ready codebase

## Prerequisites

- Python 3.8 or higher
- Bluesky account (https://bsky.app)
- App password for Bluesky (not your main password)

## Installation

1. Clone or download this repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Copy `env.example` to `.env`:
   ```bash
   cp env.example .env
   ```

2. Edit `.env` with your configuration:
   ```bash
   # Bluesky Configuration
   BLUESKY_IDENTIFIER=your-username.bsky.social
   BLUESKY_PASSWORD=your-app-password
   
   # CVE Sources (comma-separated)
   CVE_SOURCES=nvd,cisa,github
   
   # NVD API Configuration
   NVD_API_KEY=your-nvd-api-key-optional
   NVD_RESULTS_PER_PAGE=2000
   NVD_MAX_DAYS_BACK=7
   
   # NVD Filtering Options
   NVD_SEVERITY_FILTER=CRITICAL,HIGH
   NVD_INCLUDE_KEV=true
   NVD_INCLUDE_CERT_ALERTS=false
   NVD_INCLUDE_CERT_NOTES=false
   
   # Posting Configuration
   POST_INTERVAL_MINUTES=30
   MAX_POSTS_PER_RUN=5
   ```

### Getting Bluesky App Password

1. Go to https://bsky.app
2. Sign in to your account
3. Go to Settings → App Passwords
4. Generate a new app password
5. Use this password in your `.env` file

### Getting NVD API Key (Optional)

**The bot works perfectly without an NVD API key!** However, getting one provides higher rate limits:

1. **Go to:** https://nvd.nist.gov/developers/request-an-api-key
2. **Fill out the form** with your email and intended use
3. **Wait 1-2 business days** for approval (usually automatic)
4. **Add to your `.env` file** for 10x higher rate limits

**Rate Limits:**
- **Without API key:** 5 requests per 6 seconds
- **With API key:** 50 requests per 6 seconds

**Note:** This is completely optional and free. The bot will work fine without it.

## Usage

### Run Once
```bash
python3 cve_bot.py
# Choose option 1 when prompted
```

### Run Scheduled
```bash
python3 cve_bot.py
# Choose option 2 when prompted
```

### Clear Processed CVEs and Run
```bash
python3 cve_bot.py
# Choose option 3 when prompted
```

The bot automatically tests connections before running.

## CVE Sources

### NVD (National Vulnerability Database)
- **URL:** https://services.nvd.nist.gov/rest/json/cves/2.0
- Official CVE database with comprehensive API access
- Includes CVSS v3/v4 scores, CWE information, and detailed metadata
- Advanced filtering by severity, KEV status, CERT alerts, and more
- Rate limited without API key (higher limits with API key)
- Configurable date ranges and result limits

### CISA (Cybersecurity & Infrastructure Security Agency)
- **URL:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Known Exploited Vulnerabilities catalog
- Focuses on actively exploited CVEs
- No rate limiting
- Public JSON feed

### GitHub Security Advisories
- **URL:** https://github.com/advisories
- Security advisories from GitHub repositories
- Currently simplified implementation

## Post Format

Posts include:
- CVE ID and severity level
- Description (smartly truncated to fit Bluesky's 300-character limit)
- CVSS score (if available)
- Exploitation status (if known)
- Source and publication date
- Relevant hashtags

Example post:
```
🔴 CVE-2024-1234 - Critical

A critical vulnerability in the example software that allows remote code execution through crafted input...

CVSS: 9.8
🚨 Exploited
Source: CISA
#CVE #Security #HighPriority
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `POST_INTERVAL_MINUTES` | Minutes between bot runs | 30 |
| `MAX_POSTS_PER_RUN` | Maximum CVEs to post per run | 5 |
| `CVE_SOURCES` | Comma-separated list of sources | nvd,cisa,github |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | INFO |
| `LOG_FILE` | Log file path | cve_bot.log |

### NVD-Specific Options

| Option | Description | Default |
|--------|-------------|---------|
| `NVD_API_KEY` | NVD API key for higher rate limits | (none) |
| `NVD_RESULTS_PER_PAGE` | Maximum results per API request | 2000 |
| `NVD_MAX_DAYS_BACK` | Days back to search for CVEs | 7 |
| `NVD_SEVERITY_FILTER` | Comma-separated severity levels | CRITICAL,HIGH |
| `NVD_INCLUDE_KEV` | Include Known Exploited Vulnerabilities | true |
| `NVD_INCLUDE_CERT_ALERTS` | Include CERT Technical Alerts | false |
| `NVD_INCLUDE_CERT_NOTES` | Include CERT Vulnerability Notes | false |

## Project Structure

```
CVE_Bost/
├── cve_bot.py          # Main bot orchestration
├── cve_sources.py      # CVE data fetching
├── bluesky_client.py   # Bluesky authentication & posting
├── config.py           # Configuration management
├── requirements.txt    # Python dependencies
├── .env               # Your credentials (create from env.example)
├── env.example        # Configuration template
├── README.md          # This file
└── .gitignore         # Git exclusions
```

## Logging

The bot creates detailed logs in `cve_bot.log` and also displays them in the console. Logs include:
- CVE discovery and processing
- Bluesky posting attempts and results
- Error messages and debugging information
- Connection test results

## Error Handling

The bot includes comprehensive error handling:
- Automatic re-authentication on Bluesky errors
- Graceful handling of API failures
- Retry logic for transient errors
- Detailed error logging
- Individual source failure isolation

## Security Considerations

- Never commit your `.env` file to version control
- Use app passwords, not your main Bluesky password
- The bot only reads CVE data and posts to your account
- No sensitive data is stored or transmitted

## Troubleshooting

### Authentication Errors
- Verify your Bluesky credentials
- Ensure you're using an app password, not your main password
- Check if your account has any restrictions

### NVD API Issues
- **Without API key:** Bot will work but may be slower due to rate limits
- **Rate limiting errors:** Increase delays between requests or get an API key
- **API key not working:** Verify the key is correctly copied to `.env` file
- **No CVEs found:** Check if your severity filters are too restrictive

### No CVEs Found
- Check your internet connection
- Verify the CVE sources are accessible
- Check the logs for specific error messages
- Use option 3 to clear processed CVEs and re-run

### Rate Limiting
- Increase delays between posts
- Get an NVD API key for higher limits
- Reduce posting frequency

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the bot.

## License

This project is open source and available under the MIT License.

## Disclaimer

This bot is for educational and legitimate security awareness purposes. Users are responsible for ensuring their use complies with Bluesky's terms of service and applicable laws. The authors are not responsible for any misuse of this software.
