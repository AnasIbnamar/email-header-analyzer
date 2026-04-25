# Email Header Analyzer

A web-based cybersecurity tool that analyzes raw email headers to detect
phishing, spoofing, and email authentication failures.

## Live Demo
[Coming soon — link after deployment]

## Features
- **SPF / DMARC / DKIM** validation via live DNS lookups
- **IP geolocation** of all sending servers
- **Spoofing detection** — Reply-To/Return-Path domain mismatch analysis
- **Delivery chain** visualization showing every mail server hop
- **Risk score** from 0–100 based on authentication and spoofing signals
- **X-Header** extraction revealing mail client and spam score metadata

## Tech Stack
- Python 3.14
- Flask 3.1
- dnspython — DNS record lookups
- requests — IP geolocation via ip-api.com
- Jinja2 — HTML templating

## How to Use
1. Open any suspicious email
2. Export the raw headers:
   - **Gmail**: three dots → Show original → copy all
   - **Outlook**: File → Properties → Internet headers → copy all
3. Paste into the analyzer and click Analyze
4. Review the risk score, authentication results, and spoofing indicators

## Installation (local)

```bash
git clone https://github.com/AnaslbnamarXXXX/email-header-analyzer.git
cd email-header-analyzer
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## What the Risk Score Means
| Score | Level | Meaning |
|-------|-------|---------|
| 0–39 | Low | Email appears legitimate |
| 40–69 | Medium | Suspicious — review carefully |
| 70–100 | High | Likely malicious |

## Author
Anas Ibn Amar — Cybersecurity Graduate