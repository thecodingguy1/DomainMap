# URL Status Scanner

A simple Python CLI tool for checking a list of URLs and separating them into `ALIVE`, `DEAD`, and `BLOCKED` results.

It checks:

- HTTP status code
- Final redirected URL
- Page title
- Content size
- Resolved IP address
- Redirect count
- Response time

## Install

```bash
git clone [https://github.com/YOUR_USERNAME/YOUR_REPO](https://github.com/thecodingguy1/DomainMap/).git \
cd DomainMap \
pip install -r requirements.txt
```

Scan from file

``python3 url_status_scanner.py -i urls.txt``

 
 linkmap will scan from clipboard automatically if urls are detected.
