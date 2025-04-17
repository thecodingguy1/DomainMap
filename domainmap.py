#!/usr/bin/env python3
import sys
import re
import httpx
import random
import argparse
import concurrent.futures
import socket
import time
import threading
from urllib.parse import urlparse
from colorama import init, Fore, Style
from tqdm import tqdm

# Try to import tldextract for better domain extraction; fallback if unavailable.
try:
    import tldextract
except ImportError:
    tldextract = None

# Try to import plotext for terminal plotting.
try:
    import plotext as plt
except ImportError:
    plt = None

# Try to import ipwhois for WHOIS lookups on IP addresses.
try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

# List of random user agents.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
]

# Global rate limiter placeholder
rate_limiter = None

class RateLimiter:
    """Simple token-bucket style rate limiter for threads."""
    def __init__(self, rate_per_sec: int):
        self.interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0
        self.lock = threading.Lock()
        self.last = time.perf_counter()

    def wait(self):
        with self.lock:
            now = time.perf_counter()
            elapsed = now - self.last
            to_wait = self.interval - elapsed
            if to_wait > 0:
                time.sleep(to_wait)
                self.last += self.interval
            else:
                self.last = now

def get_title(html):
    """Extract the title from HTML content using a regex."""
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else "No Title Found"

def determine_default_output(urls):
    """Determine a default output filename based on the main domain of the first URL."""
    if not urls:
        return "output.txt"
    first_url = urls[0]
    if tldextract:
        ext = tldextract.extract(first_url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}.txt"
    parsed = urlparse(first_url)
    hostname = parsed.hostname
    if hostname:
        parts = hostname.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}.txt"
    return "output.txt"

def get_ip(url):
    """Retrieve the IP address of the given URL's hostname."""
    try:
        hostname = urlparse(url).hostname
        return socket.gethostbyname(hostname)
    except Exception:
        return "N/A"

def process_url(original_url):
    """
    Process a single URL:
      - Applies global rate limiting if enabled
      - Ensures a scheme is present.
      - Makes an HTTP request with a 5-second timeout.
      - For 301/303 responses, follows the redirect and uses the final URL.
      - Extracts the page title and content size.
      - Retrieves the IP address for the final URL.
    Returns a dictionary with these details.
    """
    if rate_limiter:
        rate_limiter.wait()

    if not original_url.startswith(('http://', 'https://')):
        original_url = 'http://' + original_url

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://www.google.com"
    }
    
    try:
        response = httpx.get(original_url, timeout=5, headers=headers, follow_redirects=False)
    except Exception as e:
        return {
            "url": original_url,
            "final_url": original_url,
            "status": None,
            "title": None,
            "content_size": None,
            "error": str(e),
            "ip": "N/A"
        }
    
    result = {
        "url": original_url,
        "final_url": original_url,
        "status": response.status_code,
        "title": "",
        "content_size": len(response.content),
        "error": None,
        "ip": ""
    }
    
    if response.status_code in [301, 303]:
        redirect_url = response.headers.get("Location")
        result["final_url"] = redirect_url
        try:
            response = httpx.get(redirect_url, timeout=5, headers=headers, follow_redirects=True)
            result["status"] = response.status_code
            result["content_size"] = len(response.content)
            result["title"] = get_title(response.text)
        except Exception as e:
            result["error"] = str(e)
    else:
        result["title"] = get_title(response.text)
    
    result["ip"] = get_ip(result["final_url"])
    return result

def main():
    global rate_limiter

    init(autoreset=True)
    
    parser = argparse.ArgumentParser(
        description="Scan URLs for status, title, content size, and IP addresses.",
        epilog="Example: ./script.py -i urls.txt -o report.txt --report --rate 5"
    )
    parser.add_argument("-i", "--input", type=str,
                        help="Input file containing URLs (one per line). If not provided, clipboard is used.")
    parser.add_argument("-o", "--output", type=str,
                        help="Output file name for the final report (optional).")
    parser.add_argument("--report", action="store_true",
                        help="Generate a chart and a grouped report by IP address after scanning.")
    parser.add_argument("--rate", type=int, default=None,
                        help="Limit requests to RATE requests per second.")

    args = parser.parse_args()

    if args.rate and args.rate > 0:
        rate_limiter = RateLimiter(args.rate)
        print(Fore.CYAN + f"Rate limiting enabled: {args.rate} request(s) per second" + Style.RESET_ALL)
    else:
        print(Fore.CYAN + "No rate limiting applied" + Style.RESET_ALL)
    
    urls = []
    if args.input:
        try:
            with open(args.input, "r") as file:
                urls = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(Fore.RED + f"Error reading input file '{args.input}': {e}" + Style.RESET_ALL)
            sys.exit(1)
    else:
        try:
            import pyperclip
        except ImportError:
            print(Fore.RED + "pyperclip is required to read from the clipboard if no input file is provided." + Style.RESET_ALL)
            sys.exit(1)
        clipboard_text = pyperclip.paste()
        urls = [line.strip() for line in clipboard_text.splitlines() if line.strip()]
        if not urls:
            print(Fore.RED + "No valid URLs found in clipboard." + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.CYAN + "Using URLs from clipboard." + Style.RESET_ALL)
    
    if not urls:
        print(Fore.RED + "No URLs provided." + Style.RESET_ALL)
        sys.exit(1)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        print(Fore.CYAN + f"Starting scan of {len(urls)} URLs with up to 10 workers..." + Style.RESET_ALL)
        results = list(tqdm(executor.map(process_url, urls),
                            total=len(urls),
                            desc="Scanning URLs",
                            ncols=80))
    
    # Rest of reporting, sorting, charting, and writing to file remains unchanged...
    # [The remainder of your original main function code goes here unchanged]

if __name__ == "__main__":
    main()
