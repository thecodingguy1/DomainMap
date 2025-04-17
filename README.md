**URL Scanner**

A command‑line tool to scan a list of domains and report on their HTTP status codes, page titles, content sizes and IP addresses. It can follow simple redirects, group results by IP, generate a chart, and optionally throttle request rate.


Requirements
	•	Python 3.6+
	•	httpx
	•	colorama
	•	tqdm
	•	Optional, for enhanced features:
	•	tldextract (better domain parsing)
	•	plotext (terminal bar charts)
	•	ipwhois (WHOIS lookups)
	•	pyperclip (clipboard input)

Install core dependencies with:

``pip install httpx colorama tqdm``

And any of the optional extras as needed:

``pip install tldextract plotext ipwhois pyperclip``

Usage

``./script.py [options]``

If you omit -i/--input, URLs will be read from your clipboard (one URL per line). You must have pyperclip installed for clipboard mode.

Basic scan

``./script.py -i urls.txt``

Scans each URL listed in urls.txt, prints a colorized report to the console.

Save report to file

``./script.py -i urls.txt -o report.txt``

Writes the plain‑text version of the report (no ANSI colors) to report.txt.

Enable chart & IP grouping

``./script.py -i urls.txt --report``

After scanning, prints a bar chart of “domains per IP” (requires plotext) and groups domains by IP address, with optional WHOIS info (requires ipwhois).

Throttle request rate

``./script.py -i urls.txt --rate 5``

Limits the overall request rate to 5 requests per second. Useful to avoid overwhelming servers or hitting rate limits.

Full example

./domainmap.py \
  -i urls.txt \
  -o scan_results.txt \
  --report \
  --rate 2

Scans urls.txt at up to 2 req/s, generates a console chart and IP grouping, and writes the report to scan_results.txt.

Command‑Line Options

Option	Description
-i, --input FILE	Path to a file with one URL per line. If omitted, URLs are read from the clipboard.
-o, --output FILE	Write the final plain‑text report to this file.
--report	After scanning, show a terminal bar chart and group domains by IP.
--rate N	Limit requests to N requests per second.

Notes
	•	Redirects: 301 and 303 responses are followed once to extract final URL, title and content size.
	•	Rate limiter: uses a simple token‑bucket style delay so that threads collectively do not exceed the specified rate.
	•	Clipboard mode: useful for quick one‑off scans without creating an input file.

License

This project is released under the MIT License.
