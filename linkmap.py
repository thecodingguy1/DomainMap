#!/usr/bin/env python3
"""
URL Status Scanner

Checks a list of URLs for:
  - alive/dead/blocked state
  - HTTP status code
  - final redirected URL
  - page title
  - content size
  - resolved IP address
  - optional grouped-by-IP report
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import re
import socket
import sys
import time
from dataclasses import asdict, dataclass
from html import unescape
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
from colorama import Fore, Style, init
from tqdm import tqdm

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import plotext as plt
except ImportError:
    plt = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None


DEFAULT_USER_AGENT = "url-status-scanner/1.0"


@dataclass
class ScanResult:
    state: str
    original_url: str
    normalized_url: str
    final_url: str
    status_code: Optional[int]
    status_group: str
    title: str
    content_size: Optional[int]
    ip: str
    hostname: str
    private_ip: bool
    redirect_count: int
    elapsed_ms: Optional[int]
    error: str


def normalize_url(raw_url: str, default_scheme: str = "http") -> str:
    raw_url = raw_url.strip()

    if not raw_url:
        return ""

    if raw_url.startswith(("http://", "https://")):
        return raw_url

    return f"{default_scheme}://{raw_url}"


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    output = []

    for item in items:
        key = item.strip().lower()

        if key in seen:
            continue

        seen.add(key)
        output.append(item)

    return output


def load_urls_from_file(path: str) -> List[str]:
    urls = []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            value = line.strip()

            if not value:
                continue

            if value.startswith("#"):
                continue

            urls.append(value)

    return dedupe_keep_order(urls)


def load_urls_from_clipboard() -> List[str]:
    try:
        import pyperclip
    except ImportError:
        print(
            Fore.RED
            + "pyperclip is required to read from clipboard when no input file is provided."
            + Style.RESET_ALL
        )
        sys.exit(1)

    clipboard_text = pyperclip.paste()
    urls = []

    for line in clipboard_text.splitlines():
        value = line.strip()

        if not value:
            continue

        if value.startswith("#"):
            continue

        urls.append(value)

    return dedupe_keep_order(urls)


def get_title(html: str) -> str:
    if not html:
        return "No Title Found"

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return "No Title Found"

    title = match.group(1)
    title = re.sub(r"\s+", " ", title)
    title = unescape(title).strip()

    return title if title else "No Title Found"


def get_hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def resolve_ip(hostname: str) -> str:
    if not hostname:
        return "N/A"

    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return "N/A"


def is_private_or_local_ip(ip: str) -> bool:
    if not ip or ip == "N/A":
        return False

    try:
        parsed = ipaddress.ip_address(ip)

        return any(
            [
                parsed.is_private,
                parsed.is_loopback,
                parsed.is_link_local,
                parsed.is_multicast,
                parsed.is_reserved,
                parsed.is_unspecified,
            ]
        )
    except ValueError:
        return False


def classify_status(status_code: Optional[int]) -> str:
    if status_code is None:
        return "NO_RESPONSE"

    if 200 <= status_code < 300:
        return "HTTP_2XX"

    if 300 <= status_code < 400:
        return "HTTP_3XX"

    if 400 <= status_code < 500:
        return "HTTP_4XX"

    if status_code >= 500:
        return "HTTP_5XX"

    return "OTHER_HTTP"


def simplify_error(error: str) -> str:
    if not error:
        return ""

    lowered = error.lower()

    if "name or service not known" in lowered:
        return "DNS failed"

    if "nodename nor servname provided" in lowered:
        return "DNS failed"

    if "temporary failure in name resolution" in lowered:
        return "DNS failed"

    if "connection refused" in lowered:
        return "Connection refused"

    if "timed out" in lowered or "timeout" in lowered:
        return "Timed out"

    if "ssl" in lowered or "certificate" in lowered:
        return "TLS/certificate error"

    if "too many redirects" in lowered:
        return "Too many redirects"

    if "network is unreachable" in lowered:
        return "Network unreachable"

    if "connection reset" in lowered:
        return "Connection reset"

    if len(error) > 120:
        return error[:117] + "..."

    return error


def make_result(
    state: str,
    original_url: str,
    normalized_url: str,
    final_url: str,
    error: str = "",
    status_code: Optional[int] = None,
    title: str = "",
    content_size: Optional[int] = None,
    hostname: str = "",
    ip: str = "N/A",
    private_ip: bool = False,
    redirect_count: int = 0,
    elapsed_ms: Optional[int] = None,
) -> ScanResult:
    return ScanResult(
        state=state,
        original_url=original_url,
        normalized_url=normalized_url,
        final_url=final_url,
        status_code=status_code,
        status_group=classify_status(status_code),
        title=title,
        content_size=content_size,
        ip=ip,
        hostname=hostname,
        private_ip=private_ip,
        redirect_count=redirect_count,
        elapsed_ms=elapsed_ms,
        error=simplify_error(error),
    )


def process_url(
    original_url: str,
    timeout: float,
    retries: int,
    user_agent: str,
    default_scheme: str,
    allow_private: bool,
    max_redirects: int,
) -> ScanResult:
    normalized_url = normalize_url(original_url, default_scheme=default_scheme)

    if not normalized_url:
        return make_result(
            state="DEAD",
            original_url=original_url,
            normalized_url="",
            final_url="",
            error="Empty URL",
        )

    initial_hostname = get_hostname(normalized_url)

    if not initial_hostname:
        return make_result(
            state="DEAD",
            original_url=original_url,
            normalized_url=normalized_url,
            final_url=normalized_url,
            error="Could not parse hostname",
        )

    initial_ip = resolve_ip(initial_hostname)
    initial_private = is_private_or_local_ip(initial_ip)

    if initial_private and not allow_private:
        return make_result(
            state="BLOCKED",
            original_url=original_url,
            normalized_url=normalized_url,
            final_url=normalized_url,
            error="Private/local/reserved IP blocked",
            hostname=initial_hostname,
            ip=initial_ip,
            private_ip=True,
        )

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    last_error = ""

    for attempt in range(1, retries + 1):
        start_time = time.perf_counter()

        try:
            with httpx.Client(
                headers=headers,
                timeout=timeout,
                follow_redirects=True,
                max_redirects=max_redirects,
            ) as client:
                response = client.get(normalized_url)

            elapsed_ms = int((time.perf_counter() - start_time) * 1000)

            final_url = str(response.url)
            final_hostname = get_hostname(final_url)
            final_ip = resolve_ip(final_hostname)
            final_private = is_private_or_local_ip(final_ip)

            if final_private and not allow_private:
                return make_result(
                    state="BLOCKED",
                    original_url=original_url,
                    normalized_url=normalized_url,
                    final_url=final_url,
                    error="Final URL resolved to private/local/reserved IP",
                    status_code=response.status_code,
                    hostname=final_hostname,
                    ip=final_ip,
                    private_ip=True,
                    elapsed_ms=elapsed_ms,
                )

            content_type = response.headers.get("content-type", "").lower()

            if "text/html" in content_type or not content_type:
                title = get_title(response.text)
            else:
                title = f"Non-HTML content: {content_type}"

            return make_result(
                state="ALIVE",
                original_url=original_url,
                normalized_url=normalized_url,
                final_url=final_url,
                status_code=response.status_code,
                title=title,
                content_size=len(response.content),
                hostname=final_hostname,
                ip=final_ip,
                private_ip=final_private,
                redirect_count=len(response.history),
                elapsed_ms=elapsed_ms,
            )

        except httpx.TooManyRedirects as exc:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return make_result(
                state="DEAD",
                original_url=original_url,
                normalized_url=normalized_url,
                final_url=normalized_url,
                error=f"Too many redirects: {exc}",
                hostname=initial_hostname,
                ip=initial_ip,
                private_ip=initial_private,
                elapsed_ms=elapsed_ms,
            )

        except httpx.TimeoutException as exc:
            last_error = f"Timeout: {exc}"

        except httpx.ConnectError as exc:
            last_error = f"Connection failed: {exc}"

        except httpx.RequestError as exc:
            last_error = f"Request error: {exc}"

        except Exception as exc:
            last_error = f"Unexpected error: {exc}"

        if attempt < retries:
            time.sleep(min(2 * attempt, 10))

    return make_result(
        state="DEAD",
        original_url=original_url,
        normalized_url=normalized_url,
        final_url=normalized_url,
        error=last_error or "Failed after retries",
        hostname=initial_hostname,
        ip=initial_ip,
        private_ip=initial_private,
    )


def state_color(state: str) -> str:
    if state == "ALIVE":
        return Fore.GREEN

    if state == "DEAD":
        return Fore.RED

    if state == "BLOCKED":
        return Fore.YELLOW

    return Fore.WHITE


def status_color(status_code: Optional[int]) -> str:
    if status_code is None:
        return Fore.RED

    if 200 <= status_code < 300:
        return Fore.GREEN

    if 300 <= status_code < 400:
        return Fore.CYAN

    if 400 <= status_code < 500:
        return Fore.YELLOW

    if status_code >= 500:
        return Fore.RED

    return Fore.WHITE


def print_compact_line(res: ScanResult) -> None:
    color = state_color(res.state)

    if res.state == "ALIVE":
        status = res.status_code if res.status_code is not None else "N/A"
        title = res.title or "No Title Found"

        if len(title) > 90:
            title = title[:87] + "..."

        print(
            color
            + f"[ALIVE] {status} {res.normalized_url}"
            + Style.RESET_ALL
            + f" | title='{title}' | ip={res.ip} | size={res.content_size} | {res.elapsed_ms}ms"
        )
        return

    if res.state == "BLOCKED":
        print(
            color
            + f"[BLOCKED] {res.normalized_url}"
            + Style.RESET_ALL
            + f" | ip={res.ip} | reason={res.error}"
        )
        return

    print(
        color
        + f"[DEAD] {res.normalized_url}"
        + Style.RESET_ALL
        + f" | reason={res.error or 'No response'}"
    )


def print_terminal_report(results: List[ScanResult], only_alive_details: bool = True) -> None:
    alive = [item for item in results if item.state == "ALIVE"]
    dead = [item for item in results if item.state == "DEAD"]
    blocked = [item for item in results if item.state == "BLOCKED"]

    alive = sorted(
        alive,
        key=lambda item: item.status_code if item.status_code is not None else -1,
    )

    dead = sorted(dead, key=lambda item: item.normalized_url)
    blocked = sorted(blocked, key=lambda item: item.normalized_url)

    print()
    print(Fore.GREEN + "=" * 24 + " ALIVE URLS " + "=" * 24 + Style.RESET_ALL)

    if not alive:
        print(Fore.YELLOW + "No alive URLs found." + Style.RESET_ALL)
    else:
        for res in alive:
            if only_alive_details:
                print()
                print(Fore.GREEN + f"[ALIVE] {res.normalized_url}" + Style.RESET_ALL)

                if res.final_url and res.final_url != res.normalized_url:
                    print(Fore.CYAN + f"  Final URL: {res.final_url}" + Style.RESET_ALL)

                print(status_color(res.status_code) + f"  Status: {res.status_code} ({res.status_group})" + Style.RESET_ALL)
                print(Fore.WHITE + f"  Hostname: {res.hostname}" + Style.RESET_ALL)
                print(Fore.WHITE + f"  IP: {res.ip}" + Style.RESET_ALL)
                print(Fore.WHITE + f"  Title: {res.title}" + Style.RESET_ALL)
                print(Fore.WHITE + f"  Size: {res.content_size} bytes" + Style.RESET_ALL)
                print(Fore.WHITE + f"  Redirects: {res.redirect_count}" + Style.RESET_ALL)
                print(Fore.WHITE + f"  Elapsed: {res.elapsed_ms} ms" + Style.RESET_ALL)
            else:
                print_compact_line(res)

    print()
    print(Fore.RED + "=" * 24 + " DEAD URLS " + "=" * 25 + Style.RESET_ALL)

    if not dead:
        print(Fore.GREEN + "No dead URLs found." + Style.RESET_ALL)
    else:
        for res in dead:
            print_compact_line(res)

    print()
    print(Fore.YELLOW + "=" * 23 + " BLOCKED URLS " + "=" * 23 + Style.RESET_ALL)

    if not blocked:
        print(Fore.GREEN + "No blocked URLs found." + Style.RESET_ALL)
    else:
        for res in blocked:
            print_compact_line(res)


def write_txt(path: str, results: List[ScanResult]) -> None:
    alive = [item for item in results if item.state == "ALIVE"]
    dead = [item for item in results if item.state == "DEAD"]
    blocked = [item for item in results if item.state == "BLOCKED"]

    lines = []

    lines.append("=" * 25 + " ALIVE URLS " + "=" * 25)

    if not alive:
        lines.append("No alive URLs found.")
    else:
        for res in alive:
            lines.append("")
            lines.append(f"[ALIVE] {res.normalized_url}")
            if res.final_url and res.final_url != res.normalized_url:
                lines.append(f"  Final URL: {res.final_url}")
            lines.append(f"  Status: {res.status_code} ({res.status_group})")
            lines.append(f"  Hostname: {res.hostname}")
            lines.append(f"  IP: {res.ip}")
            lines.append(f"  Title: {res.title}")
            lines.append(f"  Size: {res.content_size} bytes")
            lines.append(f"  Redirects: {res.redirect_count}")
            lines.append(f"  Elapsed: {res.elapsed_ms} ms")

    lines.append("")
    lines.append("=" * 25 + " DEAD URLS " + "=" * 26)

    if not dead:
        lines.append("No dead URLs found.")
    else:
        for res in dead:
            lines.append(f"[DEAD] {res.normalized_url} | reason={res.error or 'No response'}")

    lines.append("")
    lines.append("=" * 24 + " BLOCKED URLS " + "=" * 24)

    if not blocked:
        lines.append("No blocked URLs found.")
    else:
        for res in blocked:
            lines.append(f"[BLOCKED] {res.normalized_url} | ip={res.ip} | reason={res.error}")

    lines.append("")
    lines.append("=" * 28 + " SUMMARY " + "=" * 29)

    summary = build_summary(results)
    for key, value in summary.items():
        lines.append(f"{key}: {value}")

    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))


def write_csv(path: str, results: List[ScanResult]) -> None:
    fieldnames = list(ScanResult.__annotations__.keys())

    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for res in results:
            writer.writerow(asdict(res))


def write_json(path: str, results: List[ScanResult]) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump([asdict(res) for res in results], file, indent=2, ensure_ascii=False)


def save_output(path: str, output_format: str, results: List[ScanResult]) -> None:
    if output_format == "txt":
        write_txt(path, results)
    elif output_format == "csv":
        write_csv(path, results)
    elif output_format == "json":
        write_json(path, results)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def build_summary(results: List[ScanResult]) -> Dict[str, int]:
    summary = {
        "total": len(results),
        "alive": sum(1 for item in results if item.state == "ALIVE"),
        "dead": sum(1 for item in results if item.state == "DEAD"),
        "blocked": sum(1 for item in results if item.state == "BLOCKED"),
        "http_2xx": sum(1 for item in results if item.status_group == "HTTP_2XX"),
        "http_3xx": sum(1 for item in results if item.status_group == "HTTP_3XX"),
        "http_4xx": sum(1 for item in results if item.status_group == "HTTP_4XX"),
        "http_5xx": sum(1 for item in results if item.status_group == "HTTP_5XX"),
        "no_response": sum(1 for item in results if item.status_group == "NO_RESPONSE"),
    }

    return summary


def print_summary(results: List[ScanResult]) -> None:
    summary = build_summary(results)

    print()
    print(Fore.BLUE + "=" * 30 + " SUMMARY " + "=" * 30 + Style.RESET_ALL)

    print(Fore.WHITE + f"Total:   {summary['total']}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Alive:   {summary['alive']}" + Style.RESET_ALL)
    print(Fore.RED + f"Dead:    {summary['dead']}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"Blocked: {summary['blocked']}" + Style.RESET_ALL)

    print()
    print(Fore.GREEN + f"HTTP 2xx: {summary['http_2xx']}" + Style.RESET_ALL)
    print(Fore.CYAN + f"HTTP 3xx: {summary['http_3xx']}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"HTTP 4xx: {summary['http_4xx']}" + Style.RESET_ALL)
    print(Fore.RED + f"HTTP 5xx: {summary['http_5xx']}" + Style.RESET_ALL)
    print(Fore.RED + f"No response: {summary['no_response']}" + Style.RESET_ALL)


def grouped_ip_report(results: List[ScanResult], whois: bool) -> None:
    alive_results = [item for item in results if item.state == "ALIVE"]

    ip_to_details: Dict[str, List[ScanResult]] = {}

    for res in alive_results:
        if not res.ip or res.ip == "N/A":
            continue

        ip_to_details.setdefault(res.ip, []).append(res)

    if not ip_to_details:
        print(Fore.YELLOW + "No alive IP data available for grouped report." + Style.RESET_ALL)
        return

    ips = list(ip_to_details.keys())
    counts = [len(ip_to_details[ip]) for ip in ips]

    if plt:
        plt.clear_figure()
        plt.bar(ips, counts)
        plt.title("Number of Alive URLs per IP")
        plt.xlabel("IP Address")
        plt.ylabel("Alive URL Count")
        plt.plotsize(100, 20)
        plt.show()
    else:
        print(
            Fore.YELLOW
            + "plotext is not installed. Install it with: pip install plotext"
            + Style.RESET_ALL
        )

    print()
    print(Fore.BLUE + "Alive URLs Grouped by IP:" + Style.RESET_ALL)

    for ip, details in sorted(ip_to_details.items(), key=lambda item: len(item[1]), reverse=True):
        registrar = "WHOIS lookup skipped"
        registered_to = "WHOIS lookup skipped"

        if whois:
            if IPWhois:
                try:
                    whois_data = IPWhois(ip).lookup_whois()
                    registrar = whois_data.get("asn_description", "N/A")

                    nets = whois_data.get("nets") or []
                    if nets:
                        registered_to = nets[0].get("name", "N/A") or "N/A"
                    else:
                        registered_to = "N/A"
                except Exception as exc:
                    registrar = f"WHOIS error: {exc}"
                    registered_to = "N/A"
            else:
                registrar = "ipwhois not installed"
                registered_to = "ipwhois not installed"

        print(Fore.YELLOW + f"{ip} (Alive Count: {len(details)})" + Style.RESET_ALL)
        print(Fore.WHITE + f"WHOIS: {registrar} | Registered To: {registered_to}" + Style.RESET_ALL)

        for item in details:
            status = item.status_code if item.status_code is not None else "N/A"
            print(Fore.GREEN + f"  {item.hostname} - Status: {status}" + Style.RESET_ALL)

            if item.title and item.title != "No Title Found":
                print("    Title: " + Fore.CYAN + item.title + Style.RESET_ALL)

        print("-" * 40)


def determine_default_output(urls: List[str], output_format: str) -> str:
    if not urls:
        return f"output.{output_format}"

    first_url = normalize_url(urls[0])
    hostname = get_hostname(first_url)

    if not hostname:
        return f"output.{output_format}"

    if tldextract:
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}.{output_format}"

    parts = hostname.split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}.{output_format}"

    return f"output.{output_format}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan URLs and clearly separate alive, dead, and blocked results.",
        epilog="Example: python3 url_status_scanner.py -i urls.txt -o report.csv --format csv --report",
    )

    parser.add_argument(
        "-i",
        "--input",
        help="Input file containing URLs, one per line. If omitted, clipboard is used.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file. If omitted, results are only printed unless --save-default is used.",
    )

    parser.add_argument(
        "--save-default",
        action="store_true",
        help="Save to an automatically named output file when -o is not provided.",
    )

    parser.add_argument(
        "--format",
        choices=["txt", "csv", "json"],
        default="txt",
        help="Output format. Default: txt.",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers. Default: 10.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Request timeout in seconds. Default: 8.",
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries per URL. Default: 2.",
    )

    parser.add_argument(
        "--max-redirects",
        type=int,
        default=10,
        help="Maximum redirects to follow. Default: 10.",
    )

    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help=f"HTTP User-Agent. Default: {DEFAULT_USER_AGENT}",
    )

    parser.add_argument(
        "--default-scheme",
        choices=["http", "https"],
        default="http",
        help="Scheme to add when URL has no scheme. Default: http.",
    )

    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow requests to private, local, reserved, and link-local IPs.",
    )

    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print alive results as one-line entries instead of detailed blocks.",
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help="Show grouped-by-IP report after scanning.",
    )

    parser.add_argument(
        "--whois",
        action="store_true",
        help="Perform WHOIS lookups in grouped IP report. Requires ipwhois.",
    )

    return parser.parse_args()


def main() -> int:
    init(autoreset=True)
    args = parse_args()

    if args.workers < 1:
        print(Fore.RED + "Workers must be at least 1." + Style.RESET_ALL)
        return 1

    if args.timeout <= 0:
        print(Fore.RED + "Timeout must be greater than 0." + Style.RESET_ALL)
        return 1

    if args.retries < 1:
        print(Fore.RED + "Retries must be at least 1." + Style.RESET_ALL)
        return 1

    if args.input:
        try:
            urls = load_urls_from_file(args.input)
        except Exception as exc:
            print(Fore.RED + f"Error reading input file '{args.input}': {exc}" + Style.RESET_ALL)
            return 1
    else:
        urls = load_urls_from_clipboard()
        print(Fore.CYAN + "Using URLs from clipboard." + Style.RESET_ALL)

    if not urls:
        print(Fore.RED + "No URLs provided." + Style.RESET_ALL)
        return 1

    print(Fore.CYAN + f"Loaded {len(urls)} unique URL(s)." + Style.RESET_ALL)
    print(Fore.CYAN + f"Workers: {args.workers}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Timeout: {args.timeout}s" + Style.RESET_ALL)
    print(Fore.CYAN + f"Retries: {args.retries}" + Style.RESET_ALL)

    if not args.allow_private:
        print(Fore.YELLOW + "Private, local, reserved, and link-local IPs are blocked by default." + Style.RESET_ALL)

    results: List[ScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_url = {
            executor.submit(
                process_url,
                url,
                args.timeout,
                args.retries,
                args.user_agent,
                args.default_scheme,
                args.allow_private,
                args.max_redirects,
            ): url
            for url in urls
        }

        for future in tqdm(
            concurrent.futures.as_completed(future_to_url),
            total=len(future_to_url),
            desc="Scanning URLs",
            ncols=90,
        ):
            try:
                result = future.result()
                results.append(result)
                print_compact_line(result)
            except Exception as exc:
                original_url = future_to_url[future]
                result = make_result(
                    state="DEAD",
                    original_url=original_url,
                    normalized_url=normalize_url(original_url, args.default_scheme),
                    final_url=normalize_url(original_url, args.default_scheme),
                    error=f"Unhandled worker error: {exc}",
                )
                results.append(result)
                print_compact_line(result)

    print_terminal_report(results, only_alive_details=not args.compact)
    print_summary(results)

    output_path = args.output

    if not output_path and args.save_default:
        output_path = determine_default_output(urls, args.format)

    if output_path:
        try:
            save_output(output_path, args.format, results)
            print(Fore.GREEN + f"Report saved to: {output_path}" + Style.RESET_ALL)
        except Exception as exc:
            print(Fore.RED + f"Error writing report: {exc}" + Style.RESET_ALL)
            return 1

    if args.report:
        grouped_ip_report(results, whois=args.whois)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
