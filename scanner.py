#!/usr/bin/env python3
"""api-seclens: Command-line security auditing utility for HTTP response analysis."""

import argparse
import sys
from urllib.parse import urlparse

import requests
import urllib3
from colorama import Fore, Style, init

# Disable warnings for unverified HTTPS requests (optional audit behavior)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking defense"),
    ("X-Content-Type-Options", "MIME-sniffing defense"),
]

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
]


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url


def ok(msg: str) -> None:
    print(f"{Fore.GREEN}[✔]{Style.RESET_ALL} {msg}")


def fail(msg: str) -> None:
    print(f"{Fore.RED}[✘]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def section(title: str) -> None:
    print(f"\n{Style.BRIGHT}{title}{Style.RESET_ALL}")
    print("-" * len(title))


def check_security_headers(headers: requests.structures.CaseInsensitiveDict) -> None:
    section("1) Security Header Validation")
    for header, label in SECURITY_HEADERS:
        value = headers.get(header)
        if value:
            ok(f"{header} ({label}) present: {value}")
        else:
            fail(f"{header} ({label}) missing")


def check_disclosure(headers: requests.structures.CaseInsensitiveDict) -> None:
    section("2) Information & Technology Disclosure")
    found = False
    for header in DISCLOSURE_HEADERS:
        value = headers.get(header)
        if value:
            found = True
            warn(f"{header} disclosed: {value}")
    if not found:
        ok("No verbose technology disclosure headers found")


def check_cors(headers: requests.structures.CaseInsensitiveDict, target_origin: str) -> None:
    section("3) CORS Misconfiguration")
    acao = headers.get("Access-Control-Allow-Origin")
    if acao is None:
        ok("Access-Control-Allow-Origin not set (no permissive CORS header observed)")
        return
    if acao.strip() == "*":
        fail("Access-Control-Allow-Origin is wildcard (*) — permissive CORS policy")
        acac = headers.get("Access-Control-Allow-Credentials")
        if acac and acac.lower() == "true":
            warn("Access-Control-Allow-Credentials is true alongside wildcard ACAO (high risk)")
        return
    # Check for insecure reflection patterns
    if acao == target_origin or acao == "null":
        warn(f"Access-Control-Allow-Origin reflects origin/null: {acao} — verify server-side origin validation")
        return
    ok(f"Access-Control-Allow-Origin set to: {acao}")


def fetch(url: str, timeout: int = 10) -> requests.Response:
    headers = {
        "User-Agent": "api-seclens/1.0 (+security-audit)",
        "Origin": "https://example.com",
    }
    return requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)


def main() -> int:
    init(autoreset=True)

    parser = argparse.ArgumentParser(
        prog="api-seclens",
        description="Live HTTP security auditing utility for common response flaws.",
    )
    parser.add_argument("url", help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    target = normalize_url(args.url)
    print(f"{Style.BRIGHT}api-seclens{Style.RESET_ALL} — scanning {target}")

    try:
        resp = fetch(target, timeout=args.timeout)
    except requests.exceptions.RequestException as exc:
        fail(f"Request failed: {exc}")
        return 1

    print(f"Status: {resp.status_code} {resp.reason}")
    print(f"Final URL: {resp.url}")

    check_security_headers(resp.headers)
    check_disclosure(resp.headers)
    check_cors(resp.headers, target_origin="https://example.com")

    print(f"\n{Style.BRIGHT}Scan complete.{Style.RESET_ALL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
