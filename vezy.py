#!/usr/bin/env python3
"""
VEZY v3.1 — standalone passive OSINT toolkit for Termux.
Username checks use public profile endpoints only.
Phone checks provide numbering metadata only.
IP geolocation is approximate network information, not a person's location.
Use only with information and systems you own or are authorized to assess.
"""

import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "3.1.0"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

REPORT = {
    "tool": "VEZY",
    "version": VERSION,
    "created_at": datetime.datetime.now().astimezone().isoformat(),
    "modules": {},
}


def fetch(url, timeout=10, limit=50000):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; VEZY-OSINT/3.1)",
            "Accept": "application/json,text/html,*/*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "status": response.status,
                "url": response.geturl(),
                "headers": dict(response.headers),
                "body": response.read(limit),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "url": exc.geturl(),
            "headers": dict(exc.headers),
            "body": b"",
            "error": None,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "status": None,
            "url": url,
            "headers": {},
            "body": b"",
            "error": str(exc),
        }


def timestamp():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def banner():
    os.system("clear")
    print(CYAN + BOLD + """
VEZY
INTELLIGENCE TOOLKIT
Version 3.1.0
""" + RESET)
    print(DIM + "PASSIVE RESEARCH  |  TERMUX EDITION" + RESET)


# ---------------- USERNAME INTELLIGENCE ----------------

API_CHECKS = [
    ("GitHub", "https://api.github.com/users/{u}", "https://github.com/{u}", "object"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={u}", "https://gitlab.com/{u}", "list"),
    ("Codeberg", "https://codeberg.org/api/v1/users/{u}", "https://codeberg.org/{u}", "object"),
]

PAGE_CHECKS = [
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("X", "https://x.com/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}/"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Threads", "https://www.threads.net/@{u}"),
    ("Tumblr", "https://{u}.tumblr.com/"),
    ("Medium", "https://medium.com/@{u}"),
    ("DEV Community", "https://dev.to/{u}"),
    ("Behance", "https://www.behance.net/{u}"),
    ("Dribbble", "https://dribbble.com/{u}"),
    ("SoundCloud", "https://soundcloud.com/{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
    ("Roblox", "https://www.roblox.com/user.aspx?username={u}"),
    ("Flickr", "https://www.flickr.com/people/{u}/"),
    ("Vimeo", "https://vimeo.com/{u}"),
    ("Patreon", "https://www.patreon.com/{u}"),
    ("Facebook", "https://www.facebook.com/{u}"),
    ("Snapchat", "https://www.snapchat.com/add/{u}"),
    ("Mastodon", "https://mastodon.social/@{u}"),
]

def _username_api(item, username):
    platform, api_template, profile_template, shape = item
    encoded = urllib.parse.quote(username, safe="")
    response = fetch(api_template.format(u=encoded), timeout=8, limit=20000)
    status = response["status"]
    state = "INCONCLUSIVE"

    if status == 404:
        state = "NOT FOUND"
    elif status == 200:
        try:
            data = json.loads(response["body"].decode("utf-8", errors="replace"))
            found = bool(data) if shape == "object" else isinstance(data, list) and bool(data)
            state = "PROFILE FOUND" if found else "NOT FOUND"
        except (ValueError, UnicodeDecodeError):
            state = "INCONCLUSIVE"
    elif status in (401, 403, 429):
        state = "BLOCKED / RATE LIMITED"
    elif status is None:
        state = "NETWORK ERROR"

    return {
        "platform": platform,
        "result": state,
        "profile_url": profile_template.format(u=encoded) if state == "PROFILE FOUND" else None,
        "confidence": "API signal" if state == "PROFILE FOUND" else "not confirmed",
    }


def _username_page(item, username):
    platform, template = item
    encoded = urllib.parse.quote(username, safe="")
    profile = template.format(u=encoded)
    response = fetch(profile, timeout=8, limit=1024)
    status = response["status"]

    if status == 200:
        state = "POSSIBLE MATCH — CHECK MANUALLY"
    elif status == 404:
        state = "HTTP 404 — LIKELY NOT FOUND"
    elif status in (401, 403, 429):
        state = "BLOCKED / RATE LIMITED"
    elif status is None:
        state = "NETWORK ERROR"
    else:
        state = f"INCONCLUSIVE (HTTP {status})"

    return {
        "platform": platform,
        "result": state,
        "profile_url": profile if status == 200 else None,
        "confidence": "weak HTTP-status signal; verify manually",
    }


def username_check():
    print(CYAN + "\n>> MULTI-PLATFORM USERNAME CHECK" + RESET)
    print("Public profile checks only. No login or private-data access.")
    username = input("Username (without @): ").strip().lstrip("@")

    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,38})", username):
        print(RED + "Error: Invalid username format." + RESET)
        return

    tasks = []
    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for item in API_CHECKS:
            tasks.append(pool.submit(_username_api, item, username))
        for item in PAGE_CHECKS:
            tasks.append(pool.submit(_username_page, item, username))
        for task in as_completed(tasks):
            try:
                results.append(task.result())
            except Exception as exc:
                results.append({"platform": "Unknown", "result": "ERROR", "error": str(exc)})

    order = {name: i for i, (name, *_rest) in enumerate(API_CHECKS + PAGE_CHECKS)}
    results.sort(key=lambda row: order.get(row["platform"], 999))

    # Spotify profiles use Spotify account IDs, not reliably chosen usernames.
    spotify_url = "https://open.spotify.com/search/" + urllib.parse.quote(username, safe="")
    results.append({
        "platform": "Spotify",
        "result": "MANUAL SEARCH REQUIRED — username-to-profile lookup unsupported",
        "profile_url": spotify_url,
        "confidence": "not checked; use Spotify search and verify the profile manually",
    })

    print(CYAN + "\n--- API-backed checks ---" + RESET)
    for item in results:
        if item["platform"] in [x[0] for x in API_CHECKS]:
            color = GREEN if item["result"] == "PROFILE FOUND" else YELLOW
            print(color + f"{item['result']} — {item['platform']}" + RESET)
            if item.get("profile_url"):
                print("  " + item["profile_url"])

    print(CYAN + "\n--- Public profile-page checks ---" + RESET)
    for item in results:
        if item["platform"] not in [x[0] for x in API_CHECKS] and item["platform"] != "Spotify":
            state = item["result"]
            color = YELLOW if ("POSSIBLE" in state or "BLOCKED" in state or "ERROR" in state or "INCONCLUSIVE" in state) else RED
            print(color + f"{state} — {item['platform']}" + RESET)
            if item.get("profile_url"):
                print("  " + item["profile_url"])

    spotify = results[-1]
    print(YELLOW + f"\n{spotify['result']} — Spotify" + RESET)
    print("  " + spotify_url)

    REPORT["modules"]["username"] = {
        "username": username,
        "checked_at": timestamp(),
        "results": results,
        "warning": (
            "A match does not prove accounts belong to the same person. "
            "HTTP 200 responses are weak signals; blocked or missing results are inconclusive."
        ),
    }
    print(YELLOW + "\nNote: Results are leads, not proof of identity." + RESET)


# ---------------- DOMAIN INTELLIGENCE ----------------

def clean_domain(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    from urllib.parse import urlsplit
    host = (urlsplit(raw).hostname or "").lower().rstrip(".")
    pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    if not re.fullmatch(pattern, host):
        raise ValueError("Enter a valid domain, such as example.com.")
    return host


def domain_check():
    domain = clean_domain(input("Domain: "))
    result = {"domain": domain, "checked_at": timestamp(), "checks": {}}

    print(CYAN + "\n>> DNS / IP RECORDS" + RESET)
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
        result["checks"]["addresses"] = addresses
        for address in addresses:
            print(GREEN + "IP: " + address + RESET)
    except socket.gaierror as exc:
        result["checks"]["dns_error"] = str(exc)
        print(RED + "DNS lookup failed: " + str(exc) + RESET)

    try:
        import dns.resolver
        records = {}
        for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(domain, kind, lifetime=5)
                records[kind] = [str(x) for x in answers]
            except Exception:
                records[kind] = []
        result["checks"]["dns_records"] = records
        print(CYAN + "\n>> DNS RECORD TYPES" + RESET)
        for kind, values in records.items():
            print(f"{kind}: {', '.join(values) if values else 'No result'}")
    except ImportError:
        print(YELLOW + "Install dnspython for MX/NS/TXT/CNAME records." + RESET)

    print(CYAN + "\n>> HTTP HEADERS" + RESET)
    response = fetch("https://" + domain)
    if response["status"] is not None:
        result["checks"]["http"] = {
            "status": response["status"],
            "final_url": response["url"],
            "headers": response["headers"],
        }
        print("HTTP status:", response["status"])
        for name, value in response["headers"].items():
            print(f"{name}: {value}")
        print(CYAN + "\n>> COMMON SECURITY HEADERS" + RESET)
        for name in (
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
            "Permissions-Policy",
        ):
            present = name in response["headers"]
            print((GREEN if present else YELLOW) + f"{'PRESENT' if present else 'NOT SEEN'} — {name}" + RESET)
    else:
        result["checks"]["http_error"] = response["error"]
        print(RED + "HTTP request failed: " + str(response["error"]) + RESET)

    print(CYAN + "\n>> TLS CERTIFICATE" + RESET)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()
                cipher = conn.cipher()
                tls = {
                    "version": conn.version(),
                    "cipher": cipher[0] if cipher else None,
                    "issuer": str(cert.get("issuer")),
                    "valid_from": cert.get("notBefore"),
                    "valid_until": cert.get("notAfter"),
                }
        result["checks"]["tls"] = tls
        for key, value in tls.items():
            print(f"{key}: {value}")
    except Exception as exc:
        result["checks"]["tls_error"] = str(exc)
        print(YELLOW + "TLS check unavailable: " + str(exc) + RESET)

    print(CYAN + "\n>> ROBOTS.TXT" + RESET)
    robots = fetch("https://" + domain + "/robots.txt", limit=12000)
    if robots["status"] == 200:
        content = robots["body"].decode("utf-8", errors="replace")
        result["checks"]["robots_txt"] = content
        print(content[:3500])
    else:
        result["checks"]["robots_txt"] = {"status": robots["status"], "available": False}
        print(YELLOW + f"robots.txt unavailable (HTTP {robots['status']})" + RESET)

    REPORT["modules"]["domain"] = result


# ---------------- PHONE NUMBER METADATA ----------------

def phone_check():
    print(CYAN + "\n>> PHONE NUMBER METADATA" + RESET)
    print("Numbering metadata only — no subscriber identity or live location.")
    raw = input("Number with country code (e.g. +919876543210): ").strip()
    if not raw.startswith("+"):
        print(RED + "Include + and the country calling code." + RESET)
        return
    try:
        import phonenumbers
        parsed = phonenumbers.parse(raw, None)
        kind = phonenumbers.number_type(parsed)
        type_names = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
        }
        result = {
            "checked_at": timestamp(),
            "country_calling_code": parsed.country_code,
            "region": phonenumbers.region_code_for_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "valid_numbering_plan_format": phonenumbers.is_valid_number(parsed),
            "type": type_names.get(kind, "other"),
            "international_format": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "national_format": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            ),
            "warning": "This does not identify the subscriber, carrier owner, or live location.",
        }
        for key, value in result.items():
            print(f"{key}: {value}")
        REPORT["modules"]["phone"] = result
    except ImportError:
        print(RED + "Missing package. Run: pip install phonenumbers" + RESET)
    except Exception as exc:
        print(RED + "Could not parse number: " + str(exc) + RESET)


# ---------------- PUBLIC IP NETWORK INTELLIGENCE ----------------

def ip_check():
    print(CYAN + "\n>> PUBLIC IP NETWORK INTELLIGENCE" + RESET)
    print(YELLOW + "Use only your own IP or an IP you are authorized to assess." + RESET)
    raw = input("Public IP address: ").strip()
    try:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise ValueError("This is not a globally routable public IP.")
    except ValueError as exc:
        print(RED + "" + str(exc) + RESET)
        return

    url = "https://ipwho.is/" + urllib.parse.quote(str(address))
    response = fetch(url, timeout=10, limit=20000)
    if response["status"] != 200:
        print(RED + "IP information service unavailable." + RESET)
        return
    try:
        data = json.loads(response["body"].decode("utf-8", errors="replace"))
    except ValueError:
        print(RED + "Invalid response from IP information service." + RESET)
        return
    if not data.get("success", False):
        print(RED + "Lookup failed: " + str(data.get("message", "unknown")) + RESET)
        return

    connection = data.get("connection") or {}
    result = {
        "checked_at": timestamp(),
        "ip": data.get("ip"),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "isp": connection.get("isp"),
        "organization": connection.get("org"),
        "asn": connection.get("asn"),
        "warning": "IP geolocation is approximate network information, not a person's exact location.",
    }
    for key, value in result.items():
        print(f"{key}: {value}")
    REPORT["modules"]["ip"] = result


# ---------------- REPORT EXPORT ----------------

def export_report():
    if not REPORT["modules"]:
        print(YELLOW + "No results to export yet." + RESET)
        return
    REPORT["exported_at"] = timestamp()
    folder = "reports"
    os.makedirs(folder, exist_ok=True)
    filename = os.path.join(
        folder, "vezy_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    )
    with open(filename, "w", encoding="utf-8") as output:
        json.dump(REPORT, output, indent=2, ensure_ascii=False)
    print(GREEN + "Report saved: " + os.path.abspath(filename) + RESET)


def main():
    actions = {
        "1": username_check,
        "2": domain_check,
        "3": phone_check,
        "4": ip_check,
        "5": export_report,
    }
    while True:
        banner()
        print("""
  1. Username intelligence
  2. Domain intelligence
  3. Phone number metadata
  4. Public IP network intelligence
  5. Export JSON report
  0. Exit
""")
        choice = input("VEZY >> ").strip()
        if choice == "0":
            print(CYAN + "VEZY closed." + RESET)
            break
        action = actions.get(choice)
        if action is None:
            print(RED + "Invalid option." + RESET)
            input("Press Enter...")
            continue
        try:
            action()
        except KeyboardInterrupt:
            print(YELLOW + "\nOperation cancelled." + RESET)
        except Exception as exc:
            print(RED + "\nError: " + str(exc) + RESET)
        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nVEZY closed.")
