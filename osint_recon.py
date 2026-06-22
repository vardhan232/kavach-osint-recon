#!/usr/bin/env python3
"""
Kavach OSINT Recon Tool — Cybersecurity Pre-Engagement Reconnaissance
Gathers publicly available intelligence on a business domain before a
client pitch or security audit. All checks use ONLY public information
sources — nothing here accesses private systems or data.

Usage:
    python osint_recon.py <domain> [business_name]

Example:
    python osint_recon.py soundental.com "Sound Dental"

Output:
    Prints a full report to terminal AND saves it to:
    kavach_osint_<domain>.txt   (plain text, easy to paste/share)
    kavach_osint_<domain>.json  (structured data, for later automation)
"""

import sys
import os
import json
import socket
import ssl
import datetime
import re
import time
import requests
import dns.resolver

# ─── COLOURS FOR TERMINAL OUTPUT ──────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GOLD    = "\033[33m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    GRAY    = "\033[90m"

SEV_COLOR = {
    "CRITICAL": C.RED, "HIGH": C.ORANGE, "MEDIUM": C.YELLOW,
    "LOW": C.BLUE, "PASS": C.GREEN, "INFO": C.GRAY,
}
SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "PASS": 1, "INFO": 0}


def hdr(title):
    line = "─" * 64
    print(f"\n{C.GOLD}{line}{C.RESET}")
    print(f"{C.BOLD}{C.GOLD}  {title}{C.RESET}")
    print(f"{C.GOLD}{line}{C.RESET}")


def finding(sev, msg):
    color = SEV_COLOR.get(sev, C.GRAY)
    print(f"  {color}[{sev:^8}]{C.RESET}  {msg}")


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 1 — DOMAIN & WHOIS RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════

def recon_whois(domain):
    """Pull WHOIS registration data — registrar, creation/expiry dates, registrant org."""
    result = {"module": "Domain Registration (WHOIS)", "findings": [], "severity": "PASS"}
    try:
        import whois
        w = whois.whois(domain)

        def first_or_none(val):
            """python-whois sometimes returns a list, sometimes a single value, sometimes None."""
            if isinstance(val, list):
                return val[0] if val else None
            return val

        def as_datetime(val):
            """
            python-whois occasionally fails to parse a date string internally and
            silently returns the raw STRING instead of a datetime object (a known
            quirk in its cast_date() fallback). Guard against that here so a bad
            date from one registrar never crashes the whole scan.
            """
            val = first_or_none(val)
            if isinstance(val, datetime.datetime):
                return val
            return None  # string, None, or anything else we can't safely do date math on

        created = as_datetime(w.creation_date)
        expires = as_datetime(w.expiration_date)

        if created:
            age_days = (datetime.datetime.now(created.tzinfo) - created).days
            age_years = age_days / 365
            result["findings"].append(("INFO", f"Domain age: {age_years:.1f} years (registered {created.strftime('%Y-%m-%d')})"))
            if age_years < 0.5:
                result["findings"].append(("MEDIUM", "Domain is very new (<6 months) — verify legitimacy if unfamiliar"))
                result["severity"] = "MEDIUM"
        else:
            raw = first_or_none(w.creation_date)
            result["findings"].append(("INFO", f"Domain creation date not in a standard format{f' (raw: {raw})' if raw else ' (not available from registrar)'}"))

        if expires:
            days_left = (expires - datetime.datetime.now(expires.tzinfo)).days
            if days_left < 0:
                result["findings"].append(("CRITICAL", f"Domain registration EXPIRED {abs(days_left)} days ago"))
                result["severity"] = "CRITICAL"
            elif days_left < 30:
                result["findings"].append(("HIGH", f"Domain expires in {days_left} days — renewal needed urgently"))
                if SEV_RANK[result["severity"]] < SEV_RANK["HIGH"]: result["severity"] = "HIGH"
            else:
                result["findings"].append(("PASS", f"Domain valid for {days_left} more days"))
        else:
            raw = first_or_none(w.expiration_date)
            result["findings"].append(("INFO", f"Domain expiration date not in a standard format{f' (raw: {raw})' if raw else ' (not available from registrar)'}"))

        registrar = first_or_none(w.registrar) or "Unknown"
        result["findings"].append(("INFO", f"Registrar: {registrar}"))

        org = first_or_none(getattr(w, "org", None))
        if org:
            result["findings"].append(("INFO", f"Registrant organization: {org}"))

        # Privacy protection check
        registrant_name = first_or_none(getattr(w, "name", None))
        registrant = str(registrant_name or "").lower()
        if "privacy" in registrant or "redacted" in registrant or "whoisguard" in registrant:
            result["findings"].append(("INFO", "WHOIS privacy protection is enabled (registrant identity hidden)"))
        elif registrant_name:
            result["findings"].append(("LOW", f"Registrant name publicly visible: {registrant_name} — consider WHOIS privacy"))

    except Exception as e:
        result["findings"].append(("INFO", f"WHOIS lookup unavailable: {type(e).__name__} — some registrars block or rate-limit automated WHOIS queries"))

    return result


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 2 — DNS DEEP RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════

def doh_query(name, rtype, timeout=8):
    """Query via Cloudflare DNS-over-HTTPS — avoids local resolver issues."""
    r = requests.get(
        "https://cloudflare-dns.com/dns-query",
        params={"name": name, "type": rtype},
        headers={"Accept": "application/dns-json"},
        timeout=timeout,
    )
    return r.json()


def recon_dns(domain):
    """Full DNS footprint — A, MX, TXT, NS, CAA, DNSSEC."""
    result = {"module": "DNS Infrastructure", "findings": [], "severity": "PASS"}
    bump = lambda s: result.update(severity=s) if SEV_RANK[s] > SEV_RANK[result["severity"]] else None

    # A records (IP addresses)
    try:
        a = doh_query(domain, "A")
        ips = [ans["data"] for ans in a.get("Answer", []) if ans.get("type") == 1]
        if ips:
            result["findings"].append(("INFO", f"IP address(es): {', '.join(ips)}"))
        else:
            result["findings"].append(("INFO", "No A record found"))
    except Exception:
        result["findings"].append(("INFO", "A record lookup failed"))

    # NS records (who hosts DNS)
    try:
        ns = doh_query(domain, "NS")
        servers = [ans["data"] for ans in ns.get("Answer", []) if ans.get("type") == 2]
        if servers:
            result["findings"].append(("INFO", f"Nameservers: {', '.join(servers[:2])}"))
    except Exception:
        pass

    # MX records (email provider — reveals what email system they use)
    try:
        mx = doh_query(domain, "MX")
        mxs = [ans["data"] for ans in mx.get("Answer", []) if ans.get("type") == 15]
        if mxs:
            provider = "Google Workspace" if any("google" in m.lower() for m in mxs) else \
                       "Microsoft 365" if any("outlook" in m.lower() or "protection" in m.lower() for m in mxs) else \
                       "Unknown/Custom"
            result["findings"].append(("INFO", f"Email provider detected: {provider}"))
        else:
            result["findings"].append(("MEDIUM", "No MX records — email may not be configured for this domain"))
            bump("MEDIUM")
    except Exception:
        result["findings"].append(("INFO", "MX lookup failed"))

    # TXT records (SPF + other verifications, reveals 3rd party services in use)
    try:
        txt = doh_query(domain, "TXT")
        txts = [ans["data"] for ans in txt.get("Answer", []) if ans.get("type") == 16]
        services_found = []
        for t in txts:
            if "google-site-verification" in t: services_found.append("Google Search Console")
            if "facebook-domain-verification" in t: services_found.append("Facebook Business")
            if "stripe-verification" in t: services_found.append("Stripe payments")
            if "ms=" in t: services_found.append("Microsoft 365")
            if "shopify" in t.lower(): services_found.append("Shopify")
        if services_found:
            result["findings"].append(("INFO", f"Third-party services detected via TXT records: {', '.join(set(services_found))}"))
    except Exception:
        pass

    # DNSSEC
    try:
        ds = doh_query(domain, "DS")
        if ds.get("Answer"):
            result["findings"].append(("PASS", "DNSSEC enabled — protects against DNS spoofing"))
        else:
            result["findings"].append(("LOW", "DNSSEC not enabled — domain vulnerable to DNS spoofing/cache poisoning"))
    except Exception:
        pass

    # CAA
    try:
        caa = doh_query(domain, "CAA")
        if not caa.get("Answer"):
            result["findings"].append(("LOW", "No CAA record — any Certificate Authority can issue SSL certs for this domain"))
    except Exception:
        pass

    return result


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 3 — SUBDOMAIN DISCOVERY (Certificate Transparency)
# ═══════════════════════════════════════════════════════════════════════════

def recon_subdomains(domain):
    """
    Find subdomains via crt.sh certificate transparency logs.
    This reveals dev/staging/admin subdomains that are often less protected
    than the main website — a common real-world attack vector.
    """
    result = {"module": "Subdomain Discovery", "findings": [], "severity": "PASS"}

    # crt.sh is frequently slow/overloaded — try twice with a longer timeout
    for attempt in range(2):
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
            if r.status_code == 200 and r.text.strip():
                data = r.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(domain) and "*" not in line:
                            subdomains.add(line)

                subdomains.discard(domain)
                subdomains.discard(f"www.{domain}")

                if subdomains:
                    interesting = [s for s in subdomains if any(
                        kw in s for kw in ["dev", "staging", "test", "admin", "internal",
                                           "vpn", "remote", "old", "backup", "mail", "webmail",
                                           "ftp", "api", "portal", "secure"]
                    )]
                    result["findings"].append(("INFO", f"Found {len(subdomains)} total subdomain(s) via certificate logs"))
                    if interesting:
                        result["findings"].append(("HIGH", f"Sensitive-looking subdomains found: {', '.join(sorted(interesting)[:10])}"))
                        result["severity"] = "HIGH"
                    for s in sorted(subdomains)[:15]:
                        result["findings"].append(("INFO", f"  └─ {s}"))
                else:
                    result["findings"].append(("PASS", "No additional subdomains found in certificate transparency logs"))
                return result  # success — exit the retry loop
            else:
                result["findings"].append(("INFO", "crt.sh returned no data (may be rate limited — try again later)"))
                return result
        except requests.exceptions.Timeout:
            if attempt == 0:
                continue  # retry once
            result["findings"].append(("INFO", "Subdomain lookup timed out after 2 attempts — crt.sh is heavily loaded right now. Try running this module again in a few minutes, or check manually at crt.sh in your browser"))
        except Exception as e:
            result["findings"].append(("INFO", f"Subdomain discovery failed: {type(e).__name__}"))
            return result

    return result


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 4 — BREACH & CREDENTIAL EXPOSURE
# ═══════════════════════════════════════════════════════════════════════════

def recon_breach(domain):
    """Check HaveIBeenPwned for known breaches tied to this domain."""
    result = {"module": "Data Breach Exposure", "findings": [], "severity": "PASS"}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"User-Agent": "Kavach-OSINT-Tool/1.0 (legitimate security research)"},
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json()
            result["findings"].append(("HIGH", f"{len(breaches)} known breach(es) associated with this domain"))
            result["severity"] = "HIGH"
            for b, details in list(breaches.items())[:5]:
                result["findings"].append(("INFO", f"  └─ Breach detail: {b}"))
        elif r.status_code == 404:
            result["findings"].append(("PASS", "No known breaches found for this domain in HIBP database"))
        elif r.status_code == 401:
            result["findings"].append(("INFO", "Breach API requires authentication for this query type"))
        else:
            result["findings"].append(("INFO", f"Breach check returned status {r.status_code}"))
    except Exception as e:
        result["findings"].append(("INFO", f"Breach check skipped: {type(e).__name__}"))

    return result


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 5 — TECHNOLOGY FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════

def recon_tech_stack(domain):
    """
    Identify what software/platform the website runs on by examining
    response headers, cookies, and HTML signatures. Outdated platforms
    are a major attack surface.
    """
    result = {"module": "Technology Fingerprint", "findings": [], "severity": "PASS"}
    try:
        r = requests.get(f"https://{domain}", timeout=10, headers={"User-Agent": "Mozilla/5.0 (KavachOSINT)"}, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        html = r.text.lower()

        techs = []
        if "wordpress" in html or "wp-content" in html: techs.append("WordPress")
        if "wix.com" in html: techs.append("Wix")
        if "squarespace" in html: techs.append("Squarespace")
        if "shopify" in html: techs.append("Shopify")
        if "webflow" in html: techs.append("Webflow")
        if "react" in html and "data-reactroot" in html: techs.append("React")
        if "x-powered-by" in headers: techs.append(f"Server: {headers['x-powered-by']}")
        if "server" in headers: techs.append(f"Web server: {headers['server']}")

        if techs:
            result["findings"].append(("INFO", f"Technology stack detected: {', '.join(techs)}"))
        else:
            result["findings"].append(("INFO", "Could not fingerprint specific technology stack"))

        # WordPress version exposure check (common vulnerability)
        if "wordpress" in html or "wp-content" in html:
            ver_match = re.search(r'content="wordpress\s*([\d.]+)"', html)
            if ver_match:
                result["findings"].append(("MEDIUM", f"WordPress version {ver_match.group(1)} is publicly exposed in page source"))
                result["severity"] = "MEDIUM"
            # Check for exposed wp-login
            try:
                login_check = requests.get(f"https://{domain}/wp-login.php", timeout=6, allow_redirects=False)
                if login_check.status_code == 200:
                    result["findings"].append(("MEDIUM", "WordPress admin login page is publicly accessible at /wp-login.php"))
            except Exception:
                pass

        # Server header leaking version info
        server_hdr = headers.get("server", "")
        if re.search(r'\d+\.\d+', server_hdr):
            result["findings"].append(("LOW", f"Server header exposes version info: {server_hdr} — consider suppressing this"))

    except requests.exceptions.SSLError as e:
        result["findings"].append(("HIGH", "Could not connect via HTTPS — SSL certificate error (mismatch, expired, or untrusted). This matches what a security scanner would flag — the site's certificate is likely misconfigured for this exact domain"))
        result["severity"] = "HIGH"
    except Exception as e:
        result["findings"].append(("INFO", f"Tech fingerprint skipped: {type(e).__name__}"))

    return result


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 6 — WAYBACK MACHINE EXPOSURE (forgotten/archived pages)
# ═══════════════════════════════════════════════════════════════════════════

def recon_wayback(domain):
    """
    Check Wayback Machine for historically archived pages that may still
    be indexed or accessible — old staff directories, pricing pages,
    or admin panels that were 'removed' but never actually deleted.
    """
    result = {"module": "Historical/Archived Exposure", "findings": [], "severity": "PASS"}
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": f"{domain}/*", "output": "json", "limit": 30, "collapse": "urlkey"},
            timeout=12,
        )
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:  # first row is headers
                urls = [row[2] for row in data[1:]]
                interesting = [u for u in urls if any(
                    kw in u.lower() for kw in ["admin", "login", "staff", "employee", "password",
                                                 "backup", ".sql", ".env", "config", "test", "internal"]
                )]
                result["findings"].append(("INFO", f"{len(urls)} archived page(s) found in Wayback Machine"))
                if interesting:
                    result["findings"].append(("MEDIUM", f"Potentially sensitive archived URLs found ({len(interesting)}):"))
                    result["severity"] = "MEDIUM"
                    for u in interesting[:8]:
                        result["findings"].append(("INFO", f"  └─ {u}"))
            else:
                result["findings"].append(("PASS", "No archived snapshots found"))
    except Exception as e:
        result["findings"].append(("INFO", f"Wayback check skipped: {type(e).__name__}"))

    return result


# ═══════════════════════════════════════════════════════════════════════════
# MODULE 7 — EMAIL SECURITY (SPF/DMARC) — carried over from scanner
# ═══════════════════════════════════════════════════════════════════════════

def recon_email_auth(domain):
    result = {"module": "Email Authentication", "findings": [], "severity": "PASS"}
    bump = lambda s: result.update(severity=s) if SEV_RANK[s] > SEV_RANK[result["severity"]] else None

    try:
        spf = doh_query(domain, "TXT")
        spf_rec = next((a["data"] for a in spf.get("Answer", []) if "v=spf1" in a.get("data", "")), None)
        if spf_rec:
            result["findings"].append(("PASS", "SPF record found"))
        else:
            result["findings"].append(("HIGH", "No SPF record — email spoofing possible"))
            bump("HIGH")
    except Exception:
        result["findings"].append(("INFO", "SPF check failed"))

    try:
        dmarc = doh_query(f"_dmarc.{domain}", "TXT")
        rec = next((a["data"] for a in dmarc.get("Answer", []) if "v=DMARC1" in a.get("data", "")), None)
        if rec:
            policy_match = re.search(r'p=([^;"\s]+)', rec)
            policy = policy_match.group(1).lower() if policy_match else "none"
            if policy == "none":
                result["findings"].append(("MEDIUM", "DMARC exists but policy=none (not enforced)"))
                bump("MEDIUM")
            else:
                result["findings"].append(("PASS", f"DMARC policy={policy} — actively enforced"))
        else:
            result["findings"].append(("CRITICAL", "No DMARC record — domain fully exposed to email spoofing"))
            bump("CRITICAL")
    except Exception:
        result["findings"].append(("INFO", "DMARC check failed"))

    return result


# ═══════════════════════════════════════════════════════════════════════════
# OVERALL RISK + REPORT BUILDING
# ═══════════════════════════════════════════════════════════════════════════

def overall_risk(modules):
    top = "PASS"
    for m in modules:
        if SEV_RANK[m["severity"]] > SEV_RANK[top]:
            top = m["severity"]
    return top


def print_report(domain, business_name, modules, elapsed):
    risk = overall_risk(modules)
    print(f"\n{C.BOLD}{C.GOLD}")
    print("  ██╗  ██╗ █████╗ ██╗   ██╗ █████╗  ██████╗██╗  ██╗")
    print("  ██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║")
    print("  █████╔╝ ███████║██║   ██║███████║██║     ███████║")
    print("  ██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║")
    print("  ██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║")
    print("  ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝")
    print(f"{C.RESET}{C.BOLD}            OSINT RECONNAISSANCE REPORT{C.RESET}")
    print(f"{C.GRAY}            Cybersecurity Pre-Engagement Intelligence{C.RESET}\n")

    print(f"  {C.BOLD}Target:{C.RESET}      {domain}")
    print(f"  {C.BOLD}Business:{C.RESET}    {business_name or '(not specified)'}")
    print(f"  {C.BOLD}Scan time:{C.RESET}   {datetime.datetime.now().strftime('%B %d, %Y %H:%M')}")
    print(f"  {C.BOLD}Duration:{C.RESET}    {elapsed:.1f} seconds")

    for mod in modules:
        hdr(mod["module"])
        for sev, msg in mod["findings"]:
            finding(sev, msg)

    crit = sum(1 for m in modules for f in m["findings"] if f[0] == "CRITICAL")
    high = sum(1 for m in modules for f in m["findings"] if f[0] == "HIGH")
    med  = sum(1 for m in modules for f in m["findings"] if f[0] == "MEDIUM")

    print(f"\n{C.GOLD}{'═'*64}{C.RESET}")
    risk_color = SEV_COLOR.get(risk, C.GRAY)
    print(f"  {C.BOLD}OVERALL RISK:{C.RESET}  {risk_color}{C.BOLD}{risk}{C.RESET}")
    print(f"  {C.RED}{crit} Critical{C.RESET}  ·  {C.ORANGE}{high} High{C.RESET}  ·  {C.YELLOW}{med} Medium{C.RESET}")
    print(f"{C.GOLD}{'═'*64}{C.RESET}\n")

    print(f"{C.GRAY}  ⚠  All data above is from PUBLIC sources only (DNS, certificate")
    print(f"     transparency logs, WHOIS, public breach databases, Wayback Machine).")
    print(f"     No private systems were accessed.{C.RESET}\n")


def save_report(domain, business_name, modules, elapsed):
    risk = overall_risk(modules)
    safe_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Plain text version (no ANSI colors, easy to paste anywhere)
    txt_path = os.path.join(script_dir, f"kavach_osint_{safe_domain}.txt")
    with open(txt_path, "w") as f:
        f.write("KAVACH CYBER SOLUTIONS — OSINT RECONNAISSANCE REPORT\n")
        f.write("="*64 + "\n")
        f.write(f"Target:    {domain}\n")
        f.write(f"Business:  {business_name or '(not specified)'}\n")
        f.write(f"Scan time: {datetime.datetime.now().strftime('%B %d, %Y %H:%M')}\n")
        f.write(f"Duration:  {elapsed:.1f}s\n\n")
        for mod in modules:
            f.write(f"\n--- {mod['module']} ---\n")
            for sev, msg in mod["findings"]:
                f.write(f"  [{sev}] {msg}\n")
        f.write(f"\n{'='*64}\n")
        f.write(f"OVERALL RISK: {risk}\n")
        f.write("="*64 + "\n")
        f.write("\nAll data from public sources only. No private systems accessed.\n")

    # JSON version (structured, for future automation)
    json_path = os.path.join(script_dir, f"kavach_osint_{safe_domain}.json")
    with open(json_path, "w") as f:
        json.dump({
            "domain": domain,
            "business_name": business_name,
            "scan_time": datetime.datetime.now().isoformat(),
            "duration_seconds": elapsed,
            "overall_risk": risk,
            "modules": modules,
        }, f, indent=2)

    return txt_path, json_path


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def run_osint(domain, business_name=""):
    domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    start = time.time()

    modules_to_run = [
        ("Domain registration (WHOIS)",     recon_whois),
        ("DNS infrastructure",               recon_dns),
        ("Subdomain discovery",              recon_subdomains),
        ("Data breach exposure",             recon_breach),
        ("Technology fingerprint",           recon_tech_stack),
        ("Historical/archived exposure",     recon_wayback),
        ("Email authentication",             recon_email_auth),
    ]

    print(f"\n{C.GOLD}🛡  Kavach OSINT Recon — scanning {domain} ...{C.RESET}\n")

    modules = []
    for label, fn in modules_to_run:
        print(f"  {C.GRAY}⏳ Running: {label}...{C.RESET}", end="\r")
        try:
            result = fn(domain)
        except Exception as e:
            result = {"module": label, "findings": [("INFO", f"Module error: {e}")], "severity": "PASS"}
        modules.append(result)
        color = SEV_COLOR.get(result["severity"], C.GRAY)
        print(f"  {color}● {label} → {result['severity']}{C.RESET}" + " "*20)

    elapsed = time.time() - start
    print_report(domain, business_name, modules, elapsed)
    txt, js = save_report(domain, business_name, modules, elapsed)
    print(f"{C.GREEN}✅  Reports saved:{C.RESET}")
    print(f"    {txt}")
    print(f"    {js}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python osint_recon.py <domain> [business_name]")
        print('Example: python osint_recon.py soundental.com "Sound Dental"')
        sys.exit(1)
    domain = sys.argv[1]
    biz = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else ""
    run_osint(domain, biz)
