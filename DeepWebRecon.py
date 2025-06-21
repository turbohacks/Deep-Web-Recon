import tkinter as tk
from tkinter import messagebox
import requests
import socket
import subprocess
import datetime
import os
import threading
import ssl
import dns.resolver
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
import urllib.parse
import time
import random
import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

COMMON_SUBDOMAINS = [
    "admin", "mail", "webmail", "vpn", "test", "dev", "portal",
    "cpanel", "login", "secure", "server", "mx", "api", "shop"
]

EXTENDED_SUBDOMAINS = COMMON_SUBDOMAINS + [
    "blog", "news", "shop", "staging", "beta", "demo", "forum", "support",
    "m", "cdn", "images", "static", "downloads"
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/adminpanel", "/cpanel", "/login",
    "/user", "/wp-admin", "/manager", "/secure", "/admin/login"
]

EXPOSED_PATHS = [
    "/.git/", "/.env", "/config.php", "/db_backup.sql", "/backup.zip"
]

WAYBACK_API = "http://archive.org/wayback/available?url={}"

HEADERS_USER_AGENT = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/114.0.0.0 Safari/537.36"
}

MAX_THREADS = 15


class ZeshanInvestigatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep Web Recon")  # <-- Only this line is changed
        self.root.geometry("700x650")

        tk.Label(root, text="Domain or Stream URL:").pack(pady=5)
        self.url_entry = tk.Entry(root, width=80)
        self.url_entry.pack(pady=5)
        self.url_entry.insert(0, "enter your victim url")

        tk.Label(root, text="Output Directory (optional):").pack(pady=5)
        self.output_dir_entry = tk.Entry(root, width=80)
        self.output_dir_entry.pack(pady=5)
        self.output_dir_entry.insert(0, os.getcwd())

        tk.Button(root, text="Start Deep Recon", command=self.start_investigation).pack(pady=10)

        self.log_text = tk.Text(root, height=35, width=90)
        self.log_text.pack(pady=5)

    def log(self, message, animate=True, delay=0.01):
        if animate:
            for char in message:
                self.log_text.insert(tk.END, char)
                self.log_text.see(tk.END)
                self.root.update()
                time.sleep(delay)
            self.log_text.insert(tk.END, "\n")
        else:
            self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()

    def write_section_header(self, logf, title):
        sep = "=" * 40
        header = f"\n{sep}\n[ {title.upper()} ]\n{sep}\n"
        self.log(header, animate=False)
        logf.write(header + "\n")

    def start_investigation(self):
        domain = self.url_entry.get().strip()
        outdir = self.output_dir_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a valid domain or URL.")
            return
        if not os.path.isdir(outdir):
            messagebox.showerror("Error", "Output directory does not exist.")
            return

        self.url_entry.config(state='disabled')
        self.output_dir_entry.config(state='disabled')

        threading.Thread(target=self.deep_recon, args=(domain, outdir)).start()

    def deep_recon(self, domain, outdir):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(outdir, f"zeshan_deep_recon_{timestamp}.txt")

        self.log(f"[*] Starting deep recon for: {domain}")
        with open(log_file, "w") as logf:

            def write_log(m, animated=True):
                self.log(m, animate=animated)
                logf.write(m + "\n")
                time.sleep(random.uniform(0.02, 0.07))

            if domain.startswith("http"):
                domain = urllib.parse.urlparse(domain).netloc

            write_log(f"Target domain: {domain}")

            self.write_section_header(logf, "DNS Records")
            for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    answers = dns.resolver.resolve(domain, record_type, lifetime=5)
                    for rdata in answers:
                        write_log(f"{record_type}: {rdata.to_text()}")
                except Exception as e:
                    write_log(f"{record_type}: No records found or error - {e}")

            self.write_section_header(logf, "IP and WHOIS Info")
            try:
                ip = socket.gethostbyname(domain)
                write_log(f"IP Address: {ip}")
                try:
                    whois_obj = IPWhois(ip)
                    res = whois_obj.lookup_rdap(depth=1)
                    net = res.get('network', {})
                    whois_lines = [
                        f"Network Name: {net.get('name', 'N/A')}",
                        f"Country: {net.get('country', 'N/A')}",
                        f"CIDR: {net.get('cidr', 'N/A')}",
                        f"ASN: {res.get('asn', 'N/A')}",
                        f"ASN Description: {res.get('asn_description', 'N/A')}"
                    ]
                    for line in whois_lines:
                        write_log(line)
                except IPDefinedError:
                    write_log("WHOIS info not available for private/reserved IP.")
                except Exception as e:
                    write_log(f"WHOIS lookup failed: {e}")
            except Exception as e:
                write_log(f"DNS lookup failed: {e}")
                ip = None

            if ip:
                self.write_section_header(logf, "Geolocation Info")
                try:
                    geo = requests.get(f"http://ip-api.com/json/{ip}").json()
                    geo_lines = [
                        f"City: {geo.get('city', 'N/A')}",
                        f"Region: {geo.get('regionName', 'N/A')}",
                        f"Country: {geo.get('country', 'N/A')}",
                        f"Latitude: {geo.get('lat', 'N/A')}",
                        f"Longitude: {geo.get('lon', 'N/A')}",
                        f"ISP: {geo.get('isp', 'N/A')}",
                        f"Map: https://www.google.com/maps?q={geo.get('lat','')},{geo.get('lon','')}"
                    ]
                    for line in geo_lines:
                        write_log(line)
                except Exception as e:
                    write_log(f"Location fetch failed: {e}")

            self.write_section_header(logf, "Ping Test")
            try:
                param = "-n" if os.name == "nt" else "-c"
                ping_res = subprocess.check_output(["ping", param, "4", domain], universal_newlines=True)
                write_log(ping_res, animated=False)
            except Exception as e:
                write_log(f"Ping test failed: {e}")

            self.write_section_header(logf, "Traceroute")
            try:
                if os.name == "nt":
                    traceroute_cmd = ["tracert", "-h", "15", domain]
                else:
                    traceroute_cmd = ["traceroute", "-m", "15", domain]
                traceroute_res = subprocess.check_output(traceroute_cmd, universal_newlines=True)
                write_log(traceroute_res, animated=False)
            except Exception as e:
                write_log(f"Traceroute failed: {e}")

            self.write_section_header(logf, "Subdomain Enumeration")
            found_subdomains = []

            def check_subdomain(sub):
                fqdn = f"{sub}.{domain}"
                try:
                    ip_sub = socket.gethostbyname(fqdn)
                    return fqdn, ip_sub
                except:
                    return None

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                results = executor.map(check_subdomain, EXTENDED_SUBDOMAINS)
            for result in results:
                if result:
                    fqdn, ip_sub = result
                    write_log(f"Found subdomain: {fqdn} -> {ip_sub}")
                    found_subdomains.append(fqdn)
            if not found_subdomains:
                write_log("No common subdomains found.")

            self.write_section_header(logf, "Admin Panel URLs")
            session = requests.Session()
            possible_admins = []
            targets = found_subdomains if found_subdomains else [domain]

            for sub in targets:
                base_urls = [f"https://{sub}", f"http://{sub}"]
                for base_url in base_urls:
                    for path in ADMIN_PATHS:
                        url = base_url + path
                        try:
                            r = session.head(url, allow_redirects=True, timeout=5)
                            if r.status_code in [200, 301, 302, 401, 403]:
                                msg = f"Possible admin panel found: {url} (Status: {r.status_code})"
                                write_log(msg)
                                possible_admins.append(msg)
                        except:
                            pass

            self.write_section_header(logf, "Exposed Files Check")
            exposed_files_found = []
            base_urls = [f"https://{domain}", f"http://{domain}"]
            for base_url in base_urls:
                for path in EXPOSED_PATHS:
                    url = base_url + path
                    try:
                        r = session.head(url, allow_redirects=True, timeout=5)
                        if r.status_code == 200:
                            msg = f"Exposed file found: {url} (Status: {r.status_code})"
                            write_log(msg)
                            exposed_files_found.append(msg)
                    except:
                        pass

            self.write_section_header(logf, "SSL Certificate Info")
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    ssl_lines = [
                        f"Subject: {subject.get('commonName', 'N/A')}",
                        f"Issuer: {issuer.get('commonName', 'N/A')}",
                        f"Valid From: {cert.get('notBefore', 'N/A')}",
                        f"Valid Until: {cert.get('notAfter', 'N/A')}"
                    ]
                    for line in ssl_lines:
                        write_log(line)
            except Exception as e:
                write_log(f"SSL info retrieval failed: {e}")

            self.write_section_header(logf, "HTTP & Security Headers")
            try:
                resp = session.get(f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7)
                headers = resp.headers
                for k, v in headers.items():
                    write_log(f"{k}: {v}")

                security_headers = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security',
                                    'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
                for sh in security_headers:
                    write_log(f"Security Header - {sh}: {headers.get(sh, 'Not Found')}")
            except Exception as e:
                write_log(f"HTTP headers fetch failed: {e}")

            self.write_section_header(logf, "Wayback Machine Snapshot Info")
            try:
                url_encoded = urllib.parse.quote(domain)
                wb_url = WAYBACK_API.format(url_encoded)
                wb_resp = requests.get(wb_url, timeout=7).json()
                if 'archived_snapshots' in wb_resp and wb_resp['archived_snapshots']:
                    closest = wb_resp['archived_snapshots'].get('closest', {})
                    snapshot_url = closest.get('url', 'N/A')
                    timestamp_snap = closest.get('timestamp', 'N/A')
                    write_log(f"Latest snapshot: {snapshot_url}")
                    write_log(f"Snapshot timestamp: {timestamp_snap}")
                else:
                    write_log("No snapshots found.")
            except Exception as e:
                write_log(f"Wayback Machine fetch failed: {e}")

            self.write_section_header(logf, "CMS & Technology Detection")
            try:
                resp = session.get(f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7)
                text = resp.text.lower()
                cms_tech = []
                if 'wp-content' in text or 'wordpress' in text:
                    cms_tech.append("WordPress")
                if 'joomla' in text:
                    cms_tech.append("Joomla")
                if 'drupal' in text:
                    cms_tech.append("Drupal")
                if 'shopify' in text:
                    cms_tech.append("Shopify")
                if 'asp.net' in text or 'microsoft' in resp.headers.get('server', '').lower():
                    cms_tech.append("ASP.NET")
                if not cms_tech:
                    cms_tech.append("Unknown or Custom CMS")
                for c in cms_tech:
                    write_log(f"Detected CMS/Tech: {c}")
            except Exception as e:
                write_log(f"CMS detection failed: {e}")

            self.write_section_header(logf, "Email Harvesting")
            try:
                resp = session.get(f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7)
                emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', resp.text))
                if emails:
                    for e in emails:
                        write_log(f"Found email: {e}")
                else:
                    write_log("No emails found on homepage.")
            except Exception as e:
                write_log(f"Email harvesting failed: {e}")

            write_log("\n[✔] Deep recon finished.")
            messagebox.showinfo("Done", f"Deep recon finished!\nLog saved to {log_file}")

        self.url_entry.config(state='normal')
        self.output_dir_entry.config(state='normal')


def zeshan_cpm(root):
    return ZeshanInvestigatorApp(root)


if __name__ == "__main__":
    root = tk.Tk()
    app = zeshan_cpm(root)
    root.mainloop()