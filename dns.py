import dns.resolver
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import socket
import time

# Function to check SPF record
def check_spf(domain):
    print(f"[*] Checking SPF for {domain}")
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if rdata.to_text().startswith('"v=spf1'):
                print(f"[+] SPF record found: {rdata}")
                return rdata
        print("[-] No SPF record found.")
    except Exception as e:
        print(f"[!] Error checking SPF: {e}")

# Function to check for open ports (for vulnerable services like SMTP, HTTP, etc.)
def check_open_ports(domain):
    ports = [25, 443, 80, 110]  # SMTP, HTTPS, HTTP, POP3
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                print(f"[+] Open port found: {port}")
            else:
                print(f"[-] Port {port} closed.")
            sock.close()
        except socket.error as e:
            print(f"[!] Error checking port {port}: {e}")

# Function to check for DMARC record
def check_dmarc(domain):
    print(f"[*] Checking DMARC for {domain}")
    try:
        dmarc_record = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_record, 'TXT')
        for rdata in answers:
            print(f"[+] DMARC record found: {rdata}")
            return rdata
        print("[-] No DMARC record found.")
    except Exception as e:
        print(f"[!] Error checking DMARC: {e}")

# Function to check for DKIM record
def check_dkim(domain):
    print(f"[*] Checking DKIM for {domain}")
    try:
        dkim_record = f"selector1._domainkey.{domain}"  # Replace 'selector1' with the actual DKIM selector
        answers = dns.resolver.resolve(dkim_record, 'TXT')
        for rdata in answers:
            print(f"[+] DKIM record found: {rdata}")
            return rdata
        print("[-] No DKIM record found.")
    except Exception as e:
        print(f"[!] Error checking DKIM: {e}")

# Function to test open redirects
def test_open_redirect(url):
    print(f"[*] Testing open redirect for {url}")
    try:
        response = requests.get(url)
        if "example.com" in response.url:
            print("[!] Open Redirect vulnerability detected.")
        else:
            print("[*] No Open Redirect found.")
    except requests.RequestException as e:
        print(f"[!] Error testing open redirect: {e}")

# Function to test SSL/TLS vulnerabilities
def test_ssl(domain):
    print(f"[*] Checking SSL/TLS for {domain}")
    try:
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        connection.connect((domain, 443))
        cert = connection.getpeercert()
        ssl_version = connection.version()
        print(f"SSL Version: {ssl_version}")
        print(f"Certificate Info: {cert}")
        connection.close()
    except Exception as e:
        print(f"[!] Error checking SSL: {e}")

# Function to check for insecure cookies
def test_insecure_cookies(url):
    print(f"[*] Checking insecure cookies for {url}")
    try:
        response = requests.get(url)
        cookies = response.cookies
        for cookie in cookies:
            if "Secure" not in cookie or "HttpOnly" not in cookie:
                print(f"[!] Insecure cookie found: {cookie}")
            else:
                print(f"[*] Secure cookie: {cookie}")
    except requests.RequestException as e:
        print(f"[!] Error checking cookies: {e}")

# Function to check rate limiting on login page
def test_rate_limiting(url):
    print(f"[*] Testing rate limiting for {url}")
    try:
        for i in range(1, 100):  # Brute force attempt
            response = requests.post(url, data={"username": "test", "password": "wrongpassword"})
            if "Too many requests" in response.text:
                print("[!] Rate limiting detected.")
                return
        print("[*] No rate limiting detected.")
    except requests.RequestException as e:
        print(f"[!] Error checking rate limiting: {e}")

# Main function to run all tests
def run_tests(domain):
    # Check SPF, DMARC, DKIM
    check_spf(domain)
    check_dmarc(domain)
    check_dkim(domain)

    # Check for open ports (e.g., SMTP)
    check_open_ports(domain)

    # Check SSL/TLS vulnerabilities
    test_ssl(domain)

    # Check for insecure cookies
    test_insecure_cookies(f"http://{domain}")

    # Test open redirects
    test_open_redirect(f"http://{domain}/redirect?url=https://example.com")

    # Check rate limiting (assuming login page is available at /login)
    test_rate_limiting(f"http://{domain}/login")

# Run tests
if __name__ == "__main__":
    domain = "example.com"  # Replace with the domain you're testing
    run_tests(domain)
