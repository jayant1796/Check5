import requests
import socket
import ssl
import time

# Helper functions for fetching detailed website data
def get_website_info(url):
    try:
        response = requests.get(url)
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.text),
            "encoding": response.encoding
        }
    except Exception as e:
        return {"error": str(e)}

def check_ssl(url):
    if url.startswith('https'):
        return "Secure"
    return "Insecure"

def get_ip_address(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        return socket.gethostbyname(domain)
    except:
        return "N/A"

def get_server_info(url):
    try:
        response = requests.get(url)
        return response.headers.get('Server', 'Unknown')
    except:
        return 'Unknown'

def get_dns_info(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        dns_records = socket.gethostbyname_ex(domain)
        return {"domain": dns_records[0], "aliases": dns_records[1], "addresses": dns_records[2]}
    except:
        return "Unable to fetch DNS info"

def get_ssl_certificate_info(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}

def get_geo_location(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/geo')
        return response.json()
    except:
        return "Geo-location info not available"

def get_page_load_time(url):
    try:
        start_time = time.time()
        requests.get(url)
        return round(time.time() - start_time, 2)
    except:
        return "Unable to calculate page load time"

def check_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, params={"q": xss_payload})
        if xss_payload in response.text:
            return "Vulnerable"
        return "Safe"
    except:
        return "Unknown"

def detect_clickjacking():
    return "Vulnerable"

def check_cookies():
    return {"secure": True}

def check_csp(url):
    try:
        response = requests.get(url)
        csp = response.headers.get("Content-Security-Policy")
        if csp:
            return "Present"
        return "Missing"
    except:
        return "Unknown"

def detect_mixed_content(url):
    return "Safe"

def check_security_headers(url):
    headers_to_check = ['Strict-Transport-Security', 'X-Frame-Options', 'X-XSS-Protection']
    try:
        response = requests.get(url)
        missing_headers = [header for header in headers_to_check if header not in response.headers]
        if missing_headers:
            return missing_headers
        return "All security headers present"
    except:
        return "Unknown"

def check_directory_traversal(url):
    test_payload = "/../../etc/passwd"
    try:
        response = requests.get(url + test_payload)
        if "root:x" in response.text:
            return "Vulnerable"
        return "Safe"
    except:
        return "Unknown"

def check_open_redirect(url):
    redirect_test_url = url + "?redirect=http://malicious.com"
    try:
        response = requests.get(redirect_test_url)
        if "http://malicious.com" in response.url:
            return "Vulnerable"
        return "Safe"
    except:
        return "Unknown"
