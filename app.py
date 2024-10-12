from flask import Flask, render_template, request
from detector import (
    check_xss,
    detect_clickjacking,
    check_cookies,
    check_csp,
    detect_mixed_content,
    check_security_headers,
    get_website_info,
    check_ssl,
    get_ip_address,
    get_server_info,
    check_directory_traversal,
    check_open_redirect,
    get_dns_info,
    get_ssl_certificate_info,
    get_page_load_time,
    get_geo_location,
    get_whois_info
)
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if __name__ == '__main__':
    # Use the PORT environment variable, default to 5000 if not set
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 
    if request.method == "POST":
        url = request.form["url"]
        report = {}

        # Fetching website info, DNS, SSL, etc.
        report['website_info'] = get_website_info(url)
        report['ssl_info'] = check_ssl(url)
        report['ssl_certificate'] = get_ssl_certificate_info(url)
        report['ip_address'] = get_ip_address(url)
        report['server_info'] = get_server_info(url)
        report['dns_info'] = get_dns_info(url)
        report['geo_location'] = get_geo_location(report['ip_address'])
        report['whois_info'] = get_whois_info(url)
        report['page_load_time'] = get_page_load_time(url)

        # Perform vulnerability checks
        report['xss'] = check_xss(url)
        report['clickjacking'] = detect_clickjacking()
        report['cookies'] = check_cookies()
        report['csp'] = check_csp(url)
        report['mixed_content'] = detect_mixed_content(url)
        report['security_headers'] = check_security_headers(url)

        # New Vulnerability Checks
        report['directory_traversal'] = check_directory_traversal(url)
        report['open_redirect'] = check_open_redirect(url)

        # Calculate overall rating
        vulnerabilities_found = sum(
            [report[v] == "Vulnerable" for v in report if v in ['xss', 'clickjacking', 'directory_traversal', 'open_redirect']]
        )
        total_checks = 6  # Adjust based on the number of checks
        report['overall_rating'] = max(100 - (vulnerabilities_found / total_checks * 100), 0)

        return render_template("index.html", report=report, url=url)

    return render_template("index.html")

if __name__ == '__main__':
    # Use the PORT environment variable, default to 5000 if not set
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Enable debug mode
