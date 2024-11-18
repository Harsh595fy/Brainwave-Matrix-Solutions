import re
import requests
import socket
import ssl
from urllib.parse import urlparse

# Function to extract URLs from text
def extract_urls(text):
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(url_pattern, text)

# Check for suspicious patterns
def check_url_patterns(url):
    warnings = []
    if re.search(r'(login|verify|update|secure|account)[^/]*\.[a-zA-Z]+$', url):
        warnings.append("Contains sensitive keywords in domain.")
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        warnings.append("IP-based URL detected.")
    return warnings

# Check DNS resolution
def check_dns(url):
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        return f"Resolved Domain to IP: {ip}", False
    except socket.gaierror:
        return "Unable to resolve DNS.", True

# Validate SSL certificate
def check_ssl(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(item[0] for item in cert['issuer'])
                issued_by = issuer.get("organizationName", "Unknown Issuer")
                return f"SSL Certificate Issued By: {issued_by}", False
    except Exception:
        return "Unable to retrieve SSL certificate.", True

# Query VirusTotal API (Optional - Replace with your API key)
def check_virustotal(url):
    api_key = "your_virustotal_api_key"  # Replace with your VirusTotal API key
    api_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    try:
        # Submit URL for scanning
        response = requests.post(api_url, headers=headers, json={"url": url})
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get("data", {}).get("id")
            return f"Submitted to VirusTotal. Analysis ID: {analysis_id}", False
        return f"VirusTotal API response: {response.status_code}", True
    except Exception as e:
        return f"VirusTotal API request failed: {e}", True

# Perform comprehensive checks
def scan_url(url):
    print(f"\nScanning URL: {url}")
    results = {}
    phishing_flags = 0

    # Check for suspicious patterns
    patterns = check_url_patterns(url)
    if patterns:
        results['Patterns'] = patterns
        phishing_flags += 1
    else:
        results['Patterns'] = ["No suspicious patterns detected."]

    # Check DNS resolution
    dns_result, dns_flag = check_dns(url)
    results['DNS'] = dns_result
    phishing_flags += 1 if dns_flag else 0

    # Validate SSL certificate
    ssl_result, ssl_flag = check_ssl(url)
    results['SSL'] = ssl_result
    phishing_flags += 1 if ssl_flag else 0

    # Query VirusTotal
    # Uncomment the line below after adding your VirusTotal API key
    # vt_result, vt_flag = check_virustotal(url)
    # results['VirusTotal'] = vt_result
    # phishing_flags += 1 if vt_flag else 0

    # Final Verdict
    if phishing_flags >= 2:  # Adjust threshold as needed
        results['Verdict'] = "Phishing Link: Be cautious!"
    else:
        results['Verdict'] = "Safe Link: No significant issues detected."

    return results

# Main function
def phishing_scanner():
    print("Welcome to the Advanced Phishing Link Scanner!")
    text = input("Enter the text or URLs to scan: ")
    urls = extract_urls(text)

    if not urls:
        print("No URLs found in the input.")
        return

    print("\nScanning URLs...")
    for url in urls:
        results = scan_url(url)
        for category, info in results.items():
            print(f"{category}: {info if isinstance(info, str) else ', '.join(info)}")

if __name__ == "__main__":
    phishing_scanner()
