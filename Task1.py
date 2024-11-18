import re
import requests

# Function to extract URLs from a given text
def extract_urls(text):
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(url_pattern, text)

# Function to perform basic checks for phishing
def check_phishing(url):
    # Check for unusual domain patterns
    if re.search(r'(login|verify|update)[^/]*\.[a-zA-Z]+$', url):
        return "Suspicious: Possible phishing domain pattern detected."
    # Check for IP-based URLs
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        return "Suspicious: IP-based URL detected."
    # Send a request to verify the URL (optional)
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return f"Suspicious: Non-200 response code {response.status_code}."
    except requests.RequestException as e:
        return f"Suspicious: Request failed ({e})."
    return "Safe: No phishing indicators detected."

# Main function
def phishing_scanner():
    print("Welcome to the Phishing Link Scanner!")
    text = input("Enter the text or URLs to scan: ")
    urls = extract_urls(text)

    if not urls:
        print("No URLs found in the input.")
        return

    print("\nScanning URLs...")
    for url in urls:
        print(f"\nURL: {url}")
        result = check_phishing(url)
        print(f"Result: {result}")

if __name__ == "__main__":
    phishing_scanner()
