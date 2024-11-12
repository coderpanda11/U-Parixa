import os
import requests
import platform
import socket
import validators

# Color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

def clear_terminal():
    """Clear the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def display_banner():
    """Display the banner."""
    print(f"{GREEN}===============================")
    print(f"          U-Parixa             ")
    print(f"      made by coderpanda11     ")
    print(f"===============================\n{RESET}")

def get_system_info():
    """Retrieve system information, including external IP."""
    system = platform.system()
    version = platform.version()
    architecture = platform.architecture()
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    # Get the external IP address
    try:
        external_ip = requests.get('https://api.ipify.org').text
    except requests.exceptions.RequestException:
        external_ip = "Could not retrieve external IP"

    return (f"System: {system} {version} ({architecture[0]})\n"
            f"Hostname: {hostname}\n"
            f"Local IP Address: {ip_address}\n"
            f"External IP Address: {external_ip}")

def validate_url(url):
    """Validate and format the URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not validators.url(url):
        print(f"{RED}Invalid URL format. Please enter a valid URL.{RESET}")
        return None
    return url

def check_ssl_certificate(url):
    """Check if the SSL certificate is valid."""
    print(f"\n{CYAN}SSL Certificate Check:{RESET}")
    try:
        response = requests.get(url, verify=True)
        print(f"{GREEN}✓ SSL Certificate is valid.{RESET}")
        return True
    except requests.exceptions.SSLError:
        print(f"{RED}✗ SSL Certificate error!{RESET}")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"{RED}✗ Connection error: {e}. Check if the URL is valid and accessible.{RESET}")
        return False
    except Exception as e:
        print(f"{RED}✗ An unexpected error occurred: {e}{RESET}")
        return False

def check_http_headers(url):
    """Check for security headers and potential vulnerabilities."""
    print(f"\n{CYAN}HTTP Headers Security Check:{RESET}")
    try:
        response = requests.get(url)
        issues_found = False

        # Security headers to check with basic vulnerability analysis
        header_checks = {
            "X-Content-Type-Options": {
                "expected_value": "nosniff",
                "vulnerability": "Missing or incorrect X-Content-Type-Options; may allow MIME-type sniffing."
            },
            "X-Frame-Options": {
                "expected_value": ["DENY", "SAMEORIGIN"],
                "vulnerability": "X-Frame-Options may be vulnerable to clickjacking attacks."
            },
            "X-XSS-Protection": {
                "expected_value": "1; mode=block",
                "vulnerability": "X-XSS-Protection is missing or not set to block mode; may allow cross-site scripting attacks."
            },
            "Content-Security-Policy": {
                "expected_value": None,
                "vulnerability": "Content-Security-Policy is missing; may allow various attacks, including XSS."
            },
            "Access-Control-Allow-Origin": {
                "expected_value": None,
                "vulnerability": "Improper CORS configuration may expose the site to cross-origin attacks."
            }
        }

        for header, check in header_checks.items():
            if header not in response.headers:
                print(f"{RED}✗ {header} is missing; {check['vulnerability']}{RESET}")
                issues_found = True
            else:
                header_value = response.headers[header]
                expected_value = check["expected_value"]

                if expected_value and header_value not in (expected_value if isinstance(expected_value, list) else [expected_value]):
                    print(f"{RED}✗ {header} found, but value '{header_value}' may be vulnerable; {check['vulnerability']}{RESET}")
                    issues_found = True

        if not issues_found:
            print(f"{GREEN}✓ All security headers are properly configured.{RESET}")
        return not issues_found

    except requests.exceptions.RequestException as e:
        print(f"{RED}✗ Failed to check headers: {e}{RESET}")
        return False

def check_phishing(url):
    """Basic phishing detection based on URL patterns."""
    print(f"\n{CYAN}Phishing URL Analysis:{RESET}")
    phishing_patterns = [
    "account", "login", "secure", "bank", "update", "confirm", "verify", "expired",
    "password", "admin", "signin", "auth", "validate", "unlock", "urgent", "important", 
    "alert", "suspended", "limited", "notice", "access", "recovery", "customer-service", 
    "support", "webmail", "email", "mailbox", "new-message", "messages", "helpdesk", 
    "billing", "payment", "checkout", "invoice", "account-pay", "paypal", "credit", 
    "transfer", "transaction", "secure-login", "auth", "signin", "account-update",
    "-secure-", "-login-", "verify"]


    if any(pattern in url for pattern in phishing_patterns):
        print(f"{RED}✗ Warning: This URL may be a phishing site based on pattern analysis.{RESET}")
        return False

    print(f"{GREEN}✓ No phishing indicators found.{RESET}")
    return True

def main(url):
    """Main function to run checks."""
    clear_terminal()
    display_banner()

    print(f"{BLUE}System Information:{RESET}")
    print(get_system_info())
    print(f"\n{BLUE}Starting security checks for the domain: {url}...{RESET}\n")

    # Validate the URL before proceeding
    valid_url = validate_url(url)
    if valid_url is None:
        return  # Exit if the URL is invalid

    ssl_check = check_ssl_certificate(valid_url)
    header_check = check_http_headers(valid_url)
    phishing_check = check_phishing(valid_url)

    print("\n" + "=" * 35)
    if not (ssl_check and header_check and phishing_check):
        print(f"{RED}⚠️ Issues detected. Please review the warnings above.{RESET}")
    else:
        print(f"{GREEN}✓ Connection Secure; No issues detected.{RESET}")
    print("=" * 35 + "\n")

if __name__ == "__main__":
    test_url = input("Enter the URL to check: ")
    main(test_url)
