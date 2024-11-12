# U-Parixa - Security and Phishing Detection CLI Tool

U-Parixa is a command-line interface (CLI) tool designed to check the security of a website by evaluating SSL certificates, HTTP headers, and detecting phishing patterns. The tool provides alerts for potential vulnerabilities related to clickjacking, cross-site scripting (XSS), cross-origin resource sharing (CORS), and phishing indicators.

## Features
- **SSL Certificate Check**: Verifies if the SSL certificate of the website is valid.
- **HTTP Header Check**: Analyzes common security headers (e.g., `X-Frame-Options`, `X-XSS-Protection`, `Content-Security-Policy`) and flags missing or misconfigured headers.
- **Phishing Detection**: Scans URLs for common phishing patterns to identify potentially malicious websites.
- **System Information**: Displays basic system information, including internal and external IP addresses.

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/your-username/u-parixa.git
    ```

2. Navigate to the project directory:
    ```bash
    cd u-parixa
    ```

3. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the tool by executing the Python script:
    ```bash
    python uparixa.py
    ```

2. Enter the URL you want to check when prompted:
    ```bash
    Enter the URL to check: https://example.com
    ```

3. The tool will display:
   - **System Information**: Your system's information, including the external IP address.
   - **SSL Certificate Status**: Whether the SSL certificate is valid.
   - **HTTP Header Analysis**: A check of the website's HTTP headers for security vulnerabilities.
   - **Phishing Detection**: A warning if the URL matches common phishing patterns.

## Example Output

```bash
===============================
          U-Parixa             
      made by coderpanda11     
===============================

System Information:
System: Linux 5.4.0-80-generic (#90-Ubuntu SMP Thu Aug 12 17:56:03 UTC 2021) (64bit)
Hostname: your-hostname
Local IP Address: 192.168.1.5
External IP Address: 203.0.113.5

Starting security checks...

Checking SSL certificate...
SSL Certificate retrieved successfully.

Checking HTTP headers...
Warning: X-Frame-Options found, but value 'ALLOW-FROM https://example.com' may be vulnerable; X-Frame-Options may be vulnerable to clickjacking attacks.

Checking for phishing patterns...
Warning: This URL may be a phishing site based on pattern analysis.

Issues detected.
