import requests
import threading
import logging
from bs4 import BeautifulSoup

# Logging setup
logging.basicConfig(level=logging.INFO)

# Output file setup
RESULT_FILE = "result.txt"

# Load payloads from a file
def load_payloads(payload_file):
    with open(payload_file, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Save vulnerabilities to result.txt
def save_to_file(message):
    with open(RESULT_FILE, "a") as file:
        file.write(message + "\n")

# Function to find forms in a webpage
def find_forms(target_url, cookies=None):
    try:
        response = requests.get(target_url, cookies=cookies)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        return forms
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching the page: {e}")
        return []

# Test for reflected XSS by submitting form inputs with payloads
def test_reflected_xss(target_url, forms, payloads, cookies=None):
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')

        # Prepare data for submission
        data = {}
        for input_tag in inputs:
            input_name = input_tag.get('name')
            if input_name:
                data[input_name] = payloads[0]  # Inject first payload for testing

        # Submit the form
        try:
            if method == 'post':
                response = requests.post(target_url + action, data=data, cookies=cookies)
            else:
                response = requests.get(target_url + action, params=data, cookies=cookies)

            # Check if the payload is reflected in the response
            if payloads[0] in response.text:
                message = f"[Reflected XSS Found] Form Action: {action}, Payload: {payloads[0]}"
                logging.info(message)
                save_to_file(message)
            else:
                logging.info("No Reflected XSS Found.")
        except Exception as e:
            logging.error(f"Error during form submission: {e}")

# Multi-threaded URL injection for XSS vulnerabilities
def url_injection_test(target_url, payloads, cookies=None):
    for payload in payloads:
        vulnerable_url = f"{target_url}/{payload}"
        try:
            response = requests.get(vulnerable_url, cookies=cookies)
            if payload in response.text:
                message = f"[URL Path Injection Found] {vulnerable_url}"
                logging.info(message)
                save_to_file(message)
        except Exception as e:
            logging.error(f"Error during URL injection test: {e}")

# Handle cookies (for session-based testing)
def handle_cookies(target_url):
    try:
        response = requests.get(target_url)
        cookies = response.cookies
        logging.info(f"Session cookies: {cookies}")
        return cookies
    except Exception as e:
        logging.error(f"Error getting cookies: {e}")
        return None

# Main function for execution
def main():
    target_url = input("Enter target URL (e.g., https://example.com): ")
    payload_file = input("Enter path to payload file (e.g., payloads.txt): ")

    # Clear result file at the start
    open(RESULT_FILE, "w").close()

    # Load payloads
    payloads = load_payloads(payload_file)

    # Get session cookies for testing (if any)
    cookies = handle_cookies(target_url)

    # Test Reflected XSS
    logging.info("Finding forms for reflected XSS testing...")
    forms = find_forms(target_url, cookies)
    if forms:
        logging.info(f"Found {len(forms)} form(s). Testing for reflected XSS...")
        test_reflected_xss(target_url, forms, payloads, cookies)
    else:
        logging.info("No forms found for reflected XSS testing.")

    # URL Injection Test
    logging.info("Testing URL Path Injection...")
    threads = []
    for i in range(len(payloads)):
        thread = threading.Thread(target=url_injection_test, args=(target_url, [payloads[i]], cookies))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    logging.info(f"Scan complete. Results saved in {RESULT_FILE}.")

if __name__ == "__main__":
    main()
