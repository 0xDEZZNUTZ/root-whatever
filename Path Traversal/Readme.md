# Advanced Path Traversal Scanner

A professional tool for detecting path traversal vulnerabilities in web applications. This scanner systematically tests for directory traversal issues by attempting to access files outside the web application's intended directory structure.
BTW:This tool has been tested on various CTF machines and labs in Burp Suite.

## Features

- **Comprehensive Testing**: Tests multiple traversal techniques including standard, URL-encoded, double-encoded, and bypass methods
- **High Performance**: Uses multi-threading for faster scanning
- **Status Code Filtering**: Only displays responses with status code 200 (potential vulnerabilities)
- **Content Preview**: Shows a preview of the file content for manual verification
- **Downloadable Content Detection**: Alerts when potential binary/database files are detected
- **Flexible Configuration**: Customizable parameters, headers, cookies, proxy support
- **Professional Reporting**: Clean console output with color-coded results
- **Export Capability**: Save results to file for documentation or further analysis
- **Security-Focused**: Built with proper input validation to prevent security issues

## Requirements

- Python 3.6+
- Required packages:
  - requests
  - rich

## Installation

```bash
# Clone the repository or download the script
git clone https://github.com/yourusername/path-traversal-scanner.git
cd path-traversal-scanner

# Install required packages
pip install requests rich
```

## Usage

Basic usage:

```bash
python path_traversal_scanner.py -u "http://example.com" -p "file"
```

Advanced usage:

```bash
python path_traversal_scanner.py -u "http://example.com" -e "download" -p "file" -d 15 --threads 20 --output results.txt --verbose
```

### Command Line Arguments

| Option | Long Option | Description |
|--------|-------------|-------------|
| `-u` | `--url` | Target URL (required) |
| `-e` | `--endpoint` | Endpoint to test (default: none) |
| `-p` | `--parameter` | Query parameter name (required) |
| `-d` | `--depth` | Maximum directory traversal depth (default: 10) |
| `-t` | `--timeout` | Request timeout in seconds (default: 5.0) |
| `-o` | `--output` | Output file for results |
| `-v` | `--verbose` | Enable verbose output |
| | `--threads` | Number of concurrent threads (default: 10) |
| | `--proxy` | Specify a proxy to route requests through (e.g., http://127.0.0.1:8080 for debugging with Burp Suite) |
| | `--user-agent` | Custom User-Agent header |
| | `--cookies` | Cookies to include with requests (format: name1=value1; name2=value2) |
| | `--insecure` | Disable SSL certificate verification |
| | `--files` | Comma-separated list of files to test |

## Examples

Test for path traversal in a file parameter:
```bash
python path_traversal_scanner.py -u "http://example.com" -p "file"
```

Test with specific endpoint:
```bash
python path_traversal_scanner.py -u "http://example.com" -e "download" -p "ticket"
```

Test with authentication cookies:
```bash
python path_traversal_scanner.py -u "http://example.com" -p "file" --cookies "session=abc123; auth=xyz789"
```

Test through a proxy:
```bash
python path_traversal_scanner.py -u "http://example.com" -p "file" --proxy "http://127.0.0.1:8080"
```

Test specific files:
```bash
python path_traversal_scanner.py -u "http://example.com" -p "file" --files "/etc/passwd,wp-config.php,config.php"
```
## Downloadable Content Detection

The scanner can detect when a response is likely a binary file or database that should be downloaded rather than viewed as text. In these cases, it will show a warning:

```
⚠️ WARNING: Potential downloadable file detected at http://example.com/download?ticket=../../../var/www/html/db/site.db
   This file may need to be downloaded with: curl -o output_file 'http://example.com/download?ticket=../../../var/www/html/db/site.db'
```

## Ethical Usage

This tool is intended for:
- Security professionals conducting authorized penetration tests
- System administrators testing their own systems
- Developers checking for vulnerabilities in their code

**Always obtain proper authorization before testing any system you don't own.**

## License

[MIT License](LICENSE)
