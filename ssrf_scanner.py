import requests
import os
import datetime
import argparse
import urllib.parse
import concurrent.futures
import ipaddress
import socket
import random
import json
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init

# Suppress only the single warning from urllib3 needed
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Constants
LOG_DIR = "logs"
MAX_WORKERS = 10
DEFAULT_TIMEOUT = 5
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
]

# Create log directory
os.makedirs(LOG_DIR, exist_ok=True)

class SSRFScanner:
    def __init__(self, args):
        self.target = args.target
        self.payloads_file = args.payloads
        self.threads = args.threads
        self.timeout = args.timeout
        self.verify_ssl = not args.no_verify
        self.verbose = args.verbose
        self.output = args.output
        self.custom_headers = self._parse_headers(args.headers)
        self.proxy = args.proxy
        self.cookies = self._parse_cookies(args.cookies)
        self.method = args.method.upper()
        self.data = args.data
        self.follow_redirects = args.follow_redirects
        self.random_agent = args.random_agent
        
        # Set up logging
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file_path = os.path.join(LOG_DIR, f"ssrf_scan_{timestamp}.txt")
        self.json_results = []
        
        # Configure proxy if provided
        self.proxies = None
        if self.proxy:
            self.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
    
    def _parse_headers(self, headers_str):
        if not headers_str:
            return {}
        
        headers = {}
        try:
            for header in headers_str.split(','):
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()
            return headers
        except Exception:
            print(f"{Fore.RED}[!] Invalid header format. Use 'Name:Value,Name2:Value2'{Style.RESET_ALL}")
            return {}
            
    def _parse_cookies(self, cookies_str):
        if not cookies_str:
            return {}
        
        cookies = {}
        try:
            for cookie in cookies_str.split(','):
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()
            return cookies
        except Exception:
            print(f"{Fore.RED}[!] Invalid cookie format. Use 'name=value,name2=value2'{Style.RESET_ALL}")
            return {}
            
    def log(self, msg, level="INFO"):
        with open(self.log_file_path, "a") as log_file:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"[{timestamp}] [{level}] {msg}\n")
        
    def load_payloads(self):
        try:
            with open(self.payloads_file, "r") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Payloads file '{self.payloads_file}' not found!{Style.RESET_ALL}")
            exit(1)
            
    def apply_bypass_techniques(self, payload):
        """Apply various SSRF bypass techniques to a payload"""
        # Only apply bypasses to URL payloads
        if not (payload.startswith('http://') or payload.startswith('https://')):
            return [payload]
            
        bypasses = []
        
        # Original payload
        bypasses.append(payload)
        
        parsed = urllib.parse.urlparse(payload)
        domain = parsed.netloc
        
        # Skip IP bypasses if not working with IPs
        try:
            if ":" in domain:
                domain = domain.split(':')[0]
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False
        
        # Double URL encoding
        double_encoded = payload.replace('/', '%252F').replace(':', '%253A')
        bypasses.append(double_encoded)
        
        # Different IP formats (for IP payloads)
        if is_ip:
            try:
                ip_obj = ipaddress.ip_address(domain)
                # Decimal notation
                if ip_obj.version == 4:
                    decimal_ip = int(ip_obj)
                    decimal_url = payload.replace(domain, str(decimal_ip))
                    bypasses.append(decimal_url)
                    
                    # Hex notation
                    hex_ip = hex(int(ip_obj))
                    hex_url = payload.replace(domain, hex_ip)
                    bypasses.append(hex_url)
                    
                    # Octal with padding
                    parts = str(ip_obj).split('.')
                    octal_parts = [f"0{int(p):o}" for p in parts]
                    octal_ip = '.'.join(octal_parts)
                    octal_url = payload.replace(domain, octal_ip)
                    bypasses.append(octal_url)
            except Exception:
                pass
        
        # URL encoding special chars
        url_encoded = urllib.parse.quote(payload)
        bypasses.append(url_encoded)
        
        # Using @ in URL
        if not is_ip:
            at_url = payload.replace('://', '://user@')
            bypasses.append(at_url)
            
        # Add URL fragment
        fragment_url = payload + "#" + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))
        bypasses.append(fragment_url)
        
        # Adding port numbers for common services
        for port in ['80', '443', '8080', '8443']:
            if ':' not in domain:
                port_url = payload.replace(domain, f"{domain}:{port}")
                bypasses.append(port_url)
        
        return list(set(bypasses))  # Remove duplicates
    
    def send_request(self, test_url, payload):
        """Send HTTP request and analyze response"""
        try:
            headers = self.custom_headers.copy()
            
            # Use random User-Agent if specified
            if self.random_agent:
                headers['User-Agent'] = random.choice(USER_AGENTS)
                
            # Set request parameters
            request_kwargs = {
                'timeout': self.timeout,
                'verify': self.verify_ssl,
                'allow_redirects': self.follow_redirects,
                'headers': headers,
                'cookies': self.cookies,
                'proxies': self.proxies
            }
            
            # Send request based on method
            if self.method == 'GET':
                response = requests.get(test_url, **request_kwargs)
            elif self.method == 'POST':
                # Use data parameter if provided
                data = self.data.replace('INJECT_HERE', payload) if self.data else None
                response = requests.post(test_url, data=data, **request_kwargs)
            else:
                # For other methods like PUT, DELETE, etc.
                response = requests.request(self.method, test_url, **request_kwargs)
            
            # Extract response details
            status = response.status_code
            content_length = len(response.content)
            snippet = response.text[:100].replace('\n', ' ').replace('\r', '')
            
            # Detect potential SSRF indicators
            ssrf_indicators = self.detect_ssrf_indicators(response, payload)
            is_potential_ssrf = len(ssrf_indicators) > 0 or status == 200
            
            # Log results
            log_line = (
                f"Payload: {payload} | "
                f"Status: {status} | "
                f"Length: {content_length} | "
                f"Indicators: {', '.join(ssrf_indicators) if ssrf_indicators else 'None'} | "
                f"Snippet: {snippet}"
            )
            self.log(log_line, "POTENTIAL" if is_potential_ssrf else "INFO")
            
            # Store result for JSON output
            result = {
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'payload': payload,
                'url': test_url,
                'status_code': status,
                'content_length': content_length,
                'indicators': ssrf_indicators,
                'is_potential_ssrf': is_potential_ssrf,
                'snippet': snippet
            }
            self.json_results.append(result)
            
            # Print result to console
            if is_potential_ssrf:
                print(f"{Fore.GREEN}[+] Possible SSRF! → {payload}")
                print(f"{Fore.GREEN}    Status: {status} | Indicators: {', '.join(ssrf_indicators)}")
                print(f"{Fore.GREEN}    Snippet: {snippet}\n")
            elif self.verbose:
                print(f"{Fore.YELLOW}[-] {payload} -> {status}")
            else:
                print(f"{Fore.YELLOW}.", end="", flush=True)
                
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            self.log(f"Payload: {payload} | Error: {error_msg}", "ERROR")
            
            if self.verbose:
                print(f"{Fore.RED}[!] {payload} -> Request Failed: {e}")
            else:
                print(f"{Fore.RED}x", end="", flush=True)
                
            return {
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'payload': payload,
                'url': test_url,
                'error': error_msg,
                'is_error': True
            }
    
    def detect_ssrf_indicators(self, response, payload):
        """Detect indicators of potential SSRF vulnerabilities"""
        indicators = []
        
        # Check for common SSRF indicators in the response
        response_text = response.text.lower()
        
        # Check status code patterns
        if response.status_code in [200, 302, 307]:
            indicators.append(f"Interesting status code: {response.status_code}")
            
        # Check response content
        indicators_patterns = [
            ('internal ip disclosure', r'(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'),
            ('aws metadata', r'ami-id|instance-id|instance-type'),
            ('error disclosure', r'(error|exception|traceback|stacktrace)'),
            ('file content', r'(<!DOCTYPE|<html|<xml|<%@)'),
            ('server config', r'(apache|nginx|iis|tomcat)')
        ]
        
        for name, pattern in indicators_patterns:
            import re
            if re.search(pattern, response_text, re.I):
                indicators.append(name)
                
        # Check response timing
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 2:
            indicators.append(f"Long response time: {response.elapsed.total_seconds():.2f}s")
            
        return indicators
    
    def run(self):
        """Run the SSRF scan"""
        if "INJECT_HERE" not in self.target and (self.method != "POST" or "INJECT_HERE" not in self.data):
            print(f"{Fore.RED}[!] Target URL or POST data must contain 'INJECT_HERE' as placeholder for payload injection.{Style.RESET_ALL}")
            return
            
        # Load and process payloads
        base_payloads = self.load_payloads()
        
        # Apply bypass techniques to each payload
        all_payloads = []
        for payload in base_payloads:
            all_payloads.extend(self.apply_bypass_techniques(payload))
            
        print(f"\n{Fore.BLUE}[*] Starting SSRF Scan with {len(all_payloads)} payloads (including bypass variants)")
        print(f"{Fore.BLUE}[*] Target: {self.target}")
        print(f"{Fore.BLUE}[*] Method: {self.method}")
        print(f"{Fore.BLUE}[*] Threads: {self.threads}")
        print(f"{Fore.BLUE}[*] Logging to: {self.log_file_path}")
        print(f"{Fore.BLUE}[*] Follow redirects: {self.follow_redirects}")
        print(f"{Fore.BLUE}[*] Verify SSL: {self.verify_ssl}\n")
        
        # Scan counters
        total_payloads = len(all_payloads)
        potential_ssrf_found = 0
        errors_encountered = 0
        
        # Run scan with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for payload in all_payloads:
                if self.method == "POST" and "INJECT_HERE" in self.data:
                    # For POST method with injection in data
                    test_url = self.target
                    futures.append(executor.submit(self.send_request, test_url, payload))
                else:
                    # For GET method or other methods with injection in URL
                    test_url = self.target.replace("INJECT_HERE", urllib.parse.quote(payload))
                    futures.append(executor.submit(self.send_request, test_url, payload))
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result.get('is_potential_ssrf', False):
                    potential_ssrf_found += 1
                if result.get('is_error', False):
                    errors_encountered += 1
        
        # Write JSON results if output file specified
        if self.output:
            with open(self.output, 'w') as f:
                json.dump(self.json_results, f, indent=2)
            print(f"\n{Fore.GREEN}[*] Results saved to {self.output}")
            
        # Print summary
        print(f"\n{Fore.GREEN}✅ Scan complete!")
        print(f"{Fore.GREEN}[*] Total payloads tested: {total_payloads}")
        print(f"{Fore.GREEN}[*] Potential SSRF vulnerabilities found: {potential_ssrf_found}")
        print(f"{Fore.GREEN}[*] Errors encountered: {errors_encountered}")
        print(f"{Fore.GREEN}[*] Detailed logs saved to: {self.log_file_path}")

def main():
    parser = argparse.ArgumentParser(description="Advanced SSRF Scanner with Bypass Techniques")
    parser.add_argument("-t", "--target", required=True, help="Target URL with INJECTION POINT as 'INJECT_HERE'")
    parser.add_argument("-p", "--payloads", default="payloads.txt", help="Path to payloads file (default: payloads.txt)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method: GET, POST, etc. (default: GET)")
    parser.add_argument("-d", "--data", help="POST data with optional 'INJECT_HERE' placeholder")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-c", "--cookies", help="Cookies in format 'name=value,name2=value2'")
    parser.add_argument("-H", "--headers", help="Custom headers in format 'Name:Value,Name2:Value2'")
    parser.add_argument("-x", "--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-T", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-r", "--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-a", "--random-agent", action="store_true", help="Use random User-Agent")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    
    args = parser.parse_args()
    
    try:
        scanner = SSRFScanner(args)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
