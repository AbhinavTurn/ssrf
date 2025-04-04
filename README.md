# Enhanced SSRF Scanner User Guide

This guide explains how to use the enhanced SSRF scanner tool and describes its main features and bypass techniques.

## Setup

1. Install required Python packages:
   ```
   pip install requests colorama argparse urllib3
   ```

2. Make sure you have the following files:
   - `ssrf_scanner.py` - The main scanner script
   - `payloads.txt` - A list of SSRF payloads (provided separately)

## Basic Usage

The simplest way to run the scanner:

```bash
python ssrf_scanner.py -t "http://example.com/api?url=INJECT_HERE"
```

By default, this will:
- Test all payloads from `payloads.txt`
- Use GET requests
- Apply various SSRF bypass techniques to each payload
- Log results to the `logs` directory

## Advanced Usage

### Command Line Options

```
usage: ssrf_scanner.py [-h] -t TARGET [-p PAYLOADS] [-m METHOD] [-d DATA] [-o OUTPUT]
                               [-c COOKIES] [-H HEADERS] [-x PROXY] [-T THREADS]
                               [--timeout TIMEOUT] [-v] [-r] [-a] [--no-verify]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target URL with INJECTION POINT as 'INJECT_HERE'
  -p PAYLOADS, --payloads PAYLOADS
                        Path to payloads file (default: payloads.txt)
  -m METHOD, --method METHOD
                        HTTP method: GET, POST, etc. (default: GET)
  -d DATA, --data DATA  POST data with optional 'INJECT_HERE' placeholder
  -o OUTPUT, --output OUTPUT
                        Save results to JSON file
  -c COOKIES, --cookies COOKIES
                        Cookies in format 'name=value,name2=value2'
  -H HEADERS, --headers HEADERS
                        Custom headers in format 'Name:Value,Name2:Value2'
  -x PROXY, --proxy PROXY
                        Proxy to use (e.g., http://127.0.0.1:8080)
  -T THREADS, --threads THREADS
                        Number of threads (default: 5)
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  -v, --verbose         Verbose output
  -r, --follow-redirects
                        Follow redirects
  -a, --random-agent    Use random User-Agent
  --no-verify           Disable SSL verification
```

### Examples

#### Testing POST Requests

```bash
python ssrf_scanner.py -t "https://example.com/api" -m POST -d "url=INJECT_HERE"
```

#### Using Custom Headers and Cookies

```bash
python ssrf_scanner.py -t "http://example.com/api?url=INJECT_HERE" -H "Authorization:Bearer token,Content-Type:application/json" -c "session=abc123,csrf=xyz789"
```

#### Using a Proxy (e.g., Burp Suite)

```bash
python ssrf_scanner.py -t "http://example.com/api?url=INJECT_HERE" -x "http://127.0.0.1:8080"
```

#### Saving Results to JSON

```bash
python ssrf_scanner.py -t "http://example.com/api?url=INJECT_HERE" -o "results.json"
```

#### Parallelizing with More Threads

```bash
python ssrf_scanner.py -t "http://example.com/api?url=INJECT_HERE" -T 10
```

#### Enabling Verbose Output

```bash
python ssrf_scanner.py -t "http://example.com/api?url=INJECT_HERE" -v
```
