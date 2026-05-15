# MCP-Kali-Server

A safe MCP (Model Context Protocol) server for Kali Linux security tools with strong guardrails. Designed for defensive security work and learning only.

## Safety First

This server is designed with **defense-in-depth** security principles:

- **Never exposes raw shell access** - All commands are pre-defined and validated
- **No sudo execution** - All commands run as the current user
- **No exploit code** - Only reconnaissance and analysis tools
- **No brute-force attacks** - Rate-limited and scoped operations
- **No payload generation** - Read-only information gathering
- **Input validation** - All user inputs are sanitized and validated
- **Command allowlisting** - Only approved commands can execute
- **Timeouts** - All operations have strict time limits
- **Comprehensive logging** - Every tool call is logged

## Features

### Available Tools

- **`get_system_info`** - Get basic system information (kernel, OS distribution)
- **`list_kali_tools`** - List available Kali Linux security tools
- **`dns_lookup`** - DNS queries (A, AAAA, MX, TXT, NS, CNAME records)
- **`whois_lookup`** - Domain registration information
- **`nmap_scan`** - Safe network scanning (quick or service detection)
- **`gobuster_scan`** - Directory brute-forcing with gobuster
- **`dirb_scan`** - Directory brute-forcing with dirb
- **`nikto_scan`** - Web vulnerability scanning with nikto
- **`sqlmap_scan`** - SQL injection detection with sqlmap (detection only, no exploitation)
- **`wpscan_scan`** - WordPress vulnerability scanning with wpscan
- **`http_headers_check`** - HTTP header analysis
- **`ssl_certificate_check`** - SSL/TLS certificate validation
- **`theharvester_passive`** - Passive email/domain discovery using theHarvester
- **`shodan_host_lookup`** - Shodan API host lookup for exposed services

### Safety Guardrails

- **Public IP blocking** - By default, only private network ranges are allowed
- **Scan type restrictions** - Only safe nmap scan types are permitted
- **URL scheme validation** - Only http/https URLs are allowed
- **Port range limits** - Port numbers are validated (1-65535)
- **Command timeout** - All commands have configurable timeouts
- **Argument-based execution** - Never uses `shell=True`

## Installation

### Prerequisites

- Python 3.10 or higher
- Kali Linux or a Linux distribution with security tools
- Required system tools:
  - `uname`, `lsb_release` (usually pre-installed)
  - `dig` (dnsutils)
  - `whois`
  - `nmap`
  - `curl`
  - `python3-openssl` (or Python's ssl module)

### Install System Tools

On Kali Linux (most tools are pre-installed):

```bash
sudo apt update
sudo apt install dnsutils whois nmap curl python3-openssl
```

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install dnsutils whois nmap curl python3-openssl lsb-release
```

### Install Python Dependencies

```bash
pip install -e .
```

Or install manually:

```bash
pip install mcp pyyaml pydantic
```

## Configuration

Edit `config.yaml` to customize safety settings:

```yaml
safety:
  allow_public_ips: false  # Set to true to allow scanning public IPs
  command_timeout: 30      # Seconds before commands timeout

tools:
  nmap:
    allowed_scan_types:
      - "quick"
      - "service"
  dns:
    allowed_record_types:
      - "A"
      - "AAAA"
      - "MX"
      - "TXT"
      - "NS"
      - "CNAME"
```

## Running the Server

### Direct Execution

```bash
python server.py
```

### Using the Installed Script

```bash
mcp-kali-server
```

## Connecting to an MCP Client

### Claude Desktop Configuration

Add to your Claude Desktop MCP configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mcp-kali": {
      "command": "python",
      "args": [
        "/path/to/MCP-Kali-Server/server.py"
      ]
    }
  }
}
```

### Using stdio

The server uses stdio for communication, which is the standard MCP transport.

## Example Tool Calls

### Get System Information

```python
get_system_info()
```

Returns:
```json
{
  "kernel_info": "Linux kali 6.6.0-kali6-amd64 #1 SMP PREEMPT_DYNAMIC...",
  "distribution_info": "Distributor ID: Kali\nDescription: Kali GNU/Linux Rolling...",
  "error": null
}
```

### List Kali Tools

```python
list_kali_tools()
```

Returns:
```json
{
  "kali_tool_packages": "ii  kali-tools-gpu  2024.1.0  amd64...",
  "security_binaries": ["nmap", "netcat", "tcpdump", ...],
  "error": null
}
```

### DNS Lookup

```python
dns_lookup(domain="example.com", record_type="A")
```

Returns:
```json
{
  "success": true,
  "domain": "example.com",
  "record_type": "A",
  "results": "93.184.216.34",
  "raw_output": "93.184.216.34"
}
```

### Whois Lookup

```python
whois_lookup(domain="example.com")
```

Returns domain registration information.

### Nmap Scan

```python
nmap_scan(target="192.168.1.1", scan_type="quick")
```

Returns:
```json
{
  "success": true,
  "target": "192.168.1.1",
  "scan_type": "quick",
  "results": "Starting Nmap 7.94...",
  "raw_output": "..."
}
```

**Note**: By default, public IP addresses are blocked. Set `allow_public_ips: true` in `config.yaml` to enable.

### Gobuster Scan

```python
gobuster_scan(target="http://example.com", threads=10)
```

Returns:
```json
{
  "success": true,
  "target": "http://example.com",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "threads": 10,
  "results": ["http://example.com/admin", "http://example.com/login", ...],
  "raw_output": "..."
}
```

**Note**: By default, public IP addresses are blocked. Set `allow_public_ips: true` in `config.yaml` to enable scanning public targets.

### Dirb Scan

```python
dirb_scan(target="http://example.com")
```

Returns:
```json
{
  "success": true,
  "target": "http://example.com",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "results": ["http://example.com/admin", "http://example.com/login", ...],
  "raw_output": "..."
}
```

**Note**: By default, public IP addresses are blocked. Set `allow_public_ips: true` in `config.yaml` to enable scanning public targets.

### Nikto Scan

```python
nikto_scan(target="http://example.com")
```

Returns:
```json
{
  "success": true,
  "target": "http://example.com",
  "vulnerabilities": ["+ OSVDB-1234: X-Frame-Options header not set", ...],
  "raw_output": "..."
}
```

**Note**: By default, public IP addresses are blocked. Set `allow_public_ips: true` in `config.yaml` to enable scanning public targets.

### SQLMap Scan

```python
sqlmap_scan(target="http://example.com/page?id=1")
```

Returns:
```json
{
  "success": true,
  "target": "http://example.com/page?id=1",
  "databases": ["[*] information_schema", "[*] test_db"],
  "vulnerabilities": ["parameter 'id' appears to be injectable", ...],
  "raw_output": "..."
}
```

**Important**: SQLMap is configured for detection only (risk=1, level=1, --dbs). No exploitation or data extraction is performed. By default, public IP addresses are blocked. Set `allow_public_ips: true` in `config.yaml` to enable scanning public targets.

### WPScan Scan

```python
wpscan_scan(target="http://example.com")
```

Returns:
```json
{
  "success": true,
  "target": "http://example.com",
  "vulnerabilities": ["WordPress version 5.8.1 has known vulnerabilities", ...],
  "plugins": ["plugin1: vulnerable", "plugin2: secure"],
  "themes": ["theme1: vulnerable"],
  "raw_output": "..."
}
```

**Note**: WPScan enumerates vulnerable plugins and themes only (no brute-force or exploitation). By default, public IP addresses are blocked. Set `allow_public_ips: true` in `config.yaml` to enable scanning public targets.

### HTTP Headers Check

```python
http_headers_check(url="https://example.com")
```

Returns:
```json
{
  "success": true,
  "url": "https://example.com",
  "headers": {
    "Content-Type": "text/html",
    "Server": "ECS (dcb/7D49)"
  },
  "raw_output": "HTTP/2 200\ncontent-type: text/html..."
}
```

### SSL Certificate Check

```python
ssl_certificate_check(hostname="example.com", port=443)
```

Returns:
```json
{
  "success": true,
  "hostname": "example.com",
  "port": 443,
  "certificate": {
    "subject": {"commonName": "example.com"},
    "issuer": {"organizationName": "DigiCert Inc"},
    "not_before": "Jan  1 00:00:00 2024 GMT",
    "not_after": "Jan  1 23:59:59 2025 GMT",
    "days_until_expiry": 200,
    "is_valid": true
  }
}
```

### Shodan Host Lookup

```python
shodan_host_lookup(target="192.168.1.1", api_key="your_api_key")
```

Returns:
```json
{
  "success": true,
  "target": "192.168.1.1",
  "ip": "192.168.1.1",
  "hostnames": ["example.com"],
  "country": "United States",
  "city": "San Francisco",
  "org": "Example Organization",
  "isp": "Example ISP",
  "asn": "AS12345",
  "ports": [80, 443, 22],
  "vulns": ["CVE-2021-1234"],
  "vuln_count": 1,
  "services": [...],
  "service_count": 3,
  "raw_output": "..."
}
```

**Note**: Requires a Shodan API key. Get one from https://developer.shodan.io/api. Set the API key in `config.yaml` under `tools.shodan.api_key` or pass as a parameter. This tool queries Shodan's passive database of known exposed services.

## Project Structure

```
MCP-Kali-Server/
├── README.md
├── pyproject.toml
├── server.py              # Main MCP server
├── config.yaml            # Safety configuration
├── safe_command_runner.py # Secure subprocess wrapper
├── input_validation.py    # Input validation helpers
├── logging_setup.py       # Logging configuration
├── tools/
│   ├── __init__.py
│   ├── system_tools.py    # get_system_info
│   ├── dns_tools.py       # dns_lookup
│   ├── whois_tools.py     # whois_lookup
│   ├── nmap_tools.py      # nmap_scan
│   ├── http_tools.py      # http_headers_check
│   └── ssl_tools.py       # ssl_certificate_check
└── logs/                  # Log files directory
```

## Extending the Server

To add a new tool safely:

1. **Create a new tool module** in `tools/`:

```python
# tools/my_tool.py
import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator

def register_my_tool(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    validator = InputValidator(logger)
    
    @mcp.tool()
    def my_tool(input_param: str) -> dict[str, Any]:
        logger.info(f"Tool called: my_tool(input_param={input_param})")
        
        # Validate input
        input_param = validator.sanitize_string(input_param)
        if not validator.validate_domain(input_param):
            return {"success": False, "error": "Invalid input"}
        
        # Run safe command
        result = command_runner.run(["safe-command", input_param])
        
        if result.success:
            return {"success": True, "results": result.stdout}
        else:
            return {"success": False, "error": result.stderr}
```

2. **Register the tool** in `tools/__init__.py`:

```python
from .my_tool import register_my_tool

__all__ = [
    # ... existing imports
    'register_my_tool',
]
```

3. **Register in server.py**:

```python
from tools import register_my_tool

# In create_server():
register_my_tool(mcp, command_runner, logger, config)
```

4. **Add to config.yaml** if needed:

```yaml
tools:
  my_tool:
    setting1: value1
```

## Important Safety Rules

When extending this server:

- **NEVER** use `shell=True` in subprocess calls
- **NEVER** allow user-provided command strings
- **ALWAYS** validate all inputs
- **ALWAYS** use argument lists for subprocess
- **ALWAYS** add timeouts to commands
- **ALWAYS** add commands to the allowlist
- **NEVER** expose raw file system access
- **NEVER** allow arbitrary code execution
- **NEVER** include exploit frameworks

## Logging

All tool calls are logged to `logs/mcp_kali_server.log` with:

- Timestamp
- Tool name
- Input parameters
- Execution result
- Errors (if any)

Log rotation is configured to keep 5 backup files of 10MB each.

## Troubleshooting

### Command not found errors

If you see "Command not found" errors, install the missing tool:

```bash
sudo apt install <tool-name>
```

### Permission denied

This server never requires sudo. If you need elevated privileges, the operation is intentionally blocked.

### Timeout errors

Increase the timeout in `config.yaml`:

```yaml
safety:
  command_timeout: 60  # Increase from 30 to 60 seconds
```

## License

This project is provided as-is for educational and defensive security purposes.

## Contributing

Contributions are welcome, but must maintain the safety-first philosophy. Any changes that weaken security guardrails will not be accepted.

## Disclaimer

This tool is designed for **defensive security work and learning only**. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized scanning is illegal in many jurisdictions.