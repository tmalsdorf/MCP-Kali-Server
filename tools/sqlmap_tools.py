"""
SQLMap SQL injection testing tools.
Provides safe SQL injection detection functionality with strict guardrails.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_sqlmap_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register sqlmap testing tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allow_public_ips = config.get('safety', {}).get('allow_public_ips', False)
    scan_timeout = config.get('tools', {}).get('sqlmap', {}).get('scan_timeout', 180)
    
    @mcp.tool()
    def sqlmap_scan(target: str) -> dict[str, Any]:
        """
        Perform a safe SQL injection detection scan.
        
        This tool only performs basic SQL injection detection (no exploitation).
        Uses conservative settings to minimize impact on target systems.
        
        Args:
            target: Target URL (e.g., http://example.com/page?id=1)
        
        Returns:
            SQLMap scan results
            
        Raises:
            ValueError: If target is invalid or unsafe
        """
        logger.info(f"Tool called: sqlmap_scan(target={target})")
        
        # Sanitize input
        target = validator.sanitize_string(target, max_length=500)
        
        # Validate URL
        if not validator.validate_url(target, allowed_schemes=['http', 'https']):
            error_msg = f"Invalid target URL: {target}. Only http/https schemes are allowed."
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
        
        # Check if target is a public IP
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            
            if hostname:
                # Check if it's an IP address
                import ipaddress
                try:
                    ip = ipaddress.ip_address(hostname)
                    if not validator.validate_ip_address(hostname, allow_public=allow_public_ips):
                        error_msg = f"Public IP addresses are not allowed in configuration. Set allow_public_ips: true in config.yaml to enable."
                        logger.warning(error_msg)
                        return {
                            "success": False,
                            "error": error_msg,
                            "target": target
                        }
                except ValueError:
                    # Not an IP address, it's a hostname
                    pass
        except Exception as e:
            logger.warning(f"Error parsing target URL: {e}")
        
        # Build sqlmap command with safe defaults
        # --batch: Non-interactive mode
        # --risk=1: Lowest risk level (basic tests only)
        # --level=1: Lowest test level (basic tests only)
        # --dbs: Only enumerate databases (no data extraction)
        cmd = [
            "sqlmap",
            "--batch",
            "--url", target,
            "--risk=1",
            "--level=1",
            "--dbs",
            "--timeout=30",
        ]
        
        # Execute command with longer timeout
        result = command_runner.run(cmd, timeout=scan_timeout)
        
        if result.success:
            logger.info(f"SQLMap scan successful for {target}")
            
            # Parse results
            lines = result.stdout.strip().split('\n')
            databases = []
            vulnerabilities = []
            
            for line in lines:
                # Extract database information
                if 'available databases' in line.lower():
                    databases.append(line)
                # Extract vulnerability information
                if 'parameter' in line.lower() and 'injectable' in line.lower():
                    vulnerabilities.append(line)
            
            return {
                "success": True,
                "target": target,
                "databases": databases,
                "vulnerabilities": vulnerabilities,
                "raw_output": result.stdout
            }
        else:
            error_msg = f"SQLMap scan failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
