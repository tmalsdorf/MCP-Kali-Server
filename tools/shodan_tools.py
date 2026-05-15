"""
Shodan API tools.
Provides passive host lookup functionality using Shodan API.
"""

import logging
import json
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_shodan_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register Shodan API tools for passive reconnaissance.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    timeout = config.get('tools', {}).get('shodan', {}).get('scan_timeout', 30)
    
    @mcp.tool()
    def shodan_host_lookup(target: str, api_key: str = "") -> dict[str, Any]:
        """
        Perform passive host lookup using Shodan API.
        
        This tool queries Shodan's database for known exposed services and vulnerabilities.
        
        Args:
            target: IP address, hostname, or domain to lookup (e.g., 192.168.1.1 or example.com)
            api_key: Shodan API key (optional, can be set in config.yaml)
        
        Returns:
            Shodan host information including services, vulnerabilities, and metadata
            
        Raises:
            ValueError: If target is invalid
        """
        logger.info(f"Tool called: shodan_host_lookup(target={target})")
        
        # Sanitize inputs
        target = validator.sanitize_string(target, max_length=253)
        api_key = validator.sanitize_string(api_key, max_length=100)
        
        # Get API key from config if not provided
        if not api_key:
            api_key = config.get('tools', {}).get('shodan', {}).get('api_key', '')
        
        if not api_key:
            error_msg = "Shodan API key not provided. Set it in config.yaml under tools.shodan.api_key or pass as parameter."
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
        
        # Validate target (IP or domain)
        if not validator.validate_domain(target) and not validator.validate_ip(target):
            error_msg = f"Invalid target: {target}. Must be a valid IP address or domain."
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
        
        # Use curl to query Shodan API
        cmd = ["curl", "-s", f"https://api.shodan.io/shodan/host/{target}?key={api_key}"]
        
        # Execute command
        result = command_runner.run(cmd, timeout=timeout)
        
        if result.success:
            logger.info(f"Shodan lookup successful for {target}")
            try:
                data = json.loads(result.stdout)
                
                # Extract relevant information
                return {
                    "success": True,
                    "target": target,
                    "ip": data.get("ip_str"),
                    "hostnames": data.get("hostnames", []),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "vuln_count": len(data.get("vulns", [])),
                    "services": data.get("data", []),
                    "service_count": len(data.get("data", [])),
                    "raw_output": result.stdout
                }
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Shodan API response: {e}"
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "target": target,
                    "raw_output": result.stdout
                }
        else:
            error_msg = f"Shodan lookup failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
