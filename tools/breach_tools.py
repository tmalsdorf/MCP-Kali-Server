"""
Breach API tools.
Provides passive email/domain breach check functionality using breach APIs.
"""

import logging
import json
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_breach_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register breach API tools for passive exposure checking.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    timeout = config.get('tools', {}).get('breach', {}).get('scan_timeout', 30)
    
    @mcp.tool()
    def email_breach_domain_check(domain: str, api_key: str = "") -> dict[str, Any]:
        """
        Perform passive domain breach check using breach APIs.
        
        This tool queries breach databases (like Have I Been Pwned) to check if
        a domain's emails have been involved in any data breaches.
        
        Args:
            domain: The target domain (e.g., example.com)
            api_key: API key for breach service (optional, can be set in config.yaml)
        
        Returns:
            Breach information including breach count and details
            
        Raises:
            ValueError: If domain is invalid
        """
        logger.info(f"Tool called: email_breach_domain_check(domain={domain})")
        
        # Sanitize inputs
        domain = validator.sanitize_string(domain, max_length=253)
        api_key = validator.sanitize_string(api_key, max_length=100)
        
        # Get API key from config if not provided
        if not api_key:
            api_key = config.get('tools', {}).get('breach', {}).get('api_key', '')
        
        # Validate domain
        if not validator.validate_domain(domain):
            error_msg = f"Invalid domain: {domain}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
        
        # Use curl to query Have I Been Pwned API for breached accounts by domain
        if api_key:
            cmd = ["curl", "-s", "-H", f"hibp-api-key: {api_key}",
                   f"https://haveibeenpwned.com/api/v3/breachedaccount/{domain}?truncateResponse=false"]
        else:
            error_msg = "API key required for breach check. Set it in config.yaml under tools.breach.api_key or pass as parameter."
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
        
        # Execute command
        result = command_runner.run(cmd, timeout=timeout)
        
        if result.success:
            logger.info(f"Breach check successful for {domain}")
            try:
                data = json.loads(result.stdout)
                
                # If it's a list, process multiple breaches
                if isinstance(data, list):
                    breaches = []
                    for breach in data:
                        breach_info = {
                            "name": breach.get('Name'),
                            "title": breach.get('Title'),
                            "domain": breach.get('Domain'),
                            "breach_date": breach.get('BreachDate'),
                            "added_date": breach.get('AddedDate'),
                            "pwn_count": breach.get('PwnCount'),
                            "description": breach.get('Description'),
                            "data_classes": breach.get('DataClasses', []),
                            "is_verified": breach.get('IsVerified'),
                            "is_fabricated": breach.get('IsFabricated'),
                            "is_sensitive": breach.get('IsSensitive')
                        }
                        breaches.append(breach_info)
                    
                    return {
                        "success": True,
                        "domain": domain,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "raw_output": result.stdout
                    }
                else:
                    # Single breach or error response
                    return {
                        "success": True,
                        "domain": domain,
                        "breaches": [data] if data else [],
                        "breach_count": 1 if data else 0,
                        "raw_output": result.stdout
                    }
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse breach API response: {e}"
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "domain": domain,
                    "raw_output": result.stdout
                }
        else:
            error_msg = f"Breach check failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
