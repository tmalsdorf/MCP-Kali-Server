"""
crt.sh API tools.
Provides passive subdomain discovery using Certificate Transparency logs.
"""

import logging
import json
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_crtsh_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register crt.sh API tools for passive subdomain discovery.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    timeout = config.get('tools', {}).get('crtsh', {}).get('scan_timeout', 30)
    
    @mcp.tool()
    def crtsh_lookup(domain: str) -> dict[str, Any]:
        """
        Perform passive subdomain discovery using crt.sh Certificate Transparency logs.
        
        This tool queries crt.sh for all SSL/TLS certificates issued for a domain,
        revealing subdomains that may not be publicly advertised.
        
        Args:
            domain: The target domain (e.g., example.com)
        
        Returns:
            Discovered subdomains from certificate transparency logs
            
        Raises:
            ValueError: If domain is invalid
        """
        logger.info(f"Tool called: crtsh_lookup(domain={domain})")
        
        # Sanitize input
        domain = validator.sanitize_string(domain, max_length=253)
        
        # Validate domain
        if not validator.validate_domain(domain):
            error_msg = f"Invalid domain: {domain}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
        
        # Use curl to query crt.sh API
        cmd = ["curl", "-s", f"https://crt.sh/?q=%.{domain}&output=json"]
        
        # Execute command
        result = command_runner.run(cmd, timeout=timeout)
        
        if result.success:
            logger.info(f"crt.sh lookup successful for {domain}")
            try:
                data = json.loads(result.stdout)
                
                # Extract unique subdomains
                subdomains = set()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    # Split by newlines and handle wildcard certificates
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and not name.startswith('*.'):
                            if domain in name:
                                subdomains.add(name)
                
                # Convert to sorted list
                subdomain_list = sorted(list(subdomains))
                
                return {
                    "success": True,
                    "domain": domain,
                    "subdomains": subdomain_list,
                    "subdomain_count": len(subdomain_list),
                    "certificate_count": len(data),
                    "raw_output": result.stdout
                }
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse crt.sh API response: {e}"
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "domain": domain,
                    "raw_output": result.stdout
                }
        else:
            error_msg = f"crt.sh lookup failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
