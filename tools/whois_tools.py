"""
Whois lookup tools.
Provides safe whois query functionality.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_whois_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger
) -> None:
    """
    Register whois lookup tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
    """
    
    validator = InputValidator(logger)
    
    @mcp.tool()
    def whois_lookup(domain: str) -> dict[str, Any]:
        """
        Perform a whois lookup for a domain.
        
        Args:
            domain: The domain to query (e.g., example.com)
        
        Returns:
            Whois query results
            
        Raises:
            ValueError: If domain is invalid
        """
        logger.info(f"Tool called: whois_lookup(domain={domain})")
        
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
        
        # Build whois command
        cmd = ["whois", domain]
        
        # Execute command with longer timeout (whois can be slow)
        result = command_runner.run(cmd, timeout=60)
        
        if result.success:
            logger.info(f"Whois lookup successful for {domain}")
            return {
                "success": True,
                "domain": domain,
                "results": result.stdout.strip(),
                "raw_output": result.stdout
            }
        else:
            error_msg = f"Whois lookup failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
