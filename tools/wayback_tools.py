"""
Wayback Machine tools.
Provides passive historical URL discovery using waybackurls.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_wayback_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register wayback machine tools for passive historical URL discovery.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    timeout = config.get('tools', {}).get('wayback', {}).get('scan_timeout', 60)
    
    @mcp.tool()
    def wayback_urls_lookup(domain: str) -> dict[str, Any]:
        """
        Perform passive historical URL discovery using waybackurls.
        
        This tool queries the Wayback Machine for all historical URLs archived
        for a domain, revealing old endpoints, parameters, and forgotten pages.
        
        Args:
            domain: The target domain (e.g., example.com)
        
        Returns:
            Discovered historical URLs from the Wayback Machine
            
        Raises:
            ValueError: If domain is invalid
        """
        logger.info(f"Tool called: wayback_urls_lookup(domain={domain})")
        
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
        
        # Build waybackurls command
        cmd = ["waybackurls", "-d", domain]
        
        # Execute command
        result = command_runner.run(cmd, timeout=timeout)
        
        if result.success:
            logger.info(f"waybackurls lookup successful for {domain}")
            # Parse output to extract URLs
            urls = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                url = line.strip()
                if url:
                    urls.append(url)
            
            # Remove duplicates while preserving order
            unique_urls = list(dict.fromkeys(urls))
            
            return {
                "success": True,
                "domain": domain,
                "urls": unique_urls,
                "url_count": len(unique_urls),
                "raw_output": result.stdout
            }
        else:
            error_msg = f"waybackurls lookup failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain
            }
