"""
HTTP tools.
Provides safe HTTP header checking functionality.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_http_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register HTTP tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allowed_schemes = config.get('tools', {}).get('http', {}).get('allowed_schemes', ['http', 'https'])
    request_timeout = config.get('tools', {}).get('http', {}).get('request_timeout', 10)
    
    @mcp.tool()
    def http_headers_check(url: str) -> dict[str, Any]:
        """
        Check HTTP headers for a URL.
        
        Args:
            url: The URL to check (e.g., https://example.com)
        
        Returns:
            HTTP headers
            
        Raises:
            ValueError: If URL is invalid
        """
        logger.info(f"Tool called: http_headers_check(url={url})")
        
        # Sanitize input
        url = validator.sanitize_string(url, max_length=500)
        
        # Validate URL
        if not validator.validate_url(url, allowed_schemes=allowed_schemes):
            error_msg = f"Invalid URL: {url}. Allowed schemes: {', '.join(allowed_schemes)}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "url": url
            }
        
        # Build curl command
        # Use -I to fetch only headers
        # Use -s for silent mode (no progress bar)
        # Use --max-time for timeout
        cmd = [
            "curl",
            "-I",
            "-s",
            "--max-time", str(request_timeout),
            url
        ]
        
        # Execute command
        result = command_runner.run(cmd, timeout=request_timeout + 5)
        
        if result.success:
            logger.info(f"HTTP headers check successful for {url}")
            
            # Parse headers
            headers = {}
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            return {
                "success": True,
                "url": url,
                "headers": headers,
                "raw_output": result.stdout
            }
        else:
            error_msg = f"HTTP headers check failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "url": url
            }
