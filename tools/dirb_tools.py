"""
Dirb directory brute-forcing tools.
Provides safe dirb scanning functionality with strict guardrails.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_dirb_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register dirb scanning tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allow_public_ips = config.get('safety', {}).get('allow_public_ips', False)
    default_wordlist = config.get('tools', {}).get('dirb', {}).get('default_wordlist', '/usr/share/wordlists/dirb/common.txt')
    scan_timeout = config.get('tools', {}).get('dirb', {}).get('scan_timeout', 120)
    
    @mcp.tool()
    def dirb_scan(target: str, wordlist: str = None) -> dict[str, Any]:
        """
        Perform a safe dirb directory brute-force scan.
        
        Args:
            target: Target URL (e.g., http://example.com)
            wordlist: Path to wordlist file (optional, uses default if not provided)
        
        Returns:
            Dirb scan results
            
        Raises:
            ValueError: If target is invalid or unsafe
        """
        logger.info(f"Tool called: dirb_scan(target={target}, wordlist={wordlist})")
        
        # Sanitize inputs
        target = validator.sanitize_string(target, max_length=500)
        if wordlist:
            wordlist = validator.sanitize_string(wordlist, max_length=500)
        
        # Validate URL
        if not validator.validate_url(target, allowed_schemes=['http', 'https']):
            error_msg = f"Invalid target URL: {target}. Only http/https schemes are allowed."
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
        
        # Use default wordlist if not provided
        if not wordlist:
            wordlist = default_wordlist
        
        # Check if target is a public IP (extract from URL)
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            
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
        
        # Build dirb command with safe defaults
        cmd = [
            "dirb",
            target,
            wordlist,
            "-q",  # Quiet mode
            "-S",  # Don't show status messages
            "-N",  # Don't show warning messages
        ]
        
        # Execute command with longer timeout
        result = command_runner.run(cmd, timeout=scan_timeout)
        
        if result.success:
            logger.info(f"Dirb scan successful for {target}")
            
            # Parse results
            lines = result.stdout.strip().split('\n')
            found_dirs = []
            for line in lines:
                # Filter out status messages and empty lines
                if line and 'CODE:' not in line and '=>' not in line and 'SCANNING' not in line:
                    found_dirs.append(line)
            
            return {
                "success": True,
                "target": target,
                "wordlist": wordlist,
                "results": found_dirs,
                "raw_output": result.stdout
            }
        else:
            error_msg = f"Dirb scan failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
