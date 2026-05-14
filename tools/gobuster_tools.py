"""
Gobuster directory brute-forcing tools.
Provides safe gobuster scanning functionality with strict guardrails.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_gobuster_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register gobuster scanning tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allow_public_ips = config.get('safety', {}).get('allow_public_ips', False)
    default_wordlist = config.get('tools', {}).get('gobuster', {}).get('default_wordlist', '/usr/share/wordlists/dirb/common.txt')
    max_threads = config.get('tools', {}).get('gobuster', {}).get('max_threads', 10)
    scan_timeout = config.get('tools', {}).get('gobuster', {}).get('scan_timeout', 120)
    
    @mcp.tool()
    def gobuster_scan(target: str, wordlist: str = None, threads: int = 10) -> dict[str, Any]:
        """
        Perform a safe gobuster directory brute-force scan.
        
        Args:
            target: Target URL (e.g., http://example.com)
            wordlist: Path to wordlist file (optional, uses default if not provided)
            threads: Number of threads (default: 10, max: 50)
        
        Returns:
            Gobuster scan results
            
        Raises:
            ValueError: If target is invalid or unsafe
        """
        logger.info(f"Tool called: gobuster_scan(target={target}, wordlist={wordlist}, threads={threads})")
        
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
        
        # Validate threads
        try:
            threads = int(threads)
            if threads < 1 or threads > 50:
                error_msg = f"Invalid thread count: {threads}. Must be between 1 and 50."
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "target": target
                }
        except (ValueError, TypeError):
            error_msg = f"Invalid thread count: {threads}. Must be an integer."
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
        
        # Build gobuster command with safe defaults
        cmd = [
            "gobuster",
            "dir",
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "-q",  # Quiet mode
            "-k",  # Skip SSL verification
            "--no-error",  # Don't display errors
        ]
        
        # Execute command with longer timeout
        result = command_runner.run(cmd, timeout=scan_timeout)
        
        if result.success:
            logger.info(f"Gobuster scan successful for {target}")
            
            # Parse results
            lines = result.stdout.strip().split('\n')
            found_dirs = []
            for line in lines:
                if line and line != "Gobuster v":
                    found_dirs.append(line)
            
            return {
                "success": True,
                "target": target,
                "wordlist": wordlist,
                "threads": threads,
                "results": found_dirs,
                "raw_output": result.stdout
            }
        else:
            error_msg = f"Gobuster scan failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
