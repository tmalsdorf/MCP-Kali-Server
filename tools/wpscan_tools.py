"""
WPScan WordPress security scanner tools.
Provides safe WordPress vulnerability scanning functionality with strict guardrails.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_wpscan_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register wpscan scanning tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allow_public_ips = config.get('safety', {}).get('allow_public_ips', False)
    scan_timeout = config.get('tools', {}).get('wpscan', {}).get('scan_timeout', 180)
    
    @mcp.tool()
    def wpscan_scan(target: str) -> dict[str, Any]:
        """
        Perform a safe WordPress vulnerability scan.
        
        Args:
            target: Target URL or hostname (e.g., http://example.com or example.com)
        
        Returns:
            WPScan scan results
            
        Raises:
            ValueError: If target is invalid or unsafe
        """
        logger.info(f"Tool called: wpscan_scan(target={target})")
        
        # Sanitize input
        target = validator.sanitize_string(target, max_length=500)
        
        # Validate URL or hostname
        is_url = validator.validate_url(target, allowed_schemes=['http', 'https'])
        
        if not is_url:
            # Try as hostname
            if not validator.validate_hostname(target):
                error_msg = f"Invalid target: {target}. Must be a valid URL or hostname."
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "target": target
                }
        
        # Check if target is a public IP
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(target if is_url else f"http://{target}")
            hostname = parsed_url.hostname or target
            
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
            logger.warning(f"Error parsing target: {e}")
        
        # Build wpscan command with safe defaults
        # --no-update: Don't update the database
        # --enumerate vp: Enumerate vulnerable plugins only
        # --enumerate vt: Enumerate vulnerable themes only
        # --format json: Output in JSON format
        cmd = [
            "wpscan",
            "--url", target,
            "--no-update",
            "--enumerate", "vp,vt",
            "--format", "json",
        ]
        
        # Execute command with longer timeout
        result = command_runner.run(cmd, timeout=scan_timeout)
        
        if result.success:
            logger.info(f"WPScan scan successful for {target}")
            
            # Parse results
            lines = result.stdout.strip().split('\n')
            vulnerabilities = []
            plugins = []
            themes = []
            
            for line in lines:
                # Extract vulnerability information
                if 'vulnerability' in line.lower():
                    vulnerabilities.append(line)
                # Extract plugin information
                if 'plugin' in line.lower():
                    plugins.append(line)
                # Extract theme information
                if 'theme' in line.lower():
                    themes.append(line)
            
            return {
                "success": True,
                "target": target,
                "vulnerabilities": vulnerabilities,
                "plugins": plugins,
                "themes": themes,
                "raw_output": result.stdout
            }
        else:
            error_msg = f"WPScan scan failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target
            }
