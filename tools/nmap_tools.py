"""
Nmap scanning tools.
Provides safe nmap scanning functionality with strict guardrails.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_nmap_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register nmap scanning tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allow_public_ips = config.get('safety', {}).get('allow_public_ips', False)
    allowed_scan_types = config.get('tools', {}).get('nmap', {}).get('allowed_scan_types', ['quick', 'service'])
    safe_flags = config.get('tools', {}).get('nmap', {}).get('safe_flags', ['-T3', '-Pn'])
    max_ports = config.get('tools', {}).get('nmap', {}).get('max_ports', 100)
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "quick") -> dict[str, Any]:
        """
        Perform a safe nmap scan.
        
        Args:
            target: Target IP address or hostname
            scan_type: Type of scan - 'quick' or 'service'
        
        Returns:
            Nmap scan results
            
        Raises:
            ValueError: If target or scan_type is invalid
        """
        logger.info(f"Tool called: nmap_scan(target={target}, scan_type={scan_type})")
        
        # Sanitize inputs
        target = validator.sanitize_string(target, max_length=253)
        scan_type = validator.sanitize_string(scan_type, max_length=20)
        
        # Validate scan type
        if not validator.validate_nmap_scan_type(scan_type):
            error_msg = f"Invalid scan type: {scan_type}. Allowed types: {', '.join(allowed_scan_types)}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target,
                "scan_type": scan_type
            }
        
        # Check if scan type is in config allowlist
        if scan_type.lower() not in [st.lower() for st in allowed_scan_types]:
            error_msg = f"Scan type {scan_type} not allowed in configuration"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target,
                "scan_type": scan_type
            }
        
        # Validate target (check if it's an IP address)
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            if not validator.validate_ip_address(target, allow_public=allow_public_ips):
                error_msg = f"Public IP addresses are not allowed in configuration. Set allow_public_ips: true in config.yaml to enable."
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "target": target,
                    "scan_type": scan_type
                }
        except ValueError:
            # Not an IP address, treat as hostname
            if not validator.validate_hostname(target):
                error_msg = f"Invalid hostname: {target}"
                logger.warning(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "target": target,
                    "scan_type": scan_type
                }
        
        # Build nmap command with safe defaults
        cmd = ["nmap"]
        
        # Add safe flags from config
        cmd.extend(safe_flags)
        
        # Add scan type specific flags
        if scan_type.lower() == "quick":
            cmd.extend(["-F"])  # Fast scan - fewer ports
        elif scan_type.lower() == "service":
            cmd.extend(["-sV"])  # Service version detection
            cmd.extend(["-p", f"1-{max_ports}"])  # Limit port range
        
        # Add target
        cmd.append(target)
        
        # Execute command with longer timeout
        result = command_runner.run(cmd, timeout=120)
        
        if result.success:
            logger.info(f"Nmap scan successful for {target}")
            return {
                "success": True,
                "target": target,
                "scan_type": scan_type,
                "results": result.stdout.strip(),
                "raw_output": result.stdout
            }
        else:
            error_msg = f"Nmap scan failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "target": target,
                "scan_type": scan_type
            }
