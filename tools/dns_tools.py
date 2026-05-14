"""
DNS lookup tools.
Provides safe DNS query functionality.
"""

import logging
from typing import Any
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_dns_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register DNS lookup tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    allowed_record_types = config.get('tools', {}).get('dns', {}).get('allowed_record_types', ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'])
    dns_server = config.get('tools', {}).get('dns', {}).get('dns_server', '')
    
    @mcp.tool()
    def dns_lookup(domain: str, record_type: str = "A") -> dict[str, Any]:
        """
        Perform a DNS lookup for a domain.
        
        Args:
            domain: The domain to query (e.g., example.com)
            record_type: DNS record type (A, AAAA, MX, TXT, NS, CNAME)
        
        Returns:
            DNS query results
            
        Raises:
            ValueError: If domain or record_type is invalid
        """
        logger.info(f"Tool called: dns_lookup(domain={domain}, record_type={record_type})")
        
        # Sanitize inputs
        domain = validator.sanitize_string(domain, max_length=253)
        record_type = validator.sanitize_string(record_type, max_length=10)
        
        # Validate domain
        if not validator.validate_domain(domain):
            error_msg = f"Invalid domain: {domain}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain,
                "record_type": record_type
            }
        
        # Validate record type
        if not validator.validate_dns_record_type(record_type):
            error_msg = f"Invalid DNS record type: {record_type}. Allowed types: {', '.join(allowed_record_types)}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain,
                "record_type": record_type
            }
        
        # Check if record type is in config allowlist
        if record_type.upper() not in [rt.upper() for rt in allowed_record_types]:
            error_msg = f"Record type {record_type} not allowed in configuration"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain,
                "record_type": record_type
            }
        
        # Build dig command
        cmd = ["dig", domain, record_type, "+short"]
        
        # Add custom DNS server if configured
        if dns_server:
            cmd.insert(1, f"@{dns_server}")
        
        # Execute command
        result = command_runner.run(cmd)
        
        if result.success:
            logger.info(f"DNS lookup successful for {domain}")
            return {
                "success": True,
                "domain": domain,
                "record_type": record_type,
                "results": result.stdout.strip(),
                "raw_output": result.stdout
            }
        else:
            error_msg = f"DNS lookup failed: {result.stderr}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "domain": domain,
                "record_type": record_type
            }
