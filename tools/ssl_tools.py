"""
SSL/TLS certificate tools.
Provides safe SSL certificate checking functionality.
"""

import logging
import ssl
import socket
from typing import Any
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from safe_command_runner import SafeCommandRunner
from input_validation import InputValidator


def register_ssl_tools(
    mcp: FastMCP,
    command_runner: SafeCommandRunner,
    logger: logging.Logger,
    config: dict[str, Any]
) -> None:
    """
    Register SSL certificate tools.
    
    Args:
        mcp: FastMCP server instance
        command_runner: SafeCommandRunner instance
        logger: Logger instance
        config: Configuration dictionary
    """
    
    validator = InputValidator(logger)
    default_port = config.get('tools', {}).get('ssl', {}).get('default_port', 443)
    connection_timeout = config.get('tools', {}).get('ssl', {}).get('connection_timeout', 10)
    
    @mcp.tool()
    def ssl_certificate_check(hostname: str, port: int = 443) -> dict[str, Any]:
        """
        Check SSL/TLS certificate for a hostname.
        
        Args:
            hostname: The hostname to check (e.g., example.com)
            port: The port number (default: 443)
        
        Returns:
            SSL certificate information
            
        Raises:
            ValueError: If hostname or port is invalid
        """
        logger.info(f"Tool called: ssl_certificate_check(hostname={hostname}, port={port})")
        
        # Sanitize inputs
        hostname = validator.sanitize_string(hostname, max_length=253)
        
        # Validate hostname
        if not validator.validate_hostname(hostname):
            error_msg = f"Invalid hostname: {hostname}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "hostname": hostname,
                "port": port
            }
        
        # Validate port
        if not validator.validate_port(port):
            error_msg = f"Invalid port: {port}. Must be between 1 and 65535"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "hostname": hostname,
                "port": port
            }
        
        # Use Python's ssl module for safe certificate checking
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to the server
            with socket.create_connection((hostname, port), timeout=connection_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Parse certificate information
                    cert_info = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                    }
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    
                    cert_info["days_until_expiry"] = days_until_expiry
                    cert_info["is_valid"] = days_until_expiry > 0
                    
                    logger.info(f"SSL certificate check successful for {hostname}")
                    return {
                        "success": True,
                        "hostname": hostname,
                        "port": port,
                        "certificate": cert_info
                    }
                    
        except socket.timeout:
            error_msg = f"Connection timeout to {hostname}:{port}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "hostname": hostname,
                "port": port
            }
        except ssl.SSLCertVerificationError as e:
            error_msg = f"SSL certificate verification failed: {str(e)}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "hostname": hostname,
                "port": port
            }
        except Exception as e:
            error_msg = f"SSL certificate check failed: {str(e)}"
            logger.warning(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "hostname": hostname,
                "port": port
            }
