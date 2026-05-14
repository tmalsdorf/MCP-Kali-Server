"""
Input validation helper module.
Provides validation functions for user inputs.
"""

import re
import ipaddress
import logging
from typing import Optional, List
from urllib.parse import urlparse


class InputValidator:
    """
    Input validation helper with security-focused validation rules.
    """
    
    # DNS record types
    DNS_RECORD_TYPES = {'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'}
    
    # Nmap scan types
    NMAP_SCAN_TYPES = {'quick', 'service'}
    
    # URL schemes
    ALLOWED_URL_SCHEMES = {'http', 'https'}
    
    # Port range
    MIN_PORT = 1
    MAX_PORT = 65535
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the input validator.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
    
    def validate_domain(self, domain: str) -> bool:
        """
        Validate a domain name.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or not isinstance(domain, str):
            self.logger.warning("Invalid domain: empty or not a string")
            return False
        
        # Basic domain validation
        # Allow alphanumeric, hyphens, and dots
        # Must have at least one dot
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(pattern, domain):
            self.logger.warning(f"Invalid domain format: {domain}")
            return False
        
        # Check length
        if len(domain) > 253:
            self.logger.warning(f"Domain too long: {len(domain)} characters")
            return False
        
        # Check for at least one dot (subdomain or TLD)
        if '.' not in domain:
            self.logger.warning(f"Domain missing TLD: {domain}")
            return False
        
        return True
    
    def validate_dns_record_type(self, record_type: str) -> bool:
        """
        Validate DNS record type.
        
        Args:
            record_type: DNS record type to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not record_type or not isinstance(record_type, str):
            self.logger.warning("Invalid record type: empty or not a string")
            return False
        
        record_type_upper = record_type.upper()
        if record_type_upper not in self.DNS_RECORD_TYPES:
            self.logger.warning(f"Invalid DNS record type: {record_type}")
            return False
        
        return True
    
    def validate_ip_address(self, ip: str, allow_public: bool = False) -> bool:
        """
        Validate an IP address.
        
        Args:
            ip: IP address to validate
            allow_public: Whether to allow public IP addresses
            
        Returns:
            True if valid and allowed, False otherwise
        """
        if not ip or not isinstance(ip, str):
            self.logger.warning("Invalid IP: empty or not a string")
            return False
        
        try:
            addr = ipaddress.ip_address(ip)
            
            # Check if public IP is allowed
            if not allow_public and not addr.is_private:
                self.logger.warning(f"Public IP not allowed: {ip}")
                return False
            
            return True
            
        except ValueError:
            self.logger.warning(f"Invalid IP address format: {ip}")
            return False
    
    def validate_nmap_scan_type(self, scan_type: str) -> bool:
        """
        Validate nmap scan type.
        
        Args:
            scan_type: Scan type to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not scan_type or not isinstance(scan_type, str):
            self.logger.warning("Invalid scan type: empty or not a string")
            return False
        
        scan_type_lower = scan_type.lower()
        if scan_type_lower not in self.NMAP_SCAN_TYPES:
            self.logger.warning(f"Invalid nmap scan type: {scan_type}")
            return False
        
        return True
    
    def validate_url(self, url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
        """
        Validate a URL.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes (default: http, https)
            
        Returns:
            True if valid, False otherwise
        """
        if not url or not isinstance(url, str):
            self.logger.warning("Invalid URL: empty or not a string")
            return False
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            schemes = allowed_schemes or list(self.ALLOWED_URL_SCHEMES)
            if parsed.scheme.lower() not in [s.lower() for s in schemes]:
                self.logger.warning(f"Invalid URL scheme: {parsed.scheme}")
                return False
            
            # Check for netloc (domain)
            if not parsed.netloc:
                self.logger.warning("URL missing netloc")
                return False
            
            return True
            
        except Exception as e:
            self.logger.warning(f"URL parsing error: {e}")
            return False
    
    def validate_port(self, port: int) -> bool:
        """
        Validate a port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(port, int):
            self.logger.warning("Port must be an integer")
            return False
        
        if port < self.MIN_PORT or port > self.MAX_PORT:
            self.logger.warning(f"Port out of range: {port}")
            return False
        
        return True
    
    def validate_hostname(self, hostname: str) -> bool:
        """
        Validate a hostname.
        
        Args:
            hostname: Hostname to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not hostname or not isinstance(hostname, str):
            self.logger.warning("Invalid hostname: empty or not a string")
            return False
        
        # Hostname validation (RFC 1123)
        # Allow alphanumeric, hyphens, and dots
        # Must not start or end with hyphen
        # Must not have consecutive dots
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(pattern, hostname):
            self.logger.warning(f"Invalid hostname format: {hostname}")
            return False
        
        # Check length
        if len(hostname) > 253:
            self.logger.warning(f"Hostname too long: {len(hostname)} characters")
            return False
        
        return True
    
    def sanitize_string(self, s: str, max_length: int = 1000) -> str:
        """
        Sanitize a string input.
        
        Args:
            s: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not isinstance(s, str):
            return ""
        
        # Remove null bytes and other dangerous characters
        s = s.replace('\x00', '')
        
        # Truncate if too long
        if len(s) > max_length:
            s = s[:max_length]
            self.logger.warning(f"String truncated to {max_length} characters")
        
        return s
