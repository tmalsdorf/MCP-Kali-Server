"""
Tools package for MCP-Kali-Server.
Contains all security tool implementations with safety guardrails.
"""

from .system_tools import register_system_tools
from .dns_tools import register_dns_tools
from .nmap_tools import register_nmap_tools
from .http_tools import register_http_tools
from .ssl_tools import register_ssl_tools
from .whois_tools import register_whois_tools
from .gobuster_tools import register_gobuster_tools
from .dirb_tools import register_dirb_tools
from .nikto_tools import register_nikto_tools
from .sqlmap_tools import register_sqlmap_tools
from .wpscan_tools import register_wpscan_tools
from .theharvester_tools import register_theharvester_tools
from .shodan_tools import register_shodan_tools
from .crtsh_tools import register_crtsh_tools
from .wayback_tools import register_wayback_tools
from .github_tools import register_github_tools
from .breach_tools import register_breach_tools

__all__ = [
    'register_system_tools',
    'register_dns_tools',
    'register_nmap_tools',
    'register_http_tools',
    'register_ssl_tools',
    'register_whois_tools',
    'register_gobuster_tools',
    'register_dirb_tools',
    'register_nikto_tools',
    'register_sqlmap_tools',
    'register_wpscan_tools',
    'register_theharvester_tools',
    'register_shodan_tools',
    'register_crtsh_tools',
    'register_wayback_tools',
    'register_github_tools',
    'register_breach_tools',
]
